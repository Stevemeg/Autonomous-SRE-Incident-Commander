"""The remediation kernel.

Mirrors :class:`asic.orchestration.kernel.InvestigationKernel`'s durability guarantee
exactly - **at-least-once node execution, with effect-level idempotency** - over a
different graph and a different state shape (ADR-0023). The one behaviour investigation's
kernel does not need and this one does: a run that reaches the end of its graph without
``terminated`` set is not finished, it is **suspended** - most often on an outstanding human
approval - and :meth:`RemediationKernel.resume` is how it continues, hours or days later,
re-reading every durable reference rather than trusting what was true when it suspended.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.remediation_state import (
    RemediationGraphState,
    RemediationObjective,
    remediation_state_summary,
)
from asic.contracts.state import BudgetSnapshot, RunIdentity, TraceContext
from asic.db.models.catalog import Environment
from asic.db.models.evaluation import BehaviourVersion, ExecutionTrace, TraceSpan
from asic.db.models.incident import Incident, WorkflowRun
from asic.db.models.investigation import Hypothesis
from asic.domain.budget import BudgetPolicy, BudgetState
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import HypothesisStatus, IncidentStatus, WorkflowRunStatus
from asic.domain.errors import DomainError, LeaseNotHeld
from asic.llm.port import ModelProvider
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_span_id, derive_trace_id
from asic.orchestration.context import (
    DEFAULT_LEASE_OWNER_PREFIX,
    RunContext,
    SessionFactory,
    UnitOfWork,
)
from asic.orchestration.remediation import checkpoint as ckpt
from asic.orchestration.remediation.context import RemediationDependencies
from asic.orchestration.remediation.graph import RECURSION_LIMIT, build_graph
from asic.tools.broker import ToolBroker
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.provider import ToolProvider

LEASE_DURATION: Final[timedelta] = timedelta(minutes=15)


@dataclass(frozen=True, slots=True)
class RemediationOutcome:
    """What a completed or suspended invocation produced."""

    workflow_run_id: uuid.UUID
    incident_id: uuid.UUID
    execution_trace_id: uuid.UUID
    terminated: bool
    termination_reason: str | None
    incident_status: IncidentStatus
    nodes_executed: tuple[str, ...]
    summary: Mapping[str, Any]


class RemediationKernel:
    """Starts, advances and resumes one remediation run at a time."""

    __slots__ = (
        "_budget_policy",
        "_clock",
        "_lease_owner",
        "_model",
        "_providers",
        "_resolver",
        "_session_factory",
    )

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        resolver: CapabilityResolver,
        providers: Sequence[ToolProvider],
        model: ModelProvider,
        clock: Clock | None = None,
        budget_policy: BudgetPolicy | None = None,
        lease_owner: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._resolver = resolver
        self._providers = tuple(providers)
        self._model = model
        self._clock = clock or SystemClock()
        self._budget_policy = budget_policy or BudgetPolicy()
        self._lease_owner = (
            lease_owner or f"{DEFAULT_LEASE_OWNER_PREFIX}-remediation-{uuid.uuid4().hex[:8]}"
        )

    @property
    def lease_owner(self) -> str:
        return self._lease_owner

    # ------------------------------------------------------------------------ start

    def start(
        self,
        *,
        tenant_id: uuid.UUID,
        incident_id: uuid.UUID,
        hypothesis_id: uuid.UUID,
        behaviour_version_id: uuid.UUID,
        service_ids: list[uuid.UUID],
    ) -> RemediationOutcome:
        """Open a remediation run against an incident that is currently investigating.

        Raises:
            DomainError: the incident is not investigating, or the hypothesis does not
                belong to it, or is not in a state (proposed/accepted) that can justify an
                action. The accepted state machine has no edge into remediation from
                anywhere but ``investigating`` - see ADR-0023.
        """
        uow = UnitOfWork(self._session_factory, tenant_id=tenant_id)
        with uow as session:
            incident = _load_incident(session, tenant_id=tenant_id, incident_id=incident_id)
            if incident.status is not IncidentStatus.INVESTIGATING:
                raise DomainError(
                    f"incident {incident_id} is {incident.status.value}, not investigating; "
                    "remediation only starts against an investigating incident (the accepted "
                    "state machine has no other entry point into it)"
                )
            hypothesis = session.execute(
                sa.select(Hypothesis).where(
                    Hypothesis.tenant_id == tenant_id,
                    Hypothesis.id == hypothesis_id,
                    Hypothesis.incident_id == incident_id,
                )
            ).scalar_one_or_none()
            if hypothesis is None:
                raise DomainError(
                    f"hypothesis {hypothesis_id} does not belong to incident {incident_id}"
                )
            if hypothesis.status not in (HypothesisStatus.PROPOSED, HypothesisStatus.ACCEPTED):
                raise DomainError(
                    f"hypothesis {hypothesis_id} is {hypothesis.status.value}; only a live "
                    "hypothesis can justify a remediation action"
                )
            _assert_behaviour_version(session, behaviour_version_id)

            scope = load_incident_scope(
                session,
                tenant_id=tenant_id,
                incident_id=incident_id,
                environment_id=incident.environment_id,
                service_ids=service_ids,
            )
            environment = session.execute(
                sa.select(Environment).where(
                    Environment.tenant_id == tenant_id, Environment.id == incident.environment_id
                )
            ).scalar_one()

            correlation_id = uuid.uuid4()
            run_started_at = self._clock.now()
            run = WorkflowRun(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident_id,
                behaviour_version_id=behaviour_version_id,
                status=WorkflowRunStatus.RUNNING,
                started_at=run_started_at,
                budget_consumed=BudgetState.initial(self._budget_policy).to_dict(),
                lease_owner=self._lease_owner,
                lease_expires_at=run_started_at + LEASE_DURATION,
            )
            session.add(run)
            session.flush()

            trace_id = derive_trace_id(correlation_id)
            trace_row = ExecutionTrace(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                workflow_run_id=run.id,
                incident_id=incident_id,
                behaviour_version_id=behaviour_version_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                clock_start=run_started_at,
                fixture_refs={},
                started_at=run_started_at,
            )
            session.add(trace_row)
            session.flush()

            identity = RunIdentity(
                tenant_id=str(tenant_id),
                incident_id=str(incident_id),
                workflow_run_id=str(run.id),
                behaviour_version_id=str(behaviour_version_id),
                environment_id=str(incident.environment_id),
                execution_trace_id=str(trace_row.id),
            )
            trace = TraceContext(
                trace_id=trace_id,
                root_span_id=derive_span_id(trace_id, 0),
                correlation_id=str(correlation_id),
            )
            objective = RemediationObjective(
                incident_reference=incident.reference,
                hypothesis_id=str(hypothesis.id),
                hypothesis_statement=hypothesis.statement,
                root_cause_class=hypothesis.root_cause_class,
                service_names=scope.service_names,
                environment_name=environment.name,
                is_production=environment.is_production,
            )
            state: RemediationGraphState = {
                "identity": identity,
                "trace": trace,
                "objective": objective,
                "phase": "planning",
                "remediation_action": None,
                "policy_decision": None,
                "approval": None,
                "verification": None,
                "failures": [],
                "terminated": False,
                "termination_reason": None,
                "target_incident_status": None,
            }
            ckpt.write(
                session,
                state=state,
                reason="run_started",
                after_node=None,
                budget=BudgetState.initial(self._budget_policy),
                clock=self._clock,
            )

        context = RunContext(
            identity=identity, trace=trace, scope=scope, lease_owner=self._lease_owner
        )
        return self._drive(context, objective, state, run_started_at=run_started_at)

    # ----------------------------------------------------------------------- resume

    def resume(self, *, tenant_id: uuid.UUID, workflow_run_id: uuid.UUID) -> RemediationOutcome:
        uow = UnitOfWork(self._session_factory, tenant_id=tenant_id)
        with uow as session:
            run = session.execute(
                sa.select(WorkflowRun).where(
                    WorkflowRun.tenant_id == tenant_id, WorkflowRun.id == workflow_run_id
                )
            ).scalar_one_or_none()
            if run is None:
                raise DomainError(f"workflow run {workflow_run_id} is not visible in this tenant")
            if run.status in (WorkflowRunStatus.COMPLETED, WorkflowRunStatus.FAILED):
                raise DomainError(
                    f"workflow run {workflow_run_id} is {run.status.value}; not resumable"
                )

            self._claim_lease(session, run)

            incident = _load_incident(session, tenant_id=tenant_id, incident_id=run.incident_id)
            trace_row = session.execute(
                sa.select(ExecutionTrace).where(
                    ExecutionTrace.tenant_id == tenant_id, ExecutionTrace.workflow_run_id == run.id
                )
            ).scalar_one()
            checkpoint = ckpt.latest(session, tenant_id=tenant_id, run_id=run.id)
            if checkpoint is None:
                raise DomainError(
                    f"workflow run {workflow_run_id} has no checkpoint; not resumable"
                )

            service_ids = [s.id for s in scope_services(session, incident)]
            scope = load_incident_scope(
                session,
                tenant_id=tenant_id,
                incident_id=incident.id,
                environment_id=incident.environment_id,
                service_ids=service_ids,
            )
            environment = session.execute(
                sa.select(Environment).where(
                    Environment.tenant_id == tenant_id, Environment.id == incident.environment_id
                )
            ).scalar_one()

            identity = RunIdentity(
                tenant_id=str(tenant_id),
                incident_id=str(incident.id),
                workflow_run_id=str(run.id),
                behaviour_version_id=str(run.behaviour_version_id),
                environment_id=str(incident.environment_id),
                execution_trace_id=str(trace_row.id),
            )
            trace = TraceContext(
                trace_id=trace_row.trace_id,
                root_span_id=derive_span_id(trace_row.trace_id, 0),
                correlation_id=str(trace_row.correlation_id),
            )
            hypothesis = session.execute(
                sa.select(Hypothesis)
                .where(
                    Hypothesis.tenant_id == tenant_id,
                    Hypothesis.incident_id == incident.id,
                    Hypothesis.workflow_run_id.in_(
                        sa.select(WorkflowRun.id).where(
                            WorkflowRun.tenant_id == tenant_id,
                            WorkflowRun.incident_id == incident.id,
                        )
                    ),
                )
                .order_by(Hypothesis.rank)
                .limit(1)
            ).scalar_one()
            objective = RemediationObjective(
                incident_reference=incident.reference,
                hypothesis_id=str(hypothesis.id),
                hypothesis_statement=hypothesis.statement,
                root_cause_class=hypothesis.root_cause_class,
                service_names=scope.service_names,
                environment_name=environment.name,
                is_production=environment.is_production,
            )
            run_started_at = trace_row.started_at
            state = ckpt.rehydrate(
                session, checkpoint=checkpoint, identity=identity, trace=trace, objective=objective
            )
            run.status = WorkflowRunStatus.RUNNING
            session.flush()

            span_ordinal = int(
                session.execute(
                    sa.select(sa.func.count())
                    .select_from(TraceSpan)
                    .where(
                        TraceSpan.tenant_id == tenant_id,
                        TraceSpan.execution_trace_id == trace_row.id,
                    )
                ).scalar_one()
            )

        context = RunContext(
            identity=identity, trace=trace, scope=scope, lease_owner=self._lease_owner
        )
        return self._drive(
            context, objective, state, run_started_at=run_started_at, span_ordinal=span_ordinal
        )

    # ------------------------------------------------------------------------ drive

    def _drive(
        self,
        context: RunContext,
        objective: RemediationObjective,
        state: RemediationGraphState,
        *,
        run_started_at: datetime,
        span_ordinal: int = 0,
    ) -> RemediationOutcome:
        tracer = TraceRecorder(
            tenant_id=context.tenant_id,
            execution_trace_id=uuid.UUID(context.identity.execution_trace_id),
            trace_id=context.trace.trace_id,
            clock=self._clock,
            start_ordinal=span_ordinal,
        )
        audit = AuditWriter(tenant_id=context.tenant_id, clock=self._clock)
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        broker = ToolBroker(
            resolver=self._resolver,
            providers=list(self._providers),
            scope=context.scope,
            audit=audit,
            tracer=tracer,
            clock=self._clock,
            claim_session_factory=self._session_factory,
        )
        deps = RemediationDependencies(
            context=context,
            objective=objective,
            unit_of_work=uow,
            broker=broker,
            model=self._model,
            tracer=tracer,
            audit=audit,
            clock=self._clock,
            run_started_at=run_started_at,
            budget_policy=self._budget_policy,
        )
        graph = build_graph(deps)

        executed: list[str] = []
        current = dict(state)
        try:
            uow.begin()
            for chunk in graph.stream(
                state, stream_mode="updates", config={"recursion_limit": RECURSION_LIMIT}
            ):
                for node_name, update in chunk.items():
                    if not isinstance(update, dict):
                        continue
                    executed.append(str(node_name))
                    current = {**current, **update}
                    tracer.flush(uow.session)
                    snapshot = current.get("budget")
                    budget = deps.budget_from(
                        snapshot if isinstance(snapshot, BudgetSnapshot) else None
                    )
                    ckpt.write(
                        uow.session,
                        state=current,  # type: ignore[arg-type]
                        reason="terminal" if current.get("terminated") else "node_boundary",
                        after_node=str(node_name),
                        budget=budget,
                        clock=self._clock,
                    )
                    uow.commit()
                    uow.begin()
            uow.commit()
        except BaseException:
            uow.rollback()
            self._mark_dead_letter(context)
            raise
        finally:
            broker.close()
            if uow.is_open:
                uow.rollback()

        if not current.get("terminated"):
            self._suspend(context)
            incident_status = self._current_incident_status(context)
            return RemediationOutcome(
                workflow_run_id=context.workflow_run_id,
                incident_id=context.incident_id,
                execution_trace_id=uuid.UUID(context.identity.execution_trace_id),
                terminated=False,
                termination_reason=None,
                incident_status=incident_status,
                nodes_executed=tuple(executed),
                summary=remediation_state_summary(current),  # type: ignore[arg-type]
            )

        incident_status = self._finalise(context, current, tracer)
        return RemediationOutcome(
            workflow_run_id=context.workflow_run_id,
            incident_id=context.incident_id,
            execution_trace_id=uuid.UUID(context.identity.execution_trace_id),
            terminated=True,
            termination_reason=current.get("termination_reason"),  # type: ignore[arg-type]
            incident_status=incident_status,
            nodes_executed=tuple(executed),
            summary=remediation_state_summary(current),  # type: ignore[arg-type]
        )

    # -------------------------------------------------------------------- internals

    def _claim_lease(self, session: Session, run: WorkflowRun) -> None:
        now = self._clock.now()
        claimed = session.execute(
            sa.update(WorkflowRun)
            .where(
                WorkflowRun.tenant_id == run.tenant_id,
                WorkflowRun.id == run.id,
                sa.or_(
                    WorkflowRun.lease_owner.is_(None),
                    WorkflowRun.lease_owner == self._lease_owner,
                    WorkflowRun.lease_expires_at < now,
                ),
            )
            .values(lease_owner=self._lease_owner, lease_expires_at=now + LEASE_DURATION)
            .returning(WorkflowRun.id)
        ).scalar_one_or_none()
        if claimed is None:
            raise LeaseNotHeld(
                f"workflow run {run.id} is leased by {run.lease_owner!r}; not advancing it"
            )
        session.flush()

    def _suspend(self, context: RunContext) -> None:
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        with uow as session:
            session.execute(
                sa.update(WorkflowRun)
                .where(
                    WorkflowRun.tenant_id == context.tenant_id,
                    WorkflowRun.id == context.workflow_run_id,
                )
                .values(status=WorkflowRunStatus.SUSPENDED, lease_owner=None, lease_expires_at=None)
            )

    def _mark_dead_letter(self, context: RunContext) -> None:
        try:
            uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
            with uow as session:
                session.execute(
                    sa.update(WorkflowRun)
                    .where(
                        WorkflowRun.tenant_id == context.tenant_id,
                        WorkflowRun.id == context.workflow_run_id,
                    )
                    .values(
                        status=WorkflowRunStatus.DEAD_LETTERED,
                        lease_owner=None,
                        lease_expires_at=None,
                    )
                )
        except Exception:
            return

    def _current_incident_status(self, context: RunContext) -> IncidentStatus:
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        with uow as session:
            incident = _load_incident(
                session, tenant_id=context.tenant_id, incident_id=context.incident_id
            )
            return incident.status

    def _finalise(
        self, context: RunContext, state: Mapping[str, Any], tracer: TraceRecorder
    ) -> IncidentStatus:
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        with uow as session:
            incident = _load_incident(
                session, tenant_id=context.tenant_id, incident_id=context.incident_id
            )
            session.execute(
                sa.update(WorkflowRun)
                .where(
                    WorkflowRun.tenant_id == context.tenant_id,
                    WorkflowRun.id == context.workflow_run_id,
                )
                .values(
                    status=WorkflowRunStatus.COMPLETED,
                    completed_at=self._clock.now(),
                    lease_owner=None,
                    lease_expires_at=None,
                )
            )
            tracer.flush(session)
            session.flush()
            return incident.status


def _load_incident(session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    incident = session.execute(
        sa.select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise DomainError(f"incident {incident_id} is not visible in tenant {tenant_id}")
    return incident


def _assert_behaviour_version(session: Session, behaviour_version_id: uuid.UUID) -> None:
    exists = session.execute(
        sa.select(BehaviourVersion.id).where(BehaviourVersion.id == behaviour_version_id)
    ).scalar_one_or_none()
    if exists is None:
        raise DomainError(f"behaviour version {behaviour_version_id} does not exist")


def scope_services(session: Session, incident: Incident) -> list[Any]:
    from asic.db.models.catalog import Service
    from asic.db.models.incident import Alert

    service_ids = list(
        session.execute(
            sa.select(Alert.service_id)
            .where(
                Alert.tenant_id == incident.tenant_id,
                Alert.incident_id == incident.id,
                Alert.service_id.is_not(None),
            )
            .distinct()
        ).scalars()
    )
    if not service_ids:
        return []
    return list(
        session.execute(
            sa.select(Service).where(
                Service.tenant_id == incident.tenant_id, Service.id.in_(service_ids)
            )
        ).scalars()
    )


__all__ = ["LEASE_DURATION", "RemediationKernel", "RemediationOutcome"]
