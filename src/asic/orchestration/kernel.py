"""The orchestration kernel.

Everything durable about a run happens here: the lease that stops two orchestrators owning
one incident, the transaction boundary at each node, the checkpoint written inside that
transaction, the contract enforcement over what a node returned, and the terminal
transition applied through the Phase 3 incident state machine.

The guarantee, stated exactly and not overstated:

    **At-least-once node execution, with effect-level idempotency.**

A process can die after an adapter has answered and before the transaction commits; the
resumed run will call that adapter again. What cannot happen is a duplicated *effect* - the
broker keys each execution on the effect's business identity and returns the recorded
result instead of invoking twice - or a duplicated durable record, because a resumed run
recomputes the same step sequence and the same idempotency keys. This is not exactly-once,
and calling it exactly-once would be a claim the design does not support.

Why the kernel streams the graph rather than invoking it:
:meth:`~langgraph.graph.state.CompiledStateGraph.stream` yields after each node, which is
the only point at which the kernel can validate the node's update against its contract,
flush its spans, write a checkpoint and commit - all in the transaction the node itself
ran in.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import contract_for
from asic.contracts.state import (
    BudgetSnapshot,
    GraphState,
    InvestigationObjective,
    RunIdentity,
    TraceContext,
    state_summary,
)
from asic.db.models.catalog import Environment, Service
from asic.db.models.evaluation import BehaviourVersion, ExecutionTrace, TraceSpan
from asic.db.models.incident import Alert, Incident, WorkflowRun
from asic.db.projections import append_incident_event, apply_transition, project_timeline
from asic.domain.budget import BudgetLedger, BudgetPolicy, BudgetState
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    IncidentEventType,
    IncidentStatus,
    InvestigationPhase,
    NodeId,
    TerminationReason,
    WorkflowRunStatus,
)
from asic.domain.errors import DomainError, LeaseNotHeld
from asic.domain.idempotency import incident_event_key
from asic.domain.incident_state import allowed_targets, is_terminal
from asic.llm.port import ModelProvider
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_span_id, derive_trace_id
from asic.orchestration.checkpoint import (
    CheckpointStore,
    RehydrationReport,
    rehydrate,
)
from asic.orchestration.context import (
    DEFAULT_LEASE_OWNER_PREFIX,
    NodeDependencies,
    RunContext,
    SessionFactory,
    UnitOfWork,
)
from asic.orchestration.graph import build_graph, recursion_limit_for
from asic.tools.broker import ToolBroker
from asic.tools.capability import CapabilityResolver, IncidentScope, load_incident_scope
from asic.tools.provider import ToolProvider

#: How long a lease is held before it may be reclaimed. Longer than the longest node
#: timeout, so a slow node cannot lose a lease it is still legitimately using.
LEASE_DURATION: Final[timedelta] = timedelta(minutes=15)

#: Called after each node completes, with the node name and its ordinal. Used by the
#: resume tests to simulate a crash at a specific boundary; ``None`` in normal operation.
InterruptProbe = Callable[[str, int], None]


class KernelInterrupted(RuntimeError):
    """Raised by an interrupt probe to simulate process death at a node boundary."""


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """What a completed or interrupted invocation produced."""

    workflow_run_id: uuid.UUID
    incident_id: uuid.UUID
    execution_trace_id: uuid.UUID
    terminated: bool
    termination_reason: TerminationReason | None
    termination_rule_id: str | None
    incident_status: IncidentStatus
    nodes_executed: tuple[str, ...]
    checkpoints_written: int
    resumed_count: int
    summary: Mapping[str, Any]
    rehydration: RehydrationReport | None = None


class InvestigationKernel:
    """Starts, advances and resumes one investigation at a time."""

    __slots__ = (
        "_budget_policy",
        "_clock",
        "_interrupt",
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
        providers: list[ToolProvider],
        model: ModelProvider,
        clock: Clock | None = None,
        budget_policy: BudgetPolicy | None = None,
        lease_owner: str | None = None,
        interrupt_probe: InterruptProbe | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._resolver = resolver
        self._providers = providers
        self._model = model
        self._clock = clock or SystemClock()
        self._budget_policy = budget_policy or BudgetPolicy()
        self._lease_owner = lease_owner or f"{DEFAULT_LEASE_OWNER_PREFIX}-{uuid.uuid4().hex[:8]}"
        self._interrupt = interrupt_probe

    @property
    def lease_owner(self) -> str:
        return self._lease_owner

    # ------------------------------------------------------------------------ start

    def start(
        self,
        *,
        tenant_id: uuid.UUID,
        incident_id: uuid.UUID,
        behaviour_version_id: uuid.UUID,
        service_ids: list[uuid.UUID],
        fixture_refs: Mapping[str, Any] | None = None,
        random_seed: int | None = None,
    ) -> RunOutcome:
        """Open a run for an incident and drive it until it stops or is interrupted."""
        uow = UnitOfWork(self._session_factory, tenant_id=tenant_id)
        with uow as session:
            incident = _load_incident(session, tenant_id=tenant_id, incident_id=incident_id)
            _assert_startable(incident)
            scope = load_incident_scope(
                session,
                tenant_id=tenant_id,
                incident_id=incident_id,
                environment_id=incident.environment_id,
                service_ids=service_ids,
            )
            _assert_behaviour_version(session, behaviour_version_id)

            correlation_id = uuid.uuid4()
            run_started_at = self._clock.now()
            run = WorkflowRun(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident_id,
                behaviour_version_id=behaviour_version_id,
                status=WorkflowRunStatus.RUNNING,
                started_at=self._clock.now(),
                budget_consumed=BudgetState.initial(self._budget_policy).to_dict(),
                lease_owner=self._lease_owner,
                lease_expires_at=self._clock.now() + LEASE_DURATION,
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
                clock_start=self._clock.now(),
                random_seed=random_seed,
                fixture_refs=dict(fixture_refs or {}),
                started_at=self._clock.now(),
            )
            session.add(trace_row)
            session.flush()

            if incident.status is not IncidentStatus.INVESTIGATING:
                apply_transition(
                    session,
                    incident=incident,
                    target=IncidentStatus.INVESTIGATING,
                    actor_type=ActorType.SYSTEM,
                    source=NodeId.G2_INCIDENT_COORDINATOR.value,
                    correlation_id=correlation_id,
                )

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
            objective = _objective(session, incident, scope)
            state = _initial_state(identity, trace, objective, self._budget_policy)

        context = RunContext(
            identity=identity, trace=trace, scope=scope, lease_owner=self._lease_owner
        )
        return self._drive(context, objective, state, resumed=False, run_started_at=run_started_at)

    # ----------------------------------------------------------------------- resume

    def resume(self, *, tenant_id: uuid.UUID, workflow_run_id: uuid.UUID) -> RunOutcome:
        """Reclaim a run and continue it from its last checkpoint.

        Reconciles before resuming: working state is rebuilt from durable rows, and the
        checkpoint contributes only the ephemeral remainder. If the two disagree about how
        much was written, the rows win and the divergence is recorded - the rows are what
        actually happened.
        """
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
                    f"workflow run {workflow_run_id} is {run.status.value}; a finished run "
                    "is not resumed, a new run is opened"
                )

            self._claim_lease(session, run)

            incident = _load_incident(session, tenant_id=tenant_id, incident_id=run.incident_id)
            trace_row = session.execute(
                sa.select(ExecutionTrace).where(
                    ExecutionTrace.tenant_id == tenant_id,
                    ExecutionTrace.workflow_run_id == run.id,
                )
            ).scalar_one()

            checkpoint = CheckpointStore.latest(session, tenant_id=tenant_id, run_id=run.id)
            if checkpoint is None:
                raise DomainError(
                    f"workflow run {workflow_run_id} has no checkpoint; there is nothing to "
                    "resume from and the run must be dead-lettered for inspection"
                )

            service_ids = [service.id for service in _services_of(session, incident)]
            scope = load_incident_scope(
                session,
                tenant_id=tenant_id,
                incident_id=incident.id,
                environment_id=incident.environment_id,
                service_ids=service_ids,
            )
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
            objective = _objective(session, incident, scope)
            # The original start, not now: an interruption must not hand a run a fresh
            # wall-clock allowance.
            run_started_at = trace_row.started_at
            state, report = rehydrate(
                session,
                checkpoint=checkpoint,
                identity=identity,
                trace=trace,
                objective=objective,
            )
            run.resumed_count = state["resumed_count"]
            run.status = WorkflowRunStatus.RUNNING
            session.flush()

            # Continue the trace's span numbering rather than restarting it: this is the
            # same trace, and a restarted ordinal would collide with the spans the
            # interrupted attempt already committed.
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

            append_incident_event(
                session,
                incident=incident,
                event_type=IncidentEventType.WORKFLOW_RESUMED,
                source=NodeId.G2_INCIDENT_COORDINATOR.value,
                actor_type=ActorType.SYSTEM,
                correlation_id=uuid.UUID(trace.correlation_id),
                payload={
                    "workflow_run_id": str(run.id),
                    "resumed_count": run.resumed_count,
                    "from_checkpoint": checkpoint.sequence,
                    "reconciliation": report.describe(),
                    "diverged": report.diverged,
                },
                idempotency_key=incident_event_key(
                    tenant_id=tenant_id,
                    incident_id=incident.id,
                    event_type=IncidentEventType.WORKFLOW_RESUMED.value,
                    subject_id=run.id,
                    occurrence_discriminator=str(run.resumed_count),
                ),
            )

        context = RunContext(
            identity=identity, trace=trace, scope=scope, lease_owner=self._lease_owner
        )
        return self._drive(
            context,
            objective,
            state,
            resumed=True,
            run_started_at=run_started_at,
            rehydration=report,
            span_ordinal=span_ordinal,
        )

    # ------------------------------------------------------------------------ drive

    def _drive(
        self,
        context: RunContext,
        objective: InvestigationObjective,
        state: GraphState,
        *,
        resumed: bool,
        run_started_at: datetime,
        rehydration: RehydrationReport | None = None,
        span_ordinal: int = 0,
    ) -> RunOutcome:
        """Run the graph, committing and checkpointing at every node boundary.

        ``run_started_at`` is the instant the *run* began, taken from the execution trace,
        so a resumed run keeps counting from the original start rather than restarting its
        wall clock. That is what makes the wall-clock budget a deadline on the incident
        rather than a per-attempt allowance an interruption could reset.
        """
        tracer = TraceRecorder(
            tenant_id=context.tenant_id,
            execution_trace_id=uuid.UUID(context.identity.execution_trace_id),
            trace_id=context.trace.trace_id,
            clock=self._clock,
            start_ordinal=span_ordinal,
        )
        audit = AuditWriter(tenant_id=context.tenant_id, clock=self._clock)
        checkpoints = CheckpointStore(clock=self._clock)
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        broker = ToolBroker(
            resolver=self._resolver,
            providers=self._providers,
            scope=context.scope,
            audit=audit,
            tracer=tracer,
            clock=self._clock,
        )
        deps = NodeDependencies(
            context=context,
            objective=objective,
            unit_of_work=uow,
            broker=broker,
            model=self._model,
            tracer=tracer,
            audit=audit,
            checkpoints=checkpoints,
            clock=self._clock,
            run_started_at=run_started_at,
            budget_policy=self._budget_policy,
        )
        graph = build_graph(deps)

        executed: list[str] = []
        written = 0
        # Seed the elapsed total before the first node runs. A resumed run has already been
        # going for a while, and without this its first planning step would see a wall clock
        # of zero and take a step it had no time left for.
        state = _observe_elapsed(  # type: ignore[assignment]
            dict(state), self._budget_policy, self._clock.now(), run_started_at
        )
        current = dict(state)
        interrupted = False

        try:
            uow.begin()
            written += self._checkpoint(
                deps, current, reason="run_started" if not resumed else "node_boundary", node=None
            )
            uow.commit()

            uow.begin()
            for chunk in graph.stream(
                state,
                stream_mode="updates",
                config={"recursion_limit": recursion_limit_for(self._budget_policy.max_iterations)},
            ):
                for node_name, update in _updates(chunk):
                    executed.append(node_name)
                    self._validate(node_name, update)
                    current = _merge(current, update)
                    # Measure the wall clock here, at the boundary, so the next planning
                    # step's pre-flight budget check sees the real elapsed total. Without
                    # this the wall-clock limit would be a number nothing ever compared
                    # against, and a run could exceed its deadline indefinitely so long as
                    # it stayed under the iteration count.
                    current = _observe_elapsed(
                        current, self._budget_policy, self._clock.now(), run_started_at
                    )
                    tracer.flush(uow.session)
                    written += self._checkpoint(
                        deps,
                        current,
                        reason="terminal" if current.get("terminated") else "node_boundary",
                        node=node_name,
                    )
                    self._record_progress(deps, current)
                    uow.commit()
                    if self._interrupt is not None:
                        # Only reached in tests. Raising here simulates process death after
                        # a committed node boundary, which is exactly the state a real
                        # crash leaves behind.
                        self._interrupt(node_name, len(executed))
                    uow.begin()
            uow.commit()
        except KernelInterrupted:
            interrupted = True
            uow.rollback()
        except BaseException:
            uow.rollback()
            self._mark_dead_letter(context)
            raise
        finally:
            broker.close()
            if uow.is_open:
                uow.rollback()

        if interrupted:
            self._suspend(context)
            return _outcome(
                context, current, executed, written, terminated=False, rehydration=rehydration
            )

        status = self._finalise(context, current, tracer)
        return _outcome(
            context,
            current,
            executed,
            written,
            terminated=bool(current.get("terminated")),
            incident_status=status,
            rehydration=rehydration,
        )

    # -------------------------------------------------------------------- internals

    @staticmethod
    def _validate(node_name: str, update: Mapping[str, Any]) -> None:
        """Enforce the node's declared state mutations.

        Raises:
            ContractViolation: naming the node, the keys and the contract version.
        """
        contract_for(node_name).validate_update(update)

    def _checkpoint(
        self,
        deps: NodeDependencies,
        state: Mapping[str, Any],
        *,
        reason: str,
        node: str | None,
    ) -> int:
        budget = _budget_of(state, self._budget_policy)
        deps.checkpoints.write(
            deps.session,
            state=dict(state),  # type: ignore[arg-type]
            reason=reason,
            after_node=node,
            budget=budget,
        )
        return 1

    def _record_progress(self, deps: NodeDependencies, state: Mapping[str, Any]) -> None:
        """Persist the run's budget ledger alongside the checkpoint."""
        budget = _budget_of(state, self._budget_policy)
        deps.session.execute(
            sa.update(WorkflowRun)
            .where(
                WorkflowRun.tenant_id == deps.context.tenant_id,
                WorkflowRun.id == deps.context.workflow_run_id,
            )
            .values(
                budget_consumed=budget.to_dict(),
                lease_expires_at=self._clock.now() + LEASE_DURATION,
            )
        )

    def _claim_lease(self, session: Session, run: WorkflowRun) -> None:
        """Take the lease, or refuse to advance the run.

        A single conditional UPDATE, so two orchestrators racing produce one winner. Losing
        the race stops work immediately rather than retrying: two orchestrators advancing
        one incident is the failure with the worst consequence this system can have.
        """
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
                f"workflow run {run.id} is leased by {run.lease_owner!r} until "
                f"{run.lease_expires_at}; this worker will not advance it"
            )
        session.flush()

    def _suspend(self, context: RunContext) -> None:
        """Mark an interrupted run resumable, and release the lease."""
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        with uow as session:
            session.execute(
                sa.update(WorkflowRun)
                .where(
                    WorkflowRun.tenant_id == context.tenant_id,
                    WorkflowRun.id == context.workflow_run_id,
                )
                .values(
                    status=WorkflowRunStatus.SUSPENDED,
                    lease_owner=None,
                    lease_expires_at=None,
                )
            )

    def _mark_dead_letter(self, context: RunContext) -> None:
        """Record a run that failed in a way the graph could not express.

        Best-effort by design: if the database is what failed, this cannot succeed either,
        and raising a second exception would hide the first.
        """
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

    def _finalise(
        self, context: RunContext, state: Mapping[str, Any], tracer: TraceRecorder
    ) -> IncidentStatus:
        """Apply the terminal transition, close the run, and project the timeline."""
        uow = UnitOfWork(self._session_factory, tenant_id=context.tenant_id)
        with uow as session:
            incident = _load_incident(
                session, tenant_id=context.tenant_id, incident_id=context.incident_id
            )
            reason_value = state.get("termination_reason")
            target_value = state.get("terminal_incident_status")
            reason = TerminationReason(reason_value) if reason_value else None

            if state.get("terminated") and target_value:
                target = IncidentStatus(target_value)
                if target is not incident.status and target in allowed_targets(incident.status):
                    apply_transition(
                        session,
                        incident=incident,
                        target=target,
                        actor_type=ActorType.SYSTEM,
                        source=NodeId.G2_INCIDENT_COORDINATOR.value,
                        correlation_id=context.correlation_id,
                        termination_reason=reason,
                    )
                    append_incident_event(
                        session,
                        incident=incident,
                        event_type=IncidentEventType.INCIDENT_TERMINATED,
                        source=NodeId.G2_INCIDENT_COORDINATOR.value,
                        actor_type=ActorType.SYSTEM,
                        correlation_id=context.correlation_id,
                        payload={
                            "termination_reason": reason.value if reason else None,
                            "rule_id": state.get("termination_rule_id"),
                            "workflow_run_id": context.identity.workflow_run_id,
                        },
                        idempotency_key=incident_event_key(
                            tenant_id=context.tenant_id,
                            incident_id=context.incident_id,
                            event_type=IncidentEventType.INCIDENT_TERMINATED.value,
                            subject_id=context.workflow_run_id,
                        ),
                    )

            budget = _budget_of(state, self._budget_policy)
            session.execute(
                sa.update(WorkflowRun)
                .where(
                    WorkflowRun.tenant_id == context.tenant_id,
                    WorkflowRun.id == context.workflow_run_id,
                )
                .values(
                    status=(
                        WorkflowRunStatus.COMPLETED
                        if state.get("terminated")
                        else WorkflowRunStatus.SUSPENDED
                    ),
                    completed_at=self._clock.now() if state.get("terminated") else None,
                    termination_reason=reason,
                    budget_consumed=budget.to_dict(),
                    lease_owner=None,
                    lease_expires_at=None,
                )
            )
            session.execute(
                sa.update(ExecutionTrace)
                .where(
                    ExecutionTrace.tenant_id == context.tenant_id,
                    ExecutionTrace.id == uuid.UUID(context.identity.execution_trace_id),
                )
                .values(
                    completed_at=self._clock.now(),
                    termination_reason=reason,
                    total_tokens=budget.ledger.tokens,
                    total_cost_usd=budget.ledger.cost_usd,
                    total_tool_calls=budget.ledger.tool_calls,
                )
            )
            tracer.flush(session)
            project_timeline(session, tenant_id=context.tenant_id, incident_id=context.incident_id)
            session.flush()
            return incident.status


# ------------------------------------------------------------------------------ helpers


def _updates(chunk: Any) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """Yield ``(node_name, update)`` from one ``stream_mode="updates"`` chunk."""
    if not isinstance(chunk, dict):  # pragma: no cover - defensive
        return
    for node_name, update in chunk.items():
        if isinstance(update, dict):
            yield str(node_name), update


def _merge(current: dict[str, Any], update: Mapping[str, Any]) -> dict[str, Any]:
    """Apply an update the way the graph's reducers do.

    The kernel keeps its own copy because it checkpoints between nodes, and LangGraph's
    internal state is not exposed mid-stream. The additive keys must be appended here for
    the same reason they are annotated with ``operator.add`` in the state: replacing them
    would silently discard everything gathered before this node.
    """
    merged = dict(current)
    for key, value in update.items():
        if key in ("evidence", "steps", "hypotheses", "failures") and isinstance(value, list):
            merged[key] = [*merged.get(key, []), *value]
        else:
            merged[key] = value
    return merged


def _observe_elapsed(
    state: dict[str, Any],
    policy: BudgetPolicy,
    now: datetime,
    run_started_at: datetime,
) -> dict[str, Any]:
    """Write the run's wall-clock total into the state's budget snapshot.

    Measured against the run's start rather than summed from node durations, so it counts
    the gaps between nodes and the time a suspended run spent waiting - which is what a
    deadline on an incident actually means.
    """
    elapsed = max(0.0, (now - run_started_at).total_seconds())
    budget = _budget_of(state, policy).observe_elapsed(elapsed)
    updated = dict(state)
    kind = budget.exhausted_kind()
    updated["budget"] = BudgetSnapshot(
        consumed=budget.ledger.to_dict(),
        remaining=budget.remaining(),
        exhausted_kind=kind.value if kind else None,
    )
    return updated


def _budget_of(state: Mapping[str, Any], policy: BudgetPolicy) -> BudgetState:
    snapshot = state.get("budget")
    if snapshot is None:
        return BudgetState.initial(policy)
    consumed = snapshot.consumed if isinstance(snapshot, BudgetSnapshot) else snapshot["consumed"]
    return BudgetState(policy=policy, ledger=BudgetLedger.from_dict(consumed))


def _initial_state(
    identity: RunIdentity,
    trace: TraceContext,
    objective: InvestigationObjective,
    policy: BudgetPolicy,
) -> GraphState:
    budget = BudgetState.initial(policy)
    return {
        "identity": identity,
        "trace": trace,
        "objective": objective,
        "phase": InvestigationPhase.INITIALISING,
        "iteration": 0,
        "resumed_count": 0,
        "evidence": [],
        "steps": [],
        "hypotheses": [],
        "failures": [],
        "open_gaps": [],
        "covered_domains": [],
        "degraded_domains": [],
        "capability_menu": [],
        "last_decision": None,
        "budget": BudgetSnapshot(consumed=budget.ledger.to_dict(), remaining=budget.remaining()),
        "budget_refusal": None,
        "pending_approval": None,
        "terminated": False,
        "termination_reason": None,
        "termination_rule_id": None,
        "terminal_incident_status": None,
    }


def _outcome(
    context: RunContext,
    state: Mapping[str, Any],
    executed: list[str],
    checkpoints: int,
    *,
    terminated: bool,
    incident_status: IncidentStatus | None = None,
    rehydration: RehydrationReport | None = None,
) -> RunOutcome:
    reason_value = state.get("termination_reason")
    return RunOutcome(
        workflow_run_id=context.workflow_run_id,
        incident_id=context.incident_id,
        execution_trace_id=uuid.UUID(context.identity.execution_trace_id),
        terminated=terminated,
        termination_reason=TerminationReason(reason_value) if reason_value else None,
        termination_rule_id=state.get("termination_rule_id"),
        incident_status=incident_status or IncidentStatus.INVESTIGATING,
        nodes_executed=tuple(executed),
        checkpoints_written=checkpoints,
        resumed_count=int(state.get("resumed_count", 0)),
        summary=state_summary(state),  # type: ignore[arg-type]
        rehydration=rehydration,
    )


def _load_incident(session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    incident = session.execute(
        sa.select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    ).scalar_one_or_none()
    if incident is None:
        raise DomainError(
            f"incident {incident_id} is not visible in tenant {tenant_id}; row-level "
            "security is denying it, or it does not exist"
        )
    return incident


def _assert_startable(incident: Incident) -> None:
    if is_terminal(incident.status):
        raise DomainError(
            f"incident {incident.id} is {incident.status.value}, which is terminal; a "
            "terminal incident is not reinvestigated, a new incident is opened"
        )


def _assert_behaviour_version(session: Session, behaviour_version_id: uuid.UUID) -> None:
    exists = session.execute(
        sa.select(BehaviourVersion.id).where(BehaviourVersion.id == behaviour_version_id)
    ).scalar_one_or_none()
    if exists is None:
        raise DomainError(
            f"behaviour version {behaviour_version_id} does not exist; a run that cannot "
            "name the behaviour that produced it is not evaluable"
        )


def _services_of(session: Session, incident: Incident) -> list[Service]:
    """The services an incident is about, derived from the alerts attached to it.

    Read from durable rows rather than carried in the run's state, so a resumed run
    resolves exactly the same scope as the original. An incident whose alerts name no
    service resolves to an empty scope, and the collector then refuses to invent a target.
    """
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
            sa.select(Service)
            .where(Service.tenant_id == incident.tenant_id, Service.id.in_(service_ids))
            .order_by(Service.name)
        ).scalars()
    )


def _objective(
    session: Session, incident: Incident, scope: IncidentScope
) -> InvestigationObjective:
    """Resolve what the investigation is trying to establish, from durable rows only.

    Never from model output: an objective a model could rewrite would let it choose its own
    scope, and the window and service set are what bound every subsequent query.
    """
    environment = session.execute(
        sa.select(Environment).where(
            Environment.tenant_id == incident.tenant_id,
            Environment.id == incident.environment_id,
        )
    ).scalar_one()
    window_end = incident.opened_at
    window_start = window_end - timedelta(hours=1)
    return InvestigationObjective(
        statement=f"Determine the cause of: {incident.title}",
        service_names=scope.service_names,
        environment_name=environment.name,
        window_start=window_start.astimezone(UTC).isoformat(),
        window_end=window_end.astimezone(UTC).isoformat(),
        severity=incident.severity.value,
    )


__all__ = [
    "LEASE_DURATION",
    "InterruptProbe",
    "InvestigationKernel",
    "KernelInterrupted",
    "RunOutcome",
]
