"""The kernel: leasing, contract enforcement, checkpointing and resume.

These are the durability tests. They run against a real database because everything they
assert - the lease's atomicity, the checkpoint's ordering, the fact that a resumed run does
not duplicate committed effects - is a property of committed rows rather than of the code
that wrote them.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    AuditRecord,
    Evidence,
    ExecutionTrace,
    Hypothesis,
    IncidentEvent,
    InvestigationStep,
    ToolExecution,
    TraceSpan,
    WorkflowCheckpoint,
    WorkflowRun,
)
from asic.domain.budget import BudgetPolicy
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    IncidentEventType,
    IncidentStatus,
    TerminationReason,
    WorkflowRunStatus,
)
from asic.domain.errors import DomainError, LeaseNotHeld
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.checkpoint import CheckpointStore, digest_state
from asic.orchestration.kernel import InvestigationKernel, KernelInterrupted
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, Scenario, scenario
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import Fixture, build_fixture

pytestmark = requires_postgres


def _kernel(
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
    scenario_obj: Scenario,
    *,
    interrupt_probe: Callable[[str, int], None] | None = None,
    lease_owner: str | None = None,
    budget_policy: BudgetPolicy | None = None,
    model: DeterministicModelProvider | None = None,
) -> InvestigationKernel:
    return InvestigationKernel(
        session_factory=session_factory,
        resolver=resolver,
        providers=[SimulatorProvider(scenario_obj, clock=clock)],
        model=model or DeterministicModelProvider(scenario_obj),
        clock=clock,
        budget_policy=budget_policy or scenario_obj.budget or BudgetPolicy(),
        lease_owner=lease_owner,
        interrupt_probe=interrupt_probe,
    )


@pytest.fixture
def fixture(kernel_session: Session) -> Fixture:
    created = build_fixture(kernel_session, slug="kernel-tenant")
    kernel_session.commit()
    return created


class TestStart:
    def test_a_run_reaches_a_terminal_state(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
            fixture_refs=primary_scenario.fixture_ref(),
        )
        assert outcome.terminated is True
        assert outcome.termination_reason is not None
        assert outcome.termination_rule_id is not None

    def test_the_run_is_recorded_as_completed(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        run = kernel_session.execute(
            sa.select(WorkflowRun).where(WorkflowRun.id == outcome.workflow_run_id)
        ).scalar_one()
        assert run.status is WorkflowRunStatus.COMPLETED
        assert run.completed_at is not None
        assert run.lease_owner is None, "the lease is released when the run ends"

    def test_a_terminal_incident_is_not_reinvestigated(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        closed = build_fixture(
            kernel_session, slug="kernel-closed", incident_status=IncidentStatus.DETECTED
        )
        kernel_session.execute(
            sa.update(type(closed.incident))
            .where(type(closed.incident).id == closed.incident.id)
            .values(
                status=IncidentStatus.FAILED,
                terminated_at=clock.now(),
                termination_reason=TerminationReason.UNRECOVERABLE_FAILURE,
            )
        )
        kernel_session.commit()

        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        with pytest.raises(DomainError, match="terminal"):
            kernel.start(
                tenant_id=closed.tenant_id,
                incident_id=closed.incident.id,
                behaviour_version_id=closed.behaviour_version.id,
                service_ids=closed.service_ids,
            )

    def test_an_unknown_behaviour_version_is_refused(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        with pytest.raises(DomainError, match="behaviour version"):
            kernel.start(
                tenant_id=fixture.tenant_id,
                incident_id=fixture.incident.id,
                behaviour_version_id=uuid.uuid4(),
                service_ids=fixture.service_ids,
            )

    def test_an_incident_in_another_tenant_is_invisible(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        with pytest.raises(DomainError, match="not visible"):
            kernel.start(
                tenant_id=uuid.uuid4(),
                incident_id=fixture.incident.id,
                behaviour_version_id=fixture.behaviour_version.id,
                service_ids=fixture.service_ids,
            )


class TestCheckpointing:
    def test_checkpoints_are_written_at_every_node_boundary(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        rows = list(
            kernel_session.execute(
                sa.select(WorkflowCheckpoint)
                .where(WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id)
                .order_by(WorkflowCheckpoint.sequence)
            ).scalars()
        )
        assert len(rows) == len(outcome.nodes_executed) + 1, "one per node, plus run start"
        assert rows[0].reason == "run_started"
        assert rows[-1].reason == "terminal"
        assert [row.sequence for row in rows] == list(range(1, len(rows) + 1))

    def test_the_checkpoint_sequence_has_no_gaps(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        gaps = CheckpointStore.sequence_gaps(
            kernel_session, tenant_id=fixture.tenant_id, run_id=outcome.workflow_run_id
        )
        assert gaps == []

    def test_a_checkpoint_carries_no_evidence_content(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        # The checkpoint holds the ephemeral remainder only. Copying evidence into it would
        # create a second source of truth that diverges on the first partial resume.
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        latest = CheckpointStore.latest(
            kernel_session, tenant_id=fixture.tenant_id, run_id=outcome.workflow_run_id
        )
        assert latest is not None
        assert "evidence" not in latest.state
        assert "steps" not in latest.state
        assert "hypotheses" not in latest.state
        assert latest.durable_counts["evidence"] >= 1, "the counts are recorded instead"

    def test_the_state_digest_matches_the_stored_state(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        for row in kernel_session.execute(
            sa.select(WorkflowCheckpoint).where(
                WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id
            )
        ).scalars():
            assert digest_state(row.state) == row.state_digest


class TestResume:
    def _interrupt_after(self, node: str) -> Callable[[str, int], None]:
        def probe(name: str, _ordinal: int) -> None:
            if name == node:
                raise KernelInterrupted(f"simulated process death after {name}")

        return probe

    def test_an_interrupted_run_is_suspended_and_resumable(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=self._interrupt_after("evidence_collector"),
        )
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        assert outcome.terminated is False
        run = kernel_session.execute(
            sa.select(WorkflowRun).where(WorkflowRun.id == outcome.workflow_run_id)
        ).scalar_one()
        assert run.status is WorkflowRunStatus.SUSPENDED
        assert run.lease_owner is None, "an interrupted run releases its lease"

    def test_resuming_continues_to_a_terminal_state_without_duplicating_effects(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        crashing = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=self._interrupt_after("evidence_collector"),
            lease_owner="worker-a",
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        assert first.terminated is False

        before = _counts(kernel_session, fixture.tenant_id, first.workflow_run_id)
        assert before["steps"] >= 1
        assert before["evidence"] >= 1

        # A fresh kernel, as a restarted process would be: new model and simulator
        # instances with no memory of the first attempt.
        resuming = _kernel(
            session_factory, resolver, clock, primary_scenario, lease_owner="worker-b"
        )
        second = resuming.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)

        assert second.workflow_run_id == first.workflow_run_id, "the run id survives"
        assert second.resumed_count == 1
        assert second.terminated is True

        after = _counts(kernel_session, fixture.tenant_id, first.workflow_run_id)
        assert after["evidence"] >= before["evidence"]
        assert after["tool_executions"] >= before["tool_executions"]

        # The effect-level guarantee: no two tool executions share an idempotency key.
        keys = list(
            kernel_session.execute(
                sa.select(ToolExecution.idempotency_key).where(
                    ToolExecution.tenant_id == fixture.tenant_id
                )
            ).scalars()
        )
        assert len(keys) == len(set(keys)), "a duplicated effect was recorded"

    def test_a_resume_records_a_workflow_resumed_event(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        crashing = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=self._interrupt_after("planner"),
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        resuming = _kernel(session_factory, resolver, clock, primary_scenario)
        resuming.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)

        events = list(
            kernel_session.execute(
                sa.select(IncidentEvent).where(
                    IncidentEvent.tenant_id == fixture.tenant_id,
                    IncidentEvent.event_type == IncidentEventType.WORKFLOW_RESUMED,
                )
            ).scalars()
        )
        assert len(events) == 1
        assert events[0].payload["resumed_count"] == 1
        assert "reconciliation" in events[0].payload

    def test_the_resume_reconciles_against_durable_rows(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        crashing = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=self._interrupt_after("evidence_collector"),
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        resuming = _kernel(session_factory, resolver, clock, primary_scenario)
        second = resuming.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)
        assert second.rehydration is not None
        assert second.rehydration.diverged is False, second.rehydration.describe()

    def test_a_completed_run_is_not_resumed(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        with pytest.raises(DomainError, match="is completed"):
            kernel.resume(tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id)


class TestLeasing:
    def test_a_second_worker_cannot_advance_a_leased_run(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        # Two orchestrators advancing one incident is the failure with the worst
        # consequence this system can have, so losing the race stops work immediately.
        crashing = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=lambda name, _o: (
                (_ for _ in ()).throw(KernelInterrupted(name)) if name == "planner" else None
            ),
            lease_owner="worker-a",
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        # Re-take the lease as if worker-a were still alive and holding it.
        kernel_session.execute(
            sa.update(WorkflowRun)
            .where(WorkflowRun.id == first.workflow_run_id)
            .values(lease_owner="worker-a", lease_expires_at=clock.now().replace(year=2099))
        )
        kernel_session.commit()

        other = _kernel(session_factory, resolver, clock, primary_scenario, lease_owner="worker-b")
        with pytest.raises(LeaseNotHeld, match="worker-a"):
            other.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)

    def test_an_expired_lease_may_be_reclaimed(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        crashing = _kernel(
            session_factory,
            resolver,
            clock,
            primary_scenario,
            interrupt_probe=lambda name, _o: (
                (_ for _ in ()).throw(KernelInterrupted(name)) if name == "planner" else None
            ),
            lease_owner="worker-a",
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        kernel_session.execute(
            sa.update(WorkflowRun)
            .where(WorkflowRun.id == first.workflow_run_id)
            .values(lease_owner="worker-a", lease_expires_at=clock.now().replace(year=2000))
        )
        kernel_session.commit()

        other = _kernel(session_factory, resolver, clock, primary_scenario, lease_owner="worker-b")
        outcome = other.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)
        assert outcome.workflow_run_id == first.workflow_run_id


class TestPersistedArtefacts:
    def test_a_run_produces_a_trace_with_spans(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.id == outcome.execution_trace_id)
        ).scalar_one()
        assert trace.completed_at is not None
        assert trace.termination_reason is not None

        spans = list(
            kernel_session.execute(
                sa.select(TraceSpan).where(TraceSpan.execution_trace_id == trace.id)
            ).scalars()
        )
        assert spans, "a run with no spans is not evaluable"

    def test_a_run_produces_audit_records(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        count = kernel_session.execute(
            sa.select(sa.func.count())
            .select_from(AuditRecord)
            .where(AuditRecord.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert count >= 1

    def test_every_evidence_row_references_the_query_that_produced_it(
        self,
        fixture: Fixture,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
        kernel_session: Session,
    ) -> None:
        kernel = _kernel(session_factory, resolver, clock, primary_scenario)
        kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        rows = list(
            kernel_session.execute(
                sa.select(Evidence).where(Evidence.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert rows, "the primary scenario gathers evidence"
        for row in rows:
            assert row.tool_execution_id is not None
            assert row.citation.get("tool"), "evidence carries its citation"


def _counts(session: Session, tenant_id: uuid.UUID, run_id: uuid.UUID) -> dict[str, int]:
    def count(model: type, *where: object) -> int:
        return int(
            session.execute(
                sa.select(sa.func.count()).select_from(model).where(*where)  # type: ignore[arg-type]
            ).scalar_one()
        )

    return {
        "steps": count(
            InvestigationStep,
            InvestigationStep.tenant_id == tenant_id,
            InvestigationStep.workflow_run_id == run_id,
        ),
        "evidence": count(Evidence, Evidence.tenant_id == tenant_id),
        "hypotheses": count(
            Hypothesis,
            Hypothesis.tenant_id == tenant_id,
            Hypothesis.workflow_run_id == run_id,
        ),
        "tool_executions": count(ToolExecution, ToolExecution.tenant_id == tenant_id),
    }


def test_scenario_registry_is_reachable() -> None:
    assert scenario(PRIMARY_SCENARIO_ID).scenario_id == PRIMARY_SCENARIO_ID
