"""Lifecycle metrics for transitions written as Core ``UPDATE`` statements.

INTEGRATION: real PostgreSQL, real transactions. Workflow-run and remediation-action
lifecycles are written with Core statements rather than ORM attribute mutation, so the
unit-of-work listeners never saw them and ``asic_workflow_runs_finished_total`` stayed
empty while runs completed and dead-lettered in the database. The alert on
dead-lettered runs could therefore never fire.

What must hold after the fix is both halves at once: a *committed* Core transition counts
exactly once, and a rolled-back one - including inside a savepoint - counts not at all.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import Environment, Incident, RemediationAction, Tenant, WorkflowRun
from asic.db.session import bind_tenant
from asic.domain.enums import (
    IncidentSeverity,
    IncidentStatus,
    RemediationActionStatus,
    RiskTier,
    TenantStatus,
    WorkflowRunStatus,
)
from asic.observability import lifecycle
from asic.observability.setup import Telemetry
from tests.conftest import make_behaviour_version
from tests.observability.conftest import sample

pytestmark = pytest.mark.postgres


@pytest.fixture
def world(owner_engine: Engine) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    with Session(owner_engine) as session, session.begin():
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=f"core-{uuid.uuid4().hex[:10]}",
            display_name="core update",
            status=TenantStatus.ACTIVE,
        )
        session.add(tenant)
        session.flush()
        bind_tenant(session, tenant.id)
        environment = Environment(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="core",
            display_name="core",
            is_production=False,
        )
        session.add(environment)
        behaviour = make_behaviour_version(session, label=f"core-{uuid.uuid4().hex[:8]}")
        return tenant.id, environment.id, behaviour.id


def _factory(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def _incident(tenant_id: uuid.UUID, environment_id: uuid.UUID) -> Incident:
    return Incident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        reference=f"CORE-{uuid.uuid4().hex[:8]}",
        title="core update probe",
        environment_id=environment_id,
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.SEV4,
        opened_at=datetime.now(UTC),
    )


def _run(
    tenant_id: uuid.UUID, incident_id: uuid.UUID, behaviour_version_id: uuid.UUID
) -> WorkflowRun:
    return WorkflowRun(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        behaviour_version_id=behaviour_version_id,
        status=WorkflowRunStatus.RUNNING,
        started_at=datetime.now(UTC),
    )


def _finished(status: WorkflowRunStatus) -> float:
    return sample("asic_workflow_runs_finished_total", status=status.value)


def _transition(session: Session, run_id: uuid.UUID, status: WorkflowRunStatus) -> None:
    lifecycle.core_update(
        session,
        sa.update(WorkflowRun).where(WorkflowRun.id == run_id).values(status=status),
    )


class TestCoreUpdatesAreCountedOnlyWhenCommitted:
    @pytest.mark.parametrize(
        "status",
        [
            WorkflowRunStatus.COMPLETED,
            WorkflowRunStatus.FAILED,
            WorkflowRunStatus.DEAD_LETTERED,
        ],
    )
    def test_a_committed_core_transition_counts_once(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
        status: WorkflowRunStatus,
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(status)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            _transition(session, run.id, status)
        assert _finished(status) - before == 1

    def test_g_a_rolled_back_core_transition_counts_nothing(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.FAILED)
        session = _factory(owner_engine)()
        try:
            session.begin()
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            _transition(session, run.id, WorkflowRunStatus.FAILED)
            session.rollback()
        finally:
            session.close()
        assert _finished(WorkflowRunStatus.FAILED) == before

    def test_h_a_savepoint_rollback_counts_nothing(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.DEAD_LETTERED)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            nested = session.begin_nested()
            _transition(session, run.id, WorkflowRunStatus.DEAD_LETTERED)
            nested.rollback()
        assert _finished(WorkflowRunStatus.DEAD_LETTERED) == before

    def test_i_a_released_savepoint_under_a_commit_counts_once(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.COMPLETED)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            nested = session.begin_nested()
            _transition(session, run.id, WorkflowRunStatus.COMPLETED)
            nested.commit()
        assert _finished(WorkflowRunStatus.COMPLETED) - before == 1

    def test_j_a_released_savepoint_under_a_rollback_counts_nothing(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.FAILED)
        session = _factory(owner_engine)()
        try:
            session.begin()
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            nested = session.begin_nested()
            _transition(session, run.id, WorkflowRunStatus.FAILED)
            nested.commit()
            session.rollback()
        finally:
            session.close()
        assert _finished(WorkflowRunStatus.FAILED) == before

    def test_f_the_same_transition_issued_twice_counts_once(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.COMPLETED)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            session.add(run)
            session.flush()
            _transition(session, run.id, WorkflowRunStatus.COMPLETED)
            _transition(session, run.id, WorkflowRunStatus.COMPLETED)
        assert _finished(WorkflowRunStatus.COMPLETED) - before == 1

    def test_a_statement_that_matches_no_row_counts_nothing(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, _, _behaviour_id = world
        before = _finished(WorkflowRunStatus.COMPLETED)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            _transition(session, uuid.uuid4(), WorkflowRunStatus.COMPLETED)
        assert _finished(WorkflowRunStatus.COMPLETED) == before

    def test_k_an_orm_insert_and_a_core_transition_do_not_double_count(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        """An ORM-created row already finished, then written again by a Core statement."""
        tenant_id, environment_id, behaviour_id = world
        before = _finished(WorkflowRunStatus.COMPLETED)
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id)
            session.add(incident)
            run = _run(tenant_id, incident.id, behaviour_id)
            run.status = WorkflowRunStatus.COMPLETED
            session.add(run)
            session.flush()
            _transition(session, run.id, WorkflowRunStatus.COMPLETED)
        assert _finished(WorkflowRunStatus.COMPLETED) - before == 1

    def test_core_update_refuses_a_table_with_no_lifecycle_meaning(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        world: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    ) -> None:
        tenant_id, _environment_id, _behaviour_id = world
        with _factory(owner_engine)() as session, session.begin():
            bind_tenant(session, tenant_id)
            with pytest.raises(KeyError):
                lifecycle.core_update(
                    session,
                    sa.update(Incident)
                    .where(Incident.tenant_id == tenant_id)
                    .values(title="not a lifecycle metric"),
                )


class TestRealWorkflowsProduceTheMetrics:
    """The regression itself: a real run's outcome must reach the exposition."""

    def test_c_a_dead_lettered_run_is_counted(
        self,
        telemetry: Telemetry,
        owner_engine: Engine,
        app_engine: Engine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from asic.domain.clock import FrozenClock
        from asic.llm.deterministic import DeterministicModelProvider
        from asic.orchestration.kernel import InvestigationKernel
        from asic.simulators.provider import SimulatorProvider
        from asic.simulators.scenarios import scenario
        from asic.tools.capability import CapabilityResolver
        from asic.tools.registry import ToolRegistry
        from tests.kernel_fixtures import CLOCK_START, build_fixture

        before = _finished(WorkflowRunStatus.DEAD_LETTERED)
        with Session(owner_engine, expire_on_commit=False) as session:
            fixture = build_fixture(session, slug=f"dead-{uuid.uuid4().hex[:8]}")
            session.commit()
        selected = scenario("SC-0001-checkout-latency-after-deploy")
        clock = FrozenClock(start=CLOCK_START)

        class ProcessDeath(BaseException):
            """Not an adapter failure: the broker classifies those, and the run survives."""

        def explode(*_args: object, **_kwargs: object) -> None:
            raise ProcessDeath("node failure with no graph expression")

        monkeypatch.setattr(SimulatorProvider, "invoke", explode)
        kernel = InvestigationKernel(
            session_factory=_factory(app_engine),
            resolver=CapabilityResolver(ToolRegistry.read_only()),
            providers=[SimulatorProvider(selected, clock=clock)],
            model=DeterministicModelProvider(selected),
            clock=clock,
        )
        with pytest.raises(ProcessDeath):
            kernel.start(
                tenant_id=fixture.tenant_id,
                incident_id=fixture.incident.id,
                behaviour_version_id=fixture.behaviour_version.id,
                service_ids=list(fixture.service_ids),
            )
        monkeypatch.undo()

        with Session(owner_engine) as session:
            bind_tenant(session, fixture.tenant_id)
            statuses = list(
                session.scalars(
                    sa.select(WorkflowRun.status).where(WorkflowRun.tenant_id == fixture.tenant_id)
                )
            )
        assert WorkflowRunStatus.DEAD_LETTERED in statuses
        assert _finished(WorkflowRunStatus.DEAD_LETTERED) - before == float(
            statuses.count(WorkflowRunStatus.DEAD_LETTERED)
        )

    def test_d_e_a_real_remediation_run_reports_its_own_lifecycle(
        self, telemetry: Telemetry, owner_engine: Engine, app_engine: Engine
    ) -> None:
        """Every transition a real run writes - Core or ORM - reaches the exposition once."""
        from asic.domain.enums import ExecutionMode
        from asic.evaluation.harness import EvaluationHarness, HarnessConfig

        def counters() -> dict[str, float]:
            return {
                "completed": _finished(WorkflowRunStatus.COMPLETED),
                "executing": sample(
                    "asic_remediation_action_transitions_total",
                    status=RemediationActionStatus.EXECUTING.value,
                    risk_tier=RiskTier.R1.value,
                ),
                "succeeded": sample(
                    "asic_remediation_action_transitions_total",
                    status=RemediationActionStatus.SUCCEEDED.value,
                    risk_tier=RiskTier.R1.value,
                ),
            }

        before = counters()
        slug = f"core-life-{uuid.uuid4().hex[:8]}"
        outcome = EvaluationHarness(
            admin_factory=_factory(owner_engine), app_factory=_factory(app_engine)
        ).run(
            HarnessConfig(
                tenant_slug=slug,
                keys=("EV-REM-001",),
                mode=ExecutionMode.SIMULATOR,
                baseline="none",
            )
        )
        assert outcome.status == "passed", outcome.report

        with Session(owner_engine) as session:
            tenant_id = session.scalar(sa.select(Tenant.id).where(Tenant.slug == slug))
            assert tenant_id is not None
            bind_tenant(session, tenant_id)
            completed = list(
                session.scalars(
                    sa.select(WorkflowRun.status).where(WorkflowRun.tenant_id == tenant_id)
                )
            ).count(WorkflowRunStatus.COMPLETED)
            succeeded_actions = list(
                session.scalars(
                    sa.select(RemediationAction.status).where(
                        RemediationAction.tenant_id == tenant_id
                    )
                )
            )

        after = counters()
        assert after["completed"] - before["completed"] == completed
        # The durable pre-dispatch intent is a Core transition too, and one per dispatch.
        assert after["executing"] - before["executing"] == 1
        assert after["succeeded"] - before["succeeded"] == float(
            sum(
                1
                for status in succeeded_actions
                if status
                in (
                    RemediationActionStatus.SUCCEEDED,
                    RemediationActionStatus.VERIFIED,
                    RemediationActionStatus.NOT_VERIFIED,
                    RemediationActionStatus.INCONCLUSIVE,
                )
            )
        )
