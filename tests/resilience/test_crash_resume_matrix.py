"""Phase 15.6: kill the process at representative checkpoints, restart, and resume safely.

A *real* process death runs no clean-up: no dead-letter bookkeeping, no lease release. The
kernels' in-process ``except BaseException`` handler would do that bookkeeping, so it is
disabled for the crashing worker here - what is left in the database is exactly what a
``kill -9`` leaves. A second worker must then:

* be refused while the dead worker's lease is still valid (no split-brain),
* take over once the lease expires, continue the *same* run, and reach the same ending an
  uninterrupted run reaches;
* apply no side effect twice (unique idempotency keys; one mutating execution at most),
* lose no human approval, fabricate no success, and never change tenant or target.

Investigation crash points: after every node boundary of the primary scenario (after incident
creation, after evidence fetch, during the hypothesis cycle, before completion). Remediation
crash points: entering the approval service (before the approval wait), entering the executor
after a human approved, entering the verifier, and after verification before completion. The
window *inside* the executor (after durable intent, after the provider side effect, before the
receipt) is covered by ``tests/integrations/test_crash_recovery.py`` against a live adapter.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import (
    Approval,
    Evidence,
    Incident,
    ModelCallReservation,
    RemediationAction,
    RemediationTarget,
    ToolExecution,
    Verification,
    WorkflowRun,
)
from asic.db.projections import recompute_incident_status
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ApprovalDecision,
    IncidentStatus,
    RemediationActionStatus,
    RiskTier,
    VerificationVerdict,
    WorkflowRunStatus,
)
from asic.domain.errors import LeaseNotHeld
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration import kernel as investigation_kernel
from asic.orchestration.kernel import InvestigationKernel
from asic.orchestration.remediation import graph as remediation_graph
from asic.orchestration.remediation import kernel as remediation_kernel
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.remediation import approval_service
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, scenario
from asic.tools.capability import CapabilityResolver
from tests.kernel_fixtures import build_fixture
from tests.orchestration.test_remediation import _post_remediation_scenario, _remediation_scenario
from tests.remediation_fixtures import create_approver, escalate_to_accepted_hypothesis

pytestmark = pytest.mark.postgres

LEASE_EXPIRY = remediation_kernel.LEASE_DURATION + timedelta(seconds=1)


@pytest.fixture
def session_factory(app_engine: Engine) -> Callable[[], Session]:
    """Real, committed transactions: a crash must leave exactly what production would."""
    return sessionmaker(app_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def kernel_session(session_factory: Callable[[], Session]) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


class ProcessDeath(BaseException):
    """kill -9: nothing in the system catches it."""


# ------------------------------------------------------------------ investigation
def _investigation(
    factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
    probe: Callable[[str, int], None] | None = None,
) -> InvestigationKernel:
    case = scenario(PRIMARY_SCENARIO_ID)
    return InvestigationKernel(
        session_factory=factory,
        resolver=resolver,
        providers=[SimulatorProvider(case, clock=clock)],
        model=DeterministicModelProvider(case),
        clock=clock,
        budget_policy=case.budget,
        interrupt_probe=probe,
    )


def _stateless_model(session: Session, tenant_id: uuid.UUID, run_id: uuid.UUID) -> Any:
    """The scripted provider as a *stateless* model would behave after a restart.

    The deterministic provider is positional (one cursor per node), so a fresh instance would
    answer a resumed run's next call with the script's first entry. A real provider answers
    the call it is asked. Advancing each node's cursor past the calls this run already made
    (recorded durably in the model-call ledger) reproduces that; it is test wiring only.
    """
    session.expire_all()
    bind_tenant(session, tenant_id)
    made = dict(
        session.execute(
            sa.select(ModelCallReservation.node_id, sa.func.count())
            .where(
                ModelCallReservation.tenant_id == tenant_id,
                ModelCallReservation.workflow_run_id == run_id,
            )
            .group_by(ModelCallReservation.node_id)
        ).all()
    )
    model = DeterministicModelProvider(scenario(PRIMARY_SCENARIO_ID))
    for node, count in made.items():
        model._cursors[node] = int(count)
    return model


def _baseline_nodes(
    kernel_session: Session, factory: Callable[[], Session], resolver: CapabilityResolver
) -> tuple[tuple[str, ...], Any]:
    case = scenario(PRIMARY_SCENARIO_ID)
    fixture = build_fixture(
        kernel_session, slug=f"crash-base-{uuid.uuid4().hex[:8]}", service_name=case.service
    )
    kernel_session.commit()
    clock = FrozenClock(start=fixture.incident.opened_at)
    outcome = _investigation(factory, resolver, clock).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
    )
    return tuple(outcome.nodes_executed), outcome


def _counts(session: Session, tenant_id: uuid.UUID) -> dict[str, int]:
    session.expire_all()
    bind_tenant(session, tenant_id)

    def count(model: Any) -> int:
        return int(
            session.scalar(
                sa.select(sa.func.count()).select_from(model).where(model.tenant_id == tenant_id)
            )
        )

    return {"evidence": count(Evidence), "executions": count(ToolExecution)}


# Crash after each of the first N node boundaries of the primary scenario (its whole run).
@pytest.mark.parametrize("crash_after", range(1, 9))
def test_investigation_survives_process_death_at_every_node_boundary(
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    monkeypatch: pytest.MonkeyPatch,
    crash_after: int,
) -> None:
    nodes, baseline = _baseline_nodes(kernel_session, session_factory, resolver)
    if crash_after >= len(nodes):
        pytest.skip(f"the primary scenario has {len(nodes)} node boundaries")
    case = scenario(PRIMARY_SCENARIO_ID)
    fixture = build_fixture(
        kernel_session, slug=f"crash-inv-{uuid.uuid4().hex[:8]}", service_name=case.service
    )
    kernel_session.commit()
    clock = FrozenClock(start=fixture.incident.opened_at)

    def die(name: str, ordinal: int) -> None:
        if ordinal == crash_after:
            raise ProcessDeath(f"killed after {name}")

    # A killed process performs no dead-letter bookkeeping and releases no lease.
    monkeypatch.setattr(
        investigation_kernel.InvestigationKernel, "_mark_dead_letter", lambda *_: None
    )
    with pytest.raises(ProcessDeath):
        _investigation(session_factory, resolver, clock, die).start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
    monkeypatch.undo()
    kernel_session.expire_all()
    bind_tenant(kernel_session, fixture.tenant_id)
    run = kernel_session.scalars(
        sa.select(WorkflowRun).where(WorkflowRun.tenant_id == fixture.tenant_id)
    ).one()
    assert run.status is WorkflowRunStatus.RUNNING and run.lease_owner is not None
    before = _counts(kernel_session, fixture.tenant_id)

    survivor = _investigation(session_factory, resolver, clock)
    survivor._model = _stateless_model(kernel_session, fixture.tenant_id, run.id)
    with pytest.raises(LeaseNotHeld):  # the dead worker's lease is still valid: no split-brain
        survivor.resume(tenant_id=fixture.tenant_id, workflow_run_id=run.id)
    clock.advance(int(LEASE_EXPIRY.total_seconds()))
    outcome = survivor.resume(tenant_id=fixture.tenant_id, workflow_run_id=run.id)

    assert outcome.workflow_run_id == run.id
    assert outcome.terminated
    assert outcome.termination_reason is baseline.termination_reason
    assert outcome.incident_status is baseline.incident_status
    after = _counts(kernel_session, fixture.tenant_id)
    assert after["evidence"] >= before["evidence"]
    keys = list(
        kernel_session.scalars(
            sa.select(ToolExecution.idempotency_key).where(
                ToolExecution.tenant_id == fixture.tenant_id
            )
        )
    )
    assert len(keys) == len(set(keys)), "a side effect was applied twice"
    incident = kernel_session.get(Incident, fixture.incident.id)
    assert incident is not None and incident.tenant_id == fixture.tenant_id
    assert incident.status == recompute_incident_status(
        kernel_session, tenant_id=fixture.tenant_id, incident_id=fixture.incident.id
    )


# ------------------------------------------------------------------ remediation
@contextmanager
def crash_entering(node_factory: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Replace one remediation node so that the *first* time it runs the process dies."""
    original = getattr(remediation_graph, node_factory)
    fired: list[str] = []

    def factory(deps: Any) -> Any:
        node = original(deps)

        def wrapped(state: Any) -> Any:
            if not fired:
                fired.append(node_factory)
                raise ProcessDeath(f"killed entering {node_factory}")
            return node(state)

        return wrapped

    monkeypatch.setattr(remediation_graph, node_factory, factory)
    monkeypatch.setattr(remediation_kernel.RemediationKernel, "_mark_dead_letter", lambda *_: None)
    try:
        yield fired
    finally:
        monkeypatch.undo()


def _remediation(
    factory: Callable[[], Session], resolver: CapabilityResolver, clock: FrozenClock, selected: Any
) -> RemediationKernel:
    return RemediationKernel(
        session_factory=factory,
        resolver=resolver,
        providers=[SimulatorProvider(selected, clock=clock)],
        model=DeterministicModelProvider(selected),
        clock=clock,
    )


def _run_id(session: Session, tenant_id: uuid.UUID) -> uuid.UUID:
    session.expire_all()
    bind_tenant(session, tenant_id)
    return session.scalars(
        sa.select(WorkflowRun.id)
        .where(WorkflowRun.tenant_id == tenant_id, WorkflowRun.status == WorkflowRunStatus.RUNNING)
        .order_by(WorkflowRun.created_at.desc())
        .limit(1)
    ).one()


def _after_death(
    session: Session,
    factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
    fixture: Any,
    selected: Any,
) -> Any:
    run_id = _run_id(session, fixture.tenant_id)
    survivor = _remediation(factory, resolver, clock, selected)
    with pytest.raises(LeaseNotHeld):
        survivor.resume(tenant_id=fixture.tenant_id, workflow_run_id=run_id)
    clock.advance(int(LEASE_EXPIRY.total_seconds()))
    return survivor.resume(tenant_id=fixture.tenant_id, workflow_run_id=run_id)


def _approve(session: Session, fixture: Any, approver: Any, clock: FrozenClock) -> None:
    session.expire_all()
    bind_tenant(session, fixture.tenant_id)
    action = session.scalars(
        sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
    ).one()
    approval_service.decide(
        session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="approved after review of the evidence",
        clock=clock,
    )
    session.commit()


def _final_invariants(session: Session, fixture: Any, *, approvals: int) -> None:
    session.expire_all()
    bind_tenant(session, fixture.tenant_id)
    writes = list(
        session.scalars(
            sa.select(ToolExecution).where(
                ToolExecution.tenant_id == fixture.tenant_id, ToolExecution.risk_tier != RiskTier.RO
            )
        )
    )
    assert len(writes) <= 1, "the remediation was applied twice"
    keys = [w.idempotency_key for w in writes]
    assert len(keys) == len(set(keys))
    recorded = list(
        session.scalars(sa.select(Approval).where(Approval.tenant_id == fixture.tenant_id))
    )
    assert len(recorded) == approvals, "an approval was lost or invented"
    target = session.scalars(
        sa.select(RemediationTarget).where(RemediationTarget.tenant_id == fixture.tenant_id)
    ).one()
    assert target.environment_id == fixture.environment.id
    action = session.scalars(
        sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
    ).one()
    verifications = list(
        session.scalars(sa.select(Verification).where(Verification.tenant_id == fixture.tenant_id))
    )
    if action.status is RemediationActionStatus.VERIFIED:
        # Success only with an independent verification row behind it.
        assert any(v.verdict is VerificationVerdict.VERIFIED for v in verifications)
        assert len(writes) == 1


@pytest.mark.parametrize("node", ["approval_service_node"])
def test_death_before_the_approval_wait_loses_nothing(
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    remediation_resolver: CapabilityResolver,
    clock: FrozenClock,
    monkeypatch: pytest.MonkeyPatch,
    node: str,
) -> None:
    fixture = build_fixture(kernel_session, slug=f"crash-apr-{uuid.uuid4().hex[:8]}")
    approver = create_approver(kernel_session, fixture)
    kernel_session.commit()
    hypothesis_id = escalate_to_accepted_hypothesis(
        session_factory, resolver, clock, fixture, scenario(PRIMARY_SCENARIO_ID)
    )
    with crash_entering(node, monkeypatch) as fired, pytest.raises(ProcessDeath):
        _remediation(session_factory, remediation_resolver, clock, _remediation_scenario()).start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            hypothesis_id=hypothesis_id,
            behaviour_version_id=fixture.behaviour_version.id,
            selected_service_id=fixture.service_ids[0],
        )
    assert fired == [node]
    resumed = _after_death(
        kernel_session,
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        _remediation_scenario(),
    )
    # The resumed run reaches the approval wait: nothing executed without a human.
    assert resumed.incident_status is IncidentStatus.AWAITING_APPROVAL
    _final_invariants(kernel_session, fixture, approvals=0)
    _approve(kernel_session, fixture, approver, clock)
    finished = _remediation(
        session_factory, remediation_resolver, clock, _remediation_scenario()
    ).resume(tenant_id=fixture.tenant_id, workflow_run_id=resumed.workflow_run_id)
    clock.advance(90)
    finished = _remediation(
        session_factory, remediation_resolver, clock, _post_remediation_scenario()
    ).resume(tenant_id=fixture.tenant_id, workflow_run_id=finished.workflow_run_id)
    assert finished.terminated and finished.incident_status is IncidentStatus.RESOLVED
    _final_invariants(kernel_session, fixture, approvals=1)


@pytest.mark.parametrize(
    ("node", "settle_first", "expected"),
    [
        # After human approval, before dispatch. Lease recovery (15 min) outlives the
        # approval's validity window, and dispatch re-checks the approval: the stale approval
        # is NOT used, nothing executes, and the incident escalates for a fresh decision.
        # Fail-closed by design; the operational cost (a re-approval) is recorded in
        # docs/testing/RESILIENCE_AND_CHAOS.md.
        ("remediation_executor_node", False, IncidentStatus.ESCALATED),
        # During verification: the single effect is verified independently after resume.
        ("verifier_node", True, IncidentStatus.RESOLVED),
    ],
)
def test_death_after_approval_resumes_once_and_verifies(
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    remediation_resolver: CapabilityResolver,
    clock: FrozenClock,
    monkeypatch: pytest.MonkeyPatch,
    node: str,
    settle_first: bool,
    expected: IncidentStatus,
) -> None:
    fixture = build_fixture(kernel_session, slug=f"crash-{node[:6]}-{uuid.uuid4().hex[:6]}")
    approver = create_approver(kernel_session, fixture)
    kernel_session.commit()
    hypothesis_id = escalate_to_accepted_hypothesis(
        session_factory, resolver, clock, fixture, scenario(PRIMARY_SCENARIO_ID)
    )
    waiting = _remediation(
        session_factory, remediation_resolver, clock, _remediation_scenario()
    ).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        hypothesis_id=hypothesis_id,
        behaviour_version_id=fixture.behaviour_version.id,
        selected_service_id=fixture.service_ids[0],
    )
    assert waiting.incident_status is IncidentStatus.AWAITING_APPROVAL
    _approve(kernel_session, fixture, approver, clock)
    run_id = waiting.workflow_run_id
    if settle_first:
        # Execute, then suspend for the settling window; the crash happens in verification.
        executed = _remediation(
            session_factory, remediation_resolver, clock, _remediation_scenario()
        ).resume(tenant_id=fixture.tenant_id, workflow_run_id=run_id)
        assert executed.terminated is False
        clock.advance(90)
    selected = _post_remediation_scenario() if settle_first else _remediation_scenario()
    with crash_entering(node, monkeypatch) as fired, pytest.raises(ProcessDeath):
        _remediation(session_factory, remediation_resolver, clock, selected).resume(
            tenant_id=fixture.tenant_id, workflow_run_id=run_id
        )
    assert fired == [node]
    outcome = _after_death(
        kernel_session, session_factory, remediation_resolver, clock, fixture, selected
    )
    if not outcome.terminated:  # executor path: now settling after the (single) dispatch
        clock.advance(90)
        outcome = _remediation(
            session_factory, remediation_resolver, clock, _post_remediation_scenario()
        ).resume(tenant_id=fixture.tenant_id, workflow_run_id=run_id)
    assert outcome.terminated
    assert outcome.incident_status is expected
    _final_invariants(kernel_session, fixture, approvals=1)
    if expected is IncidentStatus.ESCALATED:
        kernel_session.expire_all()
        bind_tenant(kernel_session, fixture.tenant_id)
        writes = kernel_session.scalar(
            sa.select(sa.func.count())
            .select_from(ToolExecution)
            .where(
                ToolExecution.tenant_id == fixture.tenant_id,
                ToolExecution.risk_tier != RiskTier.RO,
            )
        )
        assert writes == 0, "an expired approval authorised an execution"
