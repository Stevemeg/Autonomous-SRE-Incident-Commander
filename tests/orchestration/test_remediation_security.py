"""Regression and guard-removal tests for remediation authorization and recovery."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import Approval, RemediationAction, UserRoleAssignment
from asic.db.models.orchestration import WorkflowCheckpoint
from asic.db.models.tools import ToolExecution
from asic.domain.enums import ApprovalDecision, IncidentStatus, RiskTier
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.remediation.approval_service import decide
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import metrics_recovered, scenario
from asic.tools.broker import ToolBroker
from tests.conftest import requires_postgres
from tests.kernel_fixtures import build_fixture
from tests.orchestration.test_remediation import (
    _remediation_scenario,
    _run_remediation,
    _sim_response,
)
from tests.remediation_fixtures import (
    create_approver,
    escalate_to_accepted_hypothesis,
)

pytestmark = requires_postgres


def _prepared(
    session: Any, factory: Any, resolver: Any, clock: Any, slug: str, production: bool = False
) -> tuple[Any, Any]:
    fixture = build_fixture(session, slug=slug)
    fixture.environment.is_production = production
    session.commit()
    hypothesis_id = escalate_to_accepted_hypothesis(
        factory, resolver, clock, fixture, scenario("SC-0001-checkout-latency-after-deploy")
    )
    return fixture, hypothesis_id


def _kernel(
    factory: Any, resolver: Any, clock: Any, model: Any = None, scenario_obj: Any = None
) -> RemediationKernel:
    selected = scenario_obj or _remediation_scenario()
    return RemediationKernel(
        session_factory=factory,
        resolver=resolver,
        clock=clock,
        model=model or DeterministicModelProvider(selected),
        providers=[SimulatorProvider(selected, clock=clock)],
    )


def test_resume_uses_persisted_proposal_and_budget(
    kernel_session: Any, session_factory: Any, resolver: Any, remediation_resolver: Any, clock: Any
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "resume-persisted", True
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    before = kernel_session.execute(
        sa.select(WorkflowCheckpoint)
        .where(WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id)
        .order_by(WorkflowCheckpoint.sequence.desc())
        .limit(1)
    ).scalar_one()
    tokens = before.budget_consumed["ledger"]["tokens"]
    assert tokens > 0
    unavailable_model = DeterministicModelProvider(_remediation_scenario(), fail_after=0)
    resumed = _kernel(session_factory, remediation_resolver, clock, unavailable_model).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert not resumed.terminated
    assert unavailable_model.call_count == 0
    after = kernel_session.execute(
        sa.select(WorkflowCheckpoint)
        .where(WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id)
        .order_by(WorkflowCheckpoint.sequence.desc())
        .limit(1)
    ).scalar_one()
    assert after.budget_consumed["ledger"]["tokens"] == tokens


@pytest.mark.parametrize("invalidation", ["expiry", "revocation"])
def test_approval_rechecked_at_dispatch(
    invalidation: str,
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, f"approval-{invalidation}", True
    )
    approver = create_approver(kernel_session, fixture)
    kernel_session.commit()
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    action = kernel_session.execute(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    ).scalar_one()
    approval = decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="reviewed exact action",
        clock=clock,
    )
    kernel_session.commit()
    if invalidation == "expiry":
        clock.advance((approval.expires_at - clock.now()).total_seconds() + 1)
    else:
        kernel_session.execute(
            sa.delete(UserRoleAssignment).where(UserRoleAssignment.user_id == approver.id)
        )
        kernel_session.commit()
    resumed = _kernel(session_factory, remediation_resolver, clock).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert resumed.terminated
    assert resumed.incident_status is not IncidentStatus.RESOLVED
    writes = kernel_session.execute(
        sa.select(sa.func.count())
        .select_from(ToolExecution)
        .where(ToolExecution.tenant_id == fixture.tenant_id, ToolExecution.risk_tier != RiskTier.RO)
    ).scalar_one()
    assert writes == 0
    assert kernel_session.execute(
        sa.select(Approval.id).where(Approval.id == approval.id)
    ).scalar_one()


@pytest.mark.parametrize("disable_claim", [False, True])
def test_crash_after_effect_claim_prevents_repeat(
    disable_claim: bool,
    monkeypatch: Any,
    owner_engine: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    factory = sessionmaker(bind=owner_engine, expire_on_commit=False, autoflush=False, future=True)
    setup = Session(owner_engine, expire_on_commit=False, autoflush=False)
    fixture, hypothesis_id = _prepared(
        setup,
        factory,
        resolver,
        clock,
        f"crash-claim-{str(disable_claim).lower()}-{__import__('uuid').uuid4().hex[:8]}",
    )
    tenant_id = fixture.tenant_id
    setup.close()
    original = ToolBroker._invoke_with_deadline
    writes = []

    class ProcessDeath(BaseException):
        pass

    def crash_once(self: Any, provider: Any, descriptor: Any, bound: Any, context: Any) -> Any:
        result = original(self, provider, descriptor, bound, context)
        if descriptor.risk_tier is not RiskTier.RO:
            writes.append(context.idempotency_key)
            if len(writes) == 1:
                raise ProcessDeath()
        return result

    monkeypatch.setattr(ToolBroker, "_invoke_with_deadline", crash_once)
    if disable_claim:
        monkeypatch.setattr(ToolBroker, "_claim_write", lambda *args: None)
    with pytest.raises(ProcessDeath):
        _run_remediation(
            factory,
            remediation_resolver,
            clock,
            fixture,
            hypothesis_id,
            _remediation_scenario(),
        )
    check = Session(owner_engine, expire_on_commit=False)
    action = check.execute(
        sa.select(RemediationAction).where(RemediationAction.tenant_id == tenant_id)
    ).scalar_one()
    resumed = _kernel(factory, remediation_resolver, clock).resume(
        tenant_id=tenant_id, workflow_run_id=action.workflow_run_id
    )
    check.close()
    assert len(writes) == (2 if disable_claim else 1)
    if not disable_claim:
        assert resumed.terminated
        assert resumed.incident_status is IncidentStatus.ESCALATED


def test_successful_executor_does_not_verify_empty_evidence(
    kernel_session: Any, session_factory: Any, resolver: Any, remediation_resolver: Any, clock: Any
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "empty-verification"
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    clock.advance(400)
    selected = _remediation_scenario()

    def empty(ctx: Any) -> Any:
        return {**metrics_recovered(ctx), "samples": []}

    responses = {**selected.responses, "read.metrics|checkout-api": _sim_response(empty)}
    selected = replace(selected, responses=responses)
    resumed = _kernel(session_factory, remediation_resolver, clock, scenario_obj=selected).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert resumed.terminated
    assert resumed.incident_status is IncidentStatus.ESCALATED
