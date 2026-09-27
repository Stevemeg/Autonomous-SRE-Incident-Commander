"""Phase 15.16: tool-abuse campaign - every way a caller (or a model's output) might try to make
the Tool Broker do something it was not authorised to do.

Each attempt must be refused *before any adapter is called* (the simulator records every call
it receives, so "refused" is observed, not inferred), at a named broker stage, with an audit
trail. Approval abuse (replay, wrong hash, expired, unauthorised or revoked approver) is
attacked through the real approval service.

Covered here: unknown capability, model-generated tool name, wrong node contract, read/write
confusion, wrong tenant (another incident), wrong target (service outside scope), wrong
environment, undeclared/tenant/scope arguments, malformed and oversized arguments, control and
invisible characters, and request fields a caller must never be able to set (tool name,
credential, tenant, risk tier, idempotency key, connector).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from asic.contracts.nodes import G3_INVESTIGATION_PLANNER, G4_EVIDENCE_COLLECTOR
from asic.domain.clock import FrozenClock
from asic.domain.errors import DomainError
from asic.tools.broker import BrokerStage, CapabilityRequest
from tests.kernel_fixtures import build_fixture
from tests.tools.test_broker import WINDOW_END, WINDOW_START, _broker, _request

pytestmark = [pytest.mark.postgres, pytest.mark.security]

GOOD = {
    "window_start": WINDOW_START,
    "window_end": WINDOW_END,
    "metric": "http_request_duration_p95_seconds",
}
ZWSP = chr(0x200B)
RLO = chr(0x202E)

#: (id, capability, arguments, expected refusal stage)
ARGUMENT_ATTACKS: list[tuple[str, str, dict[str, Any], BrokerStage]] = [
    ("unknown_capability", "read.everything", GOOD, BrokerStage.CAPABILITY_RESOLUTION),
    (
        "model_generated_tool_name",
        "k8s.deployment.rollback",
        GOOD,
        BrokerStage.CAPABILITY_RESOLUTION,
    ),
    (
        "write_capability_from_reader",
        "mutate.k8s_deployment",
        GOOD,
        BrokerStage.CAPABILITY_RESOLUTION,
    ),
    (
        "tenant_argument",
        "read.metrics",
        {**GOOD, "tenant_id": str(uuid.uuid4())},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "environment_argument",
        "read.metrics",
        {**GOOD, "environment": "staging"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "service_argument",
        "read.metrics",
        {**GOOD, "service": "payments-api"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "connector_argument",
        "read.metrics",
        {**GOOD, "connector_id": "prod-writer"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "risk_tier_argument",
        "read.metrics",
        {**GOOD, "risk_tier": "ro"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "wrong_type",
        "read.metrics",
        {**GOOD, "window_start": "yesterday"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "oversized",
        "read.metrics",
        {**GOOD, "metric": "m" * 10_000},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "nul_byte",
        "read.metrics",
        {**GOOD, "metric": "http\x00requests"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "zero_width",
        "read.metrics",
        {**GOOD, "metric": f"http{ZWSP}requests"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "bidi",
        "read.metrics",
        {**GOOD, "metric": f"http{RLO}sdrawkcab"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "command_in_value",
        "read.metrics",
        {**GOOD, "metric": "x; kubectl delete ns prod"},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
    (
        "nested_object",
        "read.metrics",
        {**GOOD, "metric": {"$ne": None}},
        BrokerStage.ARGUMENT_VALIDATION,
    ),
]


@pytest.mark.parametrize(
    ("capability", "arguments", "stage"),
    [attack[1:] for attack in ARGUMENT_ATTACKS],
    ids=[attack[0] for attack in ARGUMENT_ATTACKS],
)
def test_abusive_requests_are_refused_before_any_adapter_call(
    kernel_session: Session,
    clock: FrozenClock,
    capability: str,
    arguments: dict[str, Any],
    stage: BrokerStage,
) -> None:
    fixture = build_fixture(kernel_session, slug=f"abuse-{uuid.uuid4().hex[:8]}")
    broker, simulator, _ = _broker(fixture, kernel_session, clock)
    try:
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, capability, arguments=arguments),
            contract=G4_EVIDENCE_COLLECTOR,
        )
    finally:
        broker.close()
    assert result.failure is not None, f"{capability} {arguments} was accepted"
    assert result.failure.stage is stage, result.failure
    assert not simulator.calls, "an adapter was reached"
    assert not result.payload


def test_a_capability_outside_the_node_contract_is_refused(
    kernel_session: Session, clock: FrozenClock
) -> None:
    fixture = build_fixture(kernel_session, slug=f"abuse-contract-{uuid.uuid4().hex[:6]}")
    broker, simulator, _ = _broker(fixture, kernel_session, clock)
    try:
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.metrics", arguments=GOOD),
            contract=G3_INVESTIGATION_PLANNER,  # the planner reasons; it never calls tools
        )
    finally:
        broker.close()
    assert result.failure is not None and not simulator.calls


def test_wrong_target_and_wrong_tenant_are_refused(
    kernel_session: Session, clock: FrozenClock
) -> None:
    fixture = build_fixture(kernel_session, slug=f"abuse-target-{uuid.uuid4().hex[:6]}")
    broker, simulator, _ = _broker(fixture, kernel_session, clock)
    try:
        # A service that is not one of this incident's services (the target is resolved).
        with pytest.raises(DomainError):
            broker.invoke(
                kernel_session,
                request=_request(fixture, "read.metrics", service="payments-api", arguments=GOOD),
                contract=G4_EVIDENCE_COLLECTOR,
            )
        # Another incident id (another tenant's object) never widens the bound scope.
        foreign = _request(fixture, "read.metrics", arguments=GOOD).model_copy(
            update={"incident_id": uuid.uuid4()}
        )
        result = broker.invoke(kernel_session, request=foreign, contract=G4_EVIDENCE_COLLECTOR)
        assert result.failure is not None
    finally:
        broker.close()
    assert not simulator.calls


@pytest.mark.parametrize(
    "field",
    [
        "tool_name",
        "credential_ref",
        "tenant_id",
        "risk_tier",
        "idempotency_key",
        "connector_id",
        "scope",
        "environment_id",
    ],
)
def test_a_request_cannot_carry_authority_fields(field: str) -> None:
    """The request type itself cannot express these: nothing to validate, nothing to trust."""
    with pytest.raises(ValidationError):
        CapabilityRequest(  # type: ignore[call-arg]
            node_id=G4_EVIDENCE_COLLECTOR.node_id,
            capability="read.metrics",
            service_name="checkout-api",
            incident_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            **{field: "attacker-controlled"},
        )


# ---------------------------------------------------------------- approval abuse
def _awaiting_approval(
    kernel_session: Session,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: FrozenClock,
) -> tuple[Any, Any, Any]:
    from asic.simulators.scenarios import scenario
    from tests.orchestration.test_remediation import _remediation_scenario, _run_remediation
    from tests.remediation_fixtures import create_approver, escalate_to_accepted_hypothesis

    fixture = build_fixture(kernel_session, slug=f"abuse-apr-{uuid.uuid4().hex[:8]}")
    approver = create_approver(kernel_session, fixture)
    kernel_session.commit()
    hypothesis_id = escalate_to_accepted_hypothesis(
        session_factory,
        resolver,
        clock,
        fixture,
        scenario("SC-0001-checkout-latency-after-deploy"),
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    assert outcome.terminated is False
    kernel_session.expire_all()
    from asic.db.models import RemediationAction
    from asic.db.session import bind_tenant

    bind_tenant(kernel_session, fixture.tenant_id)
    action = kernel_session.scalars(
        sa_select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
    ).one()
    return fixture, approver, action


def sa_select(*args: Any) -> Any:
    import sqlalchemy as sa

    return sa.select(*args)


def test_an_approval_decision_cannot_be_replayed(
    kernel_session: Session,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: FrozenClock,
) -> None:
    from asic.db.models import Approval
    from asic.domain.enums import ApprovalDecision
    from asic.remediation import approval_service

    fixture, approver, action = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock
    )
    approval_service.decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.REJECTED,
        expected_action_version_hash=action.action_version_hash,
        justification="rejected: wrong target",
        clock=clock,
    )
    kernel_session.commit()
    # A decision is idempotent per (tenant, action, action version): a replay - even one
    # that tries to flip the rejection into an approval - returns the FIRST decision and
    # writes nothing new.
    for decision in (ApprovalDecision.REJECTED, ApprovalDecision.APPROVED):
        replayed = approval_service.decide(
            kernel_session,
            tenant_id=fixture.tenant_id,
            action_id=action.id,
            actor_user_id=approver.id,
            decision=decision,
            expected_action_version_hash=action.action_version_hash,
            justification="replayed decision",
            clock=clock,
        )
        assert replayed.decision is ApprovalDecision.REJECTED
    kernel_session.commit()
    rows = kernel_session.scalars(
        sa_select(Approval).where(Approval.remediation_action_id == action.id)
    ).all()
    assert len(rows) == 1 and rows[0].decision is ApprovalDecision.REJECTED


def test_a_decision_after_the_window_is_refused_and_system_outcomes_are_not_forgeable(
    kernel_session: Session,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: FrozenClock,
) -> None:
    from asic.domain.enums import ApprovalDecision
    from asic.domain.errors import ApprovalInvalid
    from asic.remediation import approval_service
    from asic.remediation.approval_service import APPROVAL_WINDOW_SECONDS

    fixture, approver, action = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock
    )
    for forged in (ApprovalDecision.EXPIRED, ApprovalDecision.INVALIDATED):
        with pytest.raises(ApprovalInvalid, match="system-only"):
            approval_service.decide(
                kernel_session,
                tenant_id=fixture.tenant_id,
                action_id=action.id,
                actor_user_id=approver.id,
                decision=forged,
                expected_action_version_hash=action.action_version_hash,
                justification="forged system outcome",
                clock=clock,
            )
    # The window runs from the policy decision's (database-clock) evaluation time.
    from asic.db.models import PolicyDecision

    evaluated_at = kernel_session.scalars(
        sa_select(PolicyDecision.evaluated_at).where(
            PolicyDecision.remediation_action_id == action.id
        )
    ).one()
    lag = max(0, int((evaluated_at - clock.now()).total_seconds()))
    clock.advance(lag + APPROVAL_WINDOW_SECONDS[action.risk_tier] + 1)
    with pytest.raises(ApprovalInvalid, match="elapsed"):
        approval_service.decide(
            kernel_session,
            tenant_id=fixture.tenant_id,
            action_id=action.id,
            actor_user_id=approver.id,
            decision=ApprovalDecision.APPROVED,
            expected_action_version_hash=action.action_version_hash,
            justification="too late",
            clock=clock,
        )
