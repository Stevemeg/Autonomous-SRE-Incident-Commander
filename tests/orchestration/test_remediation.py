"""The remediation graph and kernel, end to end: G6 through G10 (Phase 8).

Each test drives the real graph through the real kernel against a real PostgreSQL database,
starting from an incident a real investigation run (SC-0001) escalated and a human reopened -
exactly the path ADR-0023 requires, never a hand-constructed shortcut around it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Approval, PolicyDecision, RemediationAction, Verification
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ApprovalDecision,
    IncidentStatus,
    RemediationActionStatus,
    VerificationVerdict,
)
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.remediation import approval_service
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import (
    k8s_deployment_rollback_success,
    metrics_recovered,
    scenario,
)
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import Fixture, build_fixture
from tests.remediation_fixtures import create_approver, escalate_to_accepted_hypothesis

pytestmark = requires_postgres


def _remediation_scenario(**overrides: Any) -> Any:
    """SC-0001 with a scripted remediation proposal and a recovered post-action metric."""
    from dataclasses import replace

    from asic.simulators.scenarios import _remediation_plan

    base = scenario("SC-0001-checkout-latency-after-deploy")
    responses = dict(base.responses)
    responses["mutate.k8s_deployment|checkout-api"] = _sim_response(k8s_deployment_rollback_success)
    responses["read.metrics|checkout-api"] = _sim_response(metrics_recovered)
    plan = _remediation_plan(
        tool_name="k8s.deployment.rollback",
        arguments={"deployment": "checkout-api", "to_revision": 846},
    )
    return replace(
        base,
        responses=responses,
        remediation_planner_script=(plan,),
        **overrides,
    )


def _sim_response(builder: Any) -> Any:
    from asic.simulators.scenarios import SimulatedResponse

    return SimulatedResponse(builder=builder)


def _r2_remediation_scenario(**overrides: Any) -> Any:
    """SC-0001 with a scripted R2 (high-risk) proposal: cordon a node."""
    from dataclasses import replace

    from asic.simulators.scenarios import _remediation_plan, k8s_node_cordon_success

    base = scenario("SC-0001-checkout-latency-after-deploy")
    responses = dict(base.responses)
    # k8s.node.cordon declares no "service" argument (see the catalogue module docstring:
    # it scopes by tenant/environment/node, not by service), so the simulator resolves it
    # with an empty service segment regardless of the incident's own affected services.
    responses["mutate.k8s_node|"] = _sim_response(k8s_node_cordon_success)
    plan = _remediation_plan(tool_name="k8s.node.cordon", arguments={"node": "node-7"})
    return replace(base, responses=responses, remediation_planner_script=(plan,), **overrides)


def _run_remediation(
    session_factory: Callable[[], Session],
    remediation_resolver: CapabilityResolver,
    clock: FrozenClock,
    fixture: Fixture,
    hypothesis_id: uuid.UUID,
    scenario_obj: Any,
) -> Any:
    kernel = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[SimulatorProvider(scenario_obj, clock=clock)],
        model=DeterministicModelProvider(scenario_obj),
        clock=clock,
    )
    return kernel.start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        hypothesis_id=hypothesis_id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
    )


def _resume_remediation(
    session_factory: Callable[[], Session],
    remediation_resolver: CapabilityResolver,
    clock: FrozenClock,
    fixture: Fixture,
    outcome: Any,
) -> Any:
    kernel = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[SimulatorProvider(_remediation_scenario(), clock=clock)],
        model=DeterministicModelProvider(_remediation_scenario()),
        clock=clock,
    )
    return kernel.resume(tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id)


class TestAutonomousAllow:
    """R1, non-production, unambiguous: allowed without a human, per the autonomy matrix."""

    def test_r1_non_production_executes_and_verifies_autonomously(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        fixture = build_fixture(kernel_session, slug="rem-auto-allow")
        fixture.environment.is_production = False
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

        # The verifier will not judge before the tool's declared settling window elapses
        # (k8s.deployment.rollback: 60s) - it suspends exactly like the approval service
        # does, rather than judging early. Advance the clock and resume, precisely as a
        # real deployment resumes when its own settling timer fires.
        assert outcome.terminated is False
        clock.advance(90)
        outcome = _resume_remediation(
            session_factory, remediation_resolver, clock, fixture, outcome
        )

        assert outcome.terminated
        assert outcome.incident_status is IncidentStatus.RESOLVED

        kernel_session.expire_all()
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert action.status is RemediationActionStatus.SUCCEEDED
        assert action.tool_name == "k8s.deployment.rollback"

        decision = kernel_session.execute(
            sa.select(PolicyDecision).where(PolicyDecision.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert decision.rule_id == "P6_reversible_non_production_autonomous"

        verification = kernel_session.execute(
            sa.select(Verification).where(Verification.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert verification.verdict is VerificationVerdict.VERIFIED

        # No approval row at all: this path never asked a human.
        approvals = list(
            kernel_session.execute(
                sa.select(Approval).where(Approval.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert approvals == []


class TestApprovalRequired:
    """R1 in production: suspends for a human, then resumes on a real decision."""

    def test_production_r1_suspends_then_resumes_on_approval(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        fixture = build_fixture(kernel_session, slug="rem-approve")  # production by default
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
        assert outcome.incident_status is IncidentStatus.AWAITING_APPROVAL

        kernel_session.expire_all()
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert action.status is RemediationActionStatus.AWAITING_APPROVAL

        approval = approval_service.decide(
            kernel_session,
            tenant_id=fixture.tenant_id,
            action_id=action.id,
            actor_user_id=approver.id,
            decision=ApprovalDecision.APPROVED,
            expected_action_version_hash=action.action_version_hash,
            justification="looks correct, approving",
            clock=clock,
        )
        kernel_session.commit()
        assert approval.decision is ApprovalDecision.APPROVED

        resumed = _resume_remediation(
            session_factory, remediation_resolver, clock, fixture, outcome
        )

        # Approved, but the tool's settling window has not yet elapsed: suspends a second
        # time, exactly as the autonomous path does, rather than verifying early.
        assert resumed.terminated is False
        clock.advance(90)
        resumed = _resume_remediation(
            session_factory, remediation_resolver, clock, fixture, resumed
        )

        assert resumed.terminated
        assert resumed.incident_status is IncidentStatus.RESOLVED


class TestAdversarial:
    """Fabricated or unauthorized approval attempts are refused before any write occurs."""

    def test_self_approval_by_a_user_with_no_grant_is_refused(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        import pytest

        from asic.db.models import User
        from asic.domain.enums import UserStatus
        from asic.domain.errors import ApprovalInvalid

        fixture = build_fixture(kernel_session, slug="rem-unauth")
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
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()

        unauthorized_user = User(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant_id,
            external_idp_subject=f"idp|{uuid.uuid4().hex[:12]}",
            email="nobody@example.com",
            display_name="No Grant",
            status=UserStatus.ACTIVE,
        )
        kernel_session.add(unauthorized_user)
        kernel_session.flush()

        with pytest.raises(ApprovalInvalid, match="does not hold"):
            approval_service.decide(
                kernel_session,
                tenant_id=fixture.tenant_id,
                action_id=action.id,
                actor_user_id=unauthorized_user.id,
                decision=ApprovalDecision.APPROVED,
                expected_action_version_hash=action.action_version_hash,
                justification="",
                clock=clock,
            )

        # Nothing was written: still no decided approval for this action.
        assert (
            kernel_session.execute(
                sa.select(sa.func.count())
                .select_from(Approval)
                .where(Approval.tenant_id == fixture.tenant_id)
            ).scalar_one()
            == 0
        )

    def test_a_stale_action_version_hash_is_refused(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        import pytest

        from asic.domain.errors import ApprovalInvalid

        fixture = build_fixture(kernel_session, slug="rem-stale-hash")
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
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()

        with pytest.raises(ApprovalInvalid, match="version has changed"):
            approval_service.decide(
                kernel_session,
                tenant_id=fixture.tenant_id,
                action_id=action.id,
                actor_user_id=approver.id,
                decision=ApprovalDecision.APPROVED,
                expected_action_version_hash="0" * 64,  # a stale/forged view of the action
                justification="",
                clock=clock,
            )

    def test_a_cross_tenant_approval_attempt_finds_nothing_to_decide(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        """RLS plus the service's own explicit tenant filter, together: an actor who is a
        real, authorised approver in a *different* tenant cannot decide this tenant's
        action by simply naming a different ``tenant_id`` - the row is not visible to name."""
        import pytest

        from asic.domain.errors import ApprovalInvalid

        fixture = build_fixture(kernel_session, slug="rem-cross-tenant-a")
        kernel_session.commit()
        other_fixture = build_fixture(kernel_session, slug="rem-cross-tenant-b")
        other_approver_id = create_approver(kernel_session, other_fixture).id
        other_tenant_id = other_fixture.tenant_id
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
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()

        with pytest.raises(ApprovalInvalid, match="not visible in this tenant"):
            approval_service.decide(
                kernel_session,
                tenant_id=other_tenant_id,
                action_id=action.id,
                actor_user_id=other_approver_id,
                decision=ApprovalDecision.APPROVED,
                expected_action_version_hash=action.action_version_hash,
                justification="",
                clock=clock,
            )

        assert (
            kernel_session.execute(
                sa.select(sa.func.count())
                .select_from(Approval)
                .where(Approval.tenant_id == fixture.tenant_id)
            ).scalar_one()
            == 0
        )

    def test_tampering_with_the_action_after_approval_is_refused_at_dispatch(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        """Mutation proof for SI-6 at the *executor*, not merely at ``approval_service``
        (already covered above): an action approved against one version hash, then changed
        without recomputing that hash - simulating a row a race condition or a compromised
        writer touched between approval and dispatch - is refused at G9, before any tool
        call reaches the simulator, rather than executed against drifted arguments."""
        fixture = build_fixture(kernel_session, slug="rem-tamper")  # production by default
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
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()

        approval_service.decide(
            kernel_session,
            tenant_id=fixture.tenant_id,
            action_id=action.id,
            actor_user_id=approver.id,
            decision=ApprovalDecision.APPROVED,
            expected_action_version_hash=action.action_version_hash,
            justification="looks correct, approving",
            clock=clock,
        )

        # Tamper: change the target revision after approval, without recomputing
        # action_version_hash - the row itself is now internally inconsistent.
        kernel_session.execute(
            sa.update(RemediationAction)
            .where(
                RemediationAction.tenant_id == fixture.tenant_id, RemediationAction.id == action.id
            )
            .values(arguments={"deployment": "checkout-api", "to_revision": 999})
        )
        kernel_session.commit()

        resumed = _resume_remediation(
            session_factory, remediation_resolver, clock, fixture, outcome
        )

        assert resumed.terminated
        assert resumed.incident_status is IncidentStatus.ESCALATED
        assert resumed.termination_reason is not None
        assert "SI-6" in resumed.termination_reason

        kernel_session.expire_all()
        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert action.status is not RemediationActionStatus.SUCCEEDED
        assert (
            kernel_session.execute(
                sa.select(sa.func.count())
                .select_from(Verification)
                .where(Verification.tenant_id == fixture.tenant_id)
            ).scalar_one()
            == 0
        )


class TestHighRiskNeverAutonomous:
    """R2 (high-risk) requires approval in every environment, even a clean non-production
    proposal that an equivalent R1 action would execute autonomously (P3) - the end-to-end
    proof of ``tests/domain/test_policy.py``'s unit-level P3 assertion, through the real
    graph, the real registry ceiling, and the real database."""

    def test_r2_requires_approval_even_in_non_production(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        fixture = build_fixture(kernel_session, slug="rem-r2-nonprod")
        fixture.environment.is_production = False
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
            _r2_remediation_scenario(),
        )

        assert outcome.terminated is False
        assert outcome.incident_status is IncidentStatus.AWAITING_APPROVAL

        decision = kernel_session.execute(
            sa.select(PolicyDecision).where(PolicyDecision.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert decision.rule_id == "P3_high_risk_requires_approval"

        action = kernel_session.execute(
            sa.select(RemediationAction).where(RemediationAction.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert action.tool_name == "k8s.node.cordon"
        assert action.status is RemediationActionStatus.AWAITING_APPROVAL
