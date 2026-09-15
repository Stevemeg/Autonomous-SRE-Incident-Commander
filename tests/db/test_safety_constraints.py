"""Database enforcement of the safety invariants.

Each test attempts to persist a state the architecture forbids, and asserts the database
refuses it. These are the invariants that must survive an application bug, so testing them
at the application layer would miss the point.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import (
    Approval,
    PolicyDecision,
    RemediationAction,
    ToolDefinition,
    Verification,
)
from asic.db.session import bind_tenant
from asic.domain.enums import (
    ApprovalDecision,
    NodeId,
    PolicyVerdict,
    RiskTier,
    VerificationVerdict,
)
from tests.conftest import (
    make_behaviour_version,
    make_environment,
    make_incident,
    make_tenant,
    make_tool_definition,
    make_user,
)

pytestmark = pytest.mark.postgres

NOW = datetime.now(UTC)


def _hypothesis(session: Session, tenant, incident, run) -> uuid.UUID:
    from asic.db.models import Hypothesis

    hypothesis = Hypothesis(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        incident_id=incident.id,
        workflow_run_id=run.id,
        rank=1,
        root_cause_class="bad_deployment",
        statement="Revision 847 introduced a null dereference.",
        confidence=0.82,
        produced_by_node=NodeId.G5_HYPOTHESIS_ENGINE,
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis.id


def _workflow_run(session: Session, tenant, incident):
    from asic.db.models import WorkflowRun

    version = make_behaviour_version(session, label=f"bv-{uuid.uuid4().hex[:8]}")
    run = WorkflowRun(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        incident_id=incident.id,
        behaviour_version_id=version.id,
    )
    session.add(run)
    session.flush()
    return run


def _action(
    session: Session,
    tenant,
    incident,
    run,
    hypothesis_id: uuid.UUID,
    tool: ToolDefinition,
    **overrides,
) -> RemediationAction:
    from asic.db.models import Hypothesis, RemediationTarget, Service

    target = session.scalar(
        sa.select(RemediationTarget).where(RemediationTarget.workflow_run_id == run.id)
    )
    if target is None:
        hypothesis = session.get(Hypothesis, hypothesis_id)
        service = session.scalar(sa.select(Service).where(Service.tenant_id == tenant.id).limit(1))
        assert hypothesis is not None
        if service is None:
            service = Service(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                name="checkout-api",
                display_name="Checkout API",
                owner_team="checkout",
                namespaces=["checkout"],
            )
            session.add(service)
            session.flush()
        target = RemediationTarget(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            workflow_run_id=run.id,
            incident_id=incident.id,
            investigation_run_id=hypothesis.workflow_run_id,
            hypothesis_id=hypothesis_id,
            service_id=service.id,
            environment_id=incident.environment_id,
            resolved_permission_scope=dict(
                overrides.get("permission_scope", {"namespaces": ["checkout"]})
            ),
        )
        session.add(target)
        session.flush()
    defaults = {
        "id": uuid.uuid4(),
        "tenant_id": tenant.id,
        "incident_id": incident.id,
        "workflow_run_id": run.id,
        "hypothesis_id": hypothesis_id,
        "tool_definition_id": tool.id,
        "remediation_target_id": target.id,
        "reason": "Roll back the implicated deployment.",
        "expected_effect": {"http_5xx_rate": "< 0.005"},
        "risk_tier": tool.risk_tier,
        "permission_scope": {"namespaces": ["checkout"]},
        "preconditions": ["deployment_exists"],
        "rollback_tool_name": tool.rollback_tool_name,
        "approval_required": True,
        "timeout_seconds": 300,
        "verification_criteria": {"expr": "rate(http_5xx[5m]) < 0.005"},
        "verification_criteria_hash": "c" * 64,
        "tool_name": tool.name,
        "tool_version": tool.version,
        "arguments": {"namespace": "checkout", "deployment": "checkout-api"},
        "action_version_hash": "a" * 64,
        "request_idempotency_key": uuid.uuid4().hex + uuid.uuid4().hex,
        "proposed_by_node": NodeId.G6_REMEDIATION_PLANNER,
    }
    action = RemediationAction(**{**defaults, **overrides})
    session.add(action)
    session.flush()
    return action


class TestDestructiveActionsAreNotExpressible:
    """SI-5: a capability the system cannot name is safer than one it is told not to use."""

    def test_a_destructive_tool_cannot_be_registered(self, owner_session: Session) -> None:
        with pytest.raises(IntegrityError, match="no_destructive_tool_registered"):
            make_tool_definition(
                owner_session,
                name="k8s.pvc.delete",
                risk_tier=RiskTier.R3,
                rollback_tool_name=None,
            )

    def test_a_write_tool_without_a_rollback_is_rejected(self, owner_session: Session) -> None:
        with pytest.raises(IntegrityError, match="write_tool_declares_rollback"):
            make_tool_definition(
                owner_session, name="k8s.node.drain", risk_tier=RiskTier.R2, rollback_tool_name=None
            )

    def test_a_read_only_tool_may_not_declare_effect_metadata(self, owner_session: Session) -> None:
        """A settling delay on a read tool means someone modelled it as having an effect."""
        with pytest.raises(IntegrityError, match="read_only_tool_has_no_effect_metadata"):
            make_tool_definition(
                owner_session,
                name="metrics.query",
                risk_tier=RiskTier.RO,
                rollback_tool_name=None,
                settling_seconds=30,
            )

    def test_a_non_idempotent_write_tool_may_not_declare_retries(
        self, owner_session: Session
    ) -> None:
        """Retrying a non-idempotent write is how systems double-apply."""
        tool = make_tool_definition(owner_session, name="k8s.job.create", is_idempotent=False)
        tool.retry_policy = {"max_attempts": 3}
        with pytest.raises(IntegrityError, match="non_idempotent_write_declares_no_retry"):
            owner_session.flush()


class TestActionInvariants:
    def test_a_destructive_action_cannot_be_proposed(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        tool = make_tool_definition(app_session, name="t.safe", version="1.0.0")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        run = _workflow_run(app_session, tenant, incident)
        hyp = _hypothesis(app_session, tenant, incident, run)

        with pytest.raises(IntegrityError, match="no_destructive_action"):
            _action(app_session, tenant, incident, run, hyp, tool, risk_tier=RiskTier.R3)

    def test_a_high_risk_action_must_require_approval(self, app_session: Session) -> None:
        """R2 is never autonomous."""
        tenant = make_tenant(app_session, "acme")
        tool = make_tool_definition(
            app_session, name="t.r2", version="1.0.0", risk_tier=RiskTier.R2
        )
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        run = _workflow_run(app_session, tenant, incident)
        hyp = _hypothesis(app_session, tenant, incident, run)

        with pytest.raises(IntegrityError, match="high_risk_requires_approval"):
            _action(
                app_session,
                tenant,
                incident,
                run,
                hyp,
                tool,
                risk_tier=RiskTier.R2,
                approval_required=False,
            )

    def test_exactly_one_policy_decision_per_action(self, app_session: Session) -> None:
        """INV-6: an audit log that only records denials cannot prove what was permitted."""
        tenant = make_tenant(app_session, "acme")
        tool = make_tool_definition(app_session, name="t.one", version="1.0.0")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        run = _workflow_run(app_session, tenant, incident)
        hyp = _hypothesis(app_session, tenant, incident, run)
        action = _action(app_session, tenant, incident, run, hyp, tool)

        for _ in range(2):
            app_session.add(
                PolicyDecision(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    remediation_action_id=action.id,
                    verdict=PolicyVerdict.REQUIRE_APPROVAL,
                    rule_id="prod-requires-approval",
                    policy_version="v1",
                    rationale="Production environment and tier R1.",
                )
            )
        with pytest.raises(IntegrityError, match="uq_policy_decision_action"):
            app_session.flush()


class TestApprovalInvariants:
    def _setup(self, session: Session):
        tenant = make_tenant(session, "acme")
        tool = make_tool_definition(session, name="t.appr", version="1.0.0")
        bind_tenant(session, tenant.id)
        env = make_environment(session, tenant)
        incident = make_incident(session, tenant, env)
        run = _workflow_run(session, tenant, incident)
        hyp = _hypothesis(session, tenant, incident, run)
        action = _action(session, tenant, incident, run, hyp, tool)
        return tenant, action

    def test_self_approval_is_refused(self, app_session: Session) -> None:
        """INV-10: separation of duties applies to humans as it does to nodes."""
        tenant, action = self._setup(app_session)
        actor = make_user(app_session, tenant, "sre-1")

        app_session.add(
            Approval(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                action_version_hash=action.action_version_hash,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                required_role_key="sre_approver",
                proposer_user_id=actor.id,
                approver_user_id=actor.id,
                decision=ApprovalDecision.APPROVED,
                decided_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
            )
        )
        with pytest.raises(IntegrityError, match="no_self_approval"):
            app_session.flush()

    def test_a_granted_decision_must_name_its_approver(self, app_session: Session) -> None:
        tenant, action = self._setup(app_session)
        app_session.add(
            Approval(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                action_version_hash=action.action_version_hash,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                required_role_key="sre_approver",
                approver_user_id=None,
                decision=ApprovalDecision.APPROVED,
                decided_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
            )
        )
        with pytest.raises(IntegrityError, match="human_decision_names_approver"):
            app_session.flush()

    def test_expiry_is_a_system_outcome_with_no_approver(self, app_session: Session) -> None:
        """Expiry is a real, recorded outcome - not a hang and not an implicit approval."""
        tenant, action = self._setup(app_session)
        app_session.add(
            Approval(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                action_version_hash=action.action_version_hash,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                required_role_key="sre_approver",
                decision=ApprovalDecision.EXPIRED,
                expires_at=NOW + timedelta(minutes=30),
            )
        )
        app_session.flush()

    def test_one_decision_per_action_version(self, app_session: Session) -> None:
        """A re-proposed action gets a new hash and needs a fresh decision."""
        tenant, action = self._setup(app_session)
        approver = make_user(app_session, tenant, "approver")

        def approval(hash_value: str) -> Approval:
            return Approval(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                action_version_hash=hash_value,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                required_role_key="sre_approver",
                approver_user_id=approver.id,
                decision=ApprovalDecision.APPROVED,
                decided_at=NOW,
                expires_at=NOW + timedelta(minutes=30),
            )

        app_session.add(approval("a" * 64))
        app_session.flush()
        app_session.add(approval("a" * 64))
        with pytest.raises(IntegrityError, match="uq_approval_action_version"):
            app_session.flush()

    def test_duplicate_callback_delivery_collides(self, app_session: Session) -> None:
        """A chat platform delivering the same reply twice must not decide twice."""
        tenant, action = self._setup(app_session)
        approver = make_user(app_session, tenant, "approver")
        key = uuid.uuid4().hex * 2

        for version_hash in ("a" * 64, "b" * 64):
            app_session.add(
                Approval(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    remediation_action_id=action.id,
                    action_version_hash=version_hash,
                    callback_idempotency_key=key,
                    required_role_key="sre_approver",
                    approver_user_id=approver.id,
                    decision=ApprovalDecision.APPROVED,
                    decided_at=NOW,
                    expires_at=NOW + timedelta(minutes=30),
                )
            )
        with pytest.raises(IntegrityError, match="uq_approval_callback"):
            app_session.flush()

    def test_expiry_must_follow_the_request(self, app_session: Session) -> None:
        tenant, action = self._setup(app_session)
        app_session.add(
            Approval(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                action_version_hash="a" * 64,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                required_role_key="sre_approver",
                decision=ApprovalDecision.EXPIRED,
                requested_at=NOW,
                expires_at=NOW - timedelta(minutes=1),
            )
        )
        with pytest.raises(IntegrityError, match="expiry_after_request"):
            app_session.flush()


class TestVerificationInvariants:
    def test_repeated_verification_of_the_same_attempt_collides(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        tool = make_tool_definition(app_session, name="t.ver", version="1.0.0")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        run = _workflow_run(app_session, tenant, incident)
        hyp = _hypothesis(app_session, tenant, incident, run)
        action = _action(app_session, tenant, incident, run, hyp, tool)

        def verification(attempt: int, key: str) -> Verification:
            return Verification(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                attempt=attempt,
                callback_idempotency_key=key,
                criteria_hash=action.verification_criteria_hash,
                verdict=VerificationVerdict.VERIFIED,
                observation_window_start=NOW,
                observation_window_end=NOW + timedelta(minutes=5),
            )

        app_session.add(verification(1, uuid.uuid4().hex * 2))
        app_session.flush()
        app_session.add(verification(1, uuid.uuid4().hex * 2))
        with pytest.raises(IntegrityError, match="uq_verification_attempt"):
            app_session.flush()

    def test_observation_window_must_be_ordered(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        tool = make_tool_definition(app_session, name="t.win", version="1.0.0")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        run = _workflow_run(app_session, tenant, incident)
        hyp = _hypothesis(app_session, tenant, incident, run)
        action = _action(app_session, tenant, incident, run, hyp, tool)

        app_session.add(
            Verification(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                remediation_action_id=action.id,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                criteria_hash=action.verification_criteria_hash,
                verdict=VerificationVerdict.INCONCLUSIVE,
                observation_window_start=NOW,
                observation_window_end=NOW - timedelta(minutes=5),
            )
        )
        with pytest.raises(IntegrityError, match="window_ordered"):
            app_session.flush()


class TestIncidentTerminalConsistency:
    def test_a_terminal_status_must_record_when_and_why(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)

        # Raw SQL deliberately: this bypasses the ORM and the state machine, which is
        # exactly the path the database constraint has to catch.
        with pytest.raises(IntegrityError, match="terminal_status_has_terminated_at"):
            app_session.execute(
                sa.text("UPDATE incident SET status = 'resolved' WHERE id = :i"),
                {"i": incident.id},
            )

    def test_a_workflow_run_may_not_be_duplicated_while_active(self, app_session: Session) -> None:
        """Two live runs for one incident is the split-brain that double-executes."""
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        incident = make_incident(app_session, tenant, env)
        _workflow_run(app_session, tenant, incident)
        with pytest.raises(IntegrityError, match="uq_workflow_run_active"):
            _workflow_run(app_session, tenant, incident)
