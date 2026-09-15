"""A committed, tenant-isolated world for database-backed governed-memory tests.

Builds the full chain a ``verified_outcome`` proposal needs to resolve against - a
terminated incident, a remediation action, and a ``VERIFIED`` verification - plus two
distinct users: a proposer and an approver holding ``memory.promotion.decide``. Everything
goes through ``asic_test_app``, the same unprivileged role production connects as.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import (
    Hypothesis,
    Incident,
    Permission,
    RemediationAction,
    RemediationBaseline,
    Role,
    RolePermission,
    ToolDefinition,
    ToolExecution,
    User,
    UserRoleAssignment,
    Verification,
    WorkflowRun,
)
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    IncidentSeverity,
    IncidentStatus,
    NodeId,
    RemediationActionStatus,
    RiskTier,
    TerminationReason,
    ToolExecutionOutcome,
    VerificationVerdict,
)
from asic.domain.idempotency import action_version_hash
from asic.memory.policy import MemoryActor
from asic.memory.service import DECIDE_PERMISSION, MemoryGovernanceService
from asic.remediation.trust import baseline_json, baseline_provenance, observation_provenance
from asic.remediation.verification import profile_for
from tests.conftest import make_behaviour_version
from tests.kernel_fixtures import build_fixture

CLOCK_START = datetime(2026, 9, 11, 10, 0, tzinfo=UTC)


@dataclass
class MemoryWorld:
    factory: sessionmaker[Session]
    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    #: A second, independent terminated incident in the same tenant.
    other_incident_id: uuid.UUID
    verification_id: uuid.UUID
    remediation_action_id: uuid.UUID
    proposer_user_id: uuid.UUID
    approver_user_id: uuid.UUID
    #: A second approver, so tests can exercise more than one qualified decider.
    second_approver_user_id: uuid.UUID
    #: A human user in the tenant holding no permissions at all.
    unauthorized_user_id: uuid.UUID
    clock: FrozenClock
    service: MemoryGovernanceService
    #: Global-catalogue rows this world created, for teardown (see the ``world`` fixture).
    _tool_definition_id: uuid.UUID | None
    _role_ids: tuple[uuid.UUID, ...]

    @property
    def agent(self) -> MemoryActor:
        return MemoryActor(actor_type=ActorType.AGENT_NODE, actor_id="node:hypothesis-engine")

    @property
    def human_proposer(self) -> MemoryActor:
        return MemoryActor(actor_type=ActorType.HUMAN, user_id=self.proposer_user_id)

    @property
    def approver(self) -> MemoryActor:
        return MemoryActor(actor_type=ActorType.HUMAN, user_id=self.approver_user_id)

    @property
    def second_approver(self) -> MemoryActor:
        return MemoryActor(actor_type=ActorType.HUMAN, user_id=self.second_approver_user_id)

    @property
    def unauthorized_human(self) -> MemoryActor:
        return MemoryActor(actor_type=ActorType.HUMAN, user_id=self.unauthorized_user_id)

    def count_decisions(self) -> int:
        from asic.db.models import MemoryWriteDecision

        with self.factory() as session, session.begin():
            bind_tenant(session, self.tenant_id)
            return int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(MemoryWriteDecision)
                    .where(MemoryWriteDecision.tenant_id == self.tenant_id)
                )
                or 0
            )


def _user(session: Session, tenant_id: uuid.UUID, subject: str) -> uuid.UUID:
    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        external_idp_subject=subject,
        email=f"{subject}@example.invalid",
        display_name=subject,
    )
    session.add(user)
    session.flush()
    return user.id


def _grant_decide_permission(
    session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> uuid.UUID:
    """Bundle ``memory.promotion.decide`` into a role and assign it to ``user_id``.

    Global catalogue tables (``role``, ``permission``, ``role_permission``) are read-only to
    the application in production; ``asic_test_app`` gets a narrow test-only INSERT grant
    (``tests/conftest.py``) so a test can build one of these bundles for itself. Returns the
    role id so the ``world`` fixture can remove it again - nothing in this schema deletes
    itself, and a role left behind is a second, harmless kind of catalogue drift, but
    ``tool_definition`` (see below) is not harmless, so teardown cleans up both.
    """
    permission_id = session.scalar(
        sa.select(Permission.id).where(Permission.key == DECIDE_PERMISSION)
    )
    assert permission_id is not None, "migration 0008 must have seeded the decide permission"
    role = Role(
        id=uuid.uuid4(),
        key=f"memory-admin-{uuid.uuid4().hex[:8]}",
        display_name="Memory Promotion Admin",
        description="Grants memory.promotion.decide for this test world.",
        is_system=False,
    )
    session.add(role)
    session.flush()
    session.add(RolePermission(role_id=role.id, permission_id=permission_id))
    session.add(
        UserRoleAssignment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            role_id=role.id,
            environment_id=None,
        )
    )
    session.flush()
    return role.id


def make_world(
    engine: sa.Engine, *, slug: str | None = None, trusted_verification: bool = True
) -> MemoryWorld:
    factory = sessionmaker(engine, expire_on_commit=False, autoflush=False)
    with factory() as session, session.begin():
        fixture = build_fixture(session, slug=slug or f"mem-{uuid.uuid4().hex[:12]}")
        tenant_id = fixture.tenant.id
        incident = fixture.incident
        # build_fixture creates the incident DETECTED; terminate it here so status and
        # terminated_at land in the same flush (the database requires both together).
        incident.status = IncidentStatus.RESOLVED
        incident.termination_reason = TerminationReason.SUCCESS
        incident.terminated_at = CLOCK_START - timedelta(hours=1)
        session.flush()

        other_incident = _terminated_incident_like(session, tenant_id, fixture.environment.id)

        version = make_behaviour_version(session, label=f"bv-{uuid.uuid4().hex[:8]}")
        run = WorkflowRun(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            incident_id=incident.id,
            behaviour_version_id=version.id,
        )
        session.add(run)
        session.flush()

        hypothesis = Hypothesis(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            incident_id=incident.id,
            workflow_run_id=run.id,
            rank=1,
            root_cause_class="connection_pool_exhaustion",
            statement="The checkout connection pool was exhausted under load.",
            confidence=0.85,
            produced_by_node=NodeId.G5_HYPOTHESIS_ENGINE,
        )
        session.add(hypothesis)
        session.flush()

        tool = session.scalar(
            sa.select(ToolDefinition).where(
                ToolDefinition.name == "k8s.deployment.rollback",
                ToolDefinition.version == "1.0.0",
            )
        )
        read_tool = session.scalar(
            sa.select(ToolDefinition).where(
                ToolDefinition.name == "metrics.query", ToolDefinition.version == "1.0.0"
            )
        )
        assert tool is not None and read_tool is not None
        profile = profile_for(tool.name)

        from asic.db.models import RemediationTarget

        target = RemediationTarget(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            workflow_run_id=run.id,
            incident_id=incident.id,
            investigation_run_id=run.id,
            hypothesis_id=hypothesis.id,
            service_id=fixture.service.id,
            environment_id=fixture.environment.id,
            resolved_permission_scope={
                "tenant_id": str(tenant_id),
                "environment": fixture.environment.name,
                "service": fixture.service.name,
                "namespace": "checkout",
            },
        )
        session.add(target)
        session.flush()

        action_id = uuid.uuid4()
        criteria = profile.to_dict()
        criteria_hash = action_version_hash(
            action_id=action_id,
            tool_name="verification_criteria",
            tool_version="1",
            arguments=criteria,
            permission_scope={},
            preconditions=(),
            risk_tier=tool.risk_tier.value,
        )
        action = RemediationAction(
            id=action_id,
            tenant_id=tenant_id,
            incident_id=incident.id,
            workflow_run_id=run.id,
            hypothesis_id=hypothesis.id,
            tool_definition_id=tool.id,
            remediation_target_id=target.id,
            reason="Restart the checkout deployment to clear the exhausted pool.",
            expected_effect={"http_5xx_rate": "< 0.005"},
            risk_tier=tool.risk_tier,
            permission_scope={"namespaces": ["checkout"]},
            preconditions=["deployment_exists"],
            rollback_tool_name=tool.rollback_tool_name,
            approval_required=True,
            timeout_seconds=300,
            verification_criteria=criteria,
            verification_criteria_hash=criteria_hash,
            tool_name=tool.name,
            tool_version=tool.version,
            arguments={"namespace": "checkout", "deployment": "checkout-api"},
            action_version_hash="a" * 64,
            request_idempotency_key=uuid.uuid4().hex + uuid.uuid4().hex,
            proposed_by_node=NodeId.G6_REMEDIATION_PLANNER,
            # Independently verified (P6-05): the action's own denormalized status must
            # agree with the verification row below, not merely coexist with it.
            status=RemediationActionStatus.VERIFIED,
            executed_at=CLOCK_START - timedelta(minutes=55),
        )
        session.add(action)
        session.flush()

        baseline: RemediationBaseline | None = None
        post_execution: ToolExecution | None = None
        observed: dict[str, object]
        if trusted_verification:
            baseline_observed_at = action.executed_at - timedelta(seconds=90)
            baseline_captured_at = action.executed_at - timedelta(seconds=30)
            baseline_execution = ToolExecution(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident.id,
                remediation_action_id=action.id,
                tool_definition_id=read_tool.id,
                tool_name=read_tool.name,
                tool_version=read_tool.version,
                capability=profile.source_capability,
                risk_tier=RiskTier.RO,
                resolved_scope={
                    "service": fixture.service.name,
                    "environment": fixture.environment.name,
                },
                arguments_redacted={"metric": profile.metric},
                idempotency_key=uuid.uuid4().hex * 2,
                actor_type=ActorType.AGENT_NODE,
                requested_by_node=NodeId.G10_VERIFIER,
                attempt=1,
                outcome=ToolExecutionOutcome.SUCCEEDED,
                observed_effect={
                    "source": "prometheus-simulator",
                    "samples_count": 1,
                    "measurement_series": profile.metric,
                    "latest_sample": f"{baseline_observed_at.isoformat()}=0.021",
                },
                started_at=action.executed_at - timedelta(minutes=2),
                completed_at=baseline_captured_at,
                duration_ms=1,
                correlation_id=uuid.uuid4(),
            )
            session.add(baseline_execution)
            session.flush()
            baseline = RemediationBaseline(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident.id,
                remediation_target_id=target.id,
                remediation_action_id=action.id,
                service_id=fixture.service.id,
                environment_id=fixture.environment.id,
                profile_id=profile.profile_id,
                profile_version=profile.profile_version,
                criteria_hash=criteria_hash,
                metric=profile.metric,
                source_capability=profile.source_capability,
                source_provider="prometheus-simulator",
                read_execution_id=baseline_execution.id,
                observed_at=baseline_observed_at,
                captured_at=baseline_captured_at,
                observed_value=0.021,
                provenance_hash="",
            )
            baseline.provenance_hash = baseline_provenance(baseline)
            session.add(baseline)
            action.baseline_snapshot = baseline_json(baseline)

            post_observed_at = action.executed_at + timedelta(minutes=2)
            post_execution = ToolExecution(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident.id,
                remediation_action_id=action.id,
                tool_definition_id=read_tool.id,
                tool_name=read_tool.name,
                tool_version=read_tool.version,
                capability=profile.source_capability,
                risk_tier=RiskTier.RO,
                resolved_scope={
                    "service": fixture.service.name,
                    "environment": fixture.environment.name,
                },
                arguments_redacted={"metric": profile.metric},
                idempotency_key=uuid.uuid4().hex * 2,
                actor_type=ActorType.AGENT_NODE,
                requested_by_node=NodeId.G10_VERIFIER,
                attempt=1,
                outcome=ToolExecutionOutcome.SUCCEEDED,
                observed_effect={
                    "source": "prometheus-simulator",
                    "samples_count": 1,
                    "measurement_series": profile.metric,
                    "latest_sample": f"{post_observed_at.isoformat()}=0.001",
                },
                started_at=action.executed_at + timedelta(minutes=1),
                completed_at=post_observed_at,
                duration_ms=1,
                correlation_id=uuid.uuid4(),
            )
            session.add(post_execution)
            session.flush()
            observed = {
                "metric": profile.metric,
                "observed_value": 0.001,
                "observed_at": post_observed_at.isoformat(),
                "source": "prometheus-simulator",
                "tool_execution_id": str(post_execution.id),
                "target_service_id": str(fixture.service.id),
                "target_environment_id": str(fixture.environment.id),
                "source_capability": profile.source_capability,
                "profile_id": profile.profile_id,
                "profile_version": profile.profile_version,
                "baseline_value": 0.021,
                "threshold": profile.threshold,
                "threshold_passed": True,
                "direction_passed": True,
            }
        else:
            observed = {"http_5xx_rate": 0.001}

        verification = Verification(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            remediation_action_id=action.id,
            remediation_baseline_id=baseline.id if baseline else None,
            post_action_read_execution_id=post_execution.id if post_execution else None,
            profile_id=profile.profile_id if baseline else None,
            profile_version=profile.profile_version if baseline else None,
            observed_metric=profile.metric if baseline else None,
            observed_value=0.001 if baseline else None,
            observed_at=(action.executed_at + timedelta(minutes=2)) if baseline else None,
            observation_source_provider="prometheus-simulator" if baseline else None,
            observation_source_capability=profile.source_capability if baseline else None,
            observation_provenance_hash=(
                observation_provenance(
                    tenant_id=tenant_id,
                    incident_id=incident.id,
                    remediation_target_id=target.id,
                    remediation_action_id=action.id,
                    remediation_baseline_id=baseline.id,
                    service_id=fixture.service.id,
                    environment_id=fixture.environment.id,
                    profile_id=profile.profile_id,
                    profile_version=profile.profile_version,
                    criteria_hash=criteria_hash,
                    metric=profile.metric,
                    source_capability=profile.source_capability,
                    source_provider="prometheus-simulator",
                    read_execution_id=post_execution.id,
                    observed_at=action.executed_at + timedelta(minutes=2),
                    observed_value=0.001,
                )
                if baseline is not None and post_execution is not None
                else None
            ),
            attempt=1,
            callback_idempotency_key=uuid.uuid4().hex * 2,
            criteria_hash=action.verification_criteria_hash,
            verdict=VerificationVerdict.VERIFIED,
            # Real evidentiary content (P6-05): a verdict with no recorded measurement is
            # an assertion, not a verification.
            baseline=baseline_json(baseline) if baseline else {"http_5xx_rate": 0.021},
            observed=observed,
            observation_window_start=action.executed_at + timedelta(minutes=1),
            observation_window_end=action.executed_at + timedelta(minutes=3),
            verified_at=action.executed_at + timedelta(minutes=3),
        )
        session.add(verification)
        session.flush()

        proposer_id = _user(session, tenant_id, "proposer")
        approver_id = _user(session, tenant_id, "approver")
        second_approver_id = _user(session, tenant_id, "approver-two")
        unauthorized_id = _user(session, tenant_id, "no-permissions")
        role_ids = (
            _grant_decide_permission(session, tenant_id, approver_id),
            _grant_decide_permission(session, tenant_id, second_approver_id),
            # The proposer also holds the permission, so a test can isolate
            # "may decide, but not this one" from "may not decide at all".
            _grant_decide_permission(session, tenant_id, proposer_id),
        )

        ids = (
            tenant_id,
            incident.id,
            other_incident.id,
            verification.id,
            action.id,
            proposer_id,
            approver_id,
            second_approver_id,
            unauthorized_id,
        )

    clock = FrozenClock(start=CLOCK_START)
    return MemoryWorld(
        factory=factory,
        tenant_id=ids[0],
        incident_id=ids[1],
        other_incident_id=ids[2],
        verification_id=ids[3],
        remediation_action_id=ids[4],
        proposer_user_id=ids[5],
        approver_user_id=ids[6],
        second_approver_user_id=ids[7],
        unauthorized_user_id=ids[8],
        _tool_definition_id=None,
        _role_ids=role_ids,
        clock=clock,
        service=MemoryGovernanceService(factory, clock=clock),
    )


def _terminated_incident_like(
    session: Session, tenant_id: uuid.UUID, environment_id: uuid.UUID
) -> Incident:
    incident = Incident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        reference=f"INC-{uuid.uuid4().hex[:8]}",
        title="A second, unrelated incident",
        environment_id=environment_id,
        status=IncidentStatus.RESOLVED,
        severity=IncidentSeverity.SEV3,
        opened_at=CLOCK_START - timedelta(hours=4),
        termination_reason=TerminationReason.SUCCESS,
        terminated_at=CLOCK_START - timedelta(hours=3),
    )
    session.add(incident)
    session.flush()
    return incident


def _teardown(owner_engine: sa.Engine, built: MemoryWorld) -> None:
    """Remove the global-catalogue rows this world created.

    Nothing in this schema is designed to be deleted - every foreign key is ``RESTRICT``
    or append-only-guarded by design (an incident-commander audit trail should not
    silently cascade-delete). That is exactly right for the application, and exactly wrong
    for a test that commits a real ``tool_definition`` row: the tool registry cross-checks
    ``tool_definition`` against the code catalogue exhaustively (:class:`RegistryDrift`),
    so a single leftover row fails every *other* test in the suite that builds a registry,
    not just this one. Tenant-scoped rows (the incidents, the remediation action, the
    verification, the users) do not have that problem - they are isolated by row-level
    security and nothing cross-validates the tenant catalogue - so only the chain blocking
    deletion of ``tool_definition``, plus the roles this world created, is removed here.
    Runs as the schema owner: it bypasses RLS and the APPEND_ONLY_TABLES restriction that
    ``asic_test_app`` is deliberately subject to.
    """
    with owner_engine.begin() as conn:
        conn.execute(
            sa.text("DELETE FROM memory_write_decision WHERE tenant_id = :tid"),
            {"tid": built.tenant_id},
        )
        # ``memory_entry`` and ``memory_promotion`` reference each other (the entry names
        # its promotion; the promotion names the entry it produced), and memory_promotion's
        # governance CHECK constraints only accept the state transitions the service layer
        # itself makes - not "delete this, it was a test". Disabling triggers (superuser
        # only) turns off FK enforcement for this transaction without touching the CHECK
        # constraints at all, since DELETE never evaluates them.
        conn.execute(sa.text("ALTER TABLE memory_entry DISABLE TRIGGER ALL"))
        conn.execute(sa.text("ALTER TABLE memory_promotion DISABLE TRIGGER ALL"))
        conn.execute(
            sa.text("DELETE FROM memory_entry WHERE tenant_id = :tid"), {"tid": built.tenant_id}
        )
        conn.execute(
            sa.text("DELETE FROM memory_promotion WHERE tenant_id = :tid"),
            {"tid": built.tenant_id},
        )
        conn.execute(sa.text("ALTER TABLE memory_entry ENABLE TRIGGER ALL"))
        conn.execute(sa.text("ALTER TABLE memory_promotion ENABLE TRIGGER ALL"))
        conn.execute(
            sa.text("DELETE FROM verification WHERE tenant_id = :tid"), {"tid": built.tenant_id}
        )
        conn.execute(
            sa.text("DELETE FROM remediation_action WHERE tenant_id = :tid"),
            {"tid": built.tenant_id},
        )
        if built._tool_definition_id is not None:
            conn.execute(
                sa.text("DELETE FROM tool_definition WHERE id = :id"),
                {"id": built._tool_definition_id},
            )
        conn.execute(
            sa.text("DELETE FROM user_role_assignment WHERE tenant_id = :tid"),
            {"tid": built.tenant_id},
        )
        conn.execute(
            sa.text("DELETE FROM role_permission WHERE role_id = ANY(:ids)"),
            {"ids": list(built._role_ids)},
        )
        conn.execute(
            sa.text("DELETE FROM role WHERE id = ANY(:ids)"), {"ids": list(built._role_ids)}
        )


@pytest.fixture
def world(app_engine: sa.Engine, owner_engine: sa.Engine) -> Iterator[MemoryWorld]:
    built = make_world(app_engine)
    try:
        yield built
    finally:
        _teardown(owner_engine, built)
