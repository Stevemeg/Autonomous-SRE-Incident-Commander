"""Fixtures for the remediation graph and kernel (Phase 8).

Registered from ``tests/conftest.py`` alongside ``tests.kernel_fixtures``, which this module
builds directly on: a remediation run only ever starts against an incident that is
``investigating`` with a live hypothesis, and the most honest way to produce exactly that
state is to run the real investigation kernel to an escalation and then apply the same
human-authored, justified ``escalated -> investigating`` transition a real operator would
(ADR-0023) - not to hand-construct hypothesis and evidence rows that bypass every invariant
those tables' own tests already prove.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Hypothesis, Permission, Role, RolePermission, User, UserRoleAssignment
from asic.db.models.tools import ToolDefinition
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import ActorType, HypothesisStatus, IncidentStatus, RiskTier, UserStatus
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.kernel import InvestigationKernel
from asic.remediation.approval_service import REMEDIATION_APPROVE_PERMISSION
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import Scenario
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry
from tests.kernel_fixtures import Fixture


@pytest.fixture
def remediation_resolver() -> CapabilityResolver:
    """A resolver whose ceiling covers R2 (ADR-0023): what the remediation kernel uses."""
    return CapabilityResolver(ToolRegistry.remediation_full(), max_risk_tier=RiskTier.R2)


def grant_write_capabilities(
    session: Session, fixture: Fixture, *, capabilities: tuple[str, ...] | None = None
) -> None:
    """Grant the tenant every write capability, or a named subset.

    Separate from ``build_fixture``'s own grant loop so an investigation-only test's
    fixture is unaffected unless it opts in - the write catalogue exists in the same
    ``tool_definition`` table, but nothing grants it automatically.
    """
    from asic.db.models import TenantToolGrant

    definitions = list(
        session.execute(
            sa.select(ToolDefinition).where(ToolDefinition.risk_tier != RiskTier.RO)
        ).scalars()
    )
    for definition in definitions:
        if capabilities is not None and definition.capability not in capabilities:
            continue
        session.add(
            TenantToolGrant(
                id=uuid.uuid4(),
                tenant_id=fixture.tenant_id,
                tool_definition_id=definition.id,
                environment_id=fixture.environment.id,
                is_enabled=True,
            )
        )
    session.flush()


def create_approver(
    session: Session, fixture: Fixture, *, email: str = "approver@example.com"
) -> User:
    """A user holding a role that grants ``remediation.approve`` at every tier."""
    user = User(
        id=uuid.uuid4(),
        tenant_id=fixture.tenant_id,
        external_idp_subject=f"idp|{uuid.uuid4().hex[:12]}",
        email=email,
        display_name="Test Approver",
        status=UserStatus.ACTIVE,
    )
    session.add(user)
    session.flush()

    permission = session.execute(
        sa.select(Permission).where(Permission.key == REMEDIATION_APPROVE_PERMISSION)
    ).scalar_one()

    role = Role(
        id=uuid.uuid4(),
        key=f"sre_approver_{uuid.uuid4().hex[:8]}",
        display_name="SRE Approver",
        description="Test-only role granting remediation approval authority.",
        is_system=False,
    )
    session.add(role)
    session.flush()
    session.add(RolePermission(role_id=role.id, permission_id=permission.id))

    session.add(
        UserRoleAssignment(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant_id,
            user_id=user.id,
            role_id=role.id,
            environment_id=None,  # tenant-wide, every environment
        )
    )
    session.flush()
    return user


def escalate_to_accepted_hypothesis(
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
    fixture: Fixture,
    scenario_obj: Scenario,
) -> uuid.UUID:
    """Run the real investigation kernel to an escalation, then reopen it (human, justified).

    Returns the id of the resulting hypothesis - the one a remediation run is started
    against. The incident is left ``investigating``, exactly the state ADR-0023 requires.
    """
    kernel = InvestigationKernel(
        session_factory=session_factory,
        resolver=resolver,
        providers=[SimulatorProvider(scenario_obj, clock=clock)],
        model=DeterministicModelProvider(scenario_obj),
        clock=clock,
        budget_policy=scenario_obj.budget,
    )
    outcome = kernel.start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
        fixture_refs=scenario_obj.fixture_ref(),
        random_seed=42,
    )
    assert outcome.terminated

    session = session_factory()
    try:
        bind_tenant(session, fixture.tenant_id)
        from asic.db.models.incident import Incident
        from asic.db.projections import apply_transition

        incident = session.execute(
            sa.select(Incident).where(
                Incident.tenant_id == fixture.tenant_id, Incident.id == fixture.incident.id
            )
        ).scalar_one()
        if incident.status is IncidentStatus.ESCALATED:
            apply_transition(
                session,
                incident=incident,
                target=IncidentStatus.INVESTIGATING,
                actor_type=ActorType.HUMAN,
                source="test-operator",
                correlation_id=uuid.uuid4(),
                justification="test fixture: reopened to attempt automated remediation",
            )
        hypothesis = session.execute(
            sa.select(Hypothesis)
            .where(
                Hypothesis.tenant_id == fixture.tenant_id,
                Hypothesis.incident_id == fixture.incident.id,
                Hypothesis.status.in_((HypothesisStatus.PROPOSED, HypothesisStatus.ACCEPTED)),
            )
            .order_by(Hypothesis.rank)
            .limit(1)
        ).scalar_one()
        session.commit()
        return hypothesis.id
    finally:
        session.close()


__all__ = [
    "create_approver",
    "escalate_to_accepted_hypothesis",
    "grant_write_capabilities",
    "remediation_resolver",
]
