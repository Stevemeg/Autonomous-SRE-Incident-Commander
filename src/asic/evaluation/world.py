"""Arranging an evaluation world: an administrative operation, kept out of the runtime path.

Creating a tenant, a behaviour version, grants and an approver requires privileges the
application role deliberately lacks, so the harness arranges each scenario through a
separately supplied administrative session factory - exactly as onboarding would - and then
executes and observes the workflow as the application role, under row-level security.

Every scenario gets its own environment, incident and (per suite run) unique environment
name. Tool-execution idempotency keys include the environment, so neither two scenarios in
one suite nor two suite runs in one tenant can deduplicate against each other.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Alert,
    BehaviourVersion,
    ConnectorScopeBinding,
    Environment,
    Incident,
    IntegrationConnector,
    Permission,
    Role,
    RolePermission,
    Service,
    Tenant,
    TenantToolGrant,
    ToolDefinition,
    User,
    UserRoleAssignment,
)
from asic.db.session import bind_tenant
from asic.domain.enums import (
    AlertSeverity,
    AlertStatus,
    IncidentSeverity,
    IncidentStatus,
    IntegrationKind,
    UserStatus,
)
from asic.domain.idempotency import alert_key
from asic.evaluation.corpus import GoldenScenario
from asic.evaluation.versioning import digest
from asic.remediation.approval_service import REMEDIATION_APPROVE_PERMISSION


@dataclass(frozen=True, slots=True)
class ScenarioWorld:
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    environment_name: str
    service_ids: tuple[uuid.UUID, ...]
    service_names: tuple[str, ...]
    incident_id: uuid.UUID
    clock_start: datetime
    approver_user_id: uuid.UUID | None = None


def ensure_tenant(admin: Callable[[], Session], slug: str) -> uuid.UUID:
    with admin() as session, session.begin():
        existing = session.scalar(sa.select(Tenant.id).where(Tenant.slug == slug))
        if existing is not None:
            return existing
        tenant = Tenant(id=uuid.uuid4(), slug=slug, display_name=f"Evaluation {slug}")
        session.add(tenant)
        return tenant.id


def ensure_behaviour_version(
    admin: Callable[[], Session],
    *,
    code_version: str,
    prompt_set_version: str,
    model_ids: dict[str, str],
    retriever_config_version: str,
    policy_version: str,
    tool_registry_version: str,
    judge_set_version: str | None,
) -> uuid.UUID:
    fingerprint = digest(
        {
            "code_version": code_version,
            "prompt_set_version": prompt_set_version,
            "model_ids": model_ids,
            "retriever_config_version": retriever_config_version,
            "policy_version": policy_version,
            "tool_registry_version": tool_registry_version,
            "judge_set_version": judge_set_version,
        }
    )
    with admin() as session, session.begin():
        existing = session.scalar(
            sa.select(BehaviourVersion.id).where(BehaviourVersion.fingerprint == fingerprint)
        )
        if existing is not None:
            return existing
        row = BehaviourVersion(
            id=uuid.uuid4(),
            label=f"eval-{fingerprint[:16]}",
            code_version=code_version,
            prompt_set_version=prompt_set_version,
            model_ids=model_ids,
            retriever_config_version=retriever_config_version,
            policy_version=policy_version,
            tool_registry_version=tool_registry_version,
            judge_set_version=judge_set_version,
            fingerprint=fingerprint,
        )
        session.add(row)
        return row.id


def arrange(
    admin: Callable[[], Session],
    *,
    tenant_id: uuid.UUID,
    golden: GoldenScenario,
    service_name: str,
    suite_token: str,
    ordinal: int,
    clock_start: datetime,
) -> ScenarioWorld:
    """Create one scenario's environment, services, incident, alert and grants."""
    environment_name = f"ev{suite_token}{ordinal:02d}"
    with admin() as session, session.begin():
        bind_tenant(session, tenant_id)
        environment = Environment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            name=environment_name,
            display_name=f"Evaluation {golden.key}",
            is_production=golden.production,
        )
        session.add(environment)
        session.flush()
        names = (service_name, *golden.extra_services)
        services = [
            Service(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                name=name,
                display_name=name,
                owner_team="evaluation",
                namespaces=["checkout"],
            )
            for name in names
        ]
        services_by_env = [
            s
            for s in services
            if session.scalar(
                sa.select(Service.id).where(Service.tenant_id == tenant_id, Service.name == s.name)
            )
            is None
        ]
        session.add_all(services_by_env)
        session.flush()
        resolved = [
            session.scalar(
                sa.select(Service).where(Service.tenant_id == tenant_id, Service.name == name)
            )
            for name in names
        ]
        service_rows = [row for row in resolved if row is not None]
        incident = Incident(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            reference=f"EV-{suite_token[:8].upper()}-{ordinal:03d}",
            title=golden.title[:200],
            environment_id=environment.id,
            status=IncidentStatus.DETECTED,
            severity=IncidentSeverity.SEV2,
            opened_at=clock_start,
        )
        session.add(incident)
        session.flush()
        started = clock_start - timedelta(minutes=5)
        fingerprint = f"{golden.key}-{suite_token}"
        session.add(
            Alert(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident.id,
                service_id=service_rows[0].id,
                environment_id=environment.id,
                source="evaluation",
                source_fingerprint=fingerprint,
                title=golden.title[:200],
                severity=AlertSeverity.HIGH,
                status=AlertStatus.CORRELATED,
                started_at=started,
                received_at=clock_start,
                idempotency_key=alert_key(
                    tenant_id=tenant_id,
                    source="evaluation",
                    source_fingerprint=fingerprint,
                    started_at=started,
                ),
            )
        )
        for definition_id in session.scalars(sa.select(ToolDefinition.id)):
            session.add(
                TenantToolGrant(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    tool_definition_id=definition_id,
                    environment_id=environment.id,
                    is_enabled=True,
                )
            )
        approver_id: uuid.UUID | None = None
        if golden.remediation is not None and golden.remediation.approve:
            approver_id = _approver(session, tenant_id, environment.id, suite_token, ordinal)
        session.flush()
        return ScenarioWorld(
            tenant_id=tenant_id,
            environment_id=environment.id,
            environment_name=environment_name,
            service_ids=tuple(row.id for row in service_rows),
            service_names=tuple(row.name for row in service_rows),
            incident_id=incident.id,
            clock_start=clock_start,
            approver_user_id=approver_id,
        )


def _approver(
    session: Session,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    suite_token: str,
    ordinal: int,
) -> uuid.UUID:
    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        external_idp_subject=f"evaluation|approver-{suite_token}-{ordinal}",
        email=f"approver-{suite_token}-{ordinal}@evaluation.invalid",
        display_name="Evaluation approver",
        status=UserStatus.ACTIVE,
    )
    session.add(user)
    session.flush()
    permission_id = session.scalar(
        sa.select(Permission.id).where(Permission.key == REMEDIATION_APPROVE_PERMISSION)
    )
    if permission_id is None:  # pragma: no cover - seeded by migration 0011
        raise RuntimeError("remediation approval permission is not seeded")
    role = Role(
        id=uuid.uuid4(),
        key=f"eval_approver_{suite_token}_{ordinal}",
        display_name="Evaluation approver",
        description="Evaluation-only approver, scoped to one evaluation environment.",
        is_system=False,
    )
    session.add(role)
    session.flush()
    session.add(RolePermission(role_id=role.id, permission_id=permission_id))
    session.add(
        UserRoleAssignment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user.id,
            role_id=role.id,
            environment_id=environment_id,
        )
    )
    return user.id


def bind_connector(
    admin: Callable[[], Session],
    world: ScenarioWorld,
    *,
    kind: IntegrationKind,
    endpoint: str,
    credential_ref: str,
) -> str:
    connector_id = f"eval-{kind.value}-{uuid.uuid4().hex[:8]}"
    with admin() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        session.add(
            IntegrationConnector(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                connector_id=connector_id,
                kind=kind,
                environment_id=world.environment_id,
                endpoint_url=endpoint,
                credential_ref=credential_ref,
            )
        )
        session.add(
            ConnectorScopeBinding(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                connector_id=connector_id,
                source=kind.value,
                service_id=world.service_ids[0],
                environment_id=world.environment_id,
            )
        )
    return connector_id


def revoke_connector(admin: Callable[[], Session], world: ScenarioWorld, connector_id: str) -> None:
    with admin() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        session.execute(
            sa.update(ConnectorScopeBinding)
            .where(
                ConnectorScopeBinding.tenant_id == world.tenant_id,
                ConnectorScopeBinding.connector_id == connector_id,
            )
            .values(is_enabled=False, revoked_at=sa.func.now())
        )


__all__ = [
    "ScenarioWorld",
    "arrange",
    "bind_connector",
    "ensure_behaviour_version",
    "ensure_tenant",
    "revoke_connector",
]
