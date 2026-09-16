"""Committed tenants with connectors, arranged by the owner and exercised by the app role."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ConnectorScopeBinding, IntegrationConnector
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import IntegrationKind, NodeId, RiskTier
from asic.integrations.base import AdapterRuntime
from asic.integrations.credentials import StaticCredentialProvider
from asic.integrations.provider import NativeIntegrationProvider
from asic.integrations.transport import HttpClientTransport
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_trace_id
from asic.tools.broker import CapabilityRequest, ToolBroker
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.provider import ToolProvider
from asic.tools.registry import ToolRegistry
from tests.integrations.conftest import NOW, SECRETS
from tests.kernel_fixtures import build_fixture


@dataclass
class IntegrationWorld:
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    service_id: uuid.UUID
    service_name: str
    incident_id: uuid.UUID
    sleeps: list[float] = field(default_factory=list)


def make_world(
    owner_engine: sa.Engine,
    *,
    endpoint: str,
    kinds: tuple[IntegrationKind, ...],
    bind: bool = True,
    settings: dict[IntegrationKind, dict[str, Any]] | None = None,
    credential_ref: str = "asic/test/read",
) -> IntegrationWorld:
    with Session(bind=owner_engine, expire_on_commit=False) as session:
        fixture = build_fixture(session, slug=f"integ-{uuid.uuid4().hex[:10]}")
        world = IntegrationWorld(
            tenant_id=fixture.tenant_id,
            environment_id=fixture.environment.id,
            service_id=fixture.service.id,
            service_name=fixture.service.name,
            incident_id=fixture.incident.id,
        )
        session.commit()
    for kind in kinds:
        add_connector(
            owner_engine,
            world,
            kind,
            endpoint=endpoint,
            bind=bind,
            settings=(settings or {}).get(kind, {}),
            credential_ref=credential_ref,
        )
    return world


def add_connector(
    owner_engine: sa.Engine,
    world: IntegrationWorld,
    kind: IntegrationKind,
    *,
    endpoint: str,
    bind: bool = True,
    settings: dict[str, Any] | None = None,
    credential_ref: str = "asic/test/read",
    service_id: uuid.UUID | None = None,
) -> str:
    connector_id = f"{kind.value}-{uuid.uuid4().hex[:8]}"
    with Session(bind=owner_engine) as session:
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
                write_credential_ref="asic/test/write",
                settings=settings or {},
            )
        )
        if bind:
            session.add(
                ConnectorScopeBinding(
                    id=uuid.uuid4(),
                    tenant_id=world.tenant_id,
                    connector_id=connector_id,
                    source=kind.value,
                    service_id=service_id or world.service_id,
                    environment_id=world.environment_id,
                )
            )
        session.commit()
    return connector_id


def revoke_bindings(owner_engine: sa.Engine, world: IntegrationWorld) -> None:
    with owner_engine.begin() as connection:
        connection.execute(
            sa.update(ConnectorScopeBinding)
            .where(ConnectorScopeBinding.tenant_id == world.tenant_id)
            .values(is_enabled=False, revoked_at=sa.func.now())
        )


def native_provider(*, secrets: dict[str, str] | None = None) -> NativeIntegrationProvider:
    return NativeIntegrationProvider(
        AdapterRuntime(
            transport=HttpClientTransport(),
            credentials=StaticCredentialProvider(secrets or SECRETS),
            clock=FrozenClock(start=NOW),
            allow_loopback_http=True,
        )
    )


def broker_for(
    app_engine: sa.Engine,
    session: Session,
    world: IntegrationWorld,
    *,
    registry: ToolRegistry,
    providers: list[ToolProvider] | None = None,
    max_risk_tier: RiskTier = RiskTier.RO,
) -> ToolBroker:
    bind_tenant(session, world.tenant_id)
    scope = load_incident_scope(
        session,
        tenant_id=world.tenant_id,
        incident_id=world.incident_id,
        environment_id=world.environment_id,
        service_ids=[world.service_id],
    )
    clock = FrozenClock(start=NOW)

    def claim_session() -> Session:
        return Session(bind=app_engine, expire_on_commit=False, autoflush=False)

    return ToolBroker(
        resolver=CapabilityResolver(registry, max_risk_tier=max_risk_tier),
        providers=providers or [native_provider()],
        scope=scope,
        audit=AuditWriter(tenant_id=world.tenant_id, clock=clock),
        tracer=TraceRecorder(
            tenant_id=world.tenant_id,
            execution_trace_id=uuid.uuid4(),
            trace_id=derive_trace_id(uuid.uuid4()),
            clock=clock,
        ),
        clock=clock,
        claim_session_factory=claim_session,
        sleep=world.sleeps.append,
    )


def request(
    world: IntegrationWorld,
    capability: str,
    arguments: dict[str, Any],
    *,
    node_id: NodeId = NodeId.G4_EVIDENCE_COLLECTOR,
    remediation_action_id: uuid.UUID | None = None,
) -> CapabilityRequest:
    return CapabilityRequest(
        node_id=node_id,
        capability=capability,
        service_name=world.service_name,
        arguments=arguments,
        incident_id=world.incident_id,
        correlation_id=uuid.uuid4(),
        remediation_action_id=remediation_action_id,
        purpose="integration test",
    )


def app_session(app_engine: sa.Engine) -> Callable[[], Session]:
    def factory() -> Session:
        return Session(bind=app_engine, expire_on_commit=False, autoflush=False)

    return factory
