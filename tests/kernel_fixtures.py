"""Fixtures for the orchestration kernel.

Registered as a plugin from ``tests/conftest.py`` so the broker, kernel, security and
end-to-end suites all share one definition of "a tenant with an incident and grants".

The kernel commits once per node boundary - that is what makes its checkpoints mean
anything - so its tests cannot use the rollback-per-test session the rest of the suite
uses. They use SQLAlchemy's *join an external transaction* pattern instead: the test opens
one real transaction, every session the kernel creates joins it through a savepoint, and
the kernel's ``commit()`` releases the savepoint rather than the outer transaction. The
test still rolls everything back at the end, and the kernel still exercises its real commit
path.

Two details are load-bearing:

* the tenant binding is written with ``set_config(..., true)``, which is transaction-local,
  so it survives a savepoint release and is discarded with the outer rollback;
* every session shares one connection, so the "crashed" kernel and the resuming kernel see
  the same committed rows - which is what a real resume would see from the database.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy import Connection, Engine, event
from sqlalchemy.orm import Session

from asic.db.models import (
    Alert,
    BehaviourVersion,
    Environment,
    Incident,
    Service,
    Tenant,
    TenantToolGrant,
    ToolDefinition,
)
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import AlertSeverity, AlertStatus, IncidentSeverity, IncidentStatus
from asic.domain.idempotency import alert_key
from asic.llm.deterministic import DeterministicModelProvider
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, Scenario, scenario
from asic.tools.capability import CapabilityResolver
from asic.tools.catalogue import CATALOGUE_VERSION
from asic.tools.registry import ToolRegistry

#: Fixed base instant so every scenario's derived timestamps are reproducible.
CLOCK_START = datetime(2026, 9, 7, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(start=CLOCK_START)


@pytest.fixture
def kernel_connection(app_engine: Engine) -> Iterator[Connection]:
    """One connection with an outer transaction the test always rolls back."""
    connection = app_engine.connect()
    transaction = connection.begin()
    try:
        yield connection
    finally:
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def session_factory(kernel_connection: Connection) -> Callable[[], Session]:
    """Sessions that join the outer transaction and commit into a savepoint."""

    def factory() -> Session:
        session = Session(bind=kernel_connection, expire_on_commit=False, autoflush=False)
        session.begin_nested()

        @event.listens_for(session, "after_transaction_end")
        def _restart_savepoint(sess: Session, trans: sa.orm.SessionTransaction) -> None:
            # Re-open a savepoint whenever the kernel's commit released one, so the next
            # unit of work still commits *inside* the test's outer transaction.
            parent = trans.parent
            if trans.nested and (parent is None or not parent.nested):
                sess.begin_nested()

        return session

    return factory


@pytest.fixture
def kernel_session(session_factory: Callable[[], Session]) -> Iterator[Session]:
    """A session for arranging fixtures and asserting afterwards."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


class Fixture:
    """The rows one scenario run needs, created once and reused by the tests."""

    def __init__(
        self,
        *,
        tenant: Tenant,
        environment: Environment,
        service: Service,
        incident: Incident,
        behaviour_version: BehaviourVersion,
    ) -> None:
        self.tenant = tenant
        self.environment = environment
        self.service = service
        self.incident = incident
        self.behaviour_version = behaviour_version

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.tenant.id

    @property
    def service_ids(self) -> list[uuid.UUID]:
        return [self.service.id]


def build_fixture(
    session: Session,
    *,
    slug: str,
    service_name: str = "checkout-api",
    incident_status: IncidentStatus = IncidentStatus.DETECTED,
    grant_capabilities: tuple[str, ...] | None = None,
    clock_start: datetime = CLOCK_START,
) -> Fixture:
    """Create a tenant with one service, one incident, and tool grants.

    ``grant_capabilities`` narrows what the tenant may use. ``None`` grants the whole
    read-only catalogue; an explicit tuple grants only those capabilities, which is how the
    "capability not granted" tests arrange a genuine absence rather than simulating one.
    """
    tenant = Tenant(id=uuid.uuid4(), slug=slug, display_name=slug.title())
    session.add(tenant)
    session.flush()
    bind_tenant(session, tenant.id)

    environment = Environment(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name="production",
        display_name="Production",
        is_production=True,
    )
    service = Service(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=service_name,
        display_name=service_name,
        owner_team="payments",
        namespaces=["checkout"],
    )
    session.add_all([environment, service])
    session.flush()

    opened_at = clock_start
    incident = Incident(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        reference="INC-0001",
        title=f"{service_name} latency increased after a deployment",
        environment_id=environment.id,
        status=incident_status,
        severity=IncidentSeverity.SEV2,
        opened_at=opened_at,
    )
    session.add(incident)
    session.flush()

    session.add(
        Alert(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            incident_id=incident.id,
            service_id=service.id,
            environment_id=environment.id,
            source="alertmanager",
            source_fingerprint="checkout-latency-p95",
            title="p95 latency above objective",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.CORRELATED,
            started_at=opened_at - timedelta(minutes=5),
            received_at=opened_at,
            idempotency_key=alert_key(
                tenant_id=tenant.id,
                source="alertmanager",
                source_fingerprint="checkout-latency-p95",
                started_at=opened_at - timedelta(minutes=5),
            ),
        )
    )

    behaviour_version = BehaviourVersion(
        id=uuid.uuid4(),
        label=f"test-{slug}",
        code_version="0.4.0",
        prompt_set_version="2026.09.07-1",
        retriever_config_version="none",
        policy_version="none",
        tool_registry_version=CATALOGUE_VERSION,
        fingerprint=uuid.uuid4().hex,
    )
    session.add(behaviour_version)
    session.flush()

    definitions = list(session.execute(sa.select(ToolDefinition)).scalars())
    for definition in definitions:
        if grant_capabilities is not None and definition.capability not in grant_capabilities:
            continue
        session.add(
            TenantToolGrant(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                tool_definition_id=definition.id,
                environment_id=environment.id,
                is_enabled=True,
            )
        )
    session.flush()

    return Fixture(
        tenant=tenant,
        environment=environment,
        service=service,
        incident=incident,
        behaviour_version=behaviour_version,
    )


@pytest.fixture
def resolver() -> CapabilityResolver:
    return CapabilityResolver(ToolRegistry.read_only())


def make_providers(scenario_obj: Scenario, clock: FrozenClock) -> list[SimulatorProvider]:
    return [SimulatorProvider(scenario_obj, clock=clock)]


def make_model(scenario_obj: Scenario, **kwargs: object) -> DeterministicModelProvider:
    return DeterministicModelProvider(scenario_obj, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def primary_scenario() -> Scenario:
    return scenario(PRIMARY_SCENARIO_ID)
