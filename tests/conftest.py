"""Test fixtures.

Database-backed tests need a real PostgreSQL: row-level security, native enum types,
partial unique indexes and check constraints cannot be exercised against SQLite. Tests
requiring one are marked ``postgres`` and skip cleanly when ``ASIC_TEST_DATABASE_URL`` is
not set, so the pure-domain suite still runs anywhere.

Two connections are provided, and the distinction is load-bearing:

* ``app_session`` connects as a member of ``asic_app``, the least-privileged application
  role. **Every behavioural isolation test must use this.**
* ``owner_session`` connects as the schema owner, and is used only for schema
  introspection (``pg_class``, ``pg_policies``) and for the append-only grant tests that
  need to contrast owner privilege with application privilege.

Why the distinction matters more than it looks: **a superuser bypasses row-level security
entirely, and ``FORCE ROW LEVEL SECURITY`` does not change that.** In most local setups -
including the standard PostgreSQL Docker image - the bootstrap owner *is* a superuser, so
an isolation test written against the owner connection passes while proving nothing. The
first draft of this suite made exactly that mistake; the behavioural assertions caught it
where an inspection of ``pg_class.relforcerowsecurity`` alone would not have.

``asic_test_app`` is therefore created as a plain ``LOGIN`` role inheriting ``asic_app``,
with two test-only additions: ``INSERT`` on the global catalogue tables, so that a test can
create its own tenant and tool fixtures inside the same transaction it then exercises. The
application role does not hold those grants in production, and
``test_global_catalogues_are_read_only_to_the_application`` asserts that.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from asic.db.models import (
    BehaviourVersion,
    Environment,
    Incident,
    Service,
    Tenant,
    ToolDefinition,
    User,
)
from asic.domain.enums import IncidentSeverity, IncidentStatus, RiskTier

TEST_URL_ENV = "ASIC_TEST_DATABASE_URL"

#: Login role used by the application-role tests. Created by :func:`_ensure_test_app_role`
#: as a member of ``asic_app`` so it inherits exactly the application's privileges.
TEST_APP_ROLE = "asic_test_app"

#: Password for the throwaway test role in a local container. Overridable so that no
#: credential - even a disposable one - is hard-coded as the only option.
TEST_APP_PASSWORD = os.environ.get("ASIC_TEST_APP_PASSWORD", "asic-test-role-local-only")


def _database_url() -> str | None:
    return os.environ.get(TEST_URL_ENV)


requires_postgres = pytest.mark.postgres


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _database_url()
    if not url:
        pytest.skip(
            f"{TEST_URL_ENV} is not set; database-backed tests need a live PostgreSQL "
            "with the migrations applied"
        )
    return url


@pytest.fixture(scope="session")
def owner_engine(database_url: str) -> Iterator[Engine]:
    engine = create_engine(database_url, future=True, pool_pre_ping=True)
    with engine.connect() as conn:
        applied = conn.execute(
            sa.text("SELECT version_num FROM alembic_version")
        ).scalar_one_or_none()
        if applied is None:
            pytest.fail(
                "the test database has no alembic_version row; run "
                "`alembic upgrade head` against it before running these tests"
            )
    yield engine
    engine.dispose()


#: Global catalogue tables the test role may seed. In production the application role has
#: no INSERT here; these grants exist so a test can build its fixtures and exercise them
#: inside one transaction, which is what keeps tests isolated by rollback.
_TEST_ONLY_SEED_TABLES = ("tenant", "tool_definition", "behaviour_version", "role", "permission")


@pytest.fixture(scope="session")
def _ensure_test_app_role(owner_engine: Engine, database_url: str) -> str:
    """Create a non-superuser login role that inherits the application role.

    Not a superuser, and not the owner - both would bypass row-level security and make
    every isolation assertion below vacuous.
    """
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_roles WHERE rolname = '{TEST_APP_ROLE}'
                    ) THEN
                        CREATE ROLE {TEST_APP_ROLE} LOGIN PASSWORD '{TEST_APP_PASSWORD}'
                            NOSUPERUSER NOBYPASSRLS IN ROLE asic_app;
                    END IF;
                END
                $$;
                """
            )
        )
        for table in _TEST_ONLY_SEED_TABLES:
            conn.execute(sa.text(f"GRANT INSERT ON {table} TO {TEST_APP_ROLE}"))

        # Guard the guard: if this role ever gained superuser or BYPASSRLS, every
        # isolation test would pass while proving nothing.
        privileged = conn.execute(
            sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = :r"),
            {"r": TEST_APP_ROLE},
        ).scalar_one()
        if privileged:
            pytest.fail(
                f"{TEST_APP_ROLE} has SUPERUSER or BYPASSRLS; row-level security would "
                "be bypassed and the isolation tests would be meaningless"
            )

    url = sa.engine.make_url(database_url).set(username=TEST_APP_ROLE, password=TEST_APP_PASSWORD)
    # str(URL) masks the password as "***"; rendering it back into a connection string
    # needs hide_password=False or authentication fails with a misleading error.
    return url.render_as_string(hide_password=False)


@pytest.fixture(scope="session")
def app_engine(_ensure_test_app_role: str) -> Iterator[Engine]:
    engine = create_engine(_ensure_test_app_role, future=True, pool_pre_ping=True)
    yield engine
    engine.dispose()


def _rollback_session(engine: Engine) -> Iterator[Session]:
    """A session whose work is always rolled back.

    Every test gets a clean database without truncating tables, and - because the tenant
    setting is transaction-local - without leaking tenant context between tests either.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False, autoflush=False)
    try:
        yield session
    finally:
        session.close()
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def owner_session(owner_engine: Engine) -> Iterator[Session]:
    yield from _rollback_session(owner_engine)


@pytest.fixture
def app_session(app_engine: Engine) -> Iterator[Session]:
    yield from _rollback_session(app_engine)


# --------------------------------------------------------------------------- factories


def make_tenant(session: Session, slug: str) -> Tenant:
    """Create a tenant. ``tenant`` is a global table, so no context is needed."""
    tenant = Tenant(id=uuid.uuid4(), slug=slug, display_name=slug.title())
    session.add(tenant)
    session.flush()
    return tenant


def make_environment(
    session: Session, tenant: Tenant, name: str = "production", *, is_production: bool = True
) -> Environment:
    env = Environment(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=name,
        display_name=name.title(),
        is_production=is_production,
    )
    session.add(env)
    session.flush()
    return env


def make_service(session: Session, tenant: Tenant, name: str = "checkout-api") -> Service:
    service = Service(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=name,
        display_name=name,
        owner_team="payments",
        namespaces=["checkout"],
    )
    session.add(service)
    session.flush()
    return service


def make_user(session: Session, tenant: Tenant, subject: str = "user-1") -> User:
    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        external_idp_subject=subject,
        email=f"{subject}@example.invalid",
        display_name=subject,
    )
    session.add(user)
    session.flush()
    return user


def make_incident(
    session: Session,
    tenant: Tenant,
    environment: Environment,
    *,
    reference: str = "INC-0001",
    status: IncidentStatus = IncidentStatus.DETECTED,
) -> Incident:
    incident = Incident(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        reference=reference,
        title="Checkout latency breach",
        environment_id=environment.id,
        status=status,
        severity=IncidentSeverity.SEV2,
        opened_at=datetime.now(UTC),
    )
    session.add(incident)
    session.flush()
    return incident


def make_behaviour_version(session: Session, label: str = "test-1") -> BehaviourVersion:
    version = BehaviourVersion(
        id=uuid.uuid4(),
        label=label,
        code_version="0.3.0",
        prompt_set_version="none",
        retriever_config_version="none",
        policy_version="none",
        tool_registry_version="none",
        fingerprint=uuid.uuid4().hex,
    )
    session.add(version)
    session.flush()
    return version


def make_tool_definition(
    session: Session,
    *,
    name: str = "k8s.deployment.rollback",
    version: str = "1.0.0",
    risk_tier: RiskTier = RiskTier.R1,
    rollback_tool_name: str | None = "k8s.deployment.rollback",
    settling_seconds: int = 60,
    is_idempotent: bool = True,
    input_schema: dict[str, object] | None = None,
) -> ToolDefinition:
    tool = ToolDefinition(
        id=uuid.uuid4(),
        name=name,
        version=version,
        major_version=int(version.split(".")[0]),
        capability="mutate.k8s_deployment",
        description="Roll a Deployment back to its previous revision.",
        risk_tier=risk_tier,
        input_schema=input_schema
        or {"namespace": {"type": "string"}, "deployment": {"type": "string"}},
        output_schema={"new_revision": {"type": "integer"}},
        timeout_seconds=300,
        settling_seconds=settling_seconds,
        is_idempotent=is_idempotent,
        rollback_tool_name=rollback_tool_name,
    )
    session.add(tool)
    session.flush()
    return tool
