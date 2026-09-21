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

import logging
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

# LangSmith arrives transitively through langchain-core. It is not adopted (ADR-0010) and
# nothing in this project sends it anything, but a stray environment variable would turn a
# test run into an outbound request. Disabled here, before anything imports langgraph.
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

#: The orchestration-kernel fixtures live in their own module and are registered here so
#: every suite shares one definition of the scenario fixture set.
pytest_plugins = ("tests.kernel_fixtures", "tests.remediation_fixtures")

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


@pytest.fixture
def asic_log_records() -> Iterator[list[logging.LogRecord]]:
    """Every record emitted anywhere under the ``asic`` logger hierarchy.

    ``caplog`` attaches to the root logger, and ``asic.observability.logging.configure_logging``
    (run once per process by other tests) sets ``asic`` to ``propagate = False`` - after which
    ``caplog`` silently sees nothing and any "no secret in the logs" assertion becomes vacuous.
    A handler attached to the ``asic`` logger itself is unaffected by propagation.

    A second trap: the in-process Alembic tests run ``migrations/env.py``, whose
    ``fileConfig`` defaults to ``disable_existing_loggers=True`` and so *disables* every
    ``asic.*`` logger for the rest of the session. The fixture re-enables them (and restores
    their state afterwards), otherwise a captured-nothing result is indistinguishable from a
    clean one.
    """
    # Apply the production logging configuration first (idempotent). It replaces the logger's
    # handlers and disables propagation, so capture must be attached *after* it.
    from asic.observability.logging import configure_logging

    configure_logging(service="tests")
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("asic")
    handler = _Collect(level=logging.DEBUG)
    previous_level = logger.level
    disabled_before: dict[logging.Logger, bool] = {}
    for name, candidate in list(logging.root.manager.loggerDict.items()):
        if isinstance(candidate, logging.Logger) and (name == "asic" or name.startswith("asic.")):
            disabled_before[candidate] = candidate.disabled
            candidate.disabled = False
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        for candidate, was_disabled in disabled_before.items():
            candidate.disabled = was_disabled


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
_TEST_ONLY_SEED_TABLES = (
    "tenant",
    "tool_definition",
    "behaviour_version",
    "role",
    "permission",
    "role_permission",
)


#: Phase 13 (migration 0018) revoked these from ``asic_app``: the runtime reads identity,
#: role-assignment, tool-grant and scope-catalogue tables but never writes them. Fixtures
#: still need to arrange them, so the *test login role only* is re-granted the writes.
#: ``tests/security/test_least_privilege.py`` asserts ``asic_app`` itself holds none of them.
_TEST_ONLY_WRITE_TABLES = (
    "app_user",
    "environment",
    "service",
    "service_dependency",
    "tenant_tool_grant",
    "user_role_assignment",
)

#: ``DELETE`` is held by no runtime role. One fixture grant preserves the proof that row-level
#: security (not just a missing privilege) stops a cross-tenant delete.
#: The others simulate role revocation and projection rebuilds, which production performs
#: through the owner/administrative path.
_TEST_ONLY_DELETE_TABLES = ("incident", "timeline_event", "user_role_assignment")


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
        for table in _TEST_ONLY_WRITE_TABLES:
            conn.execute(sa.text(f"GRANT INSERT, UPDATE ON {table} TO {TEST_APP_ROLE}"))
        for table in _TEST_ONLY_DELETE_TABLES:
            conn.execute(sa.text(f"GRANT DELETE ON {table} TO {TEST_APP_ROLE}"))

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
