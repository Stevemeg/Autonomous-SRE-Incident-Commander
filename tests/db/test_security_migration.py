"""Migration 0018 (Phase 13): upgrade, downgrade, re-upgrade, and historical-data behaviour.

Runs on a throwaway database so it can move the schema without disturbing the rest of the
suite. The historical-data test is the one that matters operationally: a database that already
holds a malformed trace id or an orphan connector binding must still upgrade (the constraint is
left ``NOT VALID`` and enforced for new rows) and must never have those rows rewritten.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import (
    ConnectorScopeBinding,
    ExecutionTrace,
    IntegrationConnector,
    WorkflowRun,
)
from asic.db.session import bind_tenant
from asic.domain.enums import IntegrationKind, WorkflowRunStatus
from tests.conftest import (
    make_behaviour_version,
    make_environment,
    make_incident,
    make_service,
    make_tenant,
    requires_postgres,
)
from tests.db.test_migration_history import _alembic_config, throwaway_database  # noqa: F401

pytestmark = [requires_postgres, pytest.mark.security]

PREVIOUS = "0017_evaluation_harness"
CURRENT = "0018_security_hardening"
TRACE_CHECK = "ck_execution_trace_trace_id_is_w3c_trace_id"
BINDING_FK = "fk_connector_scope_binding_connector"


@pytest.fixture
def engine(throwaway_database: str) -> Iterator[sa.Engine]:  # noqa: F811
    engine = sa.create_engine(throwaway_database)
    try:
        yield engine
    finally:
        engine.dispose()


def _validated(engine: sa.Engine, name: str) -> bool | None:
    with engine.connect() as conn:
        return conn.scalar(
            sa.text("SELECT convalidated FROM pg_constraint WHERE conname = :n"), {"n": name}
        )


def _app_can(engine: sa.Engine, table: str, privilege: str) -> bool:
    with engine.connect() as conn:
        return bool(
            conn.scalar(
                sa.text("SELECT has_table_privilege('asic_app', :t, :p)"),
                {"t": f"public.{table}", "p": privilege},
            )
        )


def _seed_history(engine: sa.Engine, *, orphan: bool, bad_trace: bool) -> dict[str, uuid.UUID]:
    """Rows a real database could already hold before 0018 (no CHECK, no FK yet)."""
    with Session(bind=engine, expire_on_commit=False) as session:
        tenant = make_tenant(session, f"mig-{uuid.uuid4().hex[:8]}")
        bind_tenant(session, tenant.id)
        environment = make_environment(session, tenant)
        service = make_service(session, tenant, "legacy-svc")
        incident = make_incident(session, tenant, environment)
        behaviour = make_behaviour_version(session, f"mig-{uuid.uuid4().hex[:6]}")
        run = WorkflowRun(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            incident_id=incident.id,
            behaviour_version_id=behaviour.id,
            status=WorkflowRunStatus.RUNNING,
        )
        session.add(run)
        session.flush()
        ids = {"tenant": tenant.id, "environment": environment.id, "service": service.id}
        if bad_trace:
            trace = ExecutionTrace(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                workflow_run_id=run.id,
                incident_id=incident.id,
                behaviour_version_id=behaviour.id,
                trace_id="NOT-A-HEX-TRACE-ID-000000000000",
                correlation_id=uuid.uuid4(),
            )
            session.add(trace)
            ids["trace"] = trace.id
        if orphan:
            session.add(
                ConnectorScopeBinding(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    connector_id="ghost-connector",
                    source="legacy",
                    service_id=service.id,
                    environment_id=environment.id,
                )
            )
        session.commit()
        return ids


def test_clean_database_round_trips_and_validates_both_constraints(
    throwaway_database: str,  # noqa: F811
    engine: sa.Engine,
) -> None:
    config = _alembic_config(throwaway_database)
    command.upgrade(config, PREVIOUS)
    assert _validated(engine, TRACE_CHECK) is None and _validated(engine, BINDING_FK) is None
    assert _app_can(engine, "incident", "DELETE") is True  # the pre-0018 over-grant
    assert _app_can(engine, "alembic_version", "UPDATE") is True

    command.upgrade(config, CURRENT)
    assert _validated(engine, TRACE_CHECK) is True
    assert _validated(engine, BINDING_FK) is True
    assert _app_can(engine, "incident", "DELETE") is False
    assert _app_can(engine, "alembic_version", "UPDATE") is False
    assert _app_can(engine, "app_user", "INSERT") is False
    assert _app_can(engine, "user_role_assignment", "UPDATE") is False
    assert _app_can(engine, "incident", "UPDATE") is True  # the runtime still needs this

    command.downgrade(config, PREVIOUS)
    assert _validated(engine, TRACE_CHECK) is None and _validated(engine, BINDING_FK) is None
    assert _app_can(engine, "incident", "DELETE") is True
    assert _app_can(engine, "app_user", "INSERT") is True

    command.upgrade(config, "head")
    assert _validated(engine, TRACE_CHECK) is True and _validated(engine, BINDING_FK) is True
    assert _app_can(engine, "incident", "DELETE") is False


def test_historical_bad_rows_do_not_break_the_upgrade_and_are_never_rewritten(
    throwaway_database: str,  # noqa: F811
    engine: sa.Engine,
) -> None:
    config = _alembic_config(throwaway_database)
    command.upgrade(config, PREVIOUS)
    ids = _seed_history(engine, orphan=True, bad_trace=True)

    command.upgrade(config, CURRENT)  # must not raise

    # Both constraints exist but could not be validated over the historical rows...
    assert _validated(engine, TRACE_CHECK) is False
    assert _validated(engine, BINDING_FK) is False
    # ...and the historical rows are untouched, not repaired and not deleted.
    with engine.connect() as conn:
        assert (
            conn.scalar(
                sa.text("SELECT trace_id FROM execution_trace WHERE id = :i"), {"i": ids["trace"]}
            )
            == "NOT-A-HEX-TRACE-ID-000000000000"
        )
        assert (
            conn.scalar(
                sa.text(
                    "SELECT count(*) FROM connector_scope_binding WHERE connector_id = 'ghost-connector'"
                )
            )
            == 1
        )

    # New rows are still governed by the constraints even though old ones are not validated.
    with Session(bind=engine) as session:
        bind_tenant(session, ids["tenant"])
        session.add(
            ConnectorScopeBinding(
                id=uuid.uuid4(),
                tenant_id=ids["tenant"],
                connector_id="another-ghost",
                source="legacy",
                service_id=ids["service"],
                environment_id=ids["environment"],
            )
        )
        with pytest.raises(IntegrityError, match=BINDING_FK):
            session.flush()
        session.rollback()

    # The downgrade removes both constraints and still leaves the history alone.
    command.downgrade(config, PREVIOUS)
    assert _validated(engine, TRACE_CHECK) is None
    with engine.connect() as conn:
        assert conn.scalar(sa.text("SELECT count(*) FROM execution_trace")) == 1


def test_a_registered_connector_can_be_bound_after_the_upgrade(
    throwaway_database: str,  # noqa: F811
    engine: sa.Engine,
) -> None:
    config = _alembic_config(throwaway_database)
    command.upgrade(config, CURRENT)
    ids = _seed_history(engine, orphan=False, bad_trace=False)
    with Session(bind=engine) as session:
        bind_tenant(session, ids["tenant"])
        session.add(
            IntegrationConnector(
                id=uuid.uuid4(),
                tenant_id=ids["tenant"],
                connector_id="registered",
                kind=IntegrationKind.PROMETHEUS,
                environment_id=ids["environment"],
                is_enabled=False,
            )
        )
        session.flush()
        session.add(
            ConnectorScopeBinding(
                id=uuid.uuid4(),
                tenant_id=ids["tenant"],
                connector_id="registered",
                source="prometheus",
                service_id=ids["service"],
                environment_id=ids["environment"],
            )
        )
        session.commit()


def test_alembic_head_is_the_readiness_revision() -> None:
    from alembic.script import ScriptDirectory

    from asic.observability.health import EXPECTED_SCHEMA_REVISION

    head = ScriptDirectory.from_config(_alembic_config("postgresql://unused")).get_current_head()
    assert head == CURRENT == EXPECTED_SCHEMA_REVISION
