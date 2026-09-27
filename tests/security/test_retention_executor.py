"""Phase 15.28: the retention lifecycle executor - bounded, tenant-bound, receipted.

Runs as a real login holding only ``asic_maintenance`` (migration 0019). Proves: dry run by
default, bounded batches oldest-first, holds and policy windows honoured, other tenants and
other tables untouchable, receipts written atomically with each deletion (and immutable), the
application role unable to run it, and a controlled CLI.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import ApiIdempotencyRecord, RetentionRun, Tenant
from asic.db.session import bind_tenant
from asic.retention import __main__ as retention_cli
from asic.retention import executor as executor_module
from asic.retention.executor import execute_retention
from tests.kernel_fixtures import build_fixture

pytestmark = [pytest.mark.postgres, pytest.mark.security]

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
MAINTENANCE_LOGIN = "asic_test_maintenance"
PURE_APP_LOGIN = "asic_test_pure_app"
PASSWORD = "asic-maintenance-test-local-only"  # hygiene: synthetic-secret-fixture


def _login(owner_engine: Engine, database_url: str, login: str, member_of: str) -> Engine:
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{login}') THEN
                        CREATE ROLE {login} LOGIN PASSWORD '{PASSWORD}'
                            NOSUPERUSER NOBYPASSRLS IN ROLE {member_of};
                    END IF;
                END
                $$;
                """
            )
        )
        direct = conn.scalar(
            sa.text("SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = :r"),
            {"r": login},
        )
        assert direct == 0, f"{login} must hold no grant of its own"
    url = sa.engine.make_url(database_url).set(username=login, password=PASSWORD)
    return sa.create_engine(url.render_as_string(hide_password=False), future=True)


@pytest.fixture(scope="module")
def maintenance_engine(owner_engine: Engine, database_url: str) -> Iterator[Engine]:
    engine = _login(owner_engine, database_url, MAINTENANCE_LOGIN, "asic_maintenance")
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def pure_app_engine(owner_engine: Engine, database_url: str) -> Iterator[Engine]:
    engine = _login(owner_engine, database_url, PURE_APP_LOGIN, "asic_app")
    yield engine
    engine.dispose()


def _factory(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(engine, expire_on_commit=False, autoflush=False)


def _tenant_with_records(
    owner_engine: Engine, *, old: int, new: int, policy: dict | None = None
) -> uuid.UUID:
    with Session(owner_engine, expire_on_commit=False, autoflush=False) as session:
        fixture = build_fixture(session, slug=f"ret-{uuid.uuid4().hex[:10]}")
        session.flush()
        if policy is not None:
            session.execute(
                sa.update(Tenant)
                .where(Tenant.id == fixture.tenant_id)
                .values(retention_policy=policy)
            )
        for index in range(old + new):
            age = timedelta(days=40, minutes=index) if index < old else timedelta(hours=index)
            session.add(
                ApiIdempotencyRecord(
                    id=uuid.uuid4(),
                    tenant_id=fixture.tenant_id,
                    principal_id=uuid.uuid4(),
                    idempotency_key=f"key-{index:04d}-{uuid.uuid4().hex[:8]}",
                    operation="incident.annotate",
                    request_digest="a" * 64,
                    response_body={"ok": True},
                    created_at=NOW - age,
                )
            )
        session.commit()
        return fixture.tenant_id


def _count(owner_engine: Engine, model: type, tenant_id: uuid.UUID) -> int:
    with Session(owner_engine) as session:
        return int(
            session.scalar(
                sa.select(sa.func.count()).select_from(model).where(model.tenant_id == tenant_id)  # type: ignore[attr-defined]
            )
        )


def test_dry_run_is_the_default_and_deletes_nothing(
    owner_engine: Engine, maintenance_engine: Engine
) -> None:
    tenant = _tenant_with_records(owner_engine, old=5, new=3)
    receipts = execute_retention(
        _factory(maintenance_engine), tenant_id=tenant, now=NOW, executed_by="test-maintenance"
    )
    assert len(receipts) == 1
    (receipt,) = receipts
    assert receipt.dry_run and receipt.eligible_rows == 5 and receipt.deleted_rows == 0
    assert _count(owner_engine, ApiIdempotencyRecord, tenant) == 8
    assert _count(owner_engine, RetentionRun, tenant) == 1


def test_execution_is_bounded_oldest_first_and_tenant_bound(
    owner_engine: Engine, maintenance_engine: Engine
) -> None:
    tenant = _tenant_with_records(owner_engine, old=5, new=3)
    bystander = _tenant_with_records(owner_engine, old=4, new=0)
    receipts = execute_retention(
        _factory(maintenance_engine),
        tenant_id=tenant,
        now=NOW,
        executed_by="test-maintenance",
        execute=True,
        batch_limit=2,
        max_batches=10,
    )
    assert [r.deleted_rows for r in receipts] == [2, 2, 1]
    assert len({r.execution_id for r in receipts}) == 1
    assert _count(owner_engine, ApiIdempotencyRecord, tenant) == 3  # the recent ones remain
    assert _count(owner_engine, ApiIdempotencyRecord, bystander) == 4  # another tenant untouched
    assert _count(owner_engine, RetentionRun, tenant) == 3
    # Restartable: a re-run finds nothing more and says so.
    again = execute_retention(
        _factory(maintenance_engine), tenant_id=tenant, now=NOW, executed_by="t", execute=True
    )
    assert [r.deleted_rows for r in again] == [0]


@pytest.mark.parametrize(
    ("policy", "held"),
    [
        ({"operational_cache": {"hold": True}}, True),
        ({"operational_cache": {"days": 60}}, False),  # records are 40 days old
    ],
)
def test_holds_and_longer_policies_are_respected(
    owner_engine: Engine, maintenance_engine: Engine, policy: dict, held: bool
) -> None:
    tenant = _tenant_with_records(owner_engine, old=3, new=0, policy=policy)
    (receipt,) = execute_retention(
        _factory(maintenance_engine), tenant_id=tenant, now=NOW, executed_by="t", execute=True
    )
    assert receipt.held is held and receipt.deleted_rows == 0
    assert _count(owner_engine, ApiIdempotencyRecord, tenant) == 3


def test_a_failure_before_the_receipt_rolls_the_deletion_back(
    owner_engine: Engine, maintenance_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = _tenant_with_records(owner_engine, old=3, new=0)

    def crash(**_kwargs: object) -> None:
        raise RuntimeError("process died between delete and receipt")

    monkeypatch.setattr(executor_module, "RetentionRun", crash)
    with pytest.raises(RuntimeError):
        execute_retention(
            _factory(maintenance_engine), tenant_id=tenant, now=NOW, executed_by="t", execute=True
        )
    assert _count(owner_engine, ApiIdempotencyRecord, tenant) == 3  # nothing deleted
    assert _count(owner_engine, RetentionRun, tenant) == 0  # and no receipt


def test_the_application_role_cannot_run_the_executor(
    owner_engine: Engine, pure_app_engine: Engine
) -> None:
    tenant = _tenant_with_records(owner_engine, old=2, new=0)
    with pytest.raises(sa.exc.DBAPIError) as refused:
        execute_retention(
            _factory(pure_app_engine), tenant_id=tenant, now=NOW, executed_by="t", execute=True
        )
    assert getattr(refused.value.orig, "pgcode", None) == "42501"
    assert _count(owner_engine, ApiIdempotencyRecord, tenant) == 2


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM incident",
        "DELETE FROM audit_record",
        "UPDATE retention_run SET deleted_rows = 0",
        "DELETE FROM retention_run",
        "SELECT count(*) FROM audit_record",
        "SELECT count(*) FROM incident",
        "UPDATE api_idempotency_record SET operation = 'x'",
        "INSERT INTO tenant (id, slug, display_name) VALUES (gen_random_uuid(), 'x', 'x')",
    ],
)
def test_the_maintenance_role_can_do_nothing_else(
    owner_engine: Engine, maintenance_engine: Engine, statement: str
) -> None:
    tenant = _tenant_with_records(owner_engine, old=1, new=0)
    with maintenance_engine.connect() as connection, connection.begin():
        connection.execute(
            sa.text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": str(tenant)}
        )
        with pytest.raises(sa.exc.DBAPIError) as refused:
            connection.execute(sa.text(statement))
        assert getattr(refused.value.orig, "pgcode", None) == "42501", statement


def test_receipts_are_readable_by_the_runtime_but_immutable(
    owner_engine: Engine, maintenance_engine: Engine, pure_app_engine: Engine
) -> None:
    tenant = _tenant_with_records(owner_engine, old=1, new=0)
    execute_retention(_factory(maintenance_engine), tenant_id=tenant, now=NOW, executed_by="t")
    with _factory(pure_app_engine)() as session:
        bind_tenant(session, tenant)
        assert session.scalar(sa.select(sa.func.count()).select_from(RetentionRun)) == 1
        with pytest.raises(sa.exc.DBAPIError):
            session.execute(sa.update(RetentionRun).values(deleted_rows=0))
    with _factory(maintenance_engine)() as session:  # unbound: row-level security shows nothing
        assert session.scalar(sa.select(sa.func.count()).select_from(RetentionRun)) == 0


@pytest.mark.parametrize(
    ("argv", "env"),
    [
        (["--tenant-id", str(uuid.uuid4())], None),  # no maintenance URL
        (["--tenant-id", str(uuid.uuid4()), "--batch-limit", "0"], "set"),
        (["--tenant-id", str(uuid.uuid4()), "--max-batches", "100000"], "set"),
        (["--tenant-id", str(uuid.uuid4())], "set"),  # unknown tenant
    ],
)
def test_the_cli_refuses_cleanly(
    argv: list[str],
    env: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    database_url: str,
) -> None:
    if env:
        url = sa.engine.make_url(database_url).set(username=MAINTENANCE_LOGIN, password=PASSWORD)
        monkeypatch.setenv(
            retention_cli.MAINTENANCE_URL_ENV, url.render_as_string(hide_password=False)
        )
    else:
        monkeypatch.delenv(retention_cli.MAINTENANCE_URL_ENV, raising=False)
    assert retention_cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and PASSWORD not in err


def test_the_cli_prints_receipts(
    owner_engine: Engine,
    maintenance_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    database_url: str,
) -> None:
    import json

    tenant = _tenant_with_records(owner_engine, old=2, new=1)
    url = sa.engine.make_url(database_url).set(username=MAINTENANCE_LOGIN, password=PASSWORD)
    monkeypatch.setenv(retention_cli.MAINTENANCE_URL_ENV, url.render_as_string(hide_password=False))
    assert retention_cli.main(["--tenant-id", str(tenant)]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines and lines[0]["dry_run"] is True and lines[0]["deleted_rows"] == 0
