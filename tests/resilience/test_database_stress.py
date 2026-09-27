"""Phase 15.3: database stress, pool exhaustion and fault recovery through the real API.

Hypothesis: when PostgreSQL is saturated, slow, contended or unreachable, the API answers
within bounded time with a *classified* 503 (``database_busy``/``_timeout``/``_contention``/
``_unavailable``, ``Retry-After``), never leaks one tenant's context into another's request,
leaves no transaction open, reports itself not-ready, and recovers without a restart once the
database returns. Before Phase 15 every one of these surfaced as an opaque HTTP 500.

Faults are injected with a real TCP proxy between the application's own engine (created by
``create_app_engine`` with its production deadlines) and the real database.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine, exc
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from asic.api import create_app
from asic.api.app import DATABASE_RETRY_AFTER_SECONDS, classify_database_error
from asic.db.session import DEFAULT_STATEMENT_TIMEOUT_MS, create_app_engine
from tests.resilience.conftest import SETTINGS, ApiWorld, factory_for
from tests.resilience.fault_proxy import FaultProxy, Mode

pytestmark = pytest.mark.postgres

BOUND_SECONDS = 15.0  # generous ceiling on any single faulted request


def _client(engine: Engine) -> TestClient:
    return TestClient(create_app(settings=SETTINGS, factory=factory_for(engine)))


def _timed(call: object) -> tuple[object, float]:
    started = time.monotonic()
    result = call()  # type: ignore[operator]
    return result, time.monotonic() - started


class _Orig(Exception):
    def __init__(self, pgcode: str | None) -> None:
        super().__init__("x")
        self.pgcode = pgcode


class TestClassification:
    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (exc.TimeoutError("pool"), (503, "database_busy")),
            (exc.OperationalError("s", {}, _Orig("57014")), (503, "database_timeout")),
            (exc.OperationalError("s", {}, _Orig("55P03")), (503, "database_contention")),
            (exc.OperationalError("s", {}, _Orig("40P01")), (503, "database_contention")),
            (exc.OperationalError("s", {}, _Orig("40001")), (503, "database_contention")),
            (exc.OperationalError("s", {}, _Orig("53300")), (503, "database_unavailable")),
            (exc.OperationalError("s", {}, _Orig(None)), (503, "database_unavailable")),
            (exc.IntegrityError("s", {}, _Orig("23505")), (500, "internal_error")),
            (exc.ProgrammingError("s", {}, _Orig("42P01")), (500, "internal_error")),
            (StaleDataError("version mismatch"), (409, "concurrent_modification")),
        ],
    )
    def test_transient_conditions_are_503_and_defects_stay_500(
        self, error: exc.SQLAlchemyError, expected: tuple[int, str]
    ) -> None:
        status, code, _ = classify_database_error(error)
        assert (status, code) == expected


class TestPoolExhaustion:
    def test_saturated_pool_is_a_bounded_503_then_recovers(
        self, app_url: str, api_world: ApiWorld
    ) -> None:
        engine = create_app_engine(app_url, pool_size=1, max_overflow=0, pool_timeout=0.5)
        client = _client(engine)
        try:
            assert client.get("/api/v1/incidents", headers=api_world.headers).status_code == 200
            held = engine.connect()  # the only pooled connection
            try:
                response, elapsed = _timed(
                    lambda: client.get("/api/v1/incidents", headers=api_world.headers)
                )
                assert response.status_code == 503  # type: ignore[attr-defined]
                body = response.json()["detail"]  # type: ignore[attr-defined]
                assert body["code"] == "database_busy"
                assert response.headers["Retry-After"] == str(DATABASE_RETRY_AFTER_SECONDS)  # type: ignore[attr-defined]
                assert elapsed < 3.0
            finally:
                held.close()
            assert client.get("/api/v1/incidents", headers=api_world.headers).status_code == 200
            assert engine.pool.checkedout() == 0  # nothing leaked by the refused request
        finally:
            engine.dispose()

    def test_concurrent_overload_never_produces_500(
        self, app_url: str, api_world: ApiWorld
    ) -> None:
        engine = create_app_engine(app_url, pool_size=2, max_overflow=0, pool_timeout=0.2)
        client = _client(engine)
        statuses: list[int] = []
        lock = threading.Lock()

        def hammer() -> None:
            for _ in range(15):
                code = client.get("/api/v1/incidents", headers=api_world.headers).status_code
                with lock:
                    statuses.append(code)

        try:
            threads = [threading.Thread(target=hammer) for _ in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
            assert statuses and set(statuses) <= {200, 503}
            assert 200 in statuses
            assert engine.pool.checkedout() == 0
        finally:
            engine.dispose()


class TestSlowAndContendedDatabase:
    def test_a_slow_database_still_answers_correctly(
        self, proxied_engine: Engine, db_proxy: FaultProxy, api_world: ApiWorld
    ) -> None:
        client = _client(proxied_engine)
        db_proxy.set(Mode.LATENCY, latency=0.05)
        response, elapsed = _timed(
            lambda: client.get("/api/v1/incidents", headers=api_world.headers)
        )
        assert response.status_code == 200  # type: ignore[attr-defined]
        assert elapsed < BOUND_SECONDS

    def test_lock_contention_is_bounded_by_the_statement_deadline(
        self, app_url: str, owner_engine: Engine, api_world: ApiWorld
    ) -> None:
        """An idempotent control request waits on its advisory key lock. When another session
        holds that lock, the server-side statement deadline fires and the API answers a
        classified 503 - it never blocks a worker indefinitely."""
        engine = create_app_engine(app_url)
        client = _client(engine)
        key = f"contention-{uuid.uuid4().hex}"
        principal_user = _user_id(owner_engine, api_world)
        lock_key = f"{api_world.fixture.tenant_id}:{principal_user}:{key}"
        blocker = owner_engine.connect()
        transaction = blocker.begin()
        try:
            blocker.execute(
                sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": lock_key}
            )
            response, elapsed = _timed(
                lambda: client.post(
                    f"/api/v1/incidents/{api_world.fixture.incident.id}/escalate",
                    headers={**api_world.headers, "Idempotency-Key": key},
                    json={"justification": "contention probe"},
                )
            )
            assert response.status_code == 503  # type: ignore[attr-defined]
            assert response.json()["detail"]["code"] == "database_timeout"  # type: ignore[attr-defined]
            assert DEFAULT_STATEMENT_TIMEOUT_MS / 1000 - 1 <= elapsed < BOUND_SECONDS
        finally:
            transaction.rollback()
            blocker.close()
        retry = client.post(
            f"/api/v1/incidents/{api_world.fixture.incident.id}/escalate",
            headers={**api_world.headers, "Idempotency-Key": key},
            json={"justification": "contention probe"},
        )
        assert retry.status_code == 200
        _assert_no_open_transactions(owner_engine)
        engine.dispose()

    def test_concurrent_conflicting_controls_serialize_without_500(
        self, app_url: str, api_world: ApiWorld
    ) -> None:
        engine = create_app_engine(app_url)
        client = _client(engine)
        incident = api_world.fixture.incident.id
        results: list[int] = []
        lock = threading.Lock()

        def act(action: str, n: int) -> None:
            code = client.post(
                f"/api/v1/incidents/{incident}/{action}",
                headers={
                    **api_world.headers,
                    "Idempotency-Key": f"race-{action}-{n}-{uuid.uuid4().hex}",
                },
                json={"justification": f"race {action} {n}"},
            ).status_code
            with lock:
                results.append(code)

        threads = [
            threading.Thread(target=act, args=(action, n))
            for n in range(6)
            for action in ("escalate", "cancel")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        engine.dispose()
        # The losing writer of an optimistic-locking race is a 409 conflict (it used to be a
        # 500 StaleDataError); a request arriving after the terminal transition is a 409
        # invalid_transition. Exactly one control can win.
        assert len(results) == 12 and 500 not in results
        assert set(results) <= {200, 409, 503}
        assert results.count(200) == 1


class TestConnectionLossAndRecovery:
    def test_severed_connections_are_replaced_transparently(
        self, proxied_engine: Engine, db_proxy: FaultProxy, api_world: ApiWorld
    ) -> None:
        client = _client(proxied_engine)
        assert client.get("/api/v1/incidents", headers=api_world.headers).status_code == 200
        assert db_proxy.sever() >= 1  # every pooled connection is now dead
        # pool_pre_ping detects the dead connection and reconnects: no error at all.
        assert client.get("/api/v1/incidents", headers=api_world.headers).status_code == 200

    def test_outage_is_a_fast_classified_503_and_not_ready_then_recovers(
        self, proxied_engine: Engine, db_proxy: FaultProxy, api_world: ApiWorld
    ) -> None:
        client = _client(proxied_engine)
        assert client.get("/readyz").status_code == 200
        db_proxy.set(Mode.REFUSE)
        db_proxy.sever()
        response, elapsed = _timed(
            lambda: client.get("/api/v1/incidents", headers=api_world.headers)
        )
        assert response.status_code == 503  # type: ignore[attr-defined]
        assert response.json()["detail"]["code"] == "database_unavailable"  # type: ignore[attr-defined]
        assert elapsed < BOUND_SECONDS
        time.sleep(2.1)  # readiness cache interval
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["dependencies"]["database"]["status"] == "down"
        assert client.get("/livez").status_code == 200  # liveness never depends on the DB

        db_proxy.set(Mode.PASS)
        recovered = client.get("/api/v1/incidents", headers=api_world.headers)
        assert recovered.status_code == 200
        time.sleep(2.1)
        assert client.get("/readyz").status_code == 200
        assert proxied_engine.pool.checkedout() == 0


class TestTenantContextSurvivesFaults:
    def test_a_failed_request_never_leaks_its_tenant_to_the_next(
        self, app_url: str, owner_engine: Engine, api_world: ApiWorld
    ) -> None:
        """One pooled connection shared by two tenants, with a statement-deadline failure in
        between: the tenant binding is transaction-local, so B sees only B."""
        engine = create_app_engine(app_url, pool_size=1, max_overflow=0)
        client = _client(engine)
        try:
            with engine.connect() as connection:
                # Fresh checkout: no tenant is bound outside a transaction.
                assert connection.scalar(
                    sa.text("SELECT current_setting('app.current_tenant_id', true)")
                ) in (None, "")
            key = f"leak-{uuid.uuid4().hex}"
            user = _user_id(owner_engine, api_world)
            lock_key = f"{api_world.fixture.tenant_id}:{user}:{key}"
            with owner_engine.connect() as blocker, blocker.begin():
                blocker.execute(
                    sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                    {"k": lock_key},
                )
                failed = client.post(
                    f"/api/v1/incidents/{api_world.fixture.incident.id}/escalate",
                    headers={**api_world.headers, "Idempotency-Key": key},
                    json={"justification": "fault while bound to tenant A"},
                )
                assert failed.status_code == 503
            listing = client.get("/api/v1/incidents", headers=api_world.other_headers)
            assert listing.status_code == 200
            ids = {row["id"] for row in listing.json()["items"]}
            assert ids == {str(api_world.other.incident.id)}
            assert (
                client.get(
                    f"/api/v1/incidents/{api_world.fixture.incident.id}",
                    headers=api_world.other_headers,
                ).status_code
                == 404
            )
        finally:
            engine.dispose()


def _user_id(owner_engine: Engine, world: ApiWorld) -> uuid.UUID:
    token = world.headers["Authorization"].split()[1]
    import jwt

    subject = jwt.decode(token, options={"verify_signature": False})["sub"]
    with Session(bind=owner_engine) as session:
        return uuid.UUID(
            str(
                session.scalar(
                    sa.text("SELECT id FROM app_user WHERE external_idp_subject = :s"),
                    {"s": subject},
                )
            )
        )


def _assert_no_open_transactions(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        stuck = connection.scalar(
            sa.text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND usename = 'asic_test_app' AND state LIKE 'idle in transaction%' "
                "AND now() - state_change > interval '5 seconds'"
            )
        )
    assert stuck == 0


def test_application_connections_use_tcp_keepalives(app_url: str) -> None:
    """A silently partitioned connection must be detected in bounded time: the server-side
    statement deadline cannot fire when no packet reaches the server."""
    engine = create_app_engine(app_url, pool_size=1, max_overflow=0)
    try:
        with engine.connect() as connection:
            dsn = connection.connection.dbapi_connection.get_dsn_parameters()  # type: ignore[union-attr]
        assert dsn["keepalives"] == "1"
        assert (
            int(dsn["keepalives_idle"])
            + int(dsn["keepalives_interval"]) * int(dsn["keepalives_count"])
            <= 120
        )
    finally:
        engine.dispose()
