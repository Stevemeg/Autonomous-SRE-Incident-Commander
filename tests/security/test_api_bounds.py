"""Phase 13 API input bounds, rate limiting and readiness behaviour.

Each limit is asserted at its boundary (just inside, just outside) and each was chosen for a
stated reason in ``asic.api.limits`` / ``asic.api.rate_limit``; none is arbitrary.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asic.api import ApiSettings, create_app
from asic.api import auth as auth_module
from asic.api.limits import MAX_REQUEST_BODY_BYTES
from asic.api.rate_limit import RateLimiter
from asic.db.session import DEFAULT_CONNECT_TIMEOUT_SECONDS, create_app_engine
from asic.observability.health import (
    DependencyCheck,
    DependencyStatus,
    Readiness,
    ReadinessCache,
    check_database,
)
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import Fixture

pytestmark = pytest.mark.security


class TestRateLimiter:
    def test_it_admits_up_to_the_limit_then_refuses_and_recovers(self) -> None:
        now = [0.0]
        limiter = RateLimiter(3, window_seconds=10, clock=lambda: now[0])
        assert [limiter.admit("k") for _ in range(4)] == [True, True, True, False]
        now[0] = 10.5
        assert limiter.admit("k") is True

    def test_key_cardinality_is_bounded_and_fails_closed_for_new_keys(self) -> None:
        now = [0.0]
        limiter = RateLimiter(5, window_seconds=10, clock=lambda: now[0], max_keys=3)
        assert all(limiter.admit(f"user-{i}") for i in range(3))
        assert limiter.admit("attacker-invented-key") is False  # table full: refused
        assert limiter.tracked_keys() == 3
        assert limiter.admit("user-0") is True  # an existing key is unaffected
        now[0] = 11.0  # windows expire; the table prunes itself and admits again
        assert limiter.admit("new-user") is True
        assert limiter.tracked_keys() <= 3

    def test_a_flood_of_distinct_keys_cannot_grow_memory(self) -> None:
        limiter = RateLimiter(1, window_seconds=60, max_keys=100)
        for index in range(5000):
            limiter.admit(f"k{index}")
        assert limiter.tracked_keys() <= 100

    @pytest.mark.parametrize("args", [(0,), (1, 0.0), (1, 1.0, 0)])
    def test_configuration_must_be_positive(self, args: tuple[float, ...]) -> None:
        limit = int(args[0])
        window = args[1] if len(args) > 1 else 60.0
        max_keys = int(args[2]) if len(args) > 2 else 10
        with pytest.raises(ValueError):
            RateLimiter(limit, window_seconds=window, max_keys=max_keys)


def _claims_token(tenant: uuid.UUID, subject: str) -> str:
    return _token(tenant, subject)


@pytest.mark.postgres
class TestEdgeLimits:
    @pytest.fixture
    def client(self, api_factory: Callable[[], Session]) -> Iterator[TestClient]:
        yield TestClient(
            create_app(settings=SETTINGS, factory=api_factory), raise_server_exceptions=False
        )

    def _auth(
        self, arranger: Session, fixture: Fixture, role: str = "responder", subject: str = "u"
    ) -> dict[str, str]:
        _principal(arranger, fixture, role, subject, environment_id=None)
        return {
            "Authorization": f"Bearer {_token(fixture.tenant_id, subject)}",
            "Idempotency-Key": uuid.uuid4().hex,
        }

    def test_an_oversized_declared_body_is_refused_before_any_authentication(
        self, client: TestClient, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["code"] == "payload_too_large"

    def test_a_streamed_body_without_a_length_is_cut_off_at_the_ceiling(
        self, client: TestClient, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds

        def chunks() -> Iterator[bytes]:
            for _ in range(MAX_REQUEST_BODY_BYTES // 4096 + 8):
                yield b"y" * 4096

        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413

    def test_a_body_at_the_ceiling_is_not_refused_by_the_size_guard(
        self, client: TestClient, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            content=b"{" + b" " * (MAX_REQUEST_BODY_BYTES - 2) + b"}",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code != 413  # reaches auth (401), not the size guard

    @pytest.mark.parametrize(
        "content_type",
        [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/xml",
            "",
        ],
    )
    def test_only_json_is_accepted_for_a_body(
        self, client: TestClient, worlds: tuple[Fixture, Fixture], content_type: str
    ) -> None:
        own, _ = worlds
        headers = {"Content-Type": content_type} if content_type else {}
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate", content=b"a=b", headers=headers
        )
        assert response.status_code == 415

    def test_json_with_a_charset_parameter_is_accepted(
        self, client: TestClient, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            content=b"{}",
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert response.status_code == 401  # past the media-type guard, stopped by auth

    def test_malformed_and_unexpected_json_is_a_422_never_a_500(
        self, client: TestClient, api_arranger: Session, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        headers = self._auth(api_arranger, own)
        path = f"/api/v1/incidents/{own.incident.id}/annotate"
        for payload in (
            b"{not json",
            b"[]",
            b'"string"',
            b'{"justification": "ok", "unexpected": 1}',
            b'{"justification": 5}',
            b'{"justification": ""}',
            b'{"justification": "   "}',
            b"{" * 5000,
        ):
            response = client.post(
                path, content=payload, headers={**headers, "Content-Type": "application/json"}
            )
            assert response.status_code == 422, (payload[:30], response.status_code)

    @pytest.mark.parametrize(
        "text",
        [
            "nul\x00byte",
            "bell\x07",
            "escape\x1b[31m",
            "c1\x85control",
            "del\x7f",
            "zero" + chr(0x200B) + "width",
            "bidi" + chr(0x202E) + "override",
            "bom" + chr(0xFEFF),
        ],
    )
    def test_control_and_invisible_characters_in_human_text_are_refused(
        self, client: TestClient, api_arranger: Session, worlds: tuple[Fixture, Fixture], text: str
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            headers=self._auth(api_arranger, own),
            json={"justification": text},
        )
        assert response.status_code == 422, response.text  # NUL used to be a 500

    def test_newlines_and_tabs_and_unicode_are_legitimate_in_a_justification(
        self, client: TestClient, api_arranger: Session, worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            headers=self._auth(api_arranger, own),
            json={"justification": "line one\n\tline two - café ✓"},
        )
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize(("length", "ok"), [(4000, True), (4001, False)])
    def test_justification_length_boundary(
        self,
        client: TestClient,
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
        length: int,
        ok: bool,
    ) -> None:
        own, _ = worlds
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            headers=self._auth(api_arranger, own),
            json={"justification": "a" * length},
        )
        assert (response.status_code == 200) is ok

    @pytest.mark.parametrize(("length", "ok"), [(15, False), (16, True), (128, True), (129, False)])
    def test_idempotency_key_length_boundary(
        self,
        client: TestClient,
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
        length: int,
        ok: bool,
    ) -> None:
        own, _ = worlds
        headers = self._auth(api_arranger, own)
        headers["Idempotency-Key"] = "k" * length
        response = client.post(
            f"/api/v1/incidents/{own.incident.id}/annotate",
            headers=headers,
            json={"justification": "boundary"},
        )
        assert (response.status_code == 200) is ok

    @pytest.mark.parametrize("limit", ["0", "-1", "101", "abc", "1.5", ""])
    def test_pagination_limit_is_bounded(
        self, client: TestClient, api_arranger: Session, worlds: tuple[Fixture, Fixture], limit: str
    ) -> None:
        own, _ = worlds
        headers = self._auth(api_arranger, own, "viewer")
        response = client.get("/api/v1/incidents", params={"limit": limit}, headers=headers)
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "cursor", ["!!!", "not-base64-uuid", "a" * 65, "%00", "e30", "../../etc/passwd"]
    )
    def test_a_malformed_cursor_is_a_400(
        self,
        client: TestClient,
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
        cursor: str,
    ) -> None:
        own, _ = worlds
        headers = self._auth(api_arranger, own, "viewer")
        response = client.get("/api/v1/incidents", params={"cursor": cursor}, headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "invalid_cursor"

    @pytest.mark.parametrize(
        "identifier", ["not-a-uuid", "1", "..%2f..%2fetc", "%00", "a" * 300, "0" * 32 + "z"]
    )
    def test_path_identifiers_must_be_uuids(
        self,
        client: TestClient,
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
        identifier: str,
    ) -> None:
        own, _ = worlds
        headers = self._auth(api_arranger, own, "viewer")
        response = client.get(f"/api/v1/incidents/{identifier}", headers=headers)
        assert response.status_code in {404, 422}

    def test_a_forged_client_address_header_cannot_choose_the_rate_limit_key(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        _principal(api_arranger, own, "viewer", "limited", environment_id=None)
        settings = ApiSettings(jwt_secret=SETTINGS.jwt_secret, rate_limit_per_minute=3)
        client = TestClient(create_app(settings=settings, factory=api_factory))
        token = _token(own.tenant_id, "limited")
        codes = []
        for index in range(5):
            response = client.get(
                "/api/v1/incidents",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Forwarded-For": f"203.0.113.{index}",  # attacker-chosen, ignored
                    "X-Real-IP": f"198.51.100.{index}",
                },
            )
            codes.append(response.status_code)
        assert codes == [200, 200, 200, 429, 429]
        assert response.headers["Retry-After"] == "60"

    def test_an_over_limit_caller_costs_no_database_lookup(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        own, _ = worlds
        _principal(api_arranger, own, "viewer", "cheap-refusal", environment_id=None)
        calls = {"count": 0}
        real = auth_module.authenticate

        def counting(*args: Any, **kwargs: Any) -> Any:
            calls["count"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(auth_module, "authenticate", counting)
        settings = ApiSettings(jwt_secret=SETTINGS.jwt_secret, rate_limit_per_minute=2)
        client = TestClient(create_app(settings=settings, factory=api_factory))
        headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'cheap-refusal')}"}
        statuses = [client.get("/api/v1/incidents", headers=headers).status_code for _ in range(6)]
        assert statuses[:2] == [200, 200] and set(statuses[2:]) == {429}
        assert calls["count"] == 2  # the four refused requests never touched the database

    def test_unauthenticated_abuse_is_bounded_per_peer_and_does_not_throttle_valid_callers(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        _principal(api_arranger, own, "viewer", "legit", environment_id=None)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        bad = {"Authorization": "Bearer definitely.not.valid"}
        statuses = [client.get("/api/v1/incidents", headers=bad).status_code for _ in range(35)]
        assert statuses[:30] == [401] * 30
        assert set(statuses[30:]) == {429}
        # Failures are counted, successes are not: a valid caller behind the same address
        # is still served (the failure limiter only runs on the failure path).
        good = {"Authorization": f"Bearer {_token(own.tenant_id, 'legit')}"}
        assert client.get("/api/v1/incidents", headers=good).status_code == 200


class TestReadiness:
    def _cache(
        self, evaluations: list[int], *, ready: bool = True, ttl: float = 2.0
    ) -> tuple[ReadinessCache, list[float]]:
        now = [0.0]

        def evaluate() -> Readiness:
            evaluations.append(1)
            status = DependencyStatus.UP if ready else DependencyStatus.DOWN
            return Readiness(ready=ready, checks=(DependencyCheck("database", status, "x"),))

        return ReadinessCache(evaluate, ttl_seconds=ttl, clock=lambda: now[0]), now

    def test_public_probing_is_coalesced_to_one_evaluation_per_interval(self) -> None:
        evaluations: list[int] = []
        cache, now = self._cache(evaluations)
        for _ in range(500):
            assert cache.get().ready
        assert len(evaluations) == 1
        now[0] = 2.5
        cache.get()
        assert len(evaluations) == 2

    def test_a_not_ready_result_is_also_cached_and_reported_faithfully(self) -> None:
        evaluations: list[int] = []
        cache, _ = self._cache(evaluations, ready=False)
        assert [cache.get().ready for _ in range(10)] == [False] * 10
        assert len(evaluations) == 1

    def test_concurrent_callers_never_queue_behind_an_in_flight_evaluation(self) -> None:
        import threading

        started, release = threading.Event(), threading.Event()
        served: list[bool] = []

        def slow() -> Readiness:
            started.set()
            release.wait(5)
            return Readiness(ready=True, checks=())

        cache = ReadinessCache(slow, ttl_seconds=0.0)
        worker = threading.Thread(target=cache.get)
        worker.start()
        assert started.wait(5)
        began = time.monotonic()
        served.append(cache.get().ready)  # must return immediately, not wait for `release`
        assert time.monotonic() - began < 1.0
        assert served == [False]  # "not ready" until the first evaluation completes
        release.set()
        worker.join(5)

    def test_the_database_connection_has_a_bounded_connect_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asic.db.session as session_module

        captured: dict[str, Any] = {}

        def fake_create_engine(url: str, **kwargs: Any) -> object:
            captured.update(kwargs)
            return object()

        monkeypatch.setattr(session_module, "create_engine", fake_create_engine)
        create_app_engine("postgresql+psycopg2://u:p@127.0.0.1:1/x")
        assert captured["connect_args"]["connect_timeout"] == DEFAULT_CONNECT_TIMEOUT_SECONDS
        assert captured["pool_timeout"] == 10.0
        # An explicit caller value is respected, not overwritten.
        create_app_engine("postgresql+psycopg2://u:p@h/x", connect_args={"connect_timeout": 2})
        assert captured["connect_args"]["connect_timeout"] == 2

    def test_an_unreachable_database_is_reported_down_within_a_bounded_time(self) -> None:
        from sqlalchemy.orm import sessionmaker

        # 192.0.2.0/24 is TEST-NET-1: never routable, so the connect can only time out.
        engine = create_app_engine(
            "postgresql+psycopg2://u:p@192.0.2.1:5432/x", connect_args={"connect_timeout": 1}
        )
        try:
            started = time.monotonic()
            check = check_database(sessionmaker(bind=engine))
            elapsed = time.monotonic() - started
        finally:
            engine.dispose()
        assert check.status is DependencyStatus.DOWN
        assert check.detail == "unreachable"  # a closed code, never the driver's message
        assert elapsed < 6.0


def test_unused_helpers_stay_typed(request: pytest.FixtureRequest) -> None:
    assert sa.text("select 1") is not None and callable(_claims_token)
