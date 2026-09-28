"""Phase 15.20/15.22: bounded, seeded fuzzing of every API route, and abuse cost.

Phase 13 pinned the individual bounds (``test_api_bounds.py``). This campaign throws a seeded
mix of hostile inputs at *every* route with a real authenticated principal and asserts one
property across all of them: the answer is a bounded 4xx (or the documented classified 503),
never a 500, never a hang, never a crash. Inputs include malformed and deeply nested JSON,
duplicate keys, NaN/Infinity tokens, wrong types, oversized strings, bodies exactly at and one
byte over the size ceiling, wrong content types, invalid UUIDs and cursors, and unexpected
Unicode.

Abuse cost: a flood of invalid bearer tokens is rejected before any database work - the
statement counter on the application's engine stays at zero - and is throttled per peer.
"""

from __future__ import annotations

import dataclasses
import json
import random
import time
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.api.limits import MAX_REQUEST_BODY_BYTES
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import build_fixture

pytestmark = [pytest.mark.postgres, pytest.mark.security]

RNG_SEED = 1522


class Target:
    def __init__(self, app_engine: Engine, owner_engine: Engine) -> None:
        self.engine = app_engine
        self.factory: Callable[[], Session] = sessionmaker(
            app_engine, expire_on_commit=False, autoflush=False
        )
        with Session(owner_engine, expire_on_commit=False, autoflush=False) as arranging:
            self.fixture = build_fixture(arranging, slug=f"fuzz-{uuid.uuid4().hex[:8]}")
            arranging.commit()
            subject = f"fuzz-{uuid.uuid4().hex[:6]}"
            _principal(arranging, self.fixture, "platform_admin", subject, environment_id=None)
        self.headers = {"Authorization": f"Bearer {_token(self.fixture.tenant_id, subject)}"}
        settings = dataclasses.replace(SETTINGS, rate_limit_per_minute=100_000)
        self.client = TestClient(
            create_app(settings=settings, factory=self.factory), raise_server_exceptions=False
        )


@pytest.fixture(scope="module")
def target(app_engine: Engine, owner_engine: Engine) -> Target:
    return Target(app_engine, owner_engine)


def _bodies(rng: random.Random) -> list[tuple[str, bytes]]:
    deep_array = b"[" * 20_000 + b"]" * 20_000
    deep_object = b'{"a":' * 10_000 + b"1" + b"}" * 10_000
    prefix, suffix = b'{"justification": "', b'"}'
    filler = prefix + b"x" * (MAX_REQUEST_BODY_BYTES - len(prefix) - len(suffix)) + suffix
    over = prefix + b"x" * (MAX_REQUEST_BODY_BYTES - len(prefix) - len(suffix) + 1) + suffix
    assert len(filler) == MAX_REQUEST_BODY_BYTES and len(over) == MAX_REQUEST_BODY_BYTES + 1
    bodies = [
        ("empty", b""),
        ("not_json", b"{not json"),
        ("deep_array", deep_array),
        ("deep_object", deep_object),
        ("duplicate_keys", b'{"justification": "a", "justification": "b"}'),
        ("nan", b'{"justification": NaN}'),
        ("infinity", b'{"justification": Infinity}'),
        ("wrong_type", b'{"justification": {"$gt": ""}}'),
        ("huge_number", b'{"justification": 1' + b"0" * 5000 + b"}"),
        ("utf16", '{"justification": "x"}'.encode("utf-16")),
        ("invalid_utf8", b'{"justification": "\xff\xfe"}'),
        ("lone_surrogate", b'{"justification": "\\ud800"}'),
        ("at_ceiling", filler),
        ("over_ceiling", over),
        ("bidi", json.dumps({"justification": "a" + chr(0x202E) + "b"}).encode()),
    ]
    for index in range(40):  # seeded random structures
        depth = rng.randint(1, 60)
        value: Any = rng.choice(["", "x" * rng.randint(0, 5000), 7, None, True, [], {}])
        for _ in range(depth):
            value = rng.choice([[value], {"k": value}, {"justification": value}])
        bodies.append((f"random_{index}", json.dumps(value).encode()))
    return bodies


def _post_routes(target: Target) -> list[str]:
    incident = target.fixture.incident.id
    return [
        f"/api/v1/incidents/{incident}/annotate",
        f"/api/v1/incidents/{incident}/escalate",
        f"/api/v1/incidents/{incident}/cancel",
        f"/api/v1/incidents/{incident}/resolve",
        f"/api/v1/incidents/{incident}/remediation-requests",
        f"/api/v1/approvals/{uuid.uuid4()}/decide",
        "/api/v1/ingest/alerts",
        "/api/v1/ingest/webhooks/simulator",
    ]


def _assert_bounded(response: Any, what: str) -> None:
    assert response.status_code < 500 or response.status_code == 503, (
        what,
        response.status_code,
        response.text[:300],
    )


def test_hostile_bodies_on_every_write_route_are_bounded_4xx(target: Target) -> None:
    rng = random.Random(RNG_SEED)
    for route in _post_routes(target):
        for name, body in _bodies(rng):
            for content_type in (
                "application/json",
                "text/plain",
                "application/x-www-form-urlencoded",
            ):
                started = time.monotonic()
                response = target.client.post(
                    route,
                    content=body,
                    headers={
                        **target.headers,
                        "Content-Type": content_type,
                        "Idempotency-Key": f"fuzz-{uuid.uuid4().hex}",
                    },
                )
                _assert_bounded(response, (route, name, content_type))
                assert time.monotonic() - started < 10, (route, name)
                if name == "over_ceiling":
                    assert response.status_code == 413, (route, response.status_code)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/incidents/not-a-uuid",
        "/api/v1/incidents/00000000-0000-0000-0000-00000000000g",
        "/api/v1/incidents/%00",
        "/api/v1/incidents/" + "a" * 5000,
        "/api/v1/incidents/{incident}/timeline?cursor=" + "A" * 65,
        "/api/v1/incidents/{incident}/timeline?cursor=%FF%FE",
        "/api/v1/incidents/{incident}/timeline?cursor=====",
        "/api/v1/incidents?limit=-1",
        "/api/v1/incidents?limit=100000000000000000000",
        "/api/v1/incidents?limit=1e3",
        "/api/v1/incidents?cursor=" + "dGVzdA",
        "/api/v1/approvals/pending?limit=abc",
        "/api/v1/evaluation/suite-runs/" + str(uuid.uuid4()),
        "/api/v1/evaluation/runs?suite_run_id=not-a-uuid",
        "/api/v1/admin/audit?limit=0",
        "/api/v1/incidents/" + chr(0x202E) + "x",
        "/api/v1/../../etc/passwd",
    ],
)
def test_hostile_paths_and_queries_are_bounded_4xx(target: Target, path: str) -> None:
    resolved = path.replace("{incident}", str(target.fixture.incident.id))
    response = target.client.get(resolved, headers=target.headers)
    _assert_bounded(response, resolved)


def test_an_invalid_token_flood_costs_no_database_work_and_is_throttled(target: Target) -> None:
    statements: list[str] = []

    def count(*_args: Any) -> None:
        statements.append("x")

    event.listen(target.engine, "before_cursor_execute", count)
    try:
        statuses = [
            target.client.get(
                "/api/v1/incidents",
                headers={"Authorization": f"Bearer invalid.{n}.token"},
            ).status_code
            for n in range(120)
        ]
    finally:
        event.remove(target.engine, "before_cursor_execute", count)
    assert statements == [], f"{len(statements)} SQL statements for unauthenticated garbage"
    assert set(statuses) <= {401, 429}
    assert 429 in statuses  # the per-peer failed-authentication limiter engaged
    assert statuses[:30].count(401) == 30
