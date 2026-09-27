"""Phase 15: concurrency beyond threads + connections must queue, never deadlock.

Found by the load harness's burst profile (96 concurrent requests against a 40-thread worker
pool and a 15-connection database pool): the request-session dependency bound the tenant in
its own threadpool call, checking out a connection, and the endpoint then needed a second
thread. With more requests in flight than threads plus connections, every thread waited on the
pool while every connection-holder waited on a thread, and the API answered nothing until the
pool timeout. Here the same shape is forced small: three worker threads, two connections, many
concurrent requests on both the read path and the ingestion path.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

import anyio.to_thread
import pytest
from fastapi import Request, Response
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from asic.api import create_app
from asic.db.session import create_app_engine
from tests.resilience.conftest import SETTINGS
from tests.resilience.test_event_storms import Edge, _concurrently

pytestmark = pytest.mark.postgres

THREADS = 3
REQUESTS = 24


def test_a_burst_beyond_threads_and_connections_queues_instead_of_deadlocking(
    app_url: str, owner_engine: Engine
) -> None:
    small = create_app_engine(app_url, pool_size=2, max_overflow=0, pool_timeout=5)
    try:
        edge = Edge(small, owner_engine)
        app = create_app(
            settings=SETTINGS, factory=sessionmaker(small, expire_on_commit=False, autoflush=False)
        )

        @app.middleware("http")
        async def few_threads(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            anyio.to_thread.current_default_thread_limiter().total_tokens = THREADS
            return await call_next(request)

        headers = {"Authorization": f"Bearer {edge.token}"}
        with TestClient(app) as client:

            def read() -> int:
                return client.get("/api/v1/incidents", headers=headers).status_code

            def ingest(n: int) -> int:
                return client.post(
                    "/api/v1/ingest/alerts",
                    headers={**headers, "Idempotency-Key": f"burst-{uuid.uuid4().hex}"},
                    json=edge.event(f"burst-{n}", f"fp-burst-{n % 3}", offset=n),
                ).status_code

            calls: list[Callable[[], int]] = [read for _ in range(REQUESTS)]
            calls += [lambda n=n: ingest(n) for n in range(REQUESTS // 3)]
            started = time.monotonic()
            statuses = _concurrently(calls, workers=REQUESTS)
            elapsed = time.monotonic() - started
        assert statuses.count(200) == len(calls), sorted(statuses)
        assert elapsed < 30, f"requests stalled: {elapsed:.1f}s"
        assert small.pool.checkedout() == 0  # type: ignore[attr-defined]
    finally:
        small.dispose()


def test_a_full_ingestion_bulkhead_is_a_fast_classified_503(
    app_url: str, owner_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ingestion beyond the bulkhead waits without a connection, then answers 503 with
    ``Retry-After`` - never a hang, never a 500 - while reads are unaffected."""
    from asic.api import app as app_module

    monkeypatch.setattr(app_module, "INGEST_SLOT_WAIT_SECONDS", 0.2)
    small = create_app_engine(app_url, pool_size=2, max_overflow=0, pool_timeout=5)
    try:
        edge = Edge(small, owner_engine)
        app = create_app(
            settings=SETTINGS, factory=sessionmaker(small, expire_on_commit=False, autoflush=False)
        )
        app.state.ingest_slots = app_module.IngestSlots(0)  # every slot already taken
        headers = {"Authorization": f"Bearer {edge.token}"}
        with TestClient(app) as client:
            started = time.monotonic()
            busy = client.post(
                "/api/v1/ingest/alerts",
                headers={**headers, "Idempotency-Key": f"busy-{uuid.uuid4().hex}"},
                json=edge.event("busy-1", "fp-busy"),
            )
            waited = time.monotonic() - started
            read = client.get("/api/v1/incidents", headers=headers)
        assert busy.status_code == 503, busy.text
        assert busy.json()["detail"]["code"] == "ingestion_busy"
        assert busy.headers["Retry-After"]
        assert waited < 5
        assert read.status_code == 200
        assert small.pool.checkedout() == 0  # type: ignore[attr-defined]
    finally:
        small.dispose()
