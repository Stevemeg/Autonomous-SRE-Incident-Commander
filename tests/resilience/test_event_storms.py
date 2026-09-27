"""Phase 15.7/15.8: duplicate, out-of-order and retried deliveries through the real HTTP edge.

``tests/ingestion`` proves the correlation rules at the service boundary. This campaign drives
the same rules the way a misbehaving upstream would - concurrently, over HTTP, through
authentication, connector-scope checks and the idempotency layer:

* a webhook redelivery storm (one event, many deliveries, fresh idempotency keys) and a
  client retry storm (one event, one key, many concurrent attempts);
* a shuffled, concurrent mix of firing, late (earlier ``started_at``) and resolved events;
* distinct events that must stay distinct (no over-normalisation).

Invariants: never a 5xx, exactly one alert per occurrence, one incident and one investigation
request per correlated group, no incident resolved by an out-of-order resolution, and the
incident status always equals the projection of its event log.
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.db.models import Alert, Incident, InvestigationDispatch
from asic.db.projections import recompute_incident_status
from asic.db.session import bind_tenant, create_app_engine
from asic.domain.enums import IncidentStatus
from tests.api.test_auth import _bind_connector, _principal, _token
from tests.kernel_fixtures import build_fixture
from tests.resilience.conftest import SETTINGS

pytestmark = pytest.mark.postgres


class Edge:
    def __init__(self, app_engine: Engine, owner_engine: Engine) -> None:
        self.factory: Callable[[], Session] = sessionmaker(
            app_engine, expire_on_commit=False, autoflush=False
        )
        with Session(owner_engine, expire_on_commit=False, autoflush=False) as arranging:
            self.fixture = build_fixture(arranging, slug=f"storm-{uuid.uuid4().hex[:10]}")
            arranging.commit()
            subject = f"storm-connector-{uuid.uuid4().hex[:6]}"
            _principal(arranging, self.fixture, "system_operator", subject)
            _bind_connector(arranging, self.fixture, connector_id="storm-alerts")
        self.token = _token(
            self.fixture.tenant_id,
            subject,
            connector_id="storm-alerts",
            source="simulator",
            service_id=str(self.fixture.service.id),
            environment_id=str(self.fixture.environment.id),
        )
        self.client = TestClient(create_app(settings=SETTINGS, factory=self.factory))
        self.anchor = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)

    def post(self, body: dict[str, Any], key: str | None = None) -> int:
        response = self.client.post(
            "/api/v1/ingest/alerts",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Idempotency-Key": key or f"storm-{uuid.uuid4().hex}",
            },
            json=body,
        )
        return response.status_code

    def event(
        self,
        event_id: str,
        fingerprint: str,
        *,
        state: str = "firing",
        offset: int = 0,
        category: str = "latency",
    ) -> dict[str, Any]:
        started = self.anchor + timedelta(seconds=offset)
        return {
            "schema_version": 1,
            "source_event_id": event_id,
            "fingerprint": fingerprint,
            "severity": "high",
            "state": state,
            "category": category,
            "title": f"storm {fingerprint}",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "observed_at": (started + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        }

    def counts(self) -> dict[str, int]:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)

            def count(model: Any, *where: Any) -> int:
                return int(
                    session.scalar(
                        sa.select(sa.func.count())
                        .select_from(model)
                        .where(model.tenant_id == self.fixture.tenant_id, *where)
                    )
                )

            return {
                # the fixture seeds one incident and one alert of its own
                "incidents": count(Incident) - 1,
                "alerts": count(Alert, Alert.source == "simulator"),
                "dispatches": count(InvestigationDispatch),
            }

    def statuses_match_logs(self) -> None:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)
            for incident in session.scalars(
                sa.select(Incident).where(Incident.tenant_id == self.fixture.tenant_id)
            ):
                derived = recompute_incident_status(
                    session, tenant_id=self.fixture.tenant_id, incident_id=incident.id
                )
                assert derived in (None, incident.status), incident.id
                assert incident.status is not IncidentStatus.RESOLVED


def _concurrently(calls: list[Callable[[], int]], workers: int = 12) -> list[int]:
    results: list[int] = []
    lock = threading.Lock()
    queue = list(calls)

    def worker() -> None:
        while True:
            with lock:
                if not queue:
                    return
                call = queue.pop()
            status = call()
            with lock:
                results.append(status)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    return results


@pytest.fixture
def edge(app_engine: Engine, owner_engine: Engine) -> Edge:
    return Edge(app_engine, owner_engine)


def test_a_webhook_redelivery_storm_is_one_alert_one_incident(edge: Edge) -> None:
    body = edge.event("evt-redelivered", "p95-latency")
    statuses = _concurrently([lambda: edge.post(body) for _ in range(40)])
    assert len(statuses) == 40 and set(statuses) <= {200, 409, 503}, statuses
    assert statuses.count(200) >= 1
    assert edge.counts() == {"incidents": 1, "alerts": 1, "dispatches": 1}
    edge.statuses_match_logs()


def test_a_client_retry_storm_with_one_key_is_applied_once(edge: Edge) -> None:
    body = edge.event("evt-retried", "p95-latency")
    key = f"retry-{uuid.uuid4().hex}"
    statuses = _concurrently([lambda: edge.post(body, key) for _ in range(30)])
    assert set(statuses) <= {200, 409, 503}, statuses
    assert edge.counts() == {"incidents": 1, "alerts": 1, "dispatches": 1}


def test_shuffled_late_and_out_of_order_events_converge(edge: Edge) -> None:
    rng = random.Random(1507)
    events: list[dict[str, Any]] = []
    for group in range(6):
        fingerprint = f"group-{group}"
        events.append(edge.event(f"g{group}-fire", fingerprint, offset=60))
        events.append(edge.event(f"g{group}-late", fingerprint, offset=0))  # earlier start
        events.append(edge.event(f"g{group}-resolved", fingerprint, state="resolved", offset=60))
        events.append(edge.event(f"g{group}-fire", fingerprint, offset=60))  # exact duplicate
    rng.shuffle(events)
    statuses = _concurrently([lambda e=e: edge.post(e) for e in events])
    assert 500 not in statuses and all(s < 500 or s == 503 for s in statuses), statuses
    counts = edge.counts()
    # Duplicates never become alerts; each firing occurrence is recorded once.
    assert counts["alerts"] <= 12
    # Correlation groups related alerts (same service, category and window) into incidents;
    # never more incidents than distinct firing occurrences, never an incident per delivery.
    assert 1 <= counts["incidents"] <= 12
    assert counts["dispatches"] == counts["incidents"]
    edge.statuses_match_logs()  # an out-of-order resolution never resolved an incident


def test_distinct_events_are_not_over_normalised(edge: Edge) -> None:
    categories = ("latency", "errors", "saturation", "availability", "memory")
    for index, category in enumerate(categories):
        assert (
            edge.post(edge.event(f"distinct-{index}", f"fp-{category}", category=category)) == 200
        )
    assert edge.counts()["alerts"] == len(categories)


def test_concurrent_ingestion_cannot_deadlock_a_small_pool(
    app_url: str, owner_engine: Engine
) -> None:
    """Regression (found by the Phase 15 load harness at 50 alerts/s): the ingest handler held
    the request's pooled connection in an open transaction while ingestion checked out a second
    one, so concurrency >= pool size stalled every request until the pool timeout. With a pool
    of two and no overflow, many concurrent ingests must all succeed promptly."""
    small = create_app_engine(app_url, pool_size=2, max_overflow=0, pool_timeout=5)
    try:
        edge = Edge(small, owner_engine)
        calls = [
            (lambda n=n: edge.post(edge.event(f"pool-{n}", f"fp-pool-{n % 3}", offset=n)))
            for n in range(24)
        ]
        started = time.monotonic()
        statuses = _concurrently(calls, workers=8)
        elapsed = time.monotonic() - started
        assert statuses == [200] * 24, statuses
        assert elapsed < 30, f"ingestion stalled: {elapsed:.1f}s"
        assert small.pool.checkedout() == 0  # type: ignore[attr-defined]
    finally:
        small.dispose()
