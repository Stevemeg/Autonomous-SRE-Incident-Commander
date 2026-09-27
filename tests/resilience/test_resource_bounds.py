"""Phase 15.2: resources stay bounded under repeated, bounded workloads.

Each test repeats the same workload several times and compares the *later* rounds: warm-up
allocations (imports, caches that fill once, the connection pool reaching its size) happen
in the first round and are deliberately excluded, so a bounded cache is not mistaken for a
leak. What must not grow round over round: pooled/checked-out database connections, server
sessions, threads, sockets, traced Python memory, workflows left running, temporary files and
metric/limiter cardinality.
"""

from __future__ import annotations

import gc
import os
import socket
import tempfile
import threading
import tracemalloc
import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.api.rate_limit import RateLimiter
from asic.db.models import WorkflowRun
from asic.db.session import bind_tenant, create_app_engine
from asic.domain.clock import FrozenClock
from asic.domain.enums import WorkflowRunStatus
from asic.llm.deterministic import DeterministicModelProvider
from asic.observability.setup import render_prometheus
from asic.orchestration.service import InvestigationRequest, InvestigationService
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, scenario
from tests.kernel_fixtures import CLOCK_START, build_fixture
from tests.resilience.conftest import SETTINGS, ApiWorld, factory_for

pytestmark = pytest.mark.postgres

#: Traced-memory growth tolerated between two identical late rounds. Generous: allocator
#: noise and interned strings exist; a real per-request leak of even 1 KiB x 300 requests
#: per round would still exceed it after a few rounds.
MEMORY_SLACK_BYTES = 1_500_000


def _sockets() -> int:
    gc.collect()
    return sum(
        1 for obj in gc.get_objects() if isinstance(obj, socket.socket) and obj.fileno() != -1
    )


def _app_connections(owner_engine: Engine, role: str = "asic_test_app") -> int:
    with owner_engine.connect() as connection:
        return int(
            connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND usename = :role"
                ),
                {"role": role},
            )
        )


def test_api_request_workload_is_bounded(
    app_url: str, owner_engine: Engine, api_world: ApiWorld
) -> None:
    engine = create_app_engine(app_url, pool_size=3, max_overflow=2)
    app = create_app(settings=SETTINGS, factory=factory_for(engine))
    client = TestClient(app)
    incident = api_world.fixture.incident.id
    paths = [
        "/api/v1/incidents",
        f"/api/v1/incidents/{incident}",
        f"/api/v1/incidents/{incident}/timeline",
        f"/api/v1/incidents/{incident}/evidence",
        f"/api/v1/incidents/{incident}/hypotheses",
        "/readyz",
        f"/api/v1/not-a-route/{uuid.uuid4()}",  # unmatched: must not add a label value
    ]

    def round_() -> None:
        for n in range(150):
            client.get(paths[n % len(paths)], headers=api_world.headers)
        assert engine.pool.checkedout() == 0

    tracemalloc.start()
    try:
        round_()  # warm-up: pool fills, imports and caches settle
        baseline_threads, baseline_sockets = threading.active_count(), _sockets()
        round_()
        gc.collect()
        first, _ = tracemalloc.get_traced_memory()
        for _ in range(3):
            round_()
        gc.collect()
        last, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert last - first < MEMORY_SLACK_BYTES, f"traced memory grew {last - first} bytes"
    assert threading.active_count() <= baseline_threads + 1
    assert _sockets() <= baseline_sockets + 1
    assert engine.pool.checkedout() == 0
    assert _app_connections(owner_engine) <= 3 + 2 + 10  # this pool plus the suite's own
    exposition = render_prometheus()[0].decode()
    assert "not-a-route" not in exposition and str(incident) not in exposition
    engine.dispose()


def test_repeated_investigations_leave_no_state_or_connections_behind(
    app_engine: Engine, owner_engine: Engine
) -> None:
    factory: Callable[[], Session] = sessionmaker(app_engine, expire_on_commit=False)
    case = scenario(PRIMARY_SCENARIO_ID)
    clock = FrozenClock(start=CLOCK_START)
    service = InvestigationService(
        session_factory=factory,
        providers=[SimulatorProvider(case, clock=clock)],
        model=DeterministicModelProvider(case),
        clock=clock,
        budget_policy=case.budget,
    )
    tenants: list[uuid.UUID] = []
    before_files = set(os.listdir(tempfile.gettempdir()))

    def run_once() -> None:
        with factory() as session:
            fixture = build_fixture(
                session, slug=f"leak-{uuid.uuid4().hex[:10]}", service_name=case.service
            )
            session.commit()
        tenants.append(fixture.tenant_id)
        outcome = service.start(
            InvestigationRequest(
                tenant_id=fixture.tenant_id,
                incident_id=fixture.incident.id,
                behaviour_version_id=fixture.behaviour_version.id,
                service_ids=fixture.service_ids,
            )
        )
        assert outcome.terminated

    tracemalloc.start()
    try:
        for _ in range(2):
            run_once()
        baseline_threads = threading.active_count()
        gc.collect()
        first, _ = tracemalloc.get_traced_memory()
        for _ in range(6):
            run_once()
        gc.collect()
        last, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert last - first < 3 * MEMORY_SLACK_BYTES, f"traced memory grew {last - first} bytes"
    assert threading.active_count() <= baseline_threads + 1
    assert app_engine.pool.checkedout() == 0
    # No workflow is left running or leased: every run reached a terminal state.
    for tenant_id in tenants:
        with factory() as session:
            bind_tenant(session, tenant_id)
            open_runs = session.scalar(
                sa.select(sa.func.count())
                .select_from(WorkflowRun)
                .where(
                    WorkflowRun.tenant_id == tenant_id,
                    WorkflowRun.status.not_in(
                        (
                            WorkflowRunStatus.COMPLETED,
                            WorkflowRunStatus.FAILED,
                            WorkflowRunStatus.DEAD_LETTERED,
                        )
                    ),
                )
            )
        assert open_runs == 0
    # The shared temp directory churns with other processes; nothing this workload could
    # have created (the product writes no temp files) may appear.
    created = set(os.listdir(tempfile.gettempdir())) - before_files
    assert not [name for name in created if name.lower().startswith("asic")]


def test_rate_limiter_key_space_is_bounded_under_unique_keys() -> None:
    import time as _time

    now = [0.0]
    limiter = RateLimiter(5, window_seconds=60, clock=lambda: now[0])  # default 10,000 keys
    started = _time.perf_counter()
    for n in range(200_000):
        limiter.admit(f"attacker-{n}")
    # Refusing new keys while full is O(1): no rescan of the table per refused key.
    assert _time.perf_counter() - started < 5.0
    assert limiter.tracked_keys() == 10_000
    limiter = RateLimiter(5, window_seconds=60, clock=lambda: now[0], max_keys=1000)
    for n in range(5_000):
        limiter.admit(f"attacker-{n}")
    assert limiter.tracked_keys() == 1000
    # A verified caller already tracked keeps working; new keys are refused, not stored.
    assert limiter.admit("attacker-0") is True
    assert limiter.admit("brand-new") is False
    now[0] = 61.0  # window passes: expired keys are pruned on the next insertion
    assert limiter.admit("brand-new") is True
    assert limiter.tracked_keys() <= 1000
