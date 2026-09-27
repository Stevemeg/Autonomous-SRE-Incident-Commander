#!/usr/bin/env python3
"""Reproducible load and performance harness (Phase 15).

Drives the real API over HTTP (a separately started ``python -m asic.api`` process or
container) against a real migrated PostgreSQL, plus the real ingest -> dispatch ->
investigation pipeline in-process with the deterministic simulator and model provider. No
production traffic is claimed: every result is labelled ``LOCAL BENCHMARK`` with the
environment it ran in, and the harness derives an *observed* saturation point rather than
asserting a target.

Profiles (``--profile``; ``all`` runs them in this order):

* ``smoke``        - low concurrency correctness pass over every flow; any non-expected status fails.
* ``capacity``     - closed-loop read mix at doubling concurrency; finds where throughput stops
                     growing or latency/errors break down (the observed saturation point).
* ``steady``       - fixed-rate mixed traffic (reads + ingestion) for a sustained window.
* ``ingest``       - fixed-rate alert ingestion only (``--ingest-rps``, default 50/s: the NFR-PRF-04
                     assumption). Ingestion and correlation are synchronous, so "backlog" shows up
                     as latency from the scheduled slot and as dropped slots, both reported.
* ``burst``        - a short spike at high concurrency after an idle period.
* ``concurrency``  - many simultaneous distinct incidents: ingestion of new fingerprints, then
                     concurrent investigations through ``InvestigationDispatcher``.
* ``soak``         - (soak-lite) fixed low rate for ``--soak-seconds`` while sampling server RSS,
                     threads, open fds and database connections to expose unbounded growth.

Nothing dangerous is exercised: remediation execution is never driven to inflate load; the
investigations are read-only and use simulators.

Usage (see docs/testing/LOAD_AND_PERFORMANCE.md for the full reproduction)::

    python scripts/load_harness.py --admin-url "$ADMIN_URL" --app-url "$APP_URL" \\
        --api-url http://127.0.0.1:18080 --jwt-secret "$SECRET" --api-container asic-load-api \\
        --profile all --output tmp/load-results.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from asic.db.models import (  # noqa: E402
    BehaviourVersion,
    ConnectorScopeBinding,
    Environment,
    IntegrationConnector,
    InvestigationDispatch,
    Role,
    Service,
    Tenant,
    TenantToolGrant,
    ToolDefinition,
    User,
    UserRoleAssignment,
)
from asic.db.session import TenantContext, bind_tenant, create_app_engine  # noqa: E402
from asic.domain.enums import IntegrationKind, UserStatus  # noqa: E402
from asic.llm.prompts import PROMPT_SET_VERSION  # noqa: E402
from asic.tools.catalogue import CATALOGUE_VERSION  # noqa: E402

LABEL = "LOCAL BENCHMARK"
ISSUER = "asic-load-idp"
AUDIENCE = "asic-api"


# ------------------------------------------------------------------------------ world
@dataclass
class World:
    tenant_id: uuid.UUID
    environment_id: uuid.UUID
    service_ids: list[uuid.UUID]
    behaviour_id: uuid.UUID
    readers: list[str]
    connectors: list[tuple[str, str, uuid.UUID]]  # (subject, connector_id, service_id)
    incidents: list[str] = field(default_factory=list)


def seed_world(admin_url: str, *, readers: int, services: int) -> World:
    """Create one isolated load tenant. Runs as the schema owner (tenant onboarding is an
    administrative operation); every measured request then runs as the application role."""
    engine = create_app_engine(admin_url)
    factory = sessionmaker(engine, expire_on_commit=False, autoflush=False)
    slug = f"load-{uuid.uuid4().hex[:10]}"
    with factory() as session, session.begin():
        tenant = Tenant(id=uuid.uuid4(), slug=slug, display_name=slug)
        session.add(tenant)
        session.flush()
        bind_tenant(session, tenant.id)
        environment = Environment(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="production",
            display_name="Production",
            is_production=True,
        )
        session.add(environment)
        service_rows = [
            Service(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                name=f"svc-{index:03d}",
                display_name=f"svc-{index:03d}",
                owner_team="load",
                namespaces=["load"],
            )
            for index in range(services)
        ]
        session.add_all(service_rows)
        behaviour = BehaviourVersion(
            id=uuid.uuid4(),
            label=f"load-{uuid.uuid4().hex[:8]}",
            code_version="load",
            prompt_set_version=PROMPT_SET_VERSION,
            retriever_config_version="none",
            policy_version="none",
            tool_registry_version=CATALOGUE_VERSION,
            fingerprint=uuid.uuid4().hex,
        )
        session.add(behaviour)
        session.flush()
        for definition in session.scalars(sa.select(ToolDefinition)):
            session.add(
                TenantToolGrant(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    tool_definition_id=definition.id,
                    environment_id=environment.id,
                    is_enabled=True,
                )
            )
        roles = {role.key: role.id for role in session.scalars(sa.select(Role))}

        def principal(subject: str, *role_keys: str) -> None:
            user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                external_idp_subject=subject,
                email=f"{subject}@example.invalid",
                display_name=subject,
                status=UserStatus.ACTIVE,
            )
            session.add(user)
            session.flush()
            for key in role_keys:
                session.add(
                    UserRoleAssignment(
                        id=uuid.uuid4(),
                        tenant_id=tenant.id,
                        user_id=user.id,
                        role_id=roles[key],
                        environment_id=None,
                    )
                )

        reader_subjects = [f"reader-{n:04d}" for n in range(readers)]
        for subject in reader_subjects:
            principal(subject, "platform_admin", "system_operator")
        connectors: list[tuple[str, str, uuid.UUID]] = []
        for index, service in enumerate(service_rows):
            subject, connector_id = f"connector-{index:03d}", f"load-alerts-{index:03d}"
            principal(subject, "system_operator")
            session.add(
                IntegrationConnector(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    connector_id=connector_id,
                    kind=IntegrationKind.PROMETHEUS,
                    environment_id=environment.id,
                    is_enabled=False,  # inbound-only identity
                )
            )
            session.flush()
            session.add(
                ConnectorScopeBinding(
                    id=uuid.uuid4(),
                    tenant_id=tenant.id,
                    connector_id=connector_id,
                    source="simulator",
                    service_id=service.id,
                    environment_id=environment.id,
                    is_enabled=True,
                )
            )
            connectors.append((subject, connector_id, service.id))
    engine.dispose()
    return World(
        tenant_id=tenant.id,
        environment_id=environment.id,
        service_ids=[s.id for s in service_rows],
        behaviour_id=behaviour.id,
        readers=reader_subjects,
        connectors=connectors,
    )


# ------------------------------------------------------------------------ requests
class Tokens:
    """Short-lived HS256 development tokens (the server runs the development verifier)."""

    def __init__(self, secret: str, world: World) -> None:
        self.secret, self.world = secret, world
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def _mint(self, subject: str, **extra: str) -> str:
        now = int(time.time())
        claims = {
            "sub": subject,
            "tenant_id": str(self.world.tenant_id),
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 900,
            **extra,
        }
        return jwt.encode(claims, self.secret, algorithm="HS256")

    def get(self, subject: str, **extra: str) -> str:
        key = subject
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[0] > time.time() + 60:
                return cached[1]
            token = self._mint(subject, **extra)
            self._cache[key] = (time.time() + 900, token)
            return token


@dataclass
class Sample:
    op: str
    status: int
    seconds: float
    ok: bool


def _alert(fingerprint: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "schema_version": 1,
        "source_event_id": f"load-{uuid.uuid4().hex}",
        "fingerprint": fingerprint,
        "severity": "high",
        "state": "firing",
        "category": "latency",
        "title": "Synthetic load alert: p95 latency above objective",
        "started_at": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "observed_at": now.isoformat().replace("+00:00", "Z"),
    }


class Driver:
    """One httpx client per worker thread; every call is timed and classified."""

    def __init__(self, base: str, tokens: Tokens, world: World, timeout: float) -> None:
        self.base, self.tokens, self.world, self.timeout = base, tokens, world, timeout
        self._local = threading.local()

    def client(self) -> httpx.Client:
        client = getattr(self._local, "client", None)
        if client is None:
            client = httpx.Client(base_url=self.base, timeout=self.timeout)
            self._local.client = client
        return client

    def call(self, op: str, method: str, path: str, expected: set[int], **kwargs: Any) -> Sample:
        started = time.perf_counter()
        try:
            response = self.client().request(method, path, **kwargs)
            status = response.status_code
            if op == "incidents.list" and status == 200:
                for item in response.json().get("items", [])[:20]:
                    if len(self.world.incidents) < 500:
                        self.world.incidents.append(item["id"])
        except httpx.HTTPError:
            status = 0
        elapsed = time.perf_counter() - started
        return Sample(op, status, elapsed, status in expected)

    def reader(self) -> dict[str, str]:
        subject = random.choice(self.world.readers)
        return {"Authorization": f"Bearer {self.tokens.get(subject)}"}

    # --- the flows (15.1 load targets 1-9)
    def op_livez(self) -> Sample:
        return self.call("livez", "GET", "/livez", {200})

    def op_readyz(self) -> Sample:
        return self.call("readyz", "GET", "/readyz", {200})

    def op_list(self) -> Sample:
        return self.call(
            "incidents.list", "GET", "/api/v1/incidents?limit=50", {200}, headers=self.reader()
        )

    def _incident(self) -> str | None:
        return random.choice(self.world.incidents) if self.world.incidents else None

    def op_detail(self) -> Sample:
        incident = self._incident()
        if incident is None:
            return self.op_list()
        return self.call(
            "incidents.detail", "GET", f"/api/v1/incidents/{incident}", {200}, headers=self.reader()
        )

    def op_timeline(self) -> Sample:
        incident = self._incident()
        if incident is None:
            return self.op_list()
        sub = random.choice(("timeline", "evidence", "hypotheses", "actions"))
        return self.call(
            f"incidents.{sub}",
            "GET",
            f"/api/v1/incidents/{incident}/{sub}",
            {200},
            headers=self.reader(),
        )

    def op_approvals(self) -> Sample:
        return self.call(
            "approvals.pending", "GET", "/api/v1/approvals/pending", {200}, headers=self.reader()
        )

    def op_evaluation(self) -> Sample:
        return self.call(
            "evaluation.suite_runs",
            "GET",
            "/api/v1/evaluation/suite-runs",
            {200},
            headers=self.reader(),
        )

    def op_admin(self) -> Sample:
        return self.call("admin.tools", "GET", "/api/v1/admin/tools", {200}, headers=self.reader())

    def op_ingest(self, fingerprint: str | None = None, connector: int | None = None) -> Sample:
        subject, connector_id, service_id = (
            self.world.connectors[connector % len(self.world.connectors)]
            if connector is not None
            else random.choice(self.world.connectors)
        )
        token = self.tokens.get(
            subject,
            connector_id=connector_id,
            source="simulator",
            service_id=str(service_id),
            environment_id=str(self.world.environment_id),
        )
        return self.call(
            "ingest.alert",
            "POST",
            "/api/v1/ingest/alerts",
            {200},
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": f"load-{uuid.uuid4().hex}",
            },
            json=_alert(fingerprint or f"fp-{random.randrange(8)}"),
        )


READ_MIX: tuple[tuple[str, int], ...] = (
    ("op_list", 30),
    ("op_detail", 20),
    ("op_timeline", 20),
    ("op_approvals", 10),
    ("op_evaluation", 5),
    ("op_admin", 5),
    ("op_readyz", 5),
    ("op_livez", 5),
)
MIXED: tuple[tuple[str, int], ...] = (*READ_MIX, ("op_ingest", 20))


def _pick(mix: tuple[tuple[str, int], ...]) -> str:
    names, weights = zip(*mix, strict=True)
    return random.choices(names, weights=weights)[0]


# ------------------------------------------------------------------------ sampling
class Sampler:
    """Periodic server-side resource samples: container CPU/memory, process threads and
    fds, database connections by role and state. Uses existing instrumentation only."""

    def __init__(self, admin_url: str, container: str | None, interval: float) -> None:
        self.engine = create_app_engine(admin_url, pool_size=1, max_overflow=0)
        self.container, self.interval = container, interval
        self.samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _docker(self) -> dict[str, Any]:
        if not self.container:
            return {}
        out: dict[str, Any] = {}
        stats = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}",
                self.container,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if stats.returncode == 0 and "|" in stats.stdout:
            cpu, mem, pids = stats.stdout.strip().split("|")
            out["cpu_percent"] = float(cpu.rstrip("%") or 0)
            out["memory"] = mem.split("/")[0].strip()
            out["pids"] = int(pids or 0)
        proc = subprocess.run(
            [
                "docker",
                "exec",
                self.container,
                "sh",
                "-c",
                "grep -E '^(VmRSS|Threads)' /proc/1/status; ls /proc/1/fd | wc -l",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith("VmRSS"):
                    out["rss_kib"] = int(re.findall(r"\d+", line)[0])
                elif line.startswith("Threads"):
                    out["threads"] = int(re.findall(r"\d+", line)[0])
                elif line.strip().isdigit():
                    out["open_fds"] = int(line.strip())
        return out

    def _database(self) -> dict[str, Any]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                sa.text(
                    "SELECT usename, coalesce(state, 'none'), count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() GROUP BY 1, 2"
                )
            ).all()
        return {f"{user}:{state}": int(count) for user, state, count in rows}

    def sample(self, tag: str) -> dict[str, Any]:
        record = {"t": time.time(), "tag": tag, **self._docker(), "db": self._database()}
        self.samples.append(record)
        return record

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.sample("periodic")
            except Exception as exc:  # sampling never fails the run
                self.samples.append({"t": time.time(), "tag": "error", "error": type(exc).__name__})

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=30)
        self.engine.dispose()


# ------------------------------------------------------------------------ execution
def summarise(samples: list[Sample], wall: float) -> dict[str, Any]:
    def pct(values: list[float], q: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
        return round(ordered[index] * 1000, 2)

    latencies = [s.seconds for s in samples]
    errors = [s for s in samples if not s.ok]
    per_op: dict[str, dict[str, Any]] = {}
    for op in sorted({s.op for s in samples}):
        subset = [s for s in samples if s.op == op]
        values = [s.seconds for s in subset]
        per_op[op] = {
            "count": len(subset),
            "errors": sum(1 for s in subset if not s.ok),
            "p50_ms": pct(values, 0.50),
            "p95_ms": pct(values, 0.95),
            "p99_ms": pct(values, 0.99),
        }
    statuses: dict[str, int] = {}
    for s in samples:
        statuses[str(s.status)] = statuses.get(str(s.status), 0) + 1
    return {
        "requests": len(samples),
        "wall_seconds": round(wall, 2),
        "throughput_rps": round(len(samples) / wall, 2) if wall else None,
        "error_rate": round(len(errors) / len(samples), 5) if samples else None,
        "statuses": statuses,
        "p50_ms": pct(latencies, 0.50),
        "p95_ms": pct(latencies, 0.95),
        "p99_ms": pct(latencies, 0.99),
        "max_ms": round(max(latencies) * 1000, 2) if latencies else None,
        "mean_ms": round(statistics.fmean(latencies) * 1000, 2) if latencies else None,
        "per_operation": per_op,
    }


def closed_loop(
    driver: Driver, mix: tuple[tuple[str, int], ...], concurrency: int, seconds: float
) -> dict[str, Any]:
    """``concurrency`` workers issue requests back to back: measures capacity."""
    deadline = time.monotonic() + seconds
    lock = threading.Lock()
    collected: list[Sample] = []

    def worker() -> None:
        local: list[Sample] = []
        while time.monotonic() < deadline:
            local.append(getattr(driver, _pick(mix))())
        with lock:
            collected.extend(local)

    started = time.monotonic()
    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return {"concurrency": concurrency, **summarise(collected, time.monotonic() - started)}


def open_loop(
    driver: Driver, mix: tuple[tuple[str, int], ...], rate: float, seconds: float, workers: int
) -> dict[str, Any]:
    """Requests are *scheduled* at ``rate``/s regardless of how fast earlier ones finish, so
    queueing shows up as latency (no coordinated omission). A request that cannot start
    within one second of its slot is counted as dropped."""
    collected: list[Sample] = []
    dropped = 0
    lock = threading.Lock()
    started = time.monotonic()
    total = int(rate * seconds)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        for index in range(total):
            slot = started + index / rate
            delay = slot - time.monotonic()
            if delay > 0:
                time.sleep(delay)

            def task(slot: float = slot) -> Sample | None:
                if time.monotonic() - slot > 1.0:
                    return None
                sample = getattr(driver, _pick(mix))()
                # latency measured from the scheduled slot: queueing delay included
                sample.seconds = time.monotonic() - slot
                return sample

            futures.append(pool.submit(task))
        for future in futures:
            result = future.result()
            with lock:
                if result is None:
                    dropped += 1
                else:
                    collected.append(result)
    summary = summarise(collected, time.monotonic() - started)
    return {"target_rps": rate, "scheduled": total, "dropped": dropped, **summary}


def capacity(driver: Driver, seconds: float, levels: list[int]) -> dict[str, Any]:
    """Doubling closed-loop concurrency until throughput stops growing (<10 %) or the error
    rate exceeds 1 % or p95 exceeds 1 s. Reports the observed saturation point."""
    steps: list[dict[str, Any]] = []
    saturation: dict[str, Any] | None = None
    for level in levels:
        result = closed_loop(driver, READ_MIX, level, seconds)
        steps.append(result)
        print(
            f"  capacity c={level:3d}: {result['throughput_rps']:8.1f} rps "
            f"p95={result['p95_ms']} ms err={result['error_rate']}",
            flush=True,
        )
        if len(steps) >= 2 and saturation is None:
            previous = steps[-2]
            gain = (result["throughput_rps"] - previous["throughput_rps"]) / max(
                previous["throughput_rps"], 1e-9
            )
            if gain < 0.10 or result["error_rate"] > 0.01 or (result["p95_ms"] or 0) > 1000:
                saturation = {
                    "at_concurrency": level,
                    "previous_concurrency": previous["concurrency"],
                    "throughput_gain": round(gain, 3),
                    "reason": "throughput_plateau"
                    if gain < 0.10
                    else ("errors" if result["error_rate"] > 0.01 else "latency"),
                }
                if level >= 2 * previous["concurrency"] and len(steps) >= 3:
                    break
    best = max(steps, key=lambda s: s["throughput_rps"])
    safe = [s for s in steps if s["error_rate"] == 0 and (s["p95_ms"] or 0) <= 250]
    return {
        "steps": steps,
        "observed_saturation": saturation,
        "max_observed_throughput_rps": best["throughput_rps"],
        "max_throughput_concurrency": best["concurrency"],
        "safe_tested_region": {
            "max_concurrency": max((s["concurrency"] for s in safe), default=None),
            "criteria": "zero errors and p95 <= 250 ms",
        },
    }


def investigations(
    app_url: str,
    world: World,
    *,
    count: int,
    workers: int,
    fingerprint_prefix: str,
    driver: Driver,
) -> dict[str, Any]:
    """Ingest ``count`` alerts over HTTP, one per service (alerts of one service and category
    correlate into one incident, so distinct services give distinct incidents), then drive
    every resulting dispatch concurrently through the real dispatcher and kernel."""
    from asic.domain.clock import SystemClock
    from asic.ingestion.dispatch import InvestigationDispatcher
    from asic.llm.deterministic import DeterministicModelProvider
    from asic.orchestration.service import InvestigationService
    from asic.simulators.provider import SimulatorProvider
    from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, scenario

    ingest_samples: list[Sample] = []
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(count, 16)) as pool:
        for sample in pool.map(
            lambda n: driver.op_ingest(f"{fingerprint_prefix}-{n}", connector=n), range(count)
        ):
            ingest_samples.append(sample)
    ingest_summary = summarise(ingest_samples, time.monotonic() - started)

    engine = create_app_engine(app_url, pool_size=workers, max_overflow=workers)
    factory = sessionmaker(engine, expire_on_commit=False, autoflush=False)
    with factory() as session:
        bind_tenant(session, world.tenant_id)
        pending = list(
            session.scalars(
                sa.select(InvestigationDispatch.id).where(
                    InvestigationDispatch.tenant_id == world.tenant_id,
                    InvestigationDispatch.status == "pending",
                )
            )
        )
    case = scenario(PRIMARY_SCENARIO_ID)
    clock = SystemClock()
    dispatcher = InvestigationDispatcher(
        factory,
        InvestigationService(
            session_factory=factory,
            providers=[SimulatorProvider(case, clock=clock)],
            model=DeterministicModelProvider(case),
            clock=clock,
            budget_policy=case.budget,
        ),
    )
    context = TenantContext(world.tenant_id)
    durations: list[float] = []
    outcomes: dict[str, int] = {}
    lock = threading.Lock()

    def run(request_id: uuid.UUID) -> None:
        begun = time.perf_counter()
        try:
            status = dispatcher.dispatch(context, request_id, world.behaviour_id).status
        except Exception as exc:
            status = f"error:{type(exc).__name__}"
        elapsed = time.perf_counter() - begun
        with lock:
            durations.append(elapsed)
            outcomes[status] = outcomes.get(status, 0) + 1

    begun = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run, pending))
    wall = time.monotonic() - begun
    engine.dispose()
    ordered = sorted(durations)

    def pct(q: float) -> float | None:
        return round(ordered[round(q * (len(ordered) - 1))], 3) if ordered else None

    return {
        "ingestion": ingest_summary,
        "dispatched": len(pending),
        "workers": workers,
        "outcomes": outcomes,
        "wall_seconds": round(wall, 2),
        "runs_per_minute": round(len(pending) / wall * 60, 1) if wall else None,
        "run_seconds_p50": pct(0.5),
        "run_seconds_p95": pct(0.95),
        "run_seconds_p99": pct(0.99),
        "run_seconds_max": round(max(ordered), 3) if ordered else None,
    }


def environment(admin_url: str, api_container: str | None) -> dict[str, Any]:
    engine = create_app_engine(admin_url, pool_size=1, max_overflow=0)
    with engine.connect() as connection:
        postgres = connection.scalar(sa.text("SELECT version()"))
        max_connections = connection.scalar(sa.text("SHOW max_connections"))
    engine.dispose()
    memory = None
    if sys.platform == "win32":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("load", ctypes.c_ulong),
                ("total", ctypes.c_ulonglong),
                ("avail", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong),
                ("avail_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("avail_virtual", ctypes.c_ulonglong),
                ("extended", ctypes.c_ulonglong),
            ]

        status = Status()
        status.length = ctypes.sizeof(Status)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        memory = round(status.total / 2**30, 1)
    docker = subprocess.run(
        ["docker", "info", "--format", "{{.NCPU}} CPUs, {{.MemTotal}} bytes, {{.ServerVersion}}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    ).stdout.strip()
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=REPO, check=False
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=REPO, check=False
        ).stdout.strip()
    )
    return {
        "label": LABEL,
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "commit": commit,
        "working_tree_dirty": dirty,
        "host": {
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
            "memory_gib": memory,
            "python": platform.python_version(),
        },
        "docker": docker,
        "postgres": postgres,
        "postgres_max_connections": max_connections,
        "api_container": api_container,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--app-url", required=True, help="application-role URL (dispatcher)")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--jwt-secret", required=True)
    parser.add_argument("--api-container", default=None)
    parser.add_argument(
        "--profile",
        default="smoke",
        choices=("smoke", "capacity", "steady", "ingest", "burst", "concurrency", "soak", "all"),
    )
    parser.add_argument("--readers", type=int, default=400)
    parser.add_argument("--services", type=int, default=40)
    parser.add_argument("--step-seconds", type=float, default=20)
    parser.add_argument("--steady-rps", type=float, default=40)
    parser.add_argument("--steady-seconds", type=float, default=120)
    parser.add_argument("--ingest-rps", type=float, default=50)
    parser.add_argument("--ingest-seconds", type=float, default=60)
    parser.add_argument("--burst-concurrency", type=int, default=96)
    parser.add_argument("--incidents", type=int, default=60)
    parser.add_argument("--investigation-workers", type=int, default=8)
    parser.add_argument("--soak-seconds", type=float, default=600)
    parser.add_argument("--soak-rps", type=float, default=20)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--seed", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    random.seed(args.seed)

    # The in-process kernel logs every tool call; keep the harness output readable.
    logging.getLogger("asic").setLevel(logging.WARNING)
    world = seed_world(args.admin_url, readers=args.readers, services=args.services)
    driver = Driver(args.api_url, Tokens(args.jwt_secret, world), world, args.timeout)
    sampler = Sampler(args.admin_url, args.api_container, interval=5)
    results: dict[str, Any] = {
        "environment": environment(args.admin_url, args.api_container),
        "parameters": {k: str(v) for k, v in vars(args).items() if k not in ("jwt_secret",)},
        "profiles": {},
    }
    profiles = (
        ["smoke", "capacity", "steady", "ingest", "burst", "concurrency", "soak"]
        if args.profile == "all"
        else [args.profile]
    )
    sampler.sample("before")
    sampler.start()
    failed = False
    try:
        # Warm-up: a few incidents so reads have realistic rows to return.
        for n in range(20):
            driver.op_ingest(f"warmup-{n}")
        driver.op_list()
        for name in profiles:
            print(f"== profile {name}", flush=True)
            before = sampler.sample(f"{name}:start")
            if name == "smoke":
                smoke_started = time.monotonic()
                smoke_samples = [getattr(driver, op)() for op, _ in (*MIXED,) for _ in range(5)]
                result: dict[str, Any] = summarise(smoke_samples, time.monotonic() - smoke_started)
                bad = [(s.op, s.status) for s in smoke_samples if not s.ok]
                result["unexpected"] = bad
                failed |= bool(bad)
            elif name == "capacity":
                result = capacity(driver, args.step_seconds, [1, 2, 4, 8, 16, 32, 64, 128])
            elif name == "steady":
                result = open_loop(driver, MIXED, args.steady_rps, args.steady_seconds, workers=64)
            elif name == "ingest":
                result = open_loop(
                    driver, (("op_ingest", 1),), args.ingest_rps, args.ingest_seconds, workers=64
                )
            elif name == "burst":
                time.sleep(5)
                result = closed_loop(driver, MIXED, args.burst_concurrency, 15)
                result["recovery"] = closed_loop(driver, READ_MIX, 4, 10)
            elif name == "concurrency":
                result = investigations(
                    args.app_url,
                    world,
                    count=args.incidents,
                    workers=args.investigation_workers,
                    fingerprint_prefix=f"distinct-{uuid.uuid4().hex[:6]}",
                    driver=driver,
                )
            else:  # soak
                result = open_loop(driver, MIXED, args.soak_rps, args.soak_seconds, workers=32)
            after = sampler.sample(f"{name}:end")
            result["resources"] = {"start": before, "end": after}
            results["profiles"][name] = result
            print(json.dumps({k: v for k, v in result.items() if k != "steps"}, default=str)[:1500])
    finally:
        sampler.stop()
        results["samples"] = sampler.samples
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2, default=str), "utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
