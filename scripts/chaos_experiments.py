"""Phase 15 chaos experiments on the disposable kind cluster (``deployment_smoke.py --chaos``).

Every experiment is declared in ``EXPERIMENTS`` *before* anything runs - hypothesis, invariant,
fault, expected observable signal, recovery condition, maximum duration and cleanup - and the
declaration is printed before its fault is injected. Cleanup always runs, also after a failure;
the smoke then destroys the whole cluster regardless.

Faults are injected only into this disposable cluster: pod deletion, a Postgres process stop
(the container restarts with its data intact), revoking the runtime role's LOGIN, pointing the
OTLP exporter at a black hole, and holding a migration pod in termination. Measurements are
sampled from inside the pods at a fixed interval; outage windows are therefore approximate to
that interval and are LOCAL measurements on a single-node kind cluster, not production figures.

The model provider is in-process and deterministic in this deployment, so a provider outage has
no cluster-level fault to inject; it is exercised at process level by
``tests/resilience/test_model_provider_failure.py``.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, fields
from typing import Any

import yaml
from deploy_release import (
    MIGRATION_JOB,
    DeploymentError,
    Kubectl,
    post_rollout_smoke,
    ready_endpoints,
    run_deployment,
)

PYTHON = "/usr/local/bin/python"
NODE = "/nodejs/bin/node"
PGDATA = "/var/lib/postgresql/data/pgdata"
API = "app.kubernetes.io/name=asic-api"
FRONTEND = "app.kubernetes.io/name=asic-frontend"
POSTGRES = "app.kubernetes.io/name=postgres"
MIGRATION_PODS = f"job-name={MIGRATION_JOB}"
SAMPLE_INTERVAL = 0.25
#: Black-hole OTLP endpoint: private, outside every kind CIDR, and denied by API egress policy.
OTLP_BLACK_HOLE = "http://10.255.255.1:4318"


class ChaosFailed(RuntimeError):
    """An experiment's invariant, expected signal or recovery condition did not hold."""


@dataclass(frozen=True)
class Experiment:
    name: str
    hypothesis: str
    invariant: str
    fault: str
    expected_signal: str
    recovery: str
    max_seconds: int
    cleanup: str


EXPERIMENTS: tuple[Experiment, ...] = (
    Experiment(
        name="api_pod_kill",
        hypothesis="The Deployment replaces a force-killed API pod and the Service converges "
        "on the replacement without operator action.",
        invariant="The frontend stays live and is not restarted; network policy applies to the "
        "replacement pod from its first second (no internet egress while it is starting).",
        fault="Force-delete the only API pod (grace period 0).",
        expected_signal="API unreachable through its Service for a bounded window (one "
        "replica: an outage is expected and measured), then reachable again.",
        recovery="A new API pod is Ready, the Service has a ready endpoint and the "
        "post-rollout smoke passes.",
        max_seconds=240,
        cleanup="None needed beyond recovery; the Deployment owns the replacement.",
    ),
    Experiment(
        name="frontend_pod_kill",
        hypothesis="A force-killed frontend pod is replaced; the API is unaffected.",
        invariant="API liveness and readiness stay 200 throughout; the API is not restarted.",
        fault="Force-delete the only frontend pod (grace period 0).",
        expected_signal="Frontend Service loses and regains its ready endpoint.",
        recovery="A new frontend pod is Ready and the post-rollout smoke passes.",
        max_seconds=240,
        cleanup="None needed beyond recovery.",
    ),
    Experiment(
        name="postgres_restart",
        hypothesis="A Postgres restart makes the API unready, not dead: it recovers its "
        "connections by itself once the database returns, with no data loss.",
        invariant="API liveness stays 200 (no restart storm); no request ever returns 500; "
        "the schema revision survives the restart.",
        fault="pg_ctl stop -m fast inside the database container (the kubelet restarts the "
        "container; its data volume persists).",
        expected_signal="Authenticated requests return a classified 503 while the database is "
        "down. /readyz turns 503 only when the outage outlasts its 2 s readiness cache - the "
        "sustained-outage experiment covers readiness (first run: /readyz was declared here "
        "too, and a ~2 s restart was too short for it).",
        recovery="Database container restarted and Ready, API /readyz 200 on the same pod, "
        "post-rollout smoke passes.",
        max_seconds=300,
        cleanup="None needed: the kubelet restarts the container.",
    ),
    Experiment(
        name="readiness_failure_database_access_revoked",
        hypothesis="A sustained loss of database access removes the API (and the frontend "
        "that depends on it) from Service endpoints without restarting either.",
        invariant="API liveness stays 200; neither pod restarts; no request returns 500.",
        fault="ALTER ROLE asic_app NOLOGIN and terminate its sessions, held for 30 s.",
        expected_signal="API and frontend ready endpoints drop to 0; authenticated requests "
        "return 503.",
        recovery="LOGIN restored; both Services regain ready endpoints on the same pods; "
        "post-rollout smoke passes.",
        max_seconds=300,
        cleanup="Restore the role's original LOGIN attribute (also after a failure).",
    ),
    Experiment(
        name="otel_collector_unavailable",
        hypothesis="An unreachable trace collector never affects request handling: spans are "
        "exported off the request path and dropped when the exporter cannot deliver them.",
        invariant="API stays Ready and is not restarted; every probe and request is served; "
        "authenticated request latency stays bounded (p95 < 1 s).",
        fault=f"Point the OTLP exporter at a black hole ({OTLP_BLACK_HOLE}, dropped by "
        "egress policy) and roll the API.",
        expected_signal="Requests keep being served while export attempts time out in the "
        "background (exporter log lines are recorded when present).",
        recovery="Original telemetry configuration restored, API rolled back to it, "
        "post-rollout smoke passes.",
        max_seconds=420,
        cleanup="Restore the original ConfigMap values and roll the API.",
    ),
    Experiment(
        name="migration_pod_overlap",
        hypothesis="The orchestrator never creates a migration Job while a pod of a previous "
        "migration Job is still running, even after that Job object has been deleted.",
        invariant="At most one migration pod is non-terminal at any sampled instant while the "
        "orchestrator is in control; a timeout creates nothing.",
        fault="A migration pod that ignores SIGTERM (held for its termination grace period); "
        "its Job is deleted with background propagation while the pod still runs.",
        expected_signal="The orchestrator logs that it is waiting for the previous pod and "
        "creates the new Job only after it is gone; with a short pod timeout it refuses "
        "('the replacement was NOT created'). Bypassing the orchestrator shows 2 concurrent "
        "pods, proving the sampler would detect an overlap.",
        recovery="Held pods removed and a normal deployment succeeds.",
        max_seconds=900,
        cleanup="Force-delete any held migration pod and redeploy normally.",
    ),
)


@dataclass
class Context:
    kube: Kubectl
    migration: str
    application: str
    log: Callable[[str], None] = print
    notes: dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------------- helpers


def _pods(kube: Kubectl, selector: str) -> list[dict[str, Any]]:
    return json.loads(kube("get", "pods", "-l", selector, "-o", "json"))["items"]  # type: ignore[no-any-return]


def _alive(pod: dict[str, Any]) -> bool:
    return not pod["metadata"].get("deletionTimestamp") and pod["status"].get("phase") not in (
        "Succeeded",
        "Failed",
    )


def _ready(pod: dict[str, Any]) -> bool:
    return _alive(pod) and any(
        c["type"] == "Ready" and c["status"] == "True"
        for c in pod["status"].get("conditions") or []
    )


def _restarts(pod: dict[str, Any]) -> int:
    return sum(c.get("restartCount", 0) for c in pod["status"].get("containerStatuses") or [])


def _one(kube: Kubectl, selector: str) -> dict[str, Any]:
    alive = [pod for pod in _pods(kube, selector) if _alive(pod)]
    if len(alive) != 1:
        raise ChaosFailed(f"expected exactly one live pod for {selector}, found {len(alive)}")
    return alive[0]


def wait_for(
    predicate: Callable[[], bool], *, timeout: float, what: str, interval: float = 1.0
) -> float:
    """Poll ``predicate`` until true; return the seconds it took or raise ChaosFailed."""
    started = time.monotonic()
    while True:
        try:
            if predicate():
                return time.monotonic() - started
        except DeploymentError:
            pass  # a transient API-server error is retried within the deadline
        if time.monotonic() - started >= timeout:
            raise ChaosFailed(f"{what} not reached within {timeout:.0f}s")
        time.sleep(interval)


def _psql(kube: Kubectl, sql: str) -> str:
    return kube(
        "exec",
        "deploy/postgres",
        "--",
        "psql",
        "-U",
        "asic_owner",
        "-d",
        "asic",
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    ).strip()


# In-pod samplers. Each prints one JSON array of rows when it finishes. They stop early once a
# watched column has gone bad and then stayed good for ``settle`` seconds.
_API_SAMPLER = """
import json, os, time, urllib.error, urllib.request, uuid
import jwt
def status(url, headers=None):
    begun = time.monotonic()
    try:
        code = urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=2).status
    except urllib.error.HTTPError as error:
        code = error.code
    except Exception:
        code = 0
    return code, round((time.monotonic() - begun) * 1000, 1)
now = int(time.time())
# A real, seeded principal: an unknown one would draw 401s and trip the auth-failure limiter.
token = jwt.encode({"sub": "chaos-probe", "tenant_id": "TENANT",
    "iss": os.environ["ASIC_JWT_ISSUER"], "aud": os.environ["ASIC_JWT_AUDIENCE"],
    "iat": now, "exp": now + 900}, os.environ["ASIC_JWT_SECRET"], algorithm="HS256")
auth = {"Authorization": "Bearer " + token}
base = "http://127.0.0.1:8000"
rows, t0, bad_seen, good_since = [], time.monotonic(), False, None
while time.monotonic() - t0 < SECONDS:
    live, _ = status(base + "/livez")
    ready, _ = status(base + "/readyz")
    # Every third row only: well under the 120/min per-principal rate limit (-1 = skipped).
    auth_code, auth_ms = status(base + "/api/v1/incidents", auth) if len(rows) % 3 == 0 else (-1, 0)
    t = round(time.monotonic() - t0, 2)
    rows.append([t, live, ready, auth_code, auth_ms])
    if (live, ready) != (200, 200) or auth_code not in (200, -1):
        bad_seen, good_since = True, None
    elif bad_seen and good_since is None:
        good_since = t
    if bad_seen and good_since is not None and t - good_since >= SETTLE:
        break
    time.sleep(INTERVAL)
print(json.dumps(rows))
"""

_FRONTEND_SAMPLER = """
(async () => {
  const api = new URL('/livez', process.env.ASIC_API_BASE_URL).toString();
  const status = async (url) => {
    try { return (await fetch(url, {signal: AbortSignal.timeout(2000)})).status; }
    catch (e) { return 0; }
  };
  const rows = []; const t0 = Date.now(); let badSeen = false; let goodSince = null;
  while ((Date.now() - t0) / 1000 < SECONDS) {
    const live = await status('http://127.0.0.1:3000/livez');
    const viaService = await status(api);
    const t = (Date.now() - t0) / 1000;
    rows.push([t, live, viaService]);
    if (viaService !== 200) { badSeen = true; goodSince = null; }
    else if (badSeen && goodSince === null) { goodSince = t; }
    if (badSeen && goodSince !== null && t - goodSince >= SETTLE) break;
    await new Promise((r) => setTimeout(r, INTERVAL * 1000));
  }
  console.log(JSON.stringify(rows));
})();
"""


def _script(template: str, *, seconds: float, settle: float, tenant: str = "") -> str:
    return (
        template.replace("TENANT", tenant)
        .replace("SECONDS", str(seconds))
        .replace("SETTLE", str(settle))
        .replace("INTERVAL", str(SAMPLE_INTERVAL))
    )


class Sampler:
    """Runs an in-pod sampler in the background (so a fault can be injected meanwhile)."""

    def __init__(self, kube: Kubectl, pod: str, command: list[str], seconds: float) -> None:
        self._output: list[str] = []
        self._error: list[BaseException] = []

        def run() -> None:
            try:
                self._output.append(
                    kube("exec", pod, "--", *command, timeout=seconds + 90)  # type: ignore[arg-type]
                )
            except BaseException as error:  # reported by rows()
                self._error.append(error)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def rows(self) -> list[list[float]]:
        self._thread.join()
        if self._error:
            raise ChaosFailed(f"sampler failed: {self._error[0]}")
        return json.loads(self._output[0].strip().splitlines()[-1])  # type: ignore[no-any-return]


#: Authenticated-probe codes that mean "served normally" (-1: this row skipped the probe).
AUTH_OK = (200, -1)


def _probe_tenant(ctx: Context) -> str:
    """Seed (once) a tenant with one ``system_operator`` principal for the in-pod probe."""
    if "probe_tenant" not in ctx.notes:
        tenant = _psql(
            ctx.kube,
            "INSERT INTO tenant (slug, display_name, status) "
            "VALUES ('kind-chaos', 'Kind chaos probe', 'active') RETURNING id",
        ).splitlines()[0]
        _psql(
            ctx.kube,
            f"SELECT set_config('app.tenant_id', '{tenant}', true); "
            "INSERT INTO app_user (tenant_id, external_idp_subject, email, display_name, status) "
            f"VALUES ('{tenant}', 'chaos-probe', 'chaos-probe@example.invalid', 'chaos probe', "
            "'active'); "
            "INSERT INTO user_role_assignment (tenant_id, user_id, role_id, environment_id) "
            f"SELECT '{tenant}', u.id, r.id, NULL FROM app_user u, role r "
            "WHERE u.external_idp_subject = 'chaos-probe' AND r.key = 'system_operator'",
        )
        ctx.notes["probe_tenant"] = tenant
    return str(ctx.notes["probe_tenant"])


def api_sampler(ctx: Context, pod: str, *, seconds: float, settle: float = 6) -> Sampler:
    code = _script(_API_SAMPLER, seconds=seconds, settle=settle, tenant=_probe_tenant(ctx))
    return Sampler(ctx.kube, f"pod/{pod}", [PYTHON, "-c", code], seconds)


def frontend_sampler(kube: Kubectl, pod: str, *, seconds: float, settle: float = 6) -> Sampler:
    code = _script(_FRONTEND_SAMPLER, seconds=seconds, settle=settle)
    return Sampler(kube, f"pod/{pod}", [NODE, "-e", code], seconds)


def outage(
    rows: Iterable[list[float]], column: int, good: Iterable[int] = (200,)
) -> dict[str, Any]:
    """Summarise the non-good windows of one sampled column (times in sampler seconds)."""
    accepted = set(good)
    rows = list(rows)
    windows: list[tuple[float, float]] = []
    start: float | None = None
    for row in rows:
        if row[column] not in accepted:
            if start is None:
                start = row[0]
        elif start is not None:
            windows.append((start, row[0]))
            start = None
    if start is not None:
        windows.append((start, rows[-1][0]))
    codes = sorted({int(row[column]) for row in rows})
    return {
        "samples": len(rows),
        "bad_samples": sum(1 for row in rows if row[column] not in accepted),
        "windows": len(windows),
        "longest_window_seconds": round(max((b - a for a, b in windows), default=0.0), 2),
        "recovered": bool(rows) and rows[-1][column] in accepted,
        "codes": codes,
    }


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))]


def _egress_attempts(kube: Kubectl, pod: str, seconds: float) -> dict[str, int]:
    """Repeated connection attempts to the internet from ``pod``; none may connect."""
    code = (
        "import json, socket, time\n"
        "result = {'connected': 0, 'denied': 0, 'error': 0}\n"
        f"end = time.monotonic() + {seconds}\n"
        "while time.monotonic() < end:\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 443), timeout=1).close(); result['connected'] += 1\n"
        "    except TimeoutError:\n"
        "        result['denied'] += 1\n"
        "    except OSError:\n"
        "        result['error'] += 1\n"
        "print(json.dumps(result))\n"
    )
    out = kube("exec", f"pod/{pod}", "--", PYTHON, "-c", code, timeout=seconds + 60)
    return json.loads(out.strip().splitlines()[-1])  # type: ignore[no-any-return]


def _no_500(rows: list[list[float]], column: int, what: str) -> None:
    if any(int(row[column]) >= 500 and int(row[column]) != 503 for row in rows):
        raise ChaosFailed(f"{what}: a request returned a 5xx other than 503: {rows}")


# ------------------------------------------------------------------------- experiments


def api_pod_kill(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    victim = _one(kube, API)["metadata"]["name"]
    frontend = _one(kube, FRONTEND)
    frontend_name, frontend_restarts = frontend["metadata"]["name"], _restarts(frontend)
    sampler = frontend_sampler(kube, frontend_name, seconds=150)
    time.sleep(4)
    started = time.monotonic()
    kube("delete", "pod", victim, "--grace-period=0", "--force", "--wait=false")

    def replacement_running() -> bool:
        pods = [p for p in _pods(kube, API) if p["metadata"]["name"] != victim and _alive(p)]
        return bool(pods) and pods[0]["status"].get("phase") == "Running"

    wait_for(replacement_running, timeout=120, what="replacement API pod running", interval=0.5)
    replacement = next(
        p for p in _pods(kube, API) if p["metadata"]["name"] != victim and _alive(p)
    )["metadata"]["name"]
    # Cilium must enforce egress policy on the new endpoint from its first seconds.
    egress = _egress_attempts(kube, replacement, seconds=8)
    if egress["connected"]:
        raise ChaosFailed(f"replacement API pod reached the internet while starting: {egress}")
    wait_for(
        lambda: ready_endpoints(kube, "asic-api") >= 1 and _ready(_one(kube, API)),
        timeout=150,
        what="API ready endpoint",
    )
    ready_after = time.monotonic() - started
    rows = sampler.rows()
    frontend_live = outage(rows, 1)
    api_service = outage(rows, 2)
    if frontend_live["bad_samples"]:
        raise ChaosFailed(f"frontend liveness failed while the API pod was replaced: {rows}")
    if not api_service["bad_samples"] or not api_service["recovered"]:
        raise ChaosFailed(f"API outage not observed or not recovered via the Service: {rows}")
    post_rollout_smoke(kube, log=ctx.log)
    after = _one(kube, FRONTEND)
    if after["metadata"]["name"] != frontend_name or _restarts(after) != frontend_restarts:
        raise ChaosFailed("the frontend was restarted because the API pod was killed")
    return {
        "replica_count": 1,
        "kill_to_ready_endpoint_seconds": round(ready_after, 1),
        "api_via_service": api_service,
        "frontend_liveness": frontend_live,
        "replacement_egress_attempts": egress,
        "frontend_restarted": False,
    }


def frontend_pod_kill(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    victim = _one(kube, FRONTEND)["metadata"]["name"]
    api = _one(kube, API)
    api_name, api_restarts = api["metadata"]["name"], _restarts(api)
    sampler = api_sampler(ctx, api_name, seconds=45, settle=0)
    time.sleep(3)
    kube("delete", "pod", victim, "--grace-period=0", "--force", "--wait=false")
    ready_after = wait_for(
        lambda: (
            ready_endpoints(kube, "asic-frontend") >= 1
            and _one(kube, FRONTEND)["metadata"]["name"] != victim
            and _ready(_one(kube, FRONTEND))
        ),
        timeout=150,
        what="frontend ready endpoint",
    )
    rows = sampler.rows()
    if (
        outage(rows, 1)["bad_samples"]
        or outage(rows, 2)["bad_samples"]
        or outage(rows, 3, good=AUTH_OK)["bad_samples"]
    ):
        raise ChaosFailed(f"API health or requests changed when the frontend was killed: {rows}")
    post_rollout_smoke(kube, log=ctx.log)
    after = _one(kube, API)
    if after["metadata"]["name"] != api_name or _restarts(after) != api_restarts:
        raise ChaosFailed("the API was restarted because the frontend pod was killed")
    return {
        "seconds_to_ready_endpoint": round(ready_after, 1),
        "api_samples_all_healthy": len(rows),
    }


def postgres_restart(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    revision = _psql(kube, "SELECT version_num FROM alembic_version")
    tenants = _psql(kube, "SELECT count(*) FROM tenant")
    database = _one(kube, POSTGRES)
    database_restarts = _restarts(database)
    api = _one(kube, API)
    api_name, api_restarts = api["metadata"]["name"], _restarts(api)
    sampler = api_sampler(ctx, api_name, seconds=180)
    time.sleep(3)
    # The exec session dies with the server; its exit status is irrelevant.
    kube.probe("exec", "deploy/postgres", "--", "pg_ctl", "-D", PGDATA, "stop", "-m", "fast")
    restarted_after = wait_for(
        lambda: (
            _restarts(_one(kube, POSTGRES)) > database_restarts and _ready(_one(kube, POSTGRES))
        ),
        timeout=180,
        what="database container restarted and Ready",
    )
    rows = sampler.rows()
    live, ready, auth = outage(rows, 1), outage(rows, 2), outage(rows, 3, good=AUTH_OK)
    _no_500(rows, 3, "postgres restart")
    if live["bad_samples"]:
        raise ChaosFailed(f"API liveness failed during the database restart: {rows}")
    if 503 not in auth["codes"] or not auth["recovered"] or not ready["recovered"]:
        raise ChaosFailed(f"outage not observed as 503 by requests, or not recovered: {rows}")
    if _psql(kube, "SELECT version_num FROM alembic_version") != revision:
        raise ChaosFailed("schema revision changed across the database restart")
    if _psql(kube, "SELECT count(*) FROM tenant") != tenants:
        raise ChaosFailed("tenant rows changed across the database restart")
    after = _one(kube, API)
    if after["metadata"]["name"] != api_name or _restarts(after) != api_restarts:
        raise ChaosFailed("the API was restarted because the database restarted")
    post_rollout_smoke(kube, log=ctx.log)
    return {
        "database_back_seconds": round(restarted_after, 1),
        "api_readyz": ready,
        "readyz_observed_outage": bool(ready["bad_samples"]),
        "authenticated_requests": auth,
        "api_livez_failures": 0,
        "schema_revision_preserved": revision,
        "api_restarted": False,
    }


def _role_can_login(kube: Kubectl) -> str:
    return _psql(kube, "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'asic_app'")


def revoke_database_access(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    ctx.notes["asic_app_login"] = original = _role_can_login(kube)
    if original != "t":
        raise ChaosFailed(f"precondition: asic_app must be able to log in ({original!r})")
    api, frontend = _one(kube, API), _one(kube, FRONTEND)
    names = (api["metadata"]["name"], frontend["metadata"]["name"])
    restarts = (_restarts(api), _restarts(frontend))
    sampler = api_sampler(ctx, names[0], seconds=200)
    time.sleep(3)
    _psql(
        kube,
        "ALTER ROLE asic_app NOLOGIN; "
        "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename = 'asic_app'",
    )
    api_removed = wait_for(
        lambda: ready_endpoints(kube, "asic-api") == 0, timeout=90, what="API endpoint removal"
    )
    frontend_removed = wait_for(
        lambda: ready_endpoints(kube, "asic-frontend") == 0,
        timeout=90,
        what="frontend endpoint removal",
    )
    time.sleep(max(0.0, 30 - api_removed))
    _psql(kube, "ALTER ROLE asic_app LOGIN")
    api_back = wait_for(
        lambda: ready_endpoints(kube, "asic-api") >= 1, timeout=120, what="API endpoint return"
    )
    frontend_back = wait_for(
        lambda: ready_endpoints(kube, "asic-frontend") >= 1,
        timeout=120,
        what="frontend endpoint return",
    )
    rows = sampler.rows()
    _no_500(rows, 3, "database access revoked")
    live, ready, auth = outage(rows, 1), outage(rows, 2), outage(rows, 3, good=AUTH_OK)
    if live["bad_samples"]:
        raise ChaosFailed(f"API liveness failed while the database was unavailable: {rows}")
    if not ready["bad_samples"] or not ready["recovered"] or 503 not in auth["codes"]:
        raise ChaosFailed(f"expected 503s and a recovered /readyz: {rows}")
    now = (_one(kube, API), _one(kube, FRONTEND))
    if tuple(p["metadata"]["name"] for p in now) != names or tuple(map(_restarts, now)) != restarts:
        raise ChaosFailed("a pod was restarted or replaced during the readiness failure")
    post_rollout_smoke(kube, log=ctx.log)
    return {
        "api_endpoint_removed_after_seconds": round(api_removed, 1),
        "frontend_endpoint_removed_after_seconds": round(frontend_removed, 1),
        "api_endpoint_back_after_restore_seconds": round(api_back, 1),
        "frontend_endpoint_back_after_restore_seconds": round(frontend_back, 1),
        "api_readyz": ready,
        "authenticated_requests": auth,
        "restarts": 0,
    }


def restore_database_access(ctx: Context) -> None:
    if ctx.notes.get("asic_app_login") == "t" and _role_can_login(ctx.kube) != "t":
        _psql(ctx.kube, "ALTER ROLE asic_app LOGIN")


_TELEMETRY_KEYS = (
    "ASIC_OTEL_TRACES_EXPORTER",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "ASIC_OTLP_ALLOW_INSECURE",
)


def _roll_api(kube: Kubectl) -> None:
    kube("rollout", "restart", "deployment/asic-api")
    kube("rollout", "status", "deployment/asic-api", "--timeout=180s", timeout=240)
    wait_for(lambda: len(_pods(kube, API)) == 1, timeout=120, what="old API pod gone")


def otel_collector_unavailable(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    data = json.loads(kube("get", "configmap", "asic-runtime", "-o", "json"))["data"]
    ctx.notes["telemetry"] = {key: data.get(key) for key in _TELEMETRY_KEYS}
    patch = {
        "data": {
            "ASIC_OTEL_TRACES_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_ENDPOINT": OTLP_BLACK_HOLE,
            "ASIC_OTLP_ALLOW_INSECURE": "true",
        }
    }
    kube("patch", "configmap", "asic-runtime", "--type=merge", "-p", json.dumps(patch))
    _roll_api(kube)
    pod = _one(kube, API)
    name, restarts = pod["metadata"]["name"], _restarts(pod)
    effective = kube(
        "exec",
        f"pod/{name}",
        "--",
        PYTHON,
        "-c",
        "import os; print(os.environ['ASIC_OTEL_TRACES_EXPORTER'], os.environ['OTEL_EXPORTER_OTLP_ENDPOINT'])",
    ).split()
    if effective != ["otlp", OTLP_BLACK_HOLE]:
        raise ChaosFailed(f"the fault was not applied to the API pod: {effective}")
    # Longer than the batch schedule (5 s) plus several export timeouts (10 s each).
    rows = api_sampler(ctx, name, seconds=60, settle=0).rows()
    latencies = [row[4] for row in rows if row[3] != -1]
    if outage(rows, 1)["bad_samples"] or outage(rows, 2)["bad_samples"]:
        raise ChaosFailed(f"API health changed while the collector was unreachable: {rows}")
    if outage(rows, 3, good=AUTH_OK)["bad_samples"]:
        raise ChaosFailed(f"requests failed while the collector was unreachable: {rows}")
    p95 = percentile(latencies, 0.95)
    if p95 >= 1000:
        raise ChaosFailed(f"request latency not bounded with the collector down: p95={p95}ms")
    after = _one(kube, API)
    if after["metadata"]["name"] != name or _restarts(after) != restarts:
        raise ChaosFailed("the API restarted while the collector was unreachable")
    logs = kube("logs", f"pod/{name}", "--tail=2000")
    export_lines = sum(
        1 for line in logs.splitlines() if "export" in line.lower() and "span" in line.lower()
    )
    return {
        "exporter": "otlp",
        "endpoint": OTLP_BLACK_HOLE + " (dropped by egress policy)",
        "samples": len(rows),
        "authenticated_request_p50_ms": percentile(latencies, 0.5),
        "authenticated_request_p95_ms": p95,
        "authenticated_request_max_ms": max(latencies),
        "exporter_error_log_lines": export_lines,
        "api_restarted": False,
    }


def restore_telemetry(ctx: Context) -> None:
    original = ctx.notes.get("telemetry")
    if not original:
        return
    kube = ctx.kube
    patch = {"data": {key: value for key, value in original.items() if value is not None}}
    kube("patch", "configmap", "asic-runtime", "--type=merge", "-p", json.dumps(patch))
    for key, value in original.items():
        if value is None:
            kube.probe(
                "patch",
                "configmap",
                "asic-runtime",
                "--type=json",
                "-p",
                json.dumps([{"op": "remove", "path": f"/data/{key}"}]),
            )
    _roll_api(kube)
    post_rollout_smoke(kube, log=ctx.log)


# --------------------------------------------------------------- migration pod overlap

_HOLD = (
    "import signal, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "print('chaos: migration pod holding, SIGTERM ignored', flush=True)\n"
    "time.sleep(3600)\n"
)


def _job(migration: str, release: str, *, grace: int | None = None, hold: bool = False) -> str:
    job = next(d for d in yaml.safe_load_all(migration) if d and d["kind"] == "Job")
    job = copy.deepcopy(job)
    template = job["spec"]["template"]
    template.setdefault("metadata", {}).setdefault("annotations", {})["asic/release"] = release
    if hold:
        template["spec"]["containers"][0]["command"] = [PYTHON, "-c", _HOLD]
    if grace is not None:
        template["spec"]["terminationGracePeriodSeconds"] = grace
    return yaml.safe_dump(job, sort_keys=False)


def _migration(migration: str, release: str) -> str:
    documents = [d for d in yaml.safe_load_all(migration) if d]
    for doc in documents:
        if doc["kind"] == "Job":
            annotations = doc["spec"]["template"].setdefault("metadata", {})
            annotations.setdefault("annotations", {})["asic/release"] = release
    return yaml.safe_dump_all(documents, sort_keys=False)


class PodWatcher:
    """Samples migration pods from the host; records every non-terminal pod per sample."""

    def __init__(self, kube: Kubectl, interval: float = 0.5) -> None:
        self.samples: list[tuple[float, list[tuple[str, str, str, bool]]]] = []
        self._stop = threading.Event()

        def run() -> None:
            while not self._stop.is_set():
                begun = time.monotonic()
                raw = kube.probe("get", "pods", "-l", MIGRATION_PODS, "-o", "json")
                if raw.returncode == 0:
                    alive = []
                    for pod in json.loads(raw.stdout)["items"]:
                        phase = pod["status"].get("phase", "")
                        if phase in ("Succeeded", "Failed"):
                            continue
                        labels = pod["metadata"].get("labels") or {}
                        alive.append(
                            (
                                pod["metadata"]["name"],
                                labels.get("batch.kubernetes.io/controller-uid", "?"),
                                phase,
                                bool(pod["metadata"].get("deletionTimestamp")),
                            )
                        )
                    self.samples.append((begun, alive))
                self._stop.wait(interval)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def max_concurrent(self) -> int:
        return max((len({c for _, c, _, _ in alive}) for _, alive in self.samples), default=0)

    def last_seen(self, name: str) -> float | None:
        seen = [t for t, alive in self.samples if any(n == name for n, *_ in alive)]
        return max(seen) if seen else None


def _held_pod(ctx: Context, release: str, grace: int) -> str:
    kube = ctx.kube
    kube("create", "-f", "-", content=_job(ctx.migration, release, grace=grace, hold=True))
    wait_for(
        lambda: any(p["status"].get("phase") == "Running" for p in _pods(kube, MIGRATION_PODS)),
        timeout=120,
        what="held migration pod running",
    )
    (pod,) = [p for p in _pods(kube, MIGRATION_PODS) if _alive(p)]
    return pod["metadata"]["name"]  # type: ignore[no-any-return]


def _delete_job_leaving_pod(ctx: Context, pod: str) -> float:
    kube = ctx.kube
    kube("delete", "job", MIGRATION_JOB, "--cascade=background", "--wait=false")
    gone = wait_for(
        lambda: kube.probe("get", "job", MIGRATION_JOB).returncode != 0,
        timeout=60,
        what="Job object gone",
        interval=0.5,
    )
    state = next(p for p in _pods(kube, MIGRATION_PODS) if p["metadata"]["name"] == pod)
    if state["status"].get("phase") != "Running" or not state["metadata"].get("deletionTimestamp"):
        raise ChaosFailed("precondition: the old pod must be terminating but still running")
    return gone


def _clear_migration_pods(kube: Kubectl) -> None:
    kube.probe("delete", "job", MIGRATION_JOB, "--cascade=background", "--wait=false")
    kube.probe("delete", "pod", "-l", MIGRATION_PODS, "--grace-period=0", "--force", "--wait=true")
    wait_for(lambda: not _pods(kube, MIGRATION_PODS), timeout=120, what="migration pods gone")


def migration_pod_overlap(ctx: Context) -> dict[str, Any]:
    kube = ctx.kube
    results: dict[str, Any] = {}
    kube("delete", "job", MIGRATION_JOB, "--cascade=foreground", "--wait=true", timeout=180)
    wait_for(lambda: not _pods(kube, MIGRATION_PODS), timeout=120, what="no migration pods")

    # 1. The orchestrator waits for the held pod, then migrates.
    grace = 40
    old = _held_pod(ctx, "chaos-held-1", grace)
    watcher = PodWatcher(kube)
    deleted_at = time.monotonic()
    job_gone = _delete_job_leaving_pod(ctx, old)
    created: list[float] = []
    logs: list[str] = []

    def timed(command: Any, content: str | None, timeout: float) -> Any:
        if "create" in command and "--dry-run=server" not in command:
            created.append(time.monotonic())
        return kube.runner(command, content, timeout)

    outcome = run_deployment(
        Kubectl(kube.namespace, kube.kubeconfig, kube.binary, timed),
        _migration(ctx.migration, "chaos-after-hold"),
        ctx.application,
        poll_interval=1,
        pod_timeout=grace + 90,
        log=lambda line: (logs.append(line), ctx.log(line)),
    )
    watcher.stop()
    old_last_seen = watcher.last_seen(old)
    waited = any("waiting for previous migration pod" in line for line in logs)
    if outcome.state != "complete" or len(created) != 1 or old_last_seen is None:
        raise ChaosFailed(f"unexpected outcome {outcome.state}, creates={len(created)}")
    if not waited or created[0] <= old_last_seen:
        raise ChaosFailed("the new migration Job was created while the old pod was still seen")
    if watcher.max_concurrent() != 1:
        raise ChaosFailed(f"overlap observed: max concurrent = {watcher.max_concurrent()}")
    results["orchestrated"] = {
        "job_object_gone_after_seconds": round(job_gone, 1),
        "new_job_created_after_delete_seconds": round(created[0] - deleted_at, 1),
        "old_pod_last_seen_after_delete_seconds": round(old_last_seen - deleted_at, 1),
        "termination_grace_seconds": grace,
        "waited_for_previous_pod": True,
        "max_concurrent_migration_pods": watcher.max_concurrent(),
        "samples": len(watcher.samples),
        "migration": outcome.state,
    }

    # 2. Non-vacuity: bypassing the orchestrator produces an overlap the sampler detects.
    kube("delete", "job", MIGRATION_JOB, "--cascade=foreground", "--wait=true", timeout=180)
    wait_for(lambda: not _pods(kube, MIGRATION_PODS), timeout=120, what="no migration pods")
    old = _held_pod(ctx, "chaos-held-2", 60)
    watcher = PodWatcher(kube)
    _delete_job_leaving_pod(ctx, old)
    kube("create", "-f", "-", content=_job(ctx.migration, "chaos-bypass", grace=5, hold=True))
    wait_for(lambda: watcher.max_concurrent() >= 2, timeout=90, what="bypass overlap observed")
    watcher.stop()
    results["bypass_non_vacuity"] = {"max_concurrent_migration_pods": watcher.max_concurrent()}
    _clear_migration_pods(kube)

    # 3. Timeout: a pod that outlives the allowance means NO replacement is created.
    old = _held_pod(ctx, "chaos-held-3", 150)
    _delete_job_leaving_pod(ctx, old)
    calls: list[list[str]] = []

    def recorded(command: Any, content: str | None, timeout: float) -> Any:
        calls.append(list(command))
        return kube.runner(command, content, timeout)

    begun = time.monotonic()
    try:
        run_deployment(
            Kubectl(kube.namespace, kube.kubeconfig, kube.binary, recorded),
            _migration(ctx.migration, "chaos-timeout"),
            ctx.application,
            poll_interval=1,
            pod_timeout=20,
            log=ctx.log,
        )
    except DeploymentError as error:
        refusal = str(error)
    else:
        raise ChaosFailed("deployment proceeded while the old migration pod was still running")
    if "the replacement was NOT created" not in refusal:
        raise ChaosFailed(f"unexpected refusal: {refusal[:300]}")
    creates = [c for c in calls if "create" in c and "--dry-run=server" not in c]
    applies = [c for c in calls if "apply" in c and "--dry-run=server" not in c]
    if creates or applies or kube.probe("get", "job", MIGRATION_JOB).returncode == 0:
        raise ChaosFailed("a timed-out wait still created or applied something")
    results["timeout"] = {
        "pod_timeout_seconds": 20,
        "refused_after_seconds": round(time.monotonic() - begun, 1),
        "jobs_created": 0,
        "manifests_applied": 0,
        "refusal": refusal.splitlines()[0][:200],
    }
    return results


def recover_migration(ctx: Context) -> None:
    _clear_migration_pods(ctx.kube)
    run_deployment(
        ctx.kube, _migration(ctx.migration, "chaos-recovery"), ctx.application, poll_interval=1
    )


# ------------------------------------------------------------------------------ runner


def _nothing(_ctx: Context) -> None:
    return None


BODIES: dict[str, tuple[Callable[[Context], dict[str, Any]], Callable[[Context], None]]] = {
    "api_pod_kill": (api_pod_kill, _nothing),
    "frontend_pod_kill": (frontend_pod_kill, _nothing),
    "postgres_restart": (postgres_restart, _nothing),
    "readiness_failure_database_access_revoked": (
        revoke_database_access,
        restore_database_access,
    ),
    "otel_collector_unavailable": (otel_collector_unavailable, restore_telemetry),
    "migration_pod_overlap": (migration_pod_overlap, recover_migration),
}


def run_suite(ctx: Context) -> dict[str, Any]:
    """Run every declared experiment in order; raise ChaosFailed on the first violation."""
    declared = [e.name for e in EXPERIMENTS]
    if sorted(declared) != sorted(BODIES) or len(set(declared)) != len(declared):
        raise ChaosFailed("every experiment must be declared exactly once before it can run")
    results: dict[str, Any] = {}
    for experiment in EXPERIMENTS:
        ctx.log(f"== Chaos experiment: {experiment.name}")
        for item in fields(experiment):
            if item.name != "name":
                ctx.log(f"   {item.name}: {getattr(experiment, item.name)}")
        body, cleanup = BODIES[experiment.name]
        begun = time.monotonic()
        failure: BaseException | None = None
        try:
            observed = body(ctx)
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                cleanup(ctx)
            except Exception as error:
                if failure is None:
                    raise
                ctx.log(f"   cleanup after the failure also failed: {error}")
        elapsed = time.monotonic() - begun
        if elapsed > experiment.max_seconds:
            raise ChaosFailed(
                f"{experiment.name} took {elapsed:.0f}s, over its {experiment.max_seconds}s bound"
            )
        results[experiment.name] = {"result": "passed", "seconds": round(elapsed, 1), **observed}
        ctx.log(f"   observed: {json.dumps(results[experiment.name], sort_keys=True)}")
    return results


# ------------------------------------------------------------- retention maintenance


def retention_maintenance(
    kube: Kubectl, manifest: str, *, run_process: Callable[..., Any], kubectl: list[str]
) -> dict[str, Any]:
    """The retention CronJob as delivered: admitted, suspended, and working in-cluster.

    Seeds tenant A with three expired and one recent idempotency record and tenant B with two
    recent ones, then runs the CronJob's own Job template twice: as shipped (dry run) and with
    ``--execute``. Every count is filtered by tenant explicitly (psql runs as the owner, which
    bypasses row-level security), and every receipt must name the tenant it acted on.
    """
    dry = run_process(*kubectl, "apply", "--dry-run=server", "-f", "-", content=manifest)
    if dry.returncode or "PodSecurity" in dry.stderr:
        raise ChaosFailed(f"retention CronJob not admitted under restricted: {dry.stderr}")
    kube("apply", "-f", "-", content=manifest)
    cronjob = json.loads(kube("get", "cronjob", "asic-retention", "-o", "json"))
    if cronjob["spec"].get("suspend") is not True:
        raise ChaosFailed("the retention CronJob must be delivered suspended")
    _psql(
        kube,
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
        "'asic_maintenance_local') THEN CREATE ROLE asic_maintenance_local LOGIN "
        "NOSUPERUSER NOBYPASSRLS IN ROLE asic_maintenance; END IF; END $$",
    )
    tenant = _psql(
        kube,
        "INSERT INTO tenant (slug, display_name, status) "
        "VALUES ('kind-retention', 'Kind retention', 'active') RETURNING id",
    ).splitlines()[0]
    other = _psql(
        kube,
        "INSERT INTO tenant (slug, display_name, status) "
        "VALUES ('kind-retention-b', 'Kind retention B', 'active') RETURNING id",
    ).splitlines()[0]

    def scoped(sql: str) -> str:
        return _psql(
            kube,
            # One simple query = one implicit transaction; psql prints the last result.
            f"SELECT set_config('app.tenant_id', '{tenant}', true); {sql}",
        )

    scoped(
        "INSERT INTO api_idempotency_record (tenant_id, principal_id, idempotency_key, "
        "operation, request_digest, response_body, created_at) "
        f"SELECT '{tenant}', gen_random_uuid(), 'kind-' || g, 'incident.annotate', "
        "repeat('a', 64), '{}'::jsonb, now() - (CASE WHEN g <= 3 THEN interval '40 days' "
        "ELSE interval '1 hour' END) - g * interval '1 minute' FROM generate_series(1, 4) g"
    )
    _psql(
        kube,
        "INSERT INTO api_idempotency_record (tenant_id, principal_id, idempotency_key, "
        "operation, request_digest, response_body, created_at) "
        f"SELECT '{other}', gen_random_uuid(), 'kind-b-' || g, 'incident.annotate', "
        "repeat('b', 64), '{}'::jsonb, now() - interval '2 hours' FROM generate_series(1, 2) g",
    )

    def count(table: str, owner: str | None = None) -> int:
        # psql runs as the owner, which bypasses row-level security: filter explicitly, or rows
        # other steps of the same smoke created in other tenants are counted too.
        out = _psql(kube, f"SELECT count(*) FROM {table} WHERE tenant_id = '{owner or tenant}'")
        return int([line for line in out.splitlines() if line.strip().isdigit()][-1])

    template = cronjob["spec"]["jobTemplate"]

    def job(name: str, extra: list[str]) -> list[dict[str, Any]]:
        spec = copy.deepcopy(template["spec"])
        spec["template"]["spec"]["containers"][0]["command"] += extra
        body = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": spec}
        kube("create", "-f", "-", content=yaml.safe_dump(body))
        kube("wait", "--for=condition=Complete", f"job/{name}", "--timeout=180s", timeout=210)
        lines = kube("logs", f"job/{name}").splitlines()
        return [json.loads(line) for line in lines if line.startswith("{")]

    def mine(receipts: list[dict[str, Any]], owner: str) -> list[dict[str, Any]]:
        return [r for r in receipts if r["tenant_id"] == owner]

    before, other_before = count("api_idempotency_record"), count("api_idempotency_record", other)
    dry_all = job("asic-retention-dry-run", [])
    dry_receipts = mine(dry_all, tenant)
    after_dry = count("api_idempotency_record")
    other_after_dry = count("api_idempotency_record", other)
    executed_all = job("asic-retention-execute", ["--execute"])
    executed, executed_other = mine(executed_all, tenant), mine(executed_all, other)
    after_execute = count("api_idempotency_record")
    other_after_execute = count("api_idempotency_record", other)
    receipts = count("retention_run")
    known = {r["tenant_id"] for r in dry_all + executed_all}
    if not (
        before == 4
        and after_dry == 4
        and after_execute == 1
        and other_before == other_after_dry == other_after_execute == 2
        and [r["dry_run"] for r in dry_receipts] == [True]
        and dry_receipts[0]["eligible_rows"] == 3
        and all(r["deleted_rows"] == 0 for r in dry_all)
        and sum(r["deleted_rows"] for r in executed) == 3
        and all(r["deleted_rows"] == 0 for r in executed_other)
        and receipts == len(dry_receipts) + len(executed)
        and all(r.get("tenant_id") for r in dry_all + executed_all)
        and {tenant, other} <= known
    ):
        raise ChaosFailed(
            f"retention run mismatch: {before=} {after_dry=} {after_execute=} {receipts=} "
            f"{other_before=} {other_after_dry=} {other_after_execute=} "
            f"{dry_receipts=} {executed=} {executed_other=}"
        )
    for name in ("asic-retention-dry-run", "asic-retention-execute"):
        kube("delete", "job", name, "--wait=true", timeout=120)
    return {
        "cronjob_suspended": True,
        "server_side_admitted": True,
        "dry_run": {"eligible": 3, "deleted": 0, "rows_after": after_dry},
        "execute": {"deleted": 3, "rows_after": after_execute, "recent_row_kept": True},
        "tenant_b": {
            "rows_before": other_before,
            "rows_after_execute": other_after_execute,
            "deleted": 0,
        },
        "receipts_written": receipts,
        "receipts_tenant_bound": True,
        "identity": "asic_maintenance_local (member of asic_maintenance only)",
    }


__all__ = [
    "BODIES",
    "EXPERIMENTS",
    "ChaosFailed",
    "Context",
    "Experiment",
    "outage",
    "percentile",
    "retention_maintenance",
    "run_suite",
]
