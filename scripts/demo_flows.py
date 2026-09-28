"""The demo's product-path flows (Phase 16 closure): worker, remediation, postmortem, recovery.

``product_flow`` starts the real API (``python -m asic.api``) and the real worker
(``python -m asic.worker``, simulator profile) as separate processes and drives an incident
only through HTTP, exactly as a deployment would:

    signed connector alert -> worker investigation -> responder remediation request ->
    policy requires approval -> human approval bound to the action hash -> worker executes ->
    settling window -> independent verification -> resolved -> G11 postmortem draft

``crash_resume`` shows durable recovery. A real lease expiry takes 15 minutes, so this flow
runs the worker in-process on a test clock and simulates the process death at a node boundary
the way the crash matrix does (no clean-up runs, the lease stays held). It is labelled as such
when it prints.

Every check reads persisted rows; a mismatch is returned as a failure, never printed as success.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import sqlalchemy as sa

REPO = Path(__file__).resolve().parents[1]
JWT_SECRET = "asic-demo-hs256-signing-key-local-only-0001"  # hygiene: synthetic-secret-fixture
BEHAVIOUR_LABEL = "demo-release"
CITATION_TABLES = {
    "incident": "incident",
    "alert": "alert",
    "incident_event": "incident_event",
    "evidence": "evidence",
    "hypothesis": "hypothesis",
    "remediation_action": "remediation_action",
    "policy_decision": "policy_decision",
    "approval": "approval",
    "tool_execution": "tool_execution",
    "verification": "verification",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def seed_world(admin_url: str, slug: str) -> dict[str, str]:
    """Administrative onboarding rows (an operator's job): tenant, catalogue, people, binding."""
    from asic import __version__
    from asic.llm.prompts import PROMPT_SET_VERSION
    from asic.tools.catalogue import CATALOGUE_VERSION

    engine = sa.create_engine(admin_url)
    try:
        with engine.begin() as c:
            one = lambda q, **p: str(c.execute(sa.text(q), p).scalar())  # noqa: E731
            tenant = one(
                "INSERT INTO tenant (slug, display_name, status) VALUES (:s, :s, 'active') "
                "RETURNING id",
                s=f"{slug}-{uuid.uuid4().hex[:6]}",
            )
            environment = one(
                "INSERT INTO environment (tenant_id, name, display_name, is_production) "
                "VALUES (:t, 'production', 'Production', true) RETURNING id",
                t=tenant,
            )
            service = one(
                "INSERT INTO service (tenant_id, name, display_name, owner_team, criticality, "
                "namespaces) VALUES (:t, 'checkout-api', 'checkout-api', 'payments', 'tier_1', "
                "ARRAY['checkout']) RETURNING id",
                t=tenant,
            )
            c.execute(
                sa.text(
                    "INSERT INTO tenant_tool_grant (tenant_id, tool_definition_id, "
                    "environment_id, is_enabled) SELECT :t, id, :e, true FROM tool_definition"
                ),
                {"t": tenant, "e": environment},
            )
            c.execute(
                sa.text(
                    "INSERT INTO integration_connector (tenant_id, connector_id, kind, "
                    "environment_id, is_enabled) VALUES (:t, 'demo-alerts', 'prometheus', :e, "
                    "false)"
                ),
                {"t": tenant, "e": environment},
            )
            c.execute(
                sa.text(
                    "INSERT INTO connector_scope_binding (tenant_id, connector_id, source, "
                    "service_id, environment_id, is_enabled) VALUES (:t, 'demo-alerts', "
                    "'simulator', :s, :e, true)"
                ),
                {"t": tenant, "s": service, "e": environment},
            )
            users = {}
            for subject, role in (
                ("demo-connector", "system_operator"),
                ("demo-responder", "responder"),
                ("demo-approver", "sre_approver"),
            ):
                users[subject] = one(
                    "INSERT INTO app_user (tenant_id, external_idp_subject, email, display_name, "
                    "status) VALUES (:t, :u, :m, :u, 'active') RETURNING id",
                    t=tenant,
                    u=subject,
                    m=f"{subject}@example.invalid",
                )
                c.execute(
                    sa.text(
                        "INSERT INTO user_role_assignment (tenant_id, user_id, role_id, "
                        "environment_id) SELECT :t, :u, id, :e FROM role WHERE key = :r"
                    ),
                    {"t": tenant, "u": users[subject], "e": environment, "r": role},
                )
            c.execute(
                sa.text(
                    "INSERT INTO behaviour_version (label, code_version, prompt_set_version, "
                    "retriever_config_version, policy_version, tool_registry_version, "
                    "fingerprint) VALUES (:l, :c, :p, 'none', 'none', :k, :f) "
                    "ON CONFLICT (label) DO NOTHING"
                ),
                {
                    "l": BEHAVIOUR_LABEL,
                    "c": __version__,
                    "p": PROMPT_SET_VERSION,
                    "k": CATALOGUE_VERSION,
                    "f": uuid.uuid4().hex,
                },
            )
    finally:
        engine.dispose()
    return {
        "tenant": tenant,
        "environment": environment,
        "service": service,
        "approver": users["demo-approver"],
    }


def _token(tenant: str, subject: str, **claims: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant,
            "iss": "asic-idp",
            "aud": "asic-api",
            "iat": now,
            "exp": now + 1800,
            **claims,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def _http(
    method: str, url: str, token: str | None = None, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if method == "POST":
        headers["Idempotency-Key"] = uuid.uuid4().hex
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")
    except OSError:
        return 0, None


def _wait(what: str, predicate: Callable[[], Any], timeout: float, interval: float = 1) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise RuntimeError(f"{what} not reached within {timeout:.0f}s")


def _process(module: str, env: dict[str, str], log: Path) -> subprocess.Popen[bytes]:
    handle = log.open("wb")
    return subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=REPO,
        env={**os.environ, **env, "PYTHONPATH": str(REPO / "src")},
        stdout=handle,
        stderr=subprocess.STDOUT,
    )


def product_flow(admin_url: str, app_url: str, say: Callable[[str], None]) -> list[str]:
    """Human-approved remediation, independent verification and a G11 draft, via API + worker."""
    failures: list[str] = []
    world = seed_world(admin_url, "demo-flow")
    tenant = world["tenant"]
    api_port, health_port = _free_port(), _free_port()
    logs = REPO / "tmp"
    logs.mkdir(exist_ok=True)
    common = {"ASIC_DATABASE_URL": app_url, "ASIC_DEPLOYMENT_ENVIRONMENT": "local"}
    api = _process(
        "asic.api",
        {
            **common,
            "ASIC_AUTH_MODE": "development_hs256",
            "ASIC_JWT_SECRET": JWT_SECRET,
            "ASIC_API_HOST": "127.0.0.1",
            "ASIC_API_PORT": str(api_port),
        },
        logs / "demo-api.log",
    )
    worker = _process(
        "asic.worker",
        {
            **common,
            "ASIC_WORKER_EXECUTION_MODE": "simulator",
            "ASIC_BEHAVIOUR_VERSION_LABEL": BEHAVIOUR_LABEL,
            "ASIC_WORKER_POLL_SECONDS": "1",
            "ASIC_WORKER_RETRY_BACKOFF_SECONDS": "2",
            "ASIC_WORKER_HEALTH_PORT": str(health_port),
        },
        logs / "demo-worker.log",
    )
    base = f"http://127.0.0.1:{api_port}/api/v1"
    try:
        _wait(
            "API ready", lambda: _http("GET", f"http://127.0.0.1:{api_port}/readyz")[0] == 200, 60
        )
        _wait(
            "worker ready",
            lambda: _http("GET", f"http://127.0.0.1:{health_port}/readyz")[0] == 200,
            60,
        )
        say(f"   API (pid {api.pid}) and worker (pid {worker.pid}) running as separate processes")
        connector = _token(
            tenant,
            "demo-connector",
            connector_id="demo-alerts",
            source="simulator",
            service_id=world["service"],
            environment_id=world["environment"],
        )
        responder, approver = _token(tenant, "demo-responder"), _token(tenant, "demo-approver")
        started = datetime.now(UTC) - timedelta(minutes=3)
        code, body = _http(
            "POST",
            f"{base}/ingest/alerts",
            connector,
            {
                "schema_version": 1,
                "source_event_id": f"demo-{uuid.uuid4().hex[:8]}",
                "fingerprint": "checkout-latency-p95",
                "severity": "high",
                "state": "firing",
                "title": "checkout-api p95 latency above objective",
                "started_at": started.isoformat(),
                "observed_at": (started + timedelta(minutes=1)).isoformat(),
            },
        )
        if code != 200 or body.get("outcome") != "accepted":
            raise RuntimeError(f"alert not accepted: {code} {body}")
        incident = body["incident_id"]

        def status() -> str:
            got, row = _http("GET", f"{base}/incidents/{incident}", responder)
            return str(row.get("status")) if got == 200 else ""

        _wait("worker investigation", lambda: status() == "escalated", 120)
        _, hypotheses = _http("GET", f"{base}/incidents/{incident}/hypotheses", responder)
        top = sorted(hypotheses["items"], key=lambda h: h["rank"])[0]
        say(
            f"   alert -> worker investigation -> escalated with hypothesis ({top['root_cause_class']})"
        )
        code, _ = _http(
            "POST",
            f"{base}/incidents/{incident}/remediation-requests",
            responder,
            {
                "hypothesis_id": top["id"],
                "service_id": world["service"],
                "justification": "deployment evidence matches the rollback runbook",
            },
        )
        if code != 202:
            raise RuntimeError(f"remediation request refused: {code}")
        _wait("approval request", lambda: status() == "awaiting_approval", 120)
        _, pending = _http("GET", f"{base}/approvals/pending", approver)
        (action,) = [a for a in pending["items"] if a["incident_id"] == incident]
        say(
            f"   worker proposed {action['tool_name']} (risk {action['risk_tier']}); policy "
            f"{action['policy_verdict']} in production -> waiting for a human"
        )
        code, decision = _http(
            "POST",
            f"{base}/approvals/{action['id']}/decide",
            approver,
            {
                "decision": "approved",
                "justification": "approved: rollback of the implicated deployment",
                "action_version_hash": action["action_version_hash"],
            },
        )
        if code != 200:
            raise RuntimeError(f"approval refused: {code} {decision}")
        say("   approved; worker executes, waits out the 60 s settling window, then verifies")
        _wait("verified resolution", lambda: status() == "resolved", 240, interval=3)
        drafts = _wait(
            "postmortem draft",
            lambda: _http("GET", f"{base}/incidents/{incident}/postmortems", responder)[1]["items"],
            60,
        )
    finally:
        for process in (worker, api):
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()

    facts = _persisted_flow(admin_url, tenant, incident, action["id"])
    checks = {
        "approval recorded, approved, by the approver, bound to the action hash": (
            facts["approval"] == ("approved", world["approver"], facts["action_hash"])
        ),
        "exactly one mutating tool execution, succeeded": facts["writes"] == [("succeeded",)],
        "independent verification verdict verified": facts["verification"] == "verified",
        "incident resolved (terminal)": facts["incident_status"] == "resolved",
        "one postmortem draft, review required, never published": (
            len(drafts) == 1
            and drafts[0]["status"] == "draft"
            and drafts[0]["review_required"] is True
            and facts["non_draft_postmortems"] == 0
        ),
        "every postmortem citation resolves to a persisted record of this tenant": (
            bool(drafts) and _citations_resolve(admin_url, tenant, drafts[0]["citations"])
        ),
        "every factual claim cites a record": bool(drafts)
        and all(
            claim["citations"]
            for claims in drafts[0]["sections"].values()
            for claim in claims
            if claim["origin"] != "system"
        ),
    }
    for label, passed in checks.items():
        say(f"   {'OK' if passed else 'MISMATCH'}: {label}")
        if not passed:
            failures.append(f"product-flow: {label}")
    if drafts:
        draft = drafts[0]
        say(
            f"   postmortem v{draft['version']}: {len(draft['citations'])} citations, "
            f"basis {draft['resolution_basis']}, model claims removed "
            f"{draft['validation']['model_claims_removed']}"
        )
    return failures


def _persisted_flow(admin_url: str, tenant: str, incident: str, action: str) -> dict[str, Any]:
    engine = sa.create_engine(admin_url)
    try:
        with engine.begin() as c:
            c.execute(sa.text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant})
            q = lambda s: c.execute(sa.text(s), {"i": incident, "a": action})  # noqa: E731
            action_hash = q(
                "SELECT action_version_hash FROM remediation_action WHERE id = :a"
            ).scalar()
            approval = q(
                "SELECT decision::text, approver_user_id::text, action_version_hash FROM approval "
                "WHERE remediation_action_id = :a"
            ).one()
            writes = q(
                "SELECT t.outcome::text FROM tool_execution t JOIN remediation_action r ON "
                "r.id = t.remediation_action_id AND t.tool_name = r.tool_name WHERE r.id = :a"
            ).all()
            return {
                "action_hash": action_hash,
                "approval": tuple(approval),
                "writes": [tuple(row) for row in writes],
                "verification": q(
                    "SELECT verdict::text FROM verification WHERE remediation_action_id = :a"
                ).scalar(),
                "incident_status": q("SELECT status::text FROM incident WHERE id = :i").scalar(),
                "non_draft_postmortems": q(
                    "SELECT count(*) FROM postmortem WHERE status <> 'draft' OR NOT review_required"
                ).scalar(),
            }
    finally:
        engine.dispose()


def _citations_resolve(admin_url: str, tenant: str, citations: list[dict[str, str]]) -> bool:
    engine = sa.create_engine(admin_url)
    try:
        with engine.begin() as c:
            c.execute(sa.text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant})
            for citation in citations:
                table = CITATION_TABLES[citation["kind"]]
                found = c.execute(
                    sa.text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t AND id = :i"),
                    {"t": tenant, "i": citation["id"]},
                ).scalar()
                if found != 1:
                    return False
        return True
    finally:
        engine.dispose()


class _ProcessDeath(BaseException):
    """kill -9 at a node boundary: nothing after it runs, not even ``except Exception``."""


def crash_resume(admin_url: str, app_url: str, say: Callable[[str], None]) -> list[str]:
    """A worker dies mid-investigation; another resumes the same run without repeating effects."""
    from asic.db.session import create_app_engine, session_factory
    from asic.domain.clock import FrozenClock
    from asic.ingestion.contracts import ConnectorContext
    from asic.ingestion.service import IngestionService
    from asic.orchestration.kernel import LEASE_DURATION, InvestigationKernel
    from asic.tools.capability import CapabilityResolver
    from asic.tools.registry import ToolRegistry
    from asic.worker.profile import SimulatorProfile
    from asic.worker.runtime import Worker, resolve_behaviour_version
    from asic.worker.settings import ExecutionMode, WorkerSettings

    world = seed_world(admin_url, "demo-crash")
    engine = create_app_engine(app_url)
    factory = session_factory(engine)
    clock = FrozenClock(start=datetime.now(UTC).replace(microsecond=0))
    started = clock.now() - timedelta(minutes=3)
    result = IngestionService(factory, clock=clock).ingest(
        ConnectorContext(
            tenant_id=uuid.UUID(world["tenant"]),
            connector_id="demo-alerts",
            source="simulator",
            service_id=uuid.UUID(world["service"]),
            environment_id=uuid.UUID(world["environment"]),
        ),
        json.dumps(
            {
                "schema_version": 1,
                "fingerprint": "checkout-latency-p95",
                "title": "checkout-api p95 latency above objective",
                "severity": "high",
                "started_at": started.isoformat(),
                "observed_at": (started + timedelta(minutes=1)).isoformat(),
            }
        ).encode(),
    )
    incident = result.incident_id
    assert incident is not None
    tenant = uuid.UUID(world["tenant"])
    with factory() as session:
        session.execute(sa.text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
        dispatch = session.execute(
            sa.text("SELECT id FROM investigation_dispatch WHERE incident_id = :i"),
            {"i": incident},
        ).scalar_one()
        session.rollback()
    profile = SimulatorProfile(
        factory,
        scenario_id="SC-0001-checkout-latency-after-deploy",
        remediation_variant="autonomous_verified",
        clock=clock,
    )
    service = profile.investigation_service(tenant, None)
    behaviour = resolve_behaviour_version(factory, BEHAVIOUR_LABEL)

    def die(_node: str, ordinal: int) -> None:
        if ordinal == 3:
            raise _ProcessDeath

    class _KilledKernel(InvestigationKernel):
        """A killed process performs no dead-letter bookkeeping and releases no lease."""

        def _mark_dead_letter(self, context: Any) -> None:
            return None

    dying = _KilledKernel(
        session_factory=factory,
        resolver=CapabilityResolver(ToolRegistry.read_only()),
        providers=service._providers,
        model=service._model,
        clock=clock,
        interrupt_probe=die,
    )
    try:
        dying.start(
            tenant_id=tenant,
            incident_id=incident,
            behaviour_version_id=behaviour,
            service_ids=[uuid.UUID(world["service"])],
            dispatch_id=dispatch,
        )
    except _ProcessDeath:
        say("   worker A killed after its third node (no clean-up ran; lease still held)")
    worker = Worker(
        settings=WorkerSettings(
            mode=ExecutionMode.SIMULATOR,
            behaviour_version_label=BEHAVIOUR_LABEL,
            retry_backoff_seconds=0,
        ),
        engine=engine,
        factory=factory,
        profile=profile,
        behaviour_version_id=behaviour,
        clock=clock,
        tenants=[tenant],
    )
    busy = [outcome for _, outcome in worker.run_once()]
    say(f"   worker B while A's lease is valid: {busy} (refuses to advance the run)")
    clock.advance(LEASE_DURATION.total_seconds() + 1)
    resumed = [outcome for _, outcome in worker.run_once()]
    say(f"   test clock advanced past the 15-minute lease; worker B: {resumed}")
    with engine.begin() as c:
        c.execute(sa.text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
        q = lambda s: c.execute(sa.text(s), {"i": incident}).all()  # noqa: E731
        runs = q("SELECT resumed_count FROM workflow_run WHERE incident_id = :i")
        keys = [
            row[0] for row in q("SELECT idempotency_key FROM tool_execution WHERE incident_id = :i")
        ]
        status = q("SELECT status::text FROM incident WHERE id = :i")[0][0]
    engine.dispose()
    checks = {
        "the dead worker's lease was honoured (busy, no second run)": busy == ["busy"],
        "the same run resumed exactly once and completed": resumed == ["completed"]
        and runs == [(1,)],
        "no tool effect recorded twice": bool(keys) and len(keys) == len(set(keys)),
        "the incident reached its expected terminal state": status == "escalated",
    }
    failures = []
    for label, passed in checks.items():
        say(f"   {'OK' if passed else 'MISMATCH'}: {label}")
        if not passed:
            failures.append(f"crash-resume: {label}")
    return failures


__all__ = ["crash_resume", "product_flow", "seed_world"]
