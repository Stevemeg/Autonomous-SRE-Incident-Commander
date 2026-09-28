"""Kind acceptance for the deployed worker and G11 (Phase 16 closure, F-01/F-02).

Called by ``deployment_smoke.py`` against the images it deployed. Nothing here invokes a graph,
a kernel or a harness: the only writes it makes directly are the administrative rows a real
onboarding would create (tenant, environment, service, users, role assignments, connector
binding, tool grants, the release's behaviour version). Everything else goes through the
product's own path:

    signed connector -> POST /ingest/alerts -> durable dispatch -> worker -> investigation
    responder -> POST /incidents/{id}/remediation-requests -> worker -> G6 -> G7 (approval)
    approver -> POST /approvals/{action}/decide -> worker -> G9 execute -> settle -> G10 verify
    resolved incident -> worker -> G11 postmortem draft -> GET /incidents/{id}/postmortems

and the assertions read persisted state (API responses and the database), never printed
success. Two worker replicas run throughout, so every step is also a claim race.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from deploy_release import Kubectl, port_forward

PYTHON = "/usr/local/bin/python"
LOCAL_JWT_SECRET = "local-smoke-value-not-for-production-0001"  # overlays/local only
ISSUER, AUDIENCE = "asic-local-idp", "asic-api"
BEHAVIOUR_LABEL = "kind-local"


class AcceptanceFailed(RuntimeError):
    pass


def psql(kube: Kubectl, sql: str) -> str:
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


def behaviour_registration(versions: dict[str, str]) -> Callable[[Kubectl], None]:
    """The release step between migration and rollout: register the worker's behaviour version.

    ``versions`` is read from the image itself (prompt set and tool catalogue), so the row
    describes exactly the code that will run. Idempotent.
    """

    def register(kube: Kubectl) -> None:
        psql(
            kube,
            "INSERT INTO behaviour_version (label, code_version, prompt_set_version, "
            "retriever_config_version, policy_version, tool_registry_version, fingerprint) "
            f"VALUES ('{BEHAVIOUR_LABEL}', '{versions['code']}', '{versions['prompts']}', "
            f"'none', 'none', '{versions['catalogue']}', '{uuid.uuid4().hex}') "
            "ON CONFLICT (label) DO NOTHING",
        )

    return register


def _token(tenant: str, subject: str, **claims: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 1800,
            **claims,
        },
        LOCAL_JWT_SECRET,
        algorithm="HS256",
    )


def _call(
    base: str, method: str, path: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if method == "POST":
        headers["Idempotency-Key"] = uuid.uuid4().hex
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def _wait(what: str, predicate: Callable[[], Any], timeout: float, interval: float = 3) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AcceptanceFailed(f"{what} not reached within {timeout:.0f}s")


def _seed(kube: Kubectl) -> dict[str, str]:
    """Administrative onboarding rows, as the owner (an operator's job, not the product's)."""
    tenant = psql(
        kube,
        "INSERT INTO tenant (slug, display_name, status) VALUES "
        f"('kind-worker-{uuid.uuid4().hex[:6]}', 'Kind worker acceptance', 'active') RETURNING id",
    ).splitlines()[0]
    environment = psql(
        kube,
        "INSERT INTO environment (tenant_id, name, display_name, is_production) VALUES "
        f"('{tenant}', 'production', 'Production', true) RETURNING id",
    ).splitlines()[0]
    service = psql(
        kube,
        "INSERT INTO service (tenant_id, name, display_name, owner_team, criticality, "
        f"namespaces) VALUES ('{tenant}', 'checkout-api', 'checkout-api', 'payments', "
        "'tier_1', ARRAY['checkout']) RETURNING id",
    ).splitlines()[0]
    psql(
        kube,
        "INSERT INTO tenant_tool_grant (tenant_id, tool_definition_id, environment_id, "
        f"is_enabled) SELECT '{tenant}', id, '{environment}', true FROM tool_definition",
    )
    psql(
        kube,
        "INSERT INTO integration_connector (tenant_id, connector_id, kind, environment_id, "
        f"is_enabled) VALUES ('{tenant}', 'kind-alerts', 'prometheus', '{environment}', false)",
    )
    psql(
        kube,
        "INSERT INTO connector_scope_binding (tenant_id, connector_id, source, service_id, "
        f"environment_id, is_enabled) VALUES ('{tenant}', 'kind-alerts', 'simulator', "
        f"'{service}', '{environment}', true)",
    )
    for subject, role in (
        ("kind-connector", "system_operator"),
        ("kind-responder", "responder"),
        ("kind-approver", "sre_approver"),
    ):
        psql(
            kube,
            "INSERT INTO app_user (tenant_id, external_idp_subject, email, display_name, status) "
            f"VALUES ('{tenant}', '{subject}', '{subject}@example.invalid', '{subject}', "
            "'active')",
        )
        psql(
            kube,
            "INSERT INTO user_role_assignment (tenant_id, user_id, role_id, environment_id) "
            f"SELECT '{tenant}', u.id, r.id, '{environment}' FROM app_user u, role r "
            f"WHERE u.tenant_id = '{tenant}' AND u.external_idp_subject = '{subject}' "
            f"AND r.key = '{role}'",
        )
    return {"tenant": tenant, "environment": environment, "service": service}


def _worker_pods(kube: Kubectl) -> list[str]:
    pods = json.loads(
        kube("get", "pods", "-l", "app.kubernetes.io/name=asic-worker", "-o", "json")
    )["items"]
    return [pod["metadata"]["name"] for pod in pods if pod["status"].get("phase") == "Running"]


def _worker_items(kube: Kubectl, pods: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Every ``worker.item`` log record, per pod: who handled which item, with what outcome."""
    records: dict[str, list[dict[str, Any]]] = {}
    for pod in pods:
        lines = kube("logs", f"pod/{pod}", "--tail=-1").splitlines()
        items = []
        for line in lines:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event") == "worker.item":
                items.append({k: event.get(k) for k in ("kind", "outcome", "item_id", "tenant_id")})
        records[pod] = items
    return records


def run(kube: Kubectl) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    pods = _worker_pods(kube)
    if len(pods) != 2:
        raise AcceptanceFailed(f"expected 2 running worker replicas, found {pods}")
    evidence["worker_replicas"] = len(pods)

    ids = _seed(kube)
    tenant = ids["tenant"]
    connector = _token(
        tenant,
        "kind-connector",
        connector_id="kind-alerts",
        source="simulator",
        service_id=ids["service"],
        environment_id=ids["environment"],
    )
    responder = _token(tenant, "kind-responder")
    approver = _token(tenant, "kind-approver")

    with port_forward(kube, "service/asic-api", 8000) as local:
        base = f"http://127.0.0.1:{local}/api/v1"
        started = datetime.now(UTC) - timedelta(minutes=3)
        status, body = _call(
            base,
            "POST",
            "/ingest/alerts",
            connector,
            {
                "schema_version": 1,
                "source_event_id": f"kind-{uuid.uuid4().hex[:8]}",
                "fingerprint": "checkout-latency-p95",
                "severity": "high",
                "state": "firing",
                "title": "checkout-api p95 latency above objective",
                "started_at": started.isoformat(),
                "observed_at": (started + timedelta(minutes=1)).isoformat(),
            },
        )
        if status != 200 or body.get("outcome") != "accepted" or not body.get("incident_id"):
            raise AcceptanceFailed(f"alert ingestion failed: {status} {body}")
        incident = body["incident_id"]
        evidence["alert"] = {"http": status, "outcome": body["outcome"]}

        def incident_status() -> str:
            code, row = _call(base, "GET", f"/incidents/{incident}", responder)
            return str(row.get("status")) if code == 200 else ""

        began = time.monotonic()
        _wait(
            "worker-driven investigation to escalate",
            lambda: incident_status() == "escalated",
            timeout=240,
        )
        _, evidence_page = _call(base, "GET", f"/incidents/{incident}/evidence", responder)
        _, hypotheses = _call(base, "GET", f"/incidents/{incident}/hypotheses", responder)
        _, trace = _call(base, "GET", f"/incidents/{incident}/trace", responder)
        if not evidence_page["items"] or not hypotheses["items"] or not trace["items"]:
            raise AcceptanceFailed("investigation left no evidence, hypothesis or trace")
        evidence["investigation"] = {
            "terminal_status": "escalated",
            "seconds": round(time.monotonic() - began, 1),
            "evidence_records": len(evidence_page["items"]),
            "hypotheses": len(hypotheses["items"]),
            "execution_traces": len(trace["items"]),
        }
        hypothesis = sorted(hypotheses["items"], key=lambda h: h["rank"])[0]

        status, body = _call(
            base,
            "POST",
            f"/incidents/{incident}/remediation-requests",
            responder,
            {
                "hypothesis_id": hypothesis["id"],
                "service_id": ids["service"],
                "justification": "kind acceptance: evidence implicates the last deployment",
            },
        )
        if status != 202:
            raise AcceptanceFailed(f"remediation request refused: {status} {body}")
        _wait(
            "remediation to wait for approval",
            lambda: incident_status() == "awaiting_approval",
            timeout=180,
        )
        _, pending = _call(base, "GET", "/approvals/pending", approver)
        (action,) = [a for a in pending["items"] if a["incident_id"] == incident]
        status, decision = _call(
            base,
            "POST",
            f"/approvals/{action['id']}/decide",
            approver,
            {
                "decision": "approved",
                "justification": "kind acceptance approval of the exact proposed version",
                "action_version_hash": action["action_version_hash"],
            },
        )
        if status != 200:
            raise AcceptanceFailed(f"approval refused: {status} {decision}")
        began = time.monotonic()
        # Execution, the tool's settling window (60 s for a rollback), then verification.
        _wait("verified resolution", lambda: incident_status() == "resolved", timeout=360)
        _, actions = _call(base, "GET", f"/incidents/{incident}/actions", responder)
        (final,) = actions["items"]
        if final["status"] != "verified" or final["verification"] != "verified":
            raise AcceptanceFailed(f"action not independently verified: {final}")
        evidence["remediation"] = {
            "tool": final["tool_name"],
            "policy_verdict": final["policy_verdict"],
            "approval": final["approval"],
            "action_status": final["status"],
            "verification": final["verification"],
            "seconds_after_approval": round(time.monotonic() - began, 1),
        }

        def drafts() -> list[dict[str, Any]]:
            code, page = _call(base, "GET", f"/incidents/{incident}/postmortems", responder)
            return list(page["items"]) if code == 200 else []

        (draft,) = _wait("G11 postmortem draft", drafts, timeout=120)
        if draft["status"] != "draft" or draft["review_required"] is not True:
            raise AcceptanceFailed(f"postmortem is not a review-required draft: {draft}")
        if draft["resolution_basis"] != "independently_verified" or not draft["citations"]:
            raise AcceptanceFailed("postmortem basis or citations wrong")

    # Persisted-state checks the API does not expose, read as the owner.
    scope = f"tenant_id = '{tenant}' AND incident_id = '{incident}'"
    counts = {
        "workflow_runs": psql(kube, f"SELECT count(*) FROM workflow_run WHERE {scope}"),
        "mutating_executions": psql(
            kube,
            "SELECT count(*) FROM tool_execution WHERE "
            f"{scope} AND remediation_action_id IS NOT NULL AND tool_name = "
            f"'{final['tool_name']}'",
        ),
        "resolved_transitions": psql(
            kube,
            "SELECT count(*) FROM incident_event WHERE "
            f"{scope} AND event_type = 'incident.state_changed' AND payload->>'to' = 'resolved'",
        ),
        "postmortem_rows": psql(kube, f"SELECT count(*) FROM postmortem WHERE {scope}"),
        "non_draft_postmortems": psql(
            kube, "SELECT count(*) FROM postmortem WHERE status <> 'draft' OR NOT review_required"
        ),
    }
    expected = {
        "workflow_runs": "2",
        "mutating_executions": "1",
        "resolved_transitions": "1",
        "postmortem_rows": "1",
        "non_draft_postmortems": "0",
    }
    if counts != expected:
        raise AcceptanceFailed(f"persisted state differs: {counts} != {expected}")
    unresolved = []
    for citation in draft["citations"]:
        table = {
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
        }[citation["kind"]]
        found = psql(
            kube,
            f"SELECT count(*) FROM {table} WHERE tenant_id = '{tenant}' "
            f"AND id = '{citation['id']}'",
        )
        if found != "1":
            unresolved.append(citation)
    if unresolved:
        raise AcceptanceFailed(f"postmortem citations do not resolve: {unresolved}")
    evidence["postmortem"] = {
        "status": draft["status"],
        "review_required": draft["review_required"],
        "resolution_basis": draft["resolution_basis"],
        "citations": len(draft["citations"]),
        "citations_resolved": len(draft["citations"]),
        "model_claims_removed": draft["validation"]["model_claims_removed"],
        "published": False,
    }
    evidence["persisted_state"] = counts

    items = _worker_items(kube, pods)
    ours = {pod: [i for i in records if i["tenant_id"] == tenant] for pod, records in items.items()}
    by_kind: dict[str, dict[str, int]] = {}
    for records in ours.values():
        for item in records:
            bucket = by_kind.setdefault(item["kind"], {})
            bucket[item["outcome"]] = bucket.get(item["outcome"], 0) + 1
    if by_kind.get("investigation", {}).get("completed") != 1:
        raise AcceptanceFailed(f"investigation not completed exactly once: {by_kind}")
    if by_kind.get("remediation_start", {}).get("suspended") != 1:
        raise AcceptanceFailed(f"remediation not started exactly once: {by_kind}")
    if by_kind.get("postmortem", {}).get("created") != 1:
        raise AcceptanceFailed(f"postmortem not created exactly once: {by_kind}")
    evidence["worker_items"] = {
        "by_kind_and_outcome": by_kind,
        "handled_per_pod": {pod: len(records) for pod, records in ours.items()},
    }
    return evidence


def network_and_runtime(kube: Kubectl, outsider_image: str) -> dict[str, Any]:
    """Worker identity and network policy, probed from inside the cluster."""
    pod = _worker_pods(kube)[0]
    probe = (
        "import json,os,pathlib,socket,urllib.request\n"
        "import sqlalchemy as s\n"
        "assert os.getuid() == 10001\n"
        "assert not pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists()\n"
        "try:\n"
        "    open('/opt/asic-write-test', 'w')\n"
        "    raise SystemExit('root filesystem is writable')\n"
        "except OSError:\n"
        "    pass\n"
        "for path in ('/livez', '/readyz'):\n"
        "    assert urllib.request.urlopen('http://127.0.0.1:8081' + path, timeout=5).status == 200\n"
        "c = s.create_engine(os.environ['ASIC_DATABASE_URL']).connect()\n"
        "assert c.execute(s.text('SELECT rolsuper OR rolbypassrls FROM pg_roles "
        "WHERE rolname = current_user')).scalar() is False\n"
        'assert not c.execute(s.text("SELECT has_table_privilege(current_user, '
        "'alembic_version', 'UPDATE')\")).scalar()\n"
        "def reach(host, port):\n"
        "    try:\n"
        "        socket.create_connection((host, port), timeout=3)\n"
        "        return 'CONNECTED'\n"
        "    except TimeoutError:\n"
        "        return 'DENIED_BY_POLICY'\n"
        "    except OSError as error:\n"
        "        return 'ERROR ' + str(error)\n"
        "print(json.dumps({'internet': reach('1.1.1.1', 443), "
        "'api': reach('asic-api', 8000)}))\n"
    )
    out = kube("exec", f"pod/{pod}", "--", PYTHON, "-c", probe).strip().splitlines()[-1]
    reach = json.loads(out)
    if reach != {"internet": "DENIED_BY_POLICY", "api": "DENIED_BY_POLICY"}:
        raise AcceptanceFailed(f"worker egress beyond its policy: {reach}")
    worker_ip = json.loads(kube("get", f"pod/{pod}", "-o", "json"))["status"]["podIP"]
    frontend = (
        "const net=require('node:net');"
        f"const s=net.connect({{host:'{worker_ip}',port:8081}});"
        "s.setTimeout(3000);s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});"
        "s.on('timeout',()=>{console.log('DENIED_BY_POLICY');s.destroy()});"
        "s.on('error',e=>{console.log('ERROR '+e.code)})"
    )
    from_frontend = kube(
        "exec", "deployment/asic-frontend", "--", "/nodejs/bin/node", "-e", frontend
    )
    if "DENIED_BY_POLICY" not in from_frontend:
        raise AcceptanceFailed(f"frontend reached the worker: {from_frontend}")
    del outsider_image  # the smoke's outsider namespace probe covers other namespaces -> API
    return {
        "uid_10001": True,
        "service_account_token": "absent",
        "read_only_root_filesystem": True,
        "probes": "livez/readyz 200",
        "database_role": "non-owner, no BYPASSRLS, no migration privilege",
        "worker_to_db": "allowed",
        "worker_to_internet": "denied",
        "worker_to_api": "denied",
        "frontend_to_worker": "denied",
    }


def graceful_termination(kube: Kubectl) -> dict[str, Any]:
    """Delete one worker pod (SIGTERM) and require a bounded drain and a ready replacement."""
    pod = _worker_pods(kube)[0]
    began = time.monotonic()
    kube("delete", f"pod/{pod}", "--wait=true", timeout=120)
    deleted_after = round(time.monotonic() - began, 1)
    if deleted_after > 50:
        raise AcceptanceFailed(f"worker took {deleted_after}s to terminate (grace is 45s)")
    kube("rollout", "status", "deployment/asic-worker", "--timeout=180s", timeout=240)
    return {"terminated_seconds": deleted_after, "replacement_ready": True}


__all__ = ["AcceptanceFailed", "behaviour_registration", "graceful_termination", "run"]
