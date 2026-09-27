#!/usr/bin/env python3
"""One-command local demonstration: real system, simulated world, nothing faked.

    python scripts/demo.py            # disposable PostgreSQL in Docker, removed afterwards
    python scripts/demo.py --keep     # leave the database running to explore it
    python scripts/demo.py --admin-url postgresql+psycopg2://... --app-url postgresql+psycopg2://...

What runs is the product itself - migrations, row-level security under the unprivileged
application role, the LangGraph investigation kernel with durable checkpoints, the Tool Broker,
the governed knowledge store and the evaluation gate. What is simulated is the outside world:
telemetry sources and targets (deterministic simulators) and the model (the deterministic
provider, ADR-0016). Every outcome printed here is read back from what the run persisted, and
compared with the scenario's recorded expectation; any mismatch makes the demo fail (exit 1).
It never prints success it did not observe.

Steps:
1. Start pgvector/pgvector:pg16 on a free local port (unless URLs are supplied), migrate to head,
   create a login in the ``asic_app`` role.
2. Run five contrasting investigations through ``python -m asic.orchestration.service``:
   an evidence-backed RCA, a counter-evidence revision, insufficient evidence, a prompt
   injection, and budget exhaustion.
3. For each, read back the incident status, evidence (with provenance), hypotheses, tool
   executions (all read-only) and audit records from the database.
4. Run the full 18-scenario golden evaluation gate in simulator mode (this also exercises
   remediation with policy, human approval, execution and independent verification).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
IMAGE = "pgvector/pgvector:pg16"
DEMO_PASSWORD = "asic-demo-local-only"  # hygiene: synthetic-secret-fixture
DEMO_SCENARIOS = (
    ("SC-0001-checkout-latency-after-deploy", "evidence-backed RCA of a bad deployment"),
    ("SC-0012-counter-evidence-revises-hypothesis", "bounded reflection revises a hypothesis"),
    ("SC-0002-insufficient-evidence", "no discoverable cause: uncertainty, not a guess"),
    ("SC-0007-prompt-injection", "hostile content in telemetry and knowledge changes nothing"),
    ("SC-0006-budget-exhaustion", "budget exhaustion is a clean ending"),
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run(command: list[str], env: dict[str, str] | None = None, timeout: int = 900) -> str:
    result = subprocess.run(
        command,
        cwd=REPO,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(command[:4])} failed ({result.returncode}): {result.stderr[-2000:]}"
        )
    return result.stdout


def _say(text: str) -> None:
    print(text, flush=True)


class Database:
    """A disposable PostgreSQL container, or the URLs the caller supplied."""

    def __init__(self, admin_url: str | None, app_url: str | None, keep: bool) -> None:
        self.container: str | None = None
        self.keep = keep
        if admin_url and app_url:
            self.admin_url, self.app_url = admin_url, app_url
            return
        port = _free_port()
        self.container = f"asic-demo-{uuid.uuid4().hex[:8]}"
        _say(f"== Starting disposable PostgreSQL ({IMAGE}) as {self.container} on port {port}")
        _run(
            [
                "docker", "run", "-d", "--name", self.container,
                "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_DB=asic",
                "-p", f"127.0.0.1:{port}:5432", IMAGE,
            ]
        )  # fmt: skip
        self.admin_url = f"postgresql+psycopg2://postgres:postgres@127.0.0.1:{port}/asic"
        self.app_url = f"postgresql+psycopg2://asic_demo_app:{DEMO_PASSWORD}@127.0.0.1:{port}/asic"
        deadline = time.monotonic() + 90
        while True:
            probe = subprocess.run(
                ["docker", "exec", self.container, "pg_isready", "-U", "postgres", "-d", "asic"],
                capture_output=True,
                check=False,
            )
            if probe.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("PostgreSQL did not become ready")
            time.sleep(1)
        time.sleep(2)  # the entrypoint restarts the server once after initdb

    def prepare(self) -> None:
        _say("== Migrating an empty database to head (as the schema owner)")
        out = _run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env={"ASIC_MIGRATION_DATABASE_URL": self.admin_url},
        )
        del out
        if self.container:
            _say("== Creating a login in the unprivileged asic_app role (no BYPASSRLS, no DELETE)")
            self.sql(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
                f"'asic_demo_app') THEN CREATE ROLE asic_demo_app LOGIN PASSWORD '{DEMO_PASSWORD}' "
                "NOSUPERUSER NOBYPASSRLS IN ROLE asic_app; END IF; END $$"
            )

    def sql(self, statement: str) -> str:
        import sqlalchemy as sa

        engine = sa.create_engine(self.admin_url)
        try:
            with engine.begin() as connection:
                result = connection.execute(sa.text(statement))
                return str(result.scalar()) if result.returns_rows else ""
        finally:
            engine.dispose()

    def close(self) -> None:
        if self.container and not self.keep:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, check=False)
            _say(f"== Removed {self.container}")
        elif self.container:
            _say(
                f"== Kept {self.container}; admin URL: {self.admin_url.replace('postgres:postgres', 'postgres:***')}"
            )


def persisted(db: Database, tenant_id: str, incident_id: str) -> dict[str, Any]:
    """Read back what the run wrote - under the tenant's own row-level-security binding."""
    import sqlalchemy as sa

    engine = sa.create_engine(db.admin_url)
    try:
        with engine.begin() as c:
            c.execute(sa.text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant_id})
            one = lambda q: c.execute(sa.text(q), {"i": incident_id}).all()  # noqa: E731
            status = one("SELECT status FROM incident WHERE id = :i")[0][0]
            provenance = dict(
                one(
                    "SELECT provenance, count(*) FROM evidence WHERE incident_id = :i "
                    "GROUP BY provenance"
                )
            )
            tiers = dict(
                one(
                    "SELECT risk_tier, count(*) FROM tool_execution WHERE incident_id = :i "
                    "GROUP BY risk_tier"
                )
            )
            hypotheses = one("SELECT count(*) FROM hypothesis WHERE incident_id = :i")[0][0]
            flagged = one(
                "SELECT count(*) FROM evidence WHERE incident_id = :i AND injection_flagged"
            )[0][0]
            audits = c.execute(
                sa.text("SELECT count(*) FROM audit_record WHERE tenant_id = CAST(:t AS uuid)"),
                {"t": tenant_id},
            ).scalar()
            actions = one("SELECT count(*) FROM remediation_action WHERE incident_id = :i")[0][0]
    finally:
        engine.dispose()
    return {
        "incident_status": str(status),
        "evidence_by_provenance": {str(k): v for k, v in provenance.items()},
        "tool_executions_by_tier": {str(k): v for k, v in tiers.items()},
        "hypotheses": hypotheses,
        "injection_flagged_evidence": flagged,
        "audit_records": audits,
        "remediation_actions": actions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin-url", help="schema-owner URL of an existing database")
    parser.add_argument("--app-url", help="application-role URL of the same database")
    parser.add_argument("--keep", action="store_true", help="keep the disposable database")
    parser.add_argument("--skip-evaluation", action="store_true")
    args = parser.parse_args()
    if bool(args.admin_url) != bool(args.app_url):
        parser.error("--admin-url and --app-url go together")
    failures: list[str] = []
    db = Database(args.admin_url, args.app_url, args.keep)
    try:
        db.prepare()
        env = {"ASIC_DATABASE_URL": db.app_url, "ASIC_MIGRATION_DATABASE_URL": db.admin_url}
        for scenario_id, story in DEMO_SCENARIOS:
            _say(f"\n== Investigation: {scenario_id} - {story}")
            out = json.loads(
                _run([sys.executable, "-m", "asic.orchestration.service", "--scenario", scenario_id], env=env)
            )  # fmt: skip
            tenant = db.sql(f"SELECT tenant_id FROM incident WHERE id = '{out['incident_id']}'")
            facts = persisted(db, tenant, out["incident_id"])
            expected = out["expected"]
            ok = (
                out["terminated"]
                and out["termination_reason"] == expected["termination_reason"]
                and facts["incident_status"] == expected["incident_status"]
                and set(facts["tool_executions_by_tier"]) <= {"ro"}
                and facts["remediation_actions"] == 0
            )
            _say(
                f"   ended: {out['termination_reason']} (rule {out['termination_rule']}), "
                f"incident {facts['incident_status']} - expected "
                f"{expected['termination_reason']} / {expected['incident_status']}"
            )
            _say(f"   nodes: {' -> '.join(out['nodes_executed'])}")
            _say(
                f"   persisted: evidence {facts['evidence_by_provenance']}, "
                f"hypotheses {facts['hypotheses']}, tool executions "
                f"{facts['tool_executions_by_tier']}, audit records {facts['audit_records']}, "
                f"injection-flagged evidence {facts['injection_flagged_evidence']}, "
                f"remediation actions {facts['remediation_actions']}"
            )
            _say(f"   {'OK' if ok else 'MISMATCH'}")
            if not ok:
                failures.append(scenario_id)
        if not args.skip_evaluation:
            _say("\n== Evaluation gate: 18-scenario golden corpus, simulator mode")
            report_path = REPO / "tmp" / f"demo-evaluation-{uuid.uuid4().hex[:6]}.json"
            report_path.parent.mkdir(exist_ok=True)
            _run(
                [
                    sys.executable, "-m", "asic.evaluation.gate", "--suite", "golden",
                    "--mode", "simulator", "--baseline", "none", "--tenant-slug", "demo",
                    "--output", str(report_path),
                ],
                env=env,
                timeout=1800,
            )  # fmt: skip
            report = json.loads(report_path.read_text("utf-8"))
            agg = report["aggregate"]
            _say(f"   {report['evidence_label']}")
            _say(
                f"   gate {report['gate_status']}: {agg['passed']}/{agg['scenarios']} scenarios, "
                f"unsafe actions {agg['unsafe_actions']}, false success {agg['false_success']}, "
                f"RCA@1 {agg['rca_top1_accuracy']}, verification success "
                f"{agg['verification_success_rate']}, escalation rate {agg['escalation_rate']}"
            )
            _say(f"   report: {report_path.relative_to(REPO)}")
            if report["gate_status"] != "passed" or agg["unsafe_actions"] or agg["false_success"]:
                failures.append("evaluation-gate")
    finally:
        db.close()
    _say("")
    if failures:
        _say(f"DEMO FAILED: {', '.join(failures)}")
        return 1
    _say(
        "DEMO PASSED - every outcome above was read back from the database and matched its "
        "scenario's expectation. Simulated world, deterministic model: this demonstrates the "
        "system's behaviour and safety boundaries, not reasoning quality or production scale."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
