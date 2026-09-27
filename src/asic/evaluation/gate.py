"""The executable evaluation gate.

Run it against a migrated database::

    python -m asic.evaluation.gate \\
        --database-url "$ASIC_DATABASE_URL" \\
        --admin-database-url "$ASIC_MIGRATION_DATABASE_URL" \\
        --tenant-slug evaluation --suite golden --output evaluation-report.json

Exit codes are machine-readable: ``0`` passed, ``1`` failed (a check, an invariant, or a
regression against the baseline), ``2`` errored (the harness could not produce a trustworthy
result - never treated as a pass). The JSON report is written to ``--output``; a short
human-readable summary is printed. An ``--output`` that cannot be written is checked before
the suite runs and again when the report is written; either failure exits ``2`` with a one-line
reason (F-10), because a gate whose evidence was not recorded is not a trustworthy pass.

Continuous integration wiring is Phase 14. This module only provides the executable gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from asic.db.session import DATABASE_URL_ENV, MIGRATION_URL_ENV, create_app_engine
from asic.domain.enums import ExecutionMode
from asic.evaluation.corpus import SUITE_KEY
from asic.evaluation.harness import EvaluationHarness, HarnessConfig
from asic.observability.logging import configure_logging
from asic.observability.redaction import redact_value
from asic.observability.setup import TelemetrySettings, configure_telemetry

EXIT_CODES: dict[str, int] = {"passed": 0, "failed": 1, "errored": 2}


def render_summary(report: Mapping[str, Any]) -> str:
    aggregate = report.get("aggregate", {})
    comparison = report.get("comparison", {})
    lines = [
        f"evaluation gate: {str(report.get('gate_status', 'errored')).upper()}",
        f"  suite {report.get('suite_key')} v{report.get('suite_version')} | mode "
        f"{report.get('execution_mode')} | evaluator {report.get('evaluator_version')}",
        f"  {report.get('evidence_label')}",
        f"  scenarios {aggregate.get('scenarios')}: passed {aggregate.get('passed')}, failed "
        f"{aggregate.get('failed')}, errored {aggregate.get('errored')}, contested "
        f"{aggregate.get('contested')}",
        f"  unsafe actions {aggregate.get('unsafe_actions')} | false success "
        f"{aggregate.get('false_success')} | LLM judges {aggregate.get('llm_judge')}",
        f"  baseline comparison: {comparison.get('status')}"
        + (" (cross-mode)" if comparison.get("cross_mode") else "")
        + (
            f" | selection {report.get('scenario_selection')}"
            if report.get("scenario_selection")
            else ""
        ),
    ]
    for scenario in report.get("scenarios", []):
        if scenario.get("verdict") != "passed":
            lines.append(
                f"  - {scenario['key']}: {scenario['verdict']} {scenario.get('checks_failed')} "
                f"{scenario.get('error') or ''}".rstrip()
            )
    if comparison.get("new_failures"):
        lines.append(f"  new failures vs baseline: {comparison['new_failures']}")
    if comparison.get("safety_regressions"):
        lines.append(f"  safety regressions vs baseline: {comparison['safety_regressions']}")
    for label, field in (
        ("missing vs baseline (fails the gate)", "missing_scenarios"),
        ("excluded by selection", "excluded_by_selection"),
        ("not comparable (digest changed)", "not_comparable_scenarios"),
        ("metric gaps", "metric_gaps"),
    ):
        if comparison.get(field):
            lines.append(f"  {label}: {comparison[field]}")
    return "\n".join(lines)


def _write_report(path: str, report: Mapping[str, Any]) -> str | None:
    """Write the JSON report; return a one-line reason instead of raising on failure."""
    try:
        Path(path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        return f"cannot write evaluation report to {path}: {exc.strerror or type(exc).__name__}"
    return None


def _preflight_output(path: str) -> str | None:
    """Fail before spending a suite run if the report location is unusable."""
    target = Path(path)
    if target.is_dir():
        return f"cannot write evaluation report to {path}: it is a directory"
    if not target.parent.is_dir():
        return f"cannot write evaluation report to {path}: parent directory does not exist"
    try:
        with target.open("a", encoding="utf-8"):
            pass
    except OSError as exc:
        return f"cannot write evaluation report to {path}: {exc.strerror or type(exc).__name__}"
    return None


def _factory(url: str) -> Callable[[], Session]:
    engine = create_app_engine(url)

    def factory() -> Session:
        return Session(bind=engine, expire_on_commit=False, autoflush=False)

    return factory


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the evaluation suite and gate on it.")
    parser.add_argument("--database-url", default=os.environ.get(DATABASE_URL_ENV))
    parser.add_argument("--admin-database-url", default=os.environ.get(MIGRATION_URL_ENV))
    parser.add_argument("--tenant-slug", default="evaluation")
    parser.add_argument("--suite", default=SUITE_KEY, choices=("golden", "smoke"))
    parser.add_argument("--scenario", action="append", default=[], help="limit to scenario key(s)")
    parser.add_argument("--mode", default="simulator", choices=("simulator", "replay"))
    parser.add_argument("--baseline", default="latest", help="latest | none | <suite run id>")
    parser.add_argument("--output", default=None, help="write the JSON report here")
    args = parser.parse_args(argv)
    if not args.database_url or not args.admin_database_url:
        parser.error("both --database-url and --admin-database-url are required")
    if args.output and (problem := _preflight_output(args.output)):
        print(f"evaluation gate: ERRORED - {problem}", file=sys.stderr)
        return EXIT_CODES["errored"]
    # Structured logs go to stderr so stdout stays the human summary / JSON contract.
    configure_logging(service="asic-evaluation-gate", stream=sys.stderr)
    configure_telemetry(TelemetrySettings.from_environment(default_service="asic-evaluation-gate"))
    try:
        harness = EvaluationHarness(
            admin_factory=_factory(args.admin_database_url), app_factory=_factory(args.database_url)
        )
        outcome = harness.run(
            HarnessConfig(
                tenant_slug=args.tenant_slug,
                suite=args.suite,
                keys=tuple(args.scenario) or None,
                mode=ExecutionMode(args.mode),
                baseline=args.baseline,
            )
        )
    except Exception as exc:  # an errored gate is a machine-readable result, never a pass
        report: Mapping[str, Any] = {
            "gate_status": "errored",
            # Exception text can quote a connection string or vendor payload: it is redacted
            # at emission like every other diagnostic (Phase 15 secret-leak campaign).
            "error": redact_value(f"{type(exc).__name__}: {exc}"),
        }
    else:
        report = outcome.report
    print(render_summary(report) if "suite_key" in report else json.dumps(report))
    if args.output and (problem := _write_report(args.output, report)):
        print(f"evaluation gate: ERRORED - {problem}", file=sys.stderr)
        return EXIT_CODES["errored"]
    return EXIT_CODES.get(str(report.get("gate_status")), 2)


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
