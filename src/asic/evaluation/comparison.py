"""Version-to-version comparison and the gate decision.

A scenario is comparable with its baseline only when the scenario digest and the evaluator
version are identical; otherwise the comparison is reported as ``not_comparable`` and the
baseline must be re-established. Silently comparing a changed scenario would report the
moved target as an improvement or a regression.

Runs in ``simulator`` and ``replay`` mode are deterministic, so any metric delta is an exact
behavioural change, not sampling noise. A live-model suite would need repetitions to
establish a noise band before any delta could be called meaningful; the harness records
``repetitions`` and refuses to label single-run live deltas as significant.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from asic.domain.enums import EvaluationGateStatus

#: Numeric metrics whose increase is worse, compared exactly in deterministic modes.
_COST_METRICS: Final[tuple[str, ...]] = ("tokens", "cost_usd", "tool_calls", "model_calls")
#: Metrics whose increase is a quality regression.
_QUALITY_WORSE_WHEN_HIGHER: Final[tuple[str, ...]] = (
    "unsupported_claim_rate",
    "unsafe_actions",
    "false_success",
)
_QUALITY_WORSE_WHEN_LOWER: Final[tuple[str, ...]] = (
    "evidence_recall",
    "rca_top1",
    "rca_top3",
    "tool_efficiency",
)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return None


def compare(current: Mapping[str, Any], baseline: Mapping[str, Any] | None) -> dict[str, Any]:
    if baseline is None:
        return {"baseline": None, "status": "no_baseline"}
    if baseline.get("evaluator_version") != current.get("evaluator_version"):
        return {
            "baseline": baseline.get("suite_run_id"),
            "status": "not_comparable",
            "reason": "evaluator version changed; re-establish the baseline",
        }
    base = {s["key"]: s for s in baseline.get("scenarios", [])}
    deterministic = current.get("execution_mode") in ("simulator", "replay")
    per_scenario: list[dict[str, Any]] = []
    new_failures: list[str] = []
    resolved: list[str] = []
    safety_regressions: list[str] = []
    quality_regressions: list[str] = []
    comparable = 0
    for scenario in current.get("scenarios", []):
        key = scenario["key"]
        previous = base.get(key)
        if previous is None:
            per_scenario.append({"key": key, "status": "new_scenario"})
            continue
        if previous.get("digest") != scenario.get("digest"):
            per_scenario.append(
                {"key": key, "status": "not_comparable", "reason": "scenario digest changed"}
            )
            continue
        comparable += 1
        entry: dict[str, Any] = {"key": key, "status": "compared", "metric_deltas": {}}
        was, now = previous.get("verdict"), scenario.get("verdict")
        ok = ("passed", "contested")
        if was in ok and now not in ok:
            new_failures.append(key)
        if was not in ok and now in ok:
            resolved.append(key)
        if len(scenario.get("zero_tolerance_failures", [])) > len(
            previous.get("zero_tolerance_failures", [])
        ):
            safety_regressions.append(key)
        before_metrics, after_metrics = previous.get("metrics", {}), scenario.get("metrics", {})
        for name in (*_COST_METRICS, *_QUALITY_WORSE_WHEN_HIGHER, *_QUALITY_WORSE_WHEN_LOWER):
            a, b = _number(before_metrics.get(name)), _number(after_metrics.get(name))
            if a is None or b is None or a == b:
                continue
            entry["metric_deltas"][name] = {"baseline": a, "current": b, "delta": round(b - a, 6)}
            if (name in _QUALITY_WORSE_WHEN_HIGHER and b > a) or (
                name in _QUALITY_WORSE_WHEN_LOWER and b < a
            ):
                quality_regressions.append(f"{key}:{name}")
                if name in ("unsafe_actions", "false_success"):
                    safety_regressions.append(f"{key}:{name}")
        per_scenario.append(entry)
    return {
        "baseline": baseline.get("suite_run_id"),
        "status": "compared",
        "deterministic": deterministic,
        "delta_significance": "exact (deterministic fixtures)"
        if deterministic
        else "not established (single live run)",
        "comparable_scenarios": comparable,
        "new_failures": sorted(new_failures),
        "resolved_failures": sorted(resolved),
        "safety_regressions": sorted(set(safety_regressions)),
        "quality_regressions": sorted(set(quality_regressions)),
        "regression_rate": round(len(new_failures) / comparable, 4) if comparable else None,
        "scenarios": per_scenario,
    }


def gate_status(report: Mapping[str, Any]) -> EvaluationGateStatus:
    scenarios = report.get("scenarios", [])
    if not scenarios or any(s.get("verdict") == "errored" for s in scenarios):
        return EvaluationGateStatus.ERRORED
    comparison = report.get("comparison") or {}
    if (
        any(s.get("verdict") not in ("passed", "contested") for s in scenarios)
        or comparison.get("new_failures")
        or comparison.get("safety_regressions")
    ):
        return EvaluationGateStatus.FAILED
    return EvaluationGateStatus.PASSED


__all__ = ["compare", "gate_status"]
