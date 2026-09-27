"""Version-to-version comparison and the gate decision.

A scenario is comparable with its baseline only when the scenario digest and the evaluator
version are identical; otherwise the comparison is reported as ``not_comparable`` and the
baseline must be re-established. Silently comparing a changed scenario would report the
moved target as an improvement or a regression.

Runs in ``simulator`` and ``replay`` mode are deterministic, so any metric delta is an exact
behavioural change, not sampling noise. A live-model suite would need repetitions to
establish a noise band before any delta could be called meaningful; the harness records
``repetitions`` and refuses to label single-run live deltas as significant.

Completeness (Phase 15, F-09). Nothing is omitted silently:

* every baseline scenario the current run did not produce is listed. In a run restricted with
  ``--scenario`` it is ``excluded_by_selection`` (intentional, visible, gate unaffected); in a
  full run it is ``missing`` and fails the gate - a scenario disappearing from the corpus must
  be an explicit re-baseline (``--baseline none``), not a quiet shrink of the safety net;
* a tracked metric present on one side only is reported per scenario in ``metric_gaps``; a
  safety metric (``unsafe_actions``, ``false_success``) that the current run no longer
  measures is a safety regression, because "not measured" must never read as "zero";
* the baseline's execution mode and selection are recorded, and a cross-mode comparison
  (only possible with an explicit baseline id) is flagged ``cross_mode``.
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
_TRACKED: Final[tuple[str, ...]] = (
    *_COST_METRICS,
    *_QUALITY_WORSE_WHEN_HIGHER,
    *_QUALITY_WORSE_WHEN_LOWER,
)
_SAFETY_METRICS: Final[frozenset[str]] = frozenset({"unsafe_actions", "false_success"})


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
    subset = current.get("scenario_selection", "full") != "full"
    per_scenario: list[dict[str, Any]] = []
    new_failures: list[str] = []
    resolved: list[str] = []
    safety_regressions: list[str] = []
    quality_regressions: list[str] = []
    metric_gaps: list[str] = []
    new_scenarios: list[str] = []
    not_comparable: list[str] = []
    comparable = 0
    current_keys = {s["key"] for s in current.get("scenarios", [])}
    for scenario in current.get("scenarios", []):
        key = scenario["key"]
        previous = base.get(key)
        if previous is None:
            per_scenario.append({"key": key, "status": "new_scenario"})
            new_scenarios.append(key)
            continue
        if previous.get("digest") != scenario.get("digest"):
            per_scenario.append(
                {"key": key, "status": "not_comparable", "reason": "scenario digest changed"}
            )
            not_comparable.append(key)
            continue
        comparable += 1
        entry: dict[str, Any] = {
            "key": key,
            "status": "compared",
            "metric_deltas": {},
            "metric_gaps": {},
        }
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
        for name in _TRACKED:
            a, b = _number(before_metrics.get(name)), _number(after_metrics.get(name))
            if (a is None) != (b is None):
                side = "current" if b is None else "baseline"
                entry["metric_gaps"][name] = f"not measured in {side}"
                metric_gaps.append(f"{key}:{name}")
                if b is None and name in _SAFETY_METRICS:
                    safety_regressions.append(f"{key}:{name}:not_measured")
                continue
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
    baseline_only = sorted(set(base) - current_keys)
    for key in baseline_only:
        per_scenario.append(
            {
                "key": key,
                "status": "excluded_by_selection" if subset else "missing",
                "reason": "not selected for this run"
                if subset
                else "in the baseline but not produced by this full run; re-baseline explicitly",
            }
        )
    baseline_mode = baseline.get("execution_mode")
    return {
        "baseline": baseline.get("suite_run_id"),
        "status": "compared",
        "baseline_execution_mode": baseline_mode,
        "baseline_scenario_selection": baseline.get("scenario_selection", "full"),
        "cross_mode": baseline_mode != current.get("execution_mode"),
        "deterministic": deterministic,
        "delta_significance": "exact (deterministic fixtures)"
        if deterministic
        else "not established (single live run)",
        "comparable_scenarios": comparable,
        "baseline_scenarios": len(base),
        "new_scenarios": sorted(new_scenarios),
        "not_comparable_scenarios": sorted(not_comparable),
        "excluded_by_selection": baseline_only if subset else [],
        "missing_scenarios": [] if subset else baseline_only,
        "metric_gaps": sorted(metric_gaps),
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
        or comparison.get("missing_scenarios")
    ):
        return EvaluationGateStatus.FAILED
    return EvaluationGateStatus.PASSED


__all__ = ["compare", "gate_status"]
