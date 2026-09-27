"""Phase 15: the kind chaos suite's contract, checked without a cluster.

The experiments themselves run against a disposable kind cluster
(``scripts/deployment_smoke.py --chaos``); here we prove the parts that decide pass/fail:
every experiment is fully declared before it can run, cleanup always runs, the duration bound
is enforced, and the outage arithmetic is right.
"""

from __future__ import annotations

import sys
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import chaos_experiments as chaos


def test_every_experiment_is_fully_declared_and_has_a_body() -> None:
    names = [experiment.name for experiment in chaos.EXPERIMENTS]
    assert len(names) == len(set(names))
    assert sorted(names) == sorted(chaos.BODIES)
    for experiment in chaos.EXPERIMENTS:
        for item in fields(experiment):
            value = getattr(experiment, item.name)
            assert value, f"{experiment.name}.{item.name} must be declared"
        assert 0 < experiment.max_seconds <= 900


def test_required_experiments_are_present() -> None:
    names = {experiment.name for experiment in chaos.EXPERIMENTS}
    assert {
        "api_pod_kill",
        "frontend_pod_kill",
        "postgres_restart",
        "readiness_failure_database_access_revoked",
        "otel_collector_unavailable",
        "migration_pod_overlap",
    } <= names


def test_outage_windows_are_measured_between_first_bad_and_next_good_sample() -> None:
    rows = [[0.0, 200], [0.25, 200], [0.5, 0], [0.75, 503], [1.0, 200], [1.25, 0], [1.5, 200]]
    summary = chaos.outage(rows, 1)
    assert summary["bad_samples"] == 3
    assert summary["windows"] == 2
    assert summary["longest_window_seconds"] == 0.5
    assert summary["recovered"] is True
    assert summary["codes"] == [0, 200, 503]


def test_an_unrecovered_outage_is_reported_as_such() -> None:
    summary = chaos.outage([[0.0, 200], [1.0, 503], [2.0, 503]], 1)
    assert summary["recovered"] is False
    assert summary["longest_window_seconds"] == 1.0


def test_custom_good_codes() -> None:
    summary = chaos.outage([[0.0, 401], [1.0, 503], [2.0, 403]], 1, good=(401, 403))
    assert summary["bad_samples"] == 1 and summary["recovered"]


def test_percentile() -> None:
    assert chaos.percentile([], 0.95) == 0.0
    assert chaos.percentile([5.0, 1.0, 3.0], 0.5) == 3.0
    assert chaos.percentile(list(map(float, range(1, 101))), 0.95) == 95.0


def _context(log: list[str]) -> chaos.Context:
    return chaos.Context(kube=None, migration="", application="", log=log.append)  # type: ignore[arg-type]


def _only(monkeypatch: pytest.MonkeyPatch, body: Any, cleanup: Any, max_seconds: int = 60) -> None:
    experiment = chaos.Experiment("probe", "h", "i", "f", "s", "r", max_seconds, "c")
    monkeypatch.setattr(chaos, "EXPERIMENTS", (experiment,))
    monkeypatch.setattr(chaos, "BODIES", {"probe": (body, cleanup)})


def test_the_declaration_is_printed_before_the_fault_and_cleanup_always_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log: list[str] = []
    order: list[str] = []

    def body(ctx: chaos.Context) -> dict[str, Any]:
        order.append("body")
        assert any("hypothesis: h" in line for line in log), "declared before injection"
        raise chaos.ChaosFailed("invariant violated")

    _only(monkeypatch, body, lambda ctx: order.append("cleanup"))
    with pytest.raises(chaos.ChaosFailed, match="invariant violated"):
        chaos.run_suite(_context(log))
    assert order == ["body", "cleanup"]


def test_a_cleanup_failure_after_a_body_failure_keeps_the_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def body(ctx: chaos.Context) -> dict[str, Any]:
        raise chaos.ChaosFailed("the real failure")

    def cleanup(ctx: chaos.Context) -> None:
        raise RuntimeError("cleanup broke too")

    log: list[str] = []
    _only(monkeypatch, body, cleanup)
    with pytest.raises(chaos.ChaosFailed, match="the real failure"):
        chaos.run_suite(_context(log))
    assert any("cleanup after the failure also failed" in line for line in log)


def test_the_maximum_duration_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([0.0, 61.0])
    monkeypatch.setattr(chaos.time, "monotonic", lambda: next(ticks))
    _only(monkeypatch, lambda ctx: {}, lambda ctx: None, max_seconds=60)
    with pytest.raises(chaos.ChaosFailed, match="over its 60s bound"):
        chaos.run_suite(_context([]))


def test_an_undeclared_body_cannot_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chaos, "BODIES", {**chaos.BODIES, "sneaky": (lambda c: {}, lambda c: None)})
    with pytest.raises(chaos.ChaosFailed, match="declared exactly once"):
        chaos.run_suite(_context([]))


def test_the_held_migration_job_ignores_sigterm_and_keeps_the_real_job_shape() -> None:
    import yaml

    migration = yaml.safe_dump_all(
        [
            {"kind": "Secret", "metadata": {"name": "x"}},
            {
                "kind": "Job",
                "metadata": {"name": "asic-migration"},
                "spec": {"template": {"spec": {"containers": [{"command": ["alembic"]}]}}},
            },
        ]
    )
    job = yaml.safe_load(chaos._job(migration, "r1", grace=40, hold=True))
    spec = job["spec"]["template"]["spec"]
    assert job["kind"] == "Job" and job["metadata"]["name"] == "asic-migration"
    assert spec["terminationGracePeriodSeconds"] == 40
    assert "SIG_IGN" in spec["containers"][0]["command"][-1]
    assert job["spec"]["template"]["metadata"]["annotations"]["asic/release"] == "r1"
    # The source manifest is not mutated.
    assert "alembic" in migration
