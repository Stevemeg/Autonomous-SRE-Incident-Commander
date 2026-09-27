"""Phase 15 evaluation-harness hardening: F-09, F-10, F-12 and the explicit-baseline INFO item.

* F-09 - a comparison never omits a scenario or a metric silently, and a subset or another
  execution mode never silently becomes the ``latest`` baseline.
* F-10 - an unwritable ``--output`` is a controlled ``errored`` exit, before and after the run.
* F-12 - ``unsafe_actions`` is the exact number of unauthorised mutating executions.
* INFO - an explicit baseline id that is malformed or names nothing is refused, fast.
"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from asic.db.models import EvaluationSuiteRun
from asic.db.session import bind_tenant
from asic.domain.enums import EvaluationGateStatus, ExecutionMode
from asic.evaluation import gate
from asic.evaluation.comparison import compare, gate_status
from asic.evaluation.corpus import select
from asic.evaluation.evaluators import Evaluation, invariant_checks
from asic.evaluation.harness import HarnessConfig, HarnessRefused
from asic.evaluation.versioning import digest
from tests.evaluation.test_harness import _factory, _harness
from tests.evaluation.test_judges_comparison_evaluators import _call, _observation, _report


def _two_scenarios(**overrides: Any) -> dict[str, Any]:
    report = _report(**overrides)
    second = copy.deepcopy(report["scenarios"][0])
    second["key"] = "EV-INV-002"
    report["scenarios"].append(second)
    return report


# ---------------------------------------------------------------------------- F-09
class TestComparisonCompleteness:
    def test_a_scenario_missing_from_a_full_run_is_listed_and_fails_the_gate(self) -> None:
        baseline = _two_scenarios()
        current = _report(scenario_selection="full")
        result = compare(current, baseline)
        assert result["missing_scenarios"] == ["EV-INV-002"]
        assert {"key": "EV-INV-002", "status": "missing"}.items() <= result["scenarios"][-1].items()
        report = {**current, "comparison": result}
        assert gate_status(report) is EvaluationGateStatus.FAILED

    def test_a_subset_run_lists_unselected_scenarios_without_failing(self) -> None:
        baseline = _two_scenarios()
        current = _report(scenario_selection="subset")
        result = compare(current, baseline)
        assert result["excluded_by_selection"] == ["EV-INV-002"]
        assert result["missing_scenarios"] == []
        assert result["scenarios"][-1]["status"] == "excluded_by_selection"
        assert gate_status({**current, "comparison": result}) is EvaluationGateStatus.PASSED

    def test_new_and_digest_changed_scenarios_are_listed(self) -> None:
        current = _two_scenarios()
        current["scenarios"][0]["digest"] = "e" * 64
        result = compare(current, _report())
        assert result["new_scenarios"] == ["EV-INV-002"]
        assert result["not_comparable_scenarios"] == ["EV-INV-001"]
        assert result["baseline_scenarios"] == 1

    def test_a_metric_measured_on_one_side_only_is_an_explicit_gap(self) -> None:
        current = _report()
        del current["scenarios"][0]["metrics"]["tokens"]
        baseline = _report()
        baseline["scenarios"][0]["metrics"]["rca_top3"] = True
        result = compare(current, baseline)
        gaps = result["scenarios"][0]["metric_gaps"]
        assert gaps == {"tokens": "not measured in current", "rca_top3": "not measured in current"}
        assert result["metric_gaps"] == ["EV-INV-001:rca_top3", "EV-INV-001:tokens"]
        # Quality/cost gaps are visible but not safety regressions.
        assert result["safety_regressions"] == []

    def test_a_safety_metric_no_longer_measured_is_a_safety_regression(self) -> None:
        current = _report()
        del current["scenarios"][0]["metrics"]["unsafe_actions"]
        result = compare(current, _report())
        assert result["safety_regressions"] == ["EV-INV-001:unsafe_actions:not_measured"]
        assert gate_status({**current, "comparison": result}) is EvaluationGateStatus.FAILED

    def test_metrics_absent_on_both_sides_are_not_noise(self) -> None:
        result = compare(_report(), _report())
        assert result["metric_gaps"] == [] and result["scenarios"][0]["metric_gaps"] == {}

    def test_cross_mode_comparison_is_flagged(self) -> None:
        result = compare(_report(execution_mode="replay"), _report(execution_mode="simulator"))
        assert result["cross_mode"] is True
        assert result["baseline_execution_mode"] == "simulator"
        assert compare(_report(), _report())["cross_mode"] is False

    def test_summary_names_every_gap(self) -> None:
        baseline = _two_scenarios()
        current = _report(scenario_selection="full", suite_key="golden")
        del current["scenarios"][0]["metrics"]["tokens"]
        report = {**current, "comparison": compare(current, baseline), "aggregate": {}}
        text = gate.render_summary(report)
        assert "missing vs baseline (fails the gate): ['EV-INV-002']" in text
        assert "metric gaps: ['EV-INV-001:tokens']" in text


# ---------------------------------------------------------------------------- F-12
class TestUnsafeActionSemantics:
    def test_unsafe_actions_counts_each_unauthorised_mutation(self) -> None:
        writes = [
            _call(
                tool_name="k8s.rollback",
                capability="mutate.k8s_deployment",
                effect_class="infrastructure_mutation",
                requested_by_node="g9_remediation_executor",
                risk_tier="r1",
                remediation_action_id=uuid.uuid4(),
            )
            for _ in range(3)
        ]
        evaluation = Evaluation()
        invariant_checks(_observation(tool_calls=writes), evaluation)
        assert evaluation.counts["unsafe_actions"] == 3
        failed = [c for c in evaluation.checks if c.name == "invariant.no_unauthorised_effect"]
        assert len(failed) == 1 and not failed[0].passed  # one check, three executions

    def test_reads_and_authorised_writes_are_not_unsafe(self) -> None:
        evaluation = Evaluation()
        invariant_checks(_observation(), evaluation)
        assert evaluation.counts["unsafe_actions"] == 0


# ---------------------------------------------------------------------------- F-10
class TestUnwritableOutput:
    ARGS = ("--database-url", "postgresql://x/y", "--admin-database-url", "postgresql://x/y")

    @pytest.mark.parametrize("kind", ["missing-parent", "directory"])
    def test_an_unusable_output_path_fails_before_the_suite_runs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        kind: str,
    ) -> None:
        target = tmp_path / "absent" / "report.json" if kind == "missing-parent" else tmp_path

        def never(*_a: object, **_k: object) -> None:
            raise AssertionError("the suite must not run when the report cannot be written")

        monkeypatch.setattr(gate, "EvaluationHarness", never)
        code = gate.main([*self.ARGS, "--output", str(target)])
        assert code == gate.EXIT_CODES["errored"] == 2
        err = capsys.readouterr().err
        assert "evaluation gate: ERRORED - cannot write evaluation report" in err
        assert "Traceback" not in err

    def test_a_write_failure_after_a_passing_run_is_errored_not_passed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class Passing:
            def __init__(self) -> None:
                self.report = {"gate_status": "passed"}

        class FakeHarness:
            def __init__(self, **_kwargs: object) -> None: ...

            def run(self, _config: object) -> Passing:
                return Passing()

        monkeypatch.setattr(gate, "EvaluationHarness", FakeHarness)
        monkeypatch.setattr(gate, "configure_telemetry", lambda *_a, **_k: None)
        output = tmp_path / "report.json"
        monkeypatch.setattr(
            gate, "_write_report", lambda _p, _r: "cannot write evaluation report: disk full"
        )
        assert gate.main([*self.ARGS, "--output", str(output)]) == 2
        assert "ERRORED - cannot write evaluation report: disk full" in capsys.readouterr().err

    def test_write_report_returns_a_reason_instead_of_raising(self, tmp_path: Path) -> None:
        assert gate._write_report(str(tmp_path / "ok.json"), {"a": 1}) is None
        reason = gate._write_report(str(tmp_path), {"a": 1})  # a directory
        assert reason is not None and reason.startswith("cannot write evaluation report")


# --------------------------------------------------------- explicit and latest baselines
@pytest.mark.postgres
class TestBaselineResolution:
    def _one_run(self, owner_engine: Engine, app_engine: Engine, slug: str) -> Any:
        return _harness(owner_engine, app_engine).run(
            HarnessConfig(tenant_slug=slug, keys=("EV-INV-001",), baseline="none")
        )

    @pytest.mark.parametrize("value", ["not-a-uuid", "", "latest; DROP TABLE x"])
    def test_a_malformed_baseline_id_is_refused(
        self, owner_engine: Engine, app_engine: Engine, value: str
    ) -> None:
        slug = f"ev-bl-{uuid.uuid4().hex[:8]}"
        with pytest.raises(HarnessRefused, match="baseline must be"):
            _harness(owner_engine, app_engine).run(
                HarnessConfig(tenant_slug=slug, keys=("EV-INV-001",), baseline=value)
            )

    def test_a_nonexistent_baseline_id_is_refused_before_any_scenario_runs(
        self, owner_engine: Engine, app_engine: Engine
    ) -> None:
        slug = f"ev-bl-{uuid.uuid4().hex[:8]}"
        missing = uuid.uuid4()
        with pytest.raises(HarnessRefused, match=f"baseline suite run {missing} does not exist"):
            _harness(owner_engine, app_engine).run(
                HarnessConfig(tenant_slug=slug, keys=("EV-INV-001",), baseline=str(missing))
            )
        tenant_id = _tenant(owner_engine, slug)
        with Session(bind=owner_engine) as session:
            runs = session.scalar(
                sa.select(sa.func.count())
                .select_from(EvaluationSuiteRun)
                .where(EvaluationSuiteRun.tenant_id == tenant_id)
            )
        assert runs == 0

    def test_latest_only_selects_a_full_run_of_the_same_mode(
        self, owner_engine: Engine, app_engine: Engine
    ) -> None:
        slug = f"ev-bl-{uuid.uuid4().hex[:8]}"
        subset = self._one_run(owner_engine, app_engine, slug)
        assert subset.status == "passed"
        harness = _harness(owner_engine, app_engine)
        tenant_id = _tenant(owner_engine, slug)
        config = HarnessConfig(tenant_slug=slug, baseline="latest")
        # Only a passed SUBSET run exists: it is never a latest baseline.
        assert harness._baseline(tenant_id, config) is None

        full_keys = [g.key for g in select(None, suite="golden")]
        behaviour = uuid.UUID(subset.report["behaviour_version_id"])
        replay_full = _seed(app_engine, tenant_id, behaviour, full_keys, ExecutionMode.REPLAY)
        assert harness._baseline(tenant_id, config) is None  # another mode
        replay_config = HarnessConfig(
            tenant_slug=slug, baseline="latest", mode=ExecutionMode.REPLAY
        )
        chosen = harness._baseline(tenant_id, replay_config)
        assert chosen is not None and chosen[0] == replay_full

        simulator_full = _seed(app_engine, tenant_id, behaviour, full_keys)
        _seed(app_engine, tenant_id, behaviour, full_keys, status="failed")  # newer, failed
        chosen = harness._baseline(tenant_id, config)
        assert chosen is not None and chosen[0] == simulator_full


def _tenant(owner_engine: Engine, slug: str) -> uuid.UUID:
    with Session(bind=owner_engine) as session:
        return uuid.UUID(
            str(session.scalar(sa.text("SELECT id FROM tenant WHERE slug = :s"), {"s": slug}))
        )


def _seed(
    app_engine: Engine,
    tenant_id: uuid.UUID,
    behaviour: uuid.UUID,
    keys: list[str],
    mode: ExecutionMode = ExecutionMode.SIMULATOR,
    status: str = "passed",
) -> uuid.UUID:
    run_id = uuid.uuid4()
    report = {
        "suite_run_id": str(run_id),
        "execution_mode": mode.value,
        "scenario_selection": "full",
        "scenarios": [{"key": key} for key in keys],
        "gate_status": status,
    }
    now = datetime.now(UTC)
    with _factory(app_engine)() as session, session.begin():
        bind_tenant(session, tenant_id)
        session.add(
            EvaluationSuiteRun(
                id=run_id,
                tenant_id=tenant_id,
                suite_key="golden",
                suite_version=1,
                corpus_digest="a" * 64,
                behaviour_version_id=behaviour,
                execution_mode=mode,
                evaluator_version="seeded",
                gate_status=status,
                scenario_count=len(keys),
                report=report,
                report_digest=digest(report),
                started_at=now,
                completed_at=now,
            )
        )
    return run_id
