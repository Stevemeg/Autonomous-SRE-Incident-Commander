"""UNIT: shipped observability configuration agrees with the code.

Every metric a rule or dashboard queries must be catalogued (or be a recording rule, or
Prometheus' own ``up``); every label it filters or groups on must be one that metric carries;
no query may use an identifier label; every alert is actionable (severity, summary,
description, an existing runbook); every SLO objective is labelled as an initial engineering
target. Syntax and alert behaviour are additionally checked with ``promtool`` and
``otelcol-contrib validate`` in the validation gate (LOCAL SERVICE).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from asic.observability.catalogue import FORBIDDEN_LABEL_KEYS, METRICS, InstrumentKind

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "configs" / "observability"
RULES = CONFIG / "prometheus" / "rules"
DASHBOARDS = CONFIG / "grafana" / "dashboards"
RUNBOOKS = REPO / "docs" / "runbooks"

EXPECTED_DASHBOARDS = {
    "asic-incident-operations",
    "asic-agent-behaviour",
    "asic-tool-broker-integrations",
    "asic-llm-usage-cost",
    "asic-remediation-safety",
    "asic-evaluation",
    "asic-api-health",
}
_SERIES = re.compile(r"\b(asic_[a-z0-9_]+|up)\b(?:\{([^}]*)\})?")
_BY = re.compile(r"\b(?:by|on|without)\s*\(([^)]*)\)")
_MATCHER = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|!=|=)")
_ALWAYS = {"le", "job", "instance"}


def _labels_by_series() -> dict[str, frozenset[str]]:
    known: dict[str, frozenset[str]] = {}
    for spec in METRICS:
        known[spec.prometheus_name] = spec.labels
        if spec.kind is InstrumentKind.HISTOGRAM:
            for suffix in ("_bucket", "_count", "_sum"):
                known[f"{spec.prometheus_name}{suffix}"] = spec.labels
    known["up"] = frozenset()
    return known


def _load_rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(RULES.glob("*.yml")):
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            rules.extend(group["rules"])
    return rules


def _dashboard_exprs() -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for path in sorted(DASHBOARDS.glob("*.json")):
        body = json.loads(path.read_text(encoding="utf-8"))
        for panel in body["panels"]:
            for target in panel.get("targets", []):
                found.append((path.stem, panel["datasource"]["type"], target["expr"]))
    return found


def _promql_exprs() -> list[str]:
    exprs = [rule["expr"] for rule in _load_rules()]
    exprs.extend(expr for _, kind, expr in _dashboard_exprs() if kind == "prometheus")
    return exprs


def _check_expr(expr: str, known: dict[str, frozenset[str]], recorded: set[str]) -> None:
    referenced = re.findall(r"\basic:[a-z0-9_:]+", expr)
    assert set(referenced) <= recorded, f"unknown recording rule in {expr!r}"
    stripped = re.sub(r"\basic:[a-z0-9_:]+", "", expr)
    series = _SERIES.findall(stripped)
    names = {name for name, _ in series}
    constant = re.fullmatch(r"\s*vector\([0-9.* ]+\)\s*", expr) is not None
    assert names or referenced or constant, f"no series in {expr!r}"
    for name, matchers in series:
        assert name in known, f"{name} is not a catalogued metric ({expr!r})"
        used = set(_MATCHER.findall(matchers))
        assert used <= known[name] | _ALWAYS, f"{name} filtered on {used - known[name]}"
        assert not used & FORBIDDEN_LABEL_KEYS
    grouping = {label.strip() for group in _BY.findall(stripped) for label in group.split(",")}
    grouping.discard("")
    allowed = set().union(*(known[name] for name in names), _ALWAYS)
    assert grouping <= allowed, f"grouping by {grouping - allowed} in {expr!r}"
    assert not grouping & FORBIDDEN_LABEL_KEYS


class TestPromql:
    def test_every_query_uses_catalogued_series_and_labels(self) -> None:
        known = _labels_by_series()
        recorded = {rule["record"] for rule in _load_rules() if "record" in rule}
        exprs = _promql_exprs()
        assert len(exprs) > 40
        for expr in exprs:
            _check_expr(expr, known, recorded)

    def test_the_checker_is_not_vacuous(self) -> None:
        known = _labels_by_series()
        for bad in (
            'sum(rate(asic_tool_invocations_total{tenant_id="t"}[5m]))',
            "sum by (incident_id) (rate(asic_tool_invocations_total[5m]))",
            "sum(rate(asic_made_up_total[5m]))",
            'sum(rate(asic_tool_invocations_total{stage="x"}[5m]))',
            "asic:not_a_recording_rule",
        ):
            with pytest.raises(AssertionError):
                _check_expr(bad, known, set())


class TestAlerts:
    def test_every_alert_is_actionable(self) -> None:
        alerts = [rule for rule in _load_rules() if "alert" in rule]
        assert len(alerts) >= 10
        names = [alert["alert"] for alert in alerts]
        assert len(names) == len(set(names))
        for alert in alerts:
            assert alert["labels"]["severity"] in {"page", "ticket"}, alert["alert"]
            assert {"slo", "invariant"} & set(alert["labels"]), alert["alert"]
            annotations = alert["annotations"]
            assert annotations["summary"] and annotations["description"], alert["alert"]
            runbook = REPO / annotations["runbook_url"]
            assert runbook.is_file(), f"{alert['alert']} links a missing runbook"
            assert runbook.parent == RUNBOOKS

    def test_every_runbook_is_linked_and_names_its_alert(self) -> None:
        alerts = [rule for rule in _load_rules() if "alert" in rule]
        linked = {Path(alert["annotations"]["runbook_url"]).name for alert in alerts}
        present = {path.name for path in RUNBOOKS.glob("*.md")} - {"README.md"}
        assert present == linked
        for alert in alerts:
            text = (REPO / alert["annotations"]["runbook_url"]).read_text(encoding="utf-8")
            assert alert["alert"] in text

    def test_objectives_are_labelled_as_initial_engineering_targets(self) -> None:
        for path in RULES.glob("*.yml"):
            assert "INITIAL ENGINEERING TARGET" in path.read_text(encoding="utf-8")
        slos = (REPO / "docs" / "observability" / "SLOS.md").read_text(encoding="utf-8")
        assert slos.count("INITIAL ENGINEERING TARGET") >= 5
        assert (CONFIG / "prometheus" / "tests" / "asic-alerts.test.yml").is_file()


class TestDashboards:
    def test_the_seven_dashboards_exist_with_unique_ids(self) -> None:
        bodies = {
            path.stem: json.loads(path.read_text(encoding="utf-8"))
            for path in DASHBOARDS.glob("*.json")
        }
        assert set(bodies) == EXPECTED_DASHBOARDS
        for stem, body in bodies.items():
            assert body["uid"] == stem
            ids = [panel["id"] for panel in body["panels"]]
            assert len(ids) == len(set(ids))
            for panel in body["panels"]:
                grid = panel["gridPos"]
                assert grid["x"] >= 0 and grid["x"] + grid["w"] <= 24

    def test_panel_datasources_are_provisioned(self) -> None:
        provisioned = yaml.safe_load(
            (
                CONFIG / "grafana" / "provisioning" / "datasources" / "asic-datasources.yml"
            ).read_text(encoding="utf-8")
        )
        uids = {source["uid"] for source in provisioned["datasources"]}
        for path in DASHBOARDS.glob("*.json"):
            for panel in json.loads(path.read_text(encoding="utf-8"))["panels"]:
                assert panel["datasource"]["uid"] in uids

    def test_log_panels_select_streams_only_by_service(self) -> None:
        for stem, kind, expr in _dashboard_exprs():
            if kind != "loki":
                continue
            selector = expr.split("}", 1)[0]
            assert re.fullmatch(r'\{service_name=~?"[^"]+"', selector), (stem, expr)
