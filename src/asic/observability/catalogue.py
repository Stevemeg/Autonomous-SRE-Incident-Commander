"""The metric catalogue: every instrument, its unit, and the only labels it may carry.

This module is the single source of truth for metric cardinality. The telemetry setup
builds one OpenTelemetry *view* per entry, and a view keeps only the attribute keys listed
here, so a label added at a call site without being catalogued is dropped by the SDK
rather than exported. Tests assert the catalogue, the exposition and the Prometheus rules
and dashboards all agree.

**Labels are closed vocabularies.** Tenant, incident, workflow run, user, correlation and
every other identifier are forbidden as labels (:data:`FORBIDDEN_LABEL_KEYS`): each would
make series count grow with traffic, and a tenant identifier would disclose tenancy to
anyone who can read the metrics endpoint. Per-tenant and per-incident questions are
answered from the durable records and traces, which are tenant-isolated, not from metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class InstrumentKind(StrEnum):
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"


#: Wall-clock seconds, from a millisecond round trip to a five-minute stall.
SECONDS_BUCKETS: Final[tuple[float, ...]] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
)  # fmt: skip
#: Human waits: an approval decision can take an hour.
WAIT_BUCKETS: Final[tuple[float, ...]] = (
    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0, 1800.0, 3600.0,
)  # fmt: skip
#: Small counts: iterations, chunks, results.
COUNT_BUCKETS: Final[tuple[float, ...]] = (0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 100)

#: Identifier-shaped label keys. None may appear on any instrument.
FORBIDDEN_LABEL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "tenant",
        "tenant_id",
        "incident",
        "incident_id",
        "workflow_run_id",
        "run_id",
        "user",
        "user_id",
        "actor_id",
        "approver_user_id",
        "correlation_id",
        "trace_id",
        "span_id",
        "evidence_id",
        "hypothesis_id",
        "action_id",
        "remediation_action_id",
        "tool_execution_id",
        "environment_id",
        "service_id",
        "service",
        "environment",
        "connector_id",
        "idempotency_key",
        "suite_run_id",
        "scenario_key",
        "path",
        "url",
        "query",
    }
)


@dataclass(frozen=True, slots=True)
class MetricSpec:
    name: str
    kind: InstrumentKind
    labels: frozenset[str]
    unit: str = ""
    buckets: tuple[float, ...] | None = None

    @property
    def prometheus_name(self) -> str:
        """The series name the Prometheus exporter produces for this instrument."""
        base = self.name.replace(".", "_")
        if self.unit == "s":
            base = f"{base}_seconds"
        if self.kind is InstrumentKind.COUNTER:
            return f"{base}_total"
        return base


def _spec(
    name: str,
    kind: InstrumentKind,
    *labels: str,
    unit: str = "",
    buckets: tuple[float, ...] | None = None,
) -> MetricSpec:
    return MetricSpec(name, kind, frozenset(labels), unit, buckets)


C, H, G = InstrumentKind.COUNTER, InstrumentKind.HISTOGRAM, InstrumentKind.GAUGE

METRICS: Final[tuple[MetricSpec, ...]] = (
    # --- orchestration kernel and nodes (asic.orchestration)
    _spec("asic.node.duration", H, "node", unit="s", buckets=SECONDS_BUCKETS),
    _spec("asic.node.failures", C, "node", "reason"),
    _spec("asic.schema.violations", C, "node", "tool"),
    _spec("asic.investigation.iterations", H, buckets=COUNT_BUCKETS),
    _spec("asic.budget.exhaustions", C, "budget_kind"),
    _spec("asic.workflow.checkpoints", C, "reason"),
    _spec("asic.workflow.resumes", C, "diverged"),
    _spec("asic.workflow.terminated", C, "reason"),
    _spec("asic.reflection.decisions", C, "action", "rule_id"),
    _spec("asic.hypothesis.revisions", C),
    _spec("asic.security.injection_flags", C, "source", "pattern"),
    _spec("asic.llm.calls", C, "provider", "model", "outcome"),
    # --- tool broker and integrations
    _spec("asic.tool.invocations", C, "tool", "outcome"),
    _spec("asic.tool.failures", C, "tool", "reason"),
    _spec("asic.tool.latency", H, "tool", unit="s", buckets=SECONDS_BUCKETS),
    _spec("asic.tool.refusals", C, "stage"),
    _spec("asic.integration.calls", C, "integration", "outcome", "failure_class"),
    _spec("asic.notification.failures", C, "event_type"),
    # --- ingestion (asic.ingestion)
    _spec("asic.ingestion.stages", C, "stage", "outcome"),
    _spec("asic.ingestion.duration", H, "stage", "outcome", unit="s", buckets=SECONDS_BUCKETS),
    _spec("asic.ingestion.lock.acquisitions", C, "namespace", "outcome"),
    _spec("asic.ingestion.lock.wait", H, "namespace", "outcome", unit="s", buckets=SECONDS_BUCKETS),
    # --- knowledge and memory (asic.knowledge)
    _spec(
        "asic.knowledge.stage.duration", H, "stage", "outcome", unit="s", buckets=SECONDS_BUCKETS
    ),
    _spec("asic.knowledge.ingestion.outcomes", C, "outcome", "reason"),
    _spec("asic.knowledge.versions.created", C, "document_type"),
    _spec("asic.knowledge.chunks.per_version", H, buckets=COUNT_BUCKETS),
    _spec("asic.knowledge.embedding.calls", C, "outcome"),
    _spec("asic.knowledge.retrievals", C, "mode", "outcome"),
    _spec("asic.knowledge.retrieval.results", H, "mode", buckets=COUNT_BUCKETS),
    _spec("asic.knowledge.retrieval.exclusions", C, "reason"),
    _spec("asic.memory.decisions", C, "category", "outcome", "reason"),
    # --- committed lifecycle facts (asic.lifecycle)
    _spec("asic.incidents.opened", C, "severity"),
    _spec("asic.incident.transitions", C, "to_status"),
    _spec("asic.incidents.terminated", C, "termination_reason"),
    _spec("asic.workflow.runs.started", C),
    _spec("asic.workflow.runs.finished", C, "status"),
    _spec("asic.remediation.policy_decisions", C, "verdict"),
    _spec("asic.remediation.approvals", C, "decision"),
    _spec("asic.remediation.approval.wait", H, "decision", unit="s", buckets=WAIT_BUCKETS),
    _spec("asic.remediation.action.transitions", C, "status", "risk_tier"),
    _spec("asic.remediation.verifications", C, "verdict"),
    _spec("asic.authorization.denials", C, "event_type"),
    _spec("asic.llm.usage.tokens", C, "provider", "model", "direction"),
    _spec("asic.llm.usage.cost_usd", C, "provider", "model"),
    _spec("asic.evaluation.suite_runs", C, "suite", "mode", "gate_status"),
    _spec("asic.evaluation.results", C, "mode", "verdict"),
    _spec("asic.evaluation.judge_results", C, "outcome"),
    # --- API edge and health (asic.api, asic.health)
    _spec("asic.api.requests", C, "method", "route", "status_class"),
    _spec("asic.api.request.duration", H, "method", "route", unit="s", buckets=SECONDS_BUCKETS),
    _spec("asic.dependency.up", G, "dependency"),
    _spec("asic.readiness.checks", C, "dependency", "outcome"),
)

BY_NAME: Final[dict[str, MetricSpec]] = {spec.name: spec for spec in METRICS}


def prometheus_names() -> frozenset[str]:
    """Every series family name the catalogue can produce, including histogram suffixes."""
    names: set[str] = set()
    for spec in METRICS:
        names.add(spec.prometheus_name)
        if spec.kind is InstrumentKind.HISTOGRAM:
            names.update(
                f"{spec.prometheus_name}{suffix}" for suffix in ("_bucket", "_count", "_sum")
            )
    return frozenset(names)


__all__ = [
    "BY_NAME",
    "COUNT_BUCKETS",
    "FORBIDDEN_LABEL_KEYS",
    "METRICS",
    "SECONDS_BUCKETS",
    "WAIT_BUCKETS",
    "InstrumentKind",
    "MetricSpec",
    "prometheus_names",
]
