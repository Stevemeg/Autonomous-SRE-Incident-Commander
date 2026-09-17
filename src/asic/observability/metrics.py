"""OpenTelemetry metric instruments for the orchestration kernel, nodes and broker.

Every instrument here is listed in :mod:`asic.observability.catalogue`, which fixes the only
labels it may carry. Labels are closed vocabularies - node, tool, outcome, reason code -
never tenant, incident, run or user identifiers: those would grow series count with
traffic and disclose tenancy through the metrics endpoint. Lifecycle facts (incidents,
approvals, verifications, model usage, evaluation) are counted from committed records in
:mod:`asic.observability.lifecycle`, not here.

Exporters are wired by :func:`asic.observability.setup.configure_telemetry`. Without it the
API's proxy meter absorbs the calls, so instrumentation is emitted whether or not anyone is
collecting.
"""

from __future__ import annotations

from typing import Final

from opentelemetry import metrics as otel_metrics

METER_NAME: Final[str] = "asic.orchestration"

_meter = otel_metrics.get_meter(METER_NAME)

node_duration_seconds = _meter.create_histogram(
    "asic.node.duration",
    unit="s",
    description=(
        "Wall-clock seconds from the previous node boundary to this node's update, measured "
        "by the kernel (includes the node's model and tool calls, excludes the checkpoint)."
    ),
)
node_failures_total = _meter.create_counter(
    "asic.node.failures",
    description="Typed node failures, by node and reason.",
)
schema_violations_total = _meter.create_counter(
    "asic.schema.violations",
    description="Structured outputs rejected by validation, by node or tool.",
)
tool_invocations_total = _meter.create_counter(
    "asic.tool.invocations",
    description="Capability requests reaching an adapter, by tool and outcome.",
)
tool_failures_total = _meter.create_counter(
    "asic.tool.failures",
    description="Tool failures, by tool and reason.",
)
tool_latency_seconds = _meter.create_histogram(
    "asic.tool.latency",
    unit="s",
    description="Adapter round-trip duration, by tool.",
)
tool_refusals_total = _meter.create_counter(
    "asic.tool.refusals",
    description="Capability requests refused by the broker, by the pipeline stage that refused.",
)
integration_calls_total = _meter.create_counter(
    "asic.integration.calls",
    description=(
        "Native external-integration calls, by integration kind, outcome and normalised "
        "failure class. All three dimensions are closed vocabularies."
    ),
)
notification_failures_total = _meter.create_counter(
    "asic.notification.failures",
    description=(
        "Notification announcements that could not run at all (infrastructure failure), by "
        "event type. Per-destination failures are integration calls with a failure class."
    ),
)
investigation_iterations = _meter.create_histogram(
    "asic.investigation.iterations",
    description="Planning iterations consumed per run.",
)
budget_exhaustions_total = _meter.create_counter(
    "asic.budget.exhaustions",
    description="Runs terminated by a budget, by dimension.",
)
injection_flags_total = _meter.create_counter(
    "asic.security.injection_flags",
    description="Injection patterns detected in untrusted content, by source and pattern.",
)
llm_calls_total = _meter.create_counter(
    "asic.llm.calls",
    description="Model calls, by provider, model and outcome.",
)
checkpoints_total = _meter.create_counter(
    "asic.workflow.checkpoints",
    description="Checkpoints written, by reason.",
)
resumes_total = _meter.create_counter(
    "asic.workflow.resumes",
    description="Runs resumed after interruption.",
)
runs_terminated_total = _meter.create_counter(
    "asic.workflow.terminated",
    description="Runs reaching a terminal state, by termination reason.",
)
reflection_decisions_total = _meter.create_counter(
    "asic.reflection.decisions",
    description=(
        "Validated bounded-reflection decisions, by action and by the rule that produced "
        "them. Both dimensions are closed vocabularies (ReflectionAction, a small fixed set "
        "of guard rule ids)."
    ),
)
hypothesis_revisions_total = _meter.create_counter(
    "asic.hypothesis.revisions",
    description="Hypotheses superseded by a bounded-reflection revise_hypothesis decision.",
)


__all__ = [
    "METER_NAME",
    "budget_exhaustions_total",
    "checkpoints_total",
    "hypothesis_revisions_total",
    "injection_flags_total",
    "integration_calls_total",
    "investigation_iterations",
    "llm_calls_total",
    "node_duration_seconds",
    "node_failures_total",
    "notification_failures_total",
    "reflection_decisions_total",
    "resumes_total",
    "runs_terminated_total",
    "schema_violations_total",
    "tool_failures_total",
    "tool_invocations_total",
    "tool_latency_seconds",
    "tool_refusals_total",
]
