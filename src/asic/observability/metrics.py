"""OpenTelemetry metric instruments for the orchestration kernel.

A subset of the catalogue in ``docs/architecture/observability.md`` section 4: the
instruments the read-only kernel can honestly populate today. Metrics for remediation,
approval, verification and evaluation are deliberately absent rather than present and permanently
zero - an instrument reporting zero for something that never ran is worse than no
instrument, because a dashboard cannot tell the two apart.

Every instrument is dimensioned by ``tenant_id``, ``environment`` and
``behaviour_version``, so a regression can be attributed to a version rather than merely
observed.

No exporter is configured here. Wiring an exporter is deployment configuration and belongs
to Phase 12; with no provider configured the SDK's no-op meter absorbs the calls, which
keeps the instrumentation honest - it is emitted whether or not anyone is collecting.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from opentelemetry import metrics as otel_metrics

METER_NAME: Final[str] = "asic.orchestration"

_meter = otel_metrics.get_meter(METER_NAME)

node_duration_seconds = _meter.create_histogram(
    "asic.node.duration",
    unit="s",
    description="Wall-clock duration of one node execution.",
)
node_failures_total = _meter.create_counter(
    "asic.node.failures",
    description="Typed node failures, by node and reason.",
)
schema_violations_total = _meter.create_counter(
    "asic.schema.violations",
    description="Structured outputs rejected by validation, by node.",
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
llm_tokens_total = _meter.create_counter(
    "asic.llm.tokens",
    description="Model tokens, by direction.",
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


def base_attributes(
    *, tenant_id: str, environment: str, behaviour_version: str
) -> Mapping[str, str]:
    """The dimensions every instrument carries."""
    return {
        "tenant_id": tenant_id,
        "environment": environment,
        "behaviour_version": behaviour_version,
    }


__all__ = [
    "METER_NAME",
    "base_attributes",
    "budget_exhaustions_total",
    "checkpoints_total",
    "injection_flags_total",
    "investigation_iterations",
    "llm_calls_total",
    "llm_tokens_total",
    "node_duration_seconds",
    "node_failures_total",
    "resumes_total",
    "runs_terminated_total",
    "schema_violations_total",
    "tool_failures_total",
    "tool_invocations_total",
    "tool_latency_seconds",
    "tool_refusals_total",
]
