"""Execution tracing: one span model for operations, replay and evaluation.

``docs/architecture/observability.md`` section 1 commits to a single artifact serving all
three consumers. That commitment is honoured here by emitting each span twice, from one
description, to two destinations with different lifetimes:

* an **OpenTelemetry span**, for live operational tooling;
* a **``trace_span`` row**, durable, tenant-scoped and queryable, which is what the
  evaluation harness will read in Phase 11 and what an operator reads after the fact.

Two decisions in here are worth their explanation.

**Span identifiers are ours, not OpenTelemetry's.** A replayed run must produce the same
span ids as the run it reproduces, and OpenTelemetry ids are random by construction. Ours
are derived from the trace and an ordinal, so a replay yields identical identifiers; the
OTel span carries ours as an attribute so the two views still join.

**The OpenTelemetry trace id is ours too.** Root spans are parented on a remote span
context carrying the derived trace id, so the trace an operator opens in the tracing backend
has the same id as the ``execution_trace`` row, which in turn names the incident, the
workflow run and - under the harness - the evaluation run. OpenTelemetry span ids remain
SDK-generated; the ``asic.span_id`` attribute joins them to the ``trace_span`` rows.

**Spans are buffered and flushed at the node boundary.** The kernel commits once per node,
so buffering means a span is written in the same transaction as the durable effects it
describes. A span written in its own transaction could survive a rolled-back node and
describe work that never happened.

Nothing here writes prompt text, tool payloads or credentials. Prompts are referenced by
version and hash; everything that does get written passes through
:mod:`asic.observability.redaction` first.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from opentelemetry import trace as otel_trace
from opentelemetry.trace import (
    NonRecordingSpan,
    Span,
    SpanContext,
    Status,
    StatusCode,
    TraceFlags,
)
from sqlalchemy.orm import Session

from asic.db.models.evaluation import TraceSpan
from asic.domain.clock import Clock
from asic.domain.enums import NodeId, SpanStatus, TerminationReason, TraceSpanKind
from asic.observability.redaction import redact_mapping, redact_value

#: Instrumentation scope name. Stable, because dashboards and sampling rules key on it.
INSTRUMENTATION_NAME = "asic.orchestration"


def derive_trace_id(correlation_id: uuid.UUID) -> str:
    """A W3C-shaped 32-hex trace id derived deterministically from the correlation id.

    Deterministic on purpose: replaying a run must land on the same trace id, so the
    reproduction and the original are comparable rather than merely similar.
    """
    return correlation_id.hex


def derive_span_id(trace_id: str, ordinal: int) -> str:
    """A 16-hex span id that is stable for a given (trace, ordinal) pair."""
    if ordinal < 0:
        raise ValueError("span ordinal must be non-negative")
    prefix = trace_id[:8]
    return f"{prefix}{ordinal:08x}"


@dataclass(slots=True)
class SpanHandle:
    """A span in flight. Mutated by the code inside the span, then sealed on exit."""

    span_id: str
    parent_span_id: str | None
    kind: TraceSpanKind
    name: str
    started_at: datetime
    node_id: NodeId | None = None
    node_version: str | None = None
    input_refs: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[uuid.UUID] = field(default_factory=list)
    tool_execution_id: uuid.UUID | None = None
    model_metadata: dict[str, Any] = field(default_factory=dict)
    prompt_version: str | None = None
    policy_version: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    decision: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    budget_snapshot: dict[str, Any] = field(default_factory=dict)
    failure_reason: str | None = None
    termination_reason: TerminationReason | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    status: SpanStatus = SpanStatus.UNSET
    ended_at: datetime | None = None
    duration_ms: int | None = None
    _otel: Span | None = None

    def set_decision(self, **values: Any) -> None:
        """Record what was decided, and the alternatives weighed.

        ``docs/architecture/observability.md`` section 3.1 requires the alternatives:
        without them tool-call efficiency can be measured but never diagnosed.
        """
        self.decision.update(redact_mapping(values))

    def set_attributes(self, **values: Any) -> None:
        self.attributes.update(redact_mapping(values))

    def set_model_call(
        self,
        *,
        provider: str,
        model_id: str,
        prompt_version: str,
        prompt_hash: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        finish_reason: str,
    ) -> None:
        """Record a model call by reference. Prompt *content* is deliberately absent."""
        self.prompt_version = prompt_version
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd
        self.model_metadata.update(
            {
                "provider": provider,
                "model_id": model_id,
                "prompt_hash": prompt_hash,
                "finish_reason": finish_reason,
            }
        )

    def fail(self, reason: str) -> None:
        self.status = SpanStatus.ERROR
        self.failure_reason = reason

    def succeed(self) -> None:
        if self.status is SpanStatus.UNSET:
            self.status = SpanStatus.OK


class TraceRecorder:
    """Creates spans, buffers them, and flushes them alongside the work they describe."""

    __slots__ = (
        "_buffer",
        "_clock",
        "_execution_trace_id",
        "_ordinal",
        "_otel_tracer",
        "_stack",
        "_tenant_id",
        "_trace_id",
    )

    def __init__(
        self,
        *,
        tenant_id: uuid.UUID,
        execution_trace_id: uuid.UUID,
        trace_id: str,
        clock: Clock,
        otel_tracer: otel_trace.Tracer | None = None,
        start_ordinal: int = 0,
    ) -> None:
        self._tenant_id = tenant_id
        self._execution_trace_id = execution_trace_id
        self._trace_id = trace_id
        self._clock = clock
        self._otel_tracer = otel_tracer or otel_trace.get_tracer(INSTRUMENTATION_NAME)
        # A resumed run continues the numbering of the trace it is resuming, because it is
        # the same trace. Restarting at zero would collide with the spans the earlier
        # attempt already wrote, which the unique constraint on (trace, span_id) catches.
        self._ordinal = start_ordinal
        self._buffer: list[SpanHandle] = []
        self._stack: list[SpanHandle] = []

    @property
    def trace_id(self) -> str:
        return self._trace_id

    @property
    def pending(self) -> tuple[SpanHandle, ...]:
        return tuple(self._buffer)

    @property
    def current(self) -> SpanHandle | None:
        return self._stack[-1] if self._stack else None

    def _next_span_id(self) -> str:
        span_id = derive_span_id(self._trace_id, self._ordinal)
        self._ordinal += 1
        return span_id

    @contextmanager
    def span(
        self,
        *,
        kind: TraceSpanKind,
        name: str,
        node_id: NodeId | None = None,
        node_version: str | None = None,
        input_refs: Mapping[str, Any] | None = None,
    ) -> Iterator[SpanHandle]:
        """Open a span, nested under whatever span is currently open.

        An exception escaping the body marks the span as an error and re-raises. A span
        that ended in an exception but was recorded as ``ok`` would make the trace a
        prettier record than the run deserved.
        """
        handle = SpanHandle(
            span_id=self._next_span_id(),
            parent_span_id=self.current.span_id if self.current else None,
            kind=kind,
            name=name,
            started_at=self._clock.now(),
            node_id=node_id,
            node_version=node_version,
            input_refs=redact_mapping(dict(input_refs or {})),
        )
        parent = self.current
        self._stack.append(handle)
        otel_span = self._otel_tracer.start_span(
            name,
            context=otel_trace.set_span_in_context(
                parent._otel if parent is not None and parent._otel is not None else self._root()
            ),
        )
        handle._otel = otel_span
        otel_span.set_attribute("asic.tenant_id", str(self._tenant_id))
        otel_span.set_attribute("asic.execution_trace_id", str(self._execution_trace_id))
        otel_span.set_attribute("asic.span_id", handle.span_id)
        otel_span.set_attribute("asic.span_kind", kind.value)
        if node_id is not None:
            otel_span.set_attribute("asic.node_id", node_id.value)
        if node_version is not None:
            otel_span.set_attribute("asic.node_version", node_version)
        try:
            with otel_trace.use_span(
                otel_span, end_on_exit=False, record_exception=False, set_status_on_exception=False
            ):
                yield handle
        except BaseException as exc:
            handle.fail(f"{type(exc).__name__}: {exc}")
            raise
        finally:
            handle.succeed()
            handle.ended_at = self._clock.now()
            handle.duration_ms = max(
                0, int((handle.ended_at - handle.started_at).total_seconds() * 1000)
            )
            self._finish_otel(handle, otel_span)
            self._stack.pop()
            self._buffer.append(handle)

    def _root(self) -> Span:
        """A remote parent carrying the derived trace id; never exported itself."""
        return NonRecordingSpan(
            SpanContext(
                trace_id=int(self._trace_id, 16),
                # Any non-zero id: the parent is synthetic and is not a recorded span.
                span_id=int(self._trace_id[16:32], 16) or 1,
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
        )

    def _finish_otel(self, handle: SpanHandle, otel_span: Span) -> None:
        if handle.status is SpanStatus.ERROR:
            # Failure reasons can quote untrusted content (a tool's error body); the exported
            # description is bounded and passes the same redaction as every other attribute.
            reason = str(redact_value((handle.failure_reason or "failed")[:256]))
            otel_span.set_status(Status(StatusCode.ERROR, reason))
        else:
            otel_span.set_status(Status(StatusCode.OK))
        if handle.termination_reason is not None:
            otel_span.set_attribute("asic.termination_reason", handle.termination_reason.value)
        if handle.confidence is not None:
            otel_span.set_attribute("asic.confidence", handle.confidence)
        if handle.tool_execution_id is not None:
            otel_span.set_attribute("asic.tool_execution_id", str(handle.tool_execution_id))
        for key, value in handle.model_metadata.items():
            if isinstance(value, (str, bool, int, float)):
                otel_span.set_attribute(f"asic.model.{key}", value)
        otel_span.end(end_time=None)

    def flush(self, session: Session) -> int:
        """Persist buffered spans. Returns how many rows were written."""
        written = 0
        for handle in self._buffer:
            session.add(
                TraceSpan(
                    tenant_id=self._tenant_id,
                    execution_trace_id=self._execution_trace_id,
                    span_id=handle.span_id,
                    parent_span_id=handle.parent_span_id,
                    kind=handle.kind,
                    name=handle.name,
                    status=handle.status,
                    node_id=handle.node_id,
                    node_version=handle.node_version,
                    started_at=handle.started_at,
                    ended_at=handle.ended_at,
                    duration_ms=handle.duration_ms,
                    input_refs=handle.input_refs,
                    evidence_refs=list(handle.evidence_refs),
                    tool_execution_id=handle.tool_execution_id,
                    model_metadata=handle.model_metadata,
                    prompt_version=handle.prompt_version,
                    policy_version=handle.policy_version,
                    input_tokens=handle.input_tokens,
                    output_tokens=handle.output_tokens,
                    cost_usd=handle.cost_usd,
                    decision=handle.decision,
                    confidence=handle.confidence,
                    budget_snapshot=handle.budget_snapshot,
                    failure_reason=handle.failure_reason,
                    termination_reason=handle.termination_reason,
                    attributes=handle.attributes,
                )
            )
            written += 1
        self._buffer.clear()
        session.flush()
        return written


__all__ = [
    "INSTRUMENTATION_NAME",
    "SpanHandle",
    "TraceRecorder",
    "derive_span_id",
    "derive_trace_id",
]
