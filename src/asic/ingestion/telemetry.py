"""Bounded OTel attributes; source bodies and exception messages are never exported."""

from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic

from opentelemetry import metrics, trace
from opentelemetry.trace import Status, StatusCode

_meter = metrics.get_meter("asic.ingestion")
_count = _meter.create_counter("asic.ingestion.stages")
_duration = _meter.create_histogram("asic.ingestion.duration", unit="s")


@contextmanager
def stage(name: str, **identifiers: str) -> Iterator[trace.Span]:
    started = monotonic()
    outcome = "ok"
    with trace.get_tracer("asic.ingestion").start_as_current_span(
        f"ingestion.{name}",
        attributes=identifiers,
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        try:
            yield span
        except BaseException:
            outcome = "error"
            span.set_status(Status(StatusCode.ERROR, "stage_failed"))
            raise
        finally:
            attrs = {"stage": name, "outcome": outcome}
            _count.add(1, attrs)
            _duration.record(monotonic() - started, attrs)
