"""Bounded OpenTelemetry instrumentation for knowledge and memory.

Span attributes carry identifiers, versions, counts and digests. Metric attributes carry
only closed vocabularies - stage, outcome, reason code, exclusion reason, memory category -
never tenant ids, queries, titles or document text, so cardinality is bounded by code and
nothing a document says can become a label. Exception text is never recorded.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from time import monotonic

from opentelemetry import metrics, trace
from opentelemetry.trace import Status, StatusCode

_meter = metrics.get_meter("asic.knowledge")

stage_duration = _meter.create_histogram(
    "asic.knowledge.stage.duration", unit="s", description="Duration of a knowledge stage."
)
ingestion_outcomes = _meter.create_counter(
    "asic.knowledge.ingestion.outcomes", description="Ingestion attempts by outcome and reason."
)
versions_created = _meter.create_counter(
    "asic.knowledge.versions.created", description="Immutable document versions written."
)
chunks_per_version = _meter.create_histogram(
    "asic.knowledge.chunks.per_version", description="Chunks produced for one version."
)
embedding_calls = _meter.create_counter(
    "asic.knowledge.embedding.calls", description="Embedding batches by outcome."
)
retrievals = _meter.create_counter(
    "asic.knowledge.retrievals", description="Retrievals by mode and outcome."
)
retrieval_results = _meter.create_histogram(
    "asic.knowledge.retrieval.results", description="Results returned by one retrieval."
)
retrieval_exclusions = _meter.create_counter(
    "asic.knowledge.retrieval.exclusions",
    description="Corpus chunks excluded from a retrieval, by exclusion reason.",
)
memory_decisions = _meter.create_counter(
    "asic.memory.decisions", description="Memory write decisions by category, outcome, reason."
)


@contextmanager
def stage(name: str, **identifiers: str) -> Iterator[trace.Span]:
    """A span plus a duration sample. Identifiers become span attributes only."""
    started = monotonic()
    outcome = "ok"
    with trace.get_tracer("asic.knowledge").start_as_current_span(
        f"knowledge.{name}",
        attributes=identifiers,
        record_exception=False,
        set_status_on_exception=False,
    ) as span:
        try:
            yield span
        except BaseException:
            outcome = "error"
            span.set_status(Status(StatusCode.ERROR, f"{name}_failed"))
            raise
        finally:
            stage_duration.record(monotonic() - started, {"stage": name, "outcome": outcome})


__all__ = [
    "chunks_per_version",
    "embedding_calls",
    "ingestion_outcomes",
    "memory_decisions",
    "retrieval_exclusions",
    "retrieval_results",
    "retrievals",
    "stage",
    "stage_duration",
    "versions_created",
]
