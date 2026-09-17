"""Shared fixtures for observability tests.

OpenTelemetry global providers can be installed once per process, and another test (the
evaluation gate CLI) may already have installed them. These fixtures therefore never assume
they configured telemetry first: metrics are read from the always-present Prometheus
exposition, and span capture adds an in-memory processor to whichever provider is global.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client.parser import text_string_to_metric_families

from asic.observability.setup import (
    Telemetry,
    TelemetrySettings,
    configure_telemetry,
    render_prometheus,
)


@pytest.fixture(scope="session")
def telemetry() -> Telemetry:
    return configure_telemetry(TelemetrySettings(service_name="asic-test"))


@pytest.fixture(scope="session")
def span_exporter(telemetry: Telemetry) -> InMemorySpanExporter:
    exporter = InMemorySpanExporter()
    telemetry.tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter


@pytest.fixture
def spans(span_exporter: InMemorySpanExporter) -> Iterator[InMemorySpanExporter]:
    span_exporter.clear()
    yield span_exporter
    span_exporter.clear()


def sample(name: str, **labels: str) -> float:
    """Sum of exposed samples named ``name`` whose labels include ``labels``."""
    body, _ = render_prometheus()
    total = 0.0
    for family in text_string_to_metric_families(body.decode()):
        for item in family.samples:
            if item.name == name and all(item.labels.get(k) == v for k, v in labels.items()):
                total += item.value
    return total
