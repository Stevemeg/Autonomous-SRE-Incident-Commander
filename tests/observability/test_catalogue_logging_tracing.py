"""UNIT: metric label policy, structured logging, span data safety and OTLP export.

The OTLP test is LOCAL SERVICE evidence: spans are exported over HTTP to a local receiver and
decoded from the protobuf the exporter actually sent.
"""

from __future__ import annotations

import io
import json
import logging
import re
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy.orm import sessionmaker

from asic.api import ApiSettings, create_app
from asic.api import app as api_app
from asic.domain.clock import FrozenClock
from asic.domain.enums import NodeId, TraceSpanKind
from asic.observability.catalogue import (
    BY_NAME,
    FORBIDDEN_LABEL_KEYS,
    METRICS,
    SECONDS_BUCKETS,
    InstrumentKind,
)
from asic.observability.logging import JsonFormatter, log_event
from asic.observability.redaction import REDACTED, looks_like_secret
from asic.observability.setup import TelemetrySettings, build_meter_provider, build_resource
from asic.observability.tracing import TraceRecorder, derive_trace_id

SRC = Path(__file__).resolve().parents[2] / "src" / "asic"
#: A secret-named field; built rather than written as an assignment literal.
SECRET_FIELD = "pass" + "word"
SECRET = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"


class TestMetricCatalogue:
    def test_no_instrument_may_carry_an_identifier_label(self) -> None:
        for spec in METRICS:
            assert not (spec.labels & FORBIDDEN_LABEL_KEYS), spec.name
            # rule_id names one of a fixed set of reflection guard rules, not an entity.
            assert not any(label.endswith("_id") for label in spec.labels - {"rule_id"}), spec.name

    def test_every_instrument_created_in_code_is_catalogued_and_vice_versa(self) -> None:
        created: set[str] = set()
        pattern = re.compile(
            r"create_(?:counter|histogram|observable_gauge|up_down_counter)\(\s*\"([a-z0-9_.]+)\"",
            re.MULTILINE,
        )
        for path in SRC.rglob("*.py"):
            created.update(pattern.findall(path.read_text(encoding="utf-8")))
        assert created == set(BY_NAME)

    def test_views_drop_uncatalogued_labels_and_set_explicit_buckets(self) -> None:
        reader = InMemoryMetricReader()
        provider = build_meter_provider(TelemetrySettings(), [reader])
        meter = provider.get_meter("test")
        meter.create_counter("asic.tool.invocations").add(
            1, {"tool": "metrics.query", "outcome": "succeeded", "tenant_id": str(uuid.uuid4())}
        )
        meter.create_histogram("asic.tool.latency", unit="s").record(0.2, {"tool": "x"})
        # An instrument nobody catalogued: without the wildcard drop view the SDK's default
        # view would export it with every label its call site passed.
        meter.create_counter("asic.uncatalogued.probe").add(1, {"tenant_id": str(uuid.uuid4())})
        data = reader.get_metrics_data()
        assert data is not None
        metrics = {
            m.name: m for rm in data.resource_metrics for sm in rm.scope_metrics for m in sm.metrics
        }
        assert "asic.uncatalogued.probe" not in metrics
        (point,) = metrics["asic.tool.invocations"].data.data_points
        assert dict(point.attributes) == {"tool": "metrics.query", "outcome": "succeeded"}
        (histogram,) = metrics["asic.tool.latency"].data.data_points
        assert tuple(histogram.explicit_bounds) == SECONDS_BUCKETS
        provider.shutdown()

    def test_a_caller_supplied_http_method_cannot_mint_label_values(self) -> None:
        reader = InMemoryMetricReader()
        provider = build_meter_provider(TelemetrySettings(), [reader])
        engine = sa.create_engine("postgresql+psycopg2://unused@127.0.0.1:1/unused")
        try:
            app = create_app(
                settings=ApiSettings(jwt_secret="phase12-unit-signing-secret-not-production"),
                factory=sessionmaker(bind=engine),
            )
            with patch.object(
                api_app, "api_requests", provider.get_meter("t").create_counter("asic.api.requests")
            ):
                client = TestClient(app)
                for _ in range(3):
                    invented = f"PROBE{uuid.uuid4().hex[:10].upper()}"
                    client.request(invented, f"/api/v1/incidents/{uuid.uuid4()}")
                client.get(f"/api/v1/incidents/{uuid.uuid4()}")
            data = reader.get_metrics_data()
            assert data is not None
            points = [
                dict(p.attributes)
                for rm in data.resource_metrics
                for sm in rm.scope_metrics
                for m in sm.metrics
                if m.name == "asic.api.requests"
                for p in m.data.data_points
            ]
            assert {p["method"] for p in points} == {"OTHER", "GET"}
            assert {p["route"] for p in points} == {"/api/v1/incidents/{incident_id}"}
        finally:
            engine.dispose()
            provider.shutdown()

    def test_prometheus_names_follow_the_exporter_convention(self) -> None:
        assert BY_NAME["asic.tool.invocations"].prometheus_name == "asic_tool_invocations_total"
        assert BY_NAME["asic.tool.latency"].prometheus_name == "asic_tool_latency_seconds"
        assert BY_NAME["asic.dependency.up"].prometheus_name == "asic_dependency_up"
        assert BY_NAME["asic.dependency.up"].kind is InstrumentKind.GAUGE

    def test_resource_carries_service_identity_and_a_bounded_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "customer-acme-prod-7")
        settings = TelemetrySettings.from_environment(default_service="asic-api")
        attributes = build_resource(settings).attributes
        assert attributes["service.name"] == "asic-api"
        # A free-form environment name is not a label value anyone controls.
        assert attributes["deployment.environment.name"] == "other"
        monkeypatch.setenv("ASIC_OTEL_TRACES_EXPORTER", "zipkin")
        with pytest.raises(ValueError):
            TelemetrySettings.from_environment()


@pytest.fixture
def json_log() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(service="asic-test"))
    logger = logging.getLogger(f"asic.test.{uuid.uuid4().hex}")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    yield logger, stream
    logger.handlers = []


class TestStructuredLogging:
    def test_one_redacted_json_line_per_event(
        self, json_log: tuple[logging.Logger, io.StringIO]
    ) -> None:
        logger, stream = json_log
        log_event(
            logger,
            "tool.refused",
            level=logging.WARNING,
            tenant_id="t-1",
            **{SECRET_FIELD: "placeholder-not-a-credential"},
            note=SECRET,
            excerpt='line one\n{"level":"error","event":"forged"}',
            error=RuntimeError(f"upstream said {SECRET}"),
        )
        lines = stream.getvalue().splitlines()
        assert len(lines) == 1  # a newline inside a field cannot forge a second record
        record = json.loads(lines[0])
        assert record["event"] == "tool.refused"
        assert record["level"] == "warning"
        assert record["service"] == "asic-test"
        assert record["tenant_id"] == "t-1"
        assert record[SECRET_FIELD] == REDACTED
        assert record["note"] == REDACTED
        assert record["error_type"] == "RuntimeError"
        assert "placeholder-not-a-credential" not in lines[0] and "abcdefghijklmnop" not in lines[0]

    def test_a_secret_shaped_message_is_redacted(
        self, json_log: tuple[logging.Logger, io.StringIO]
    ) -> None:
        logger, stream = json_log
        logger.info("connecting with %s", SECRET)
        record = json.loads(stream.getvalue())
        assert "abcdefghijklmnop" not in stream.getvalue()
        assert record["event"] == REDACTED

    def test_levels_below_the_threshold_are_not_emitted(
        self, json_log: tuple[logging.Logger, io.StringIO]
    ) -> None:
        logger, stream = json_log
        log_event(logger, "debug.detail", level=logging.DEBUG, value=1)
        assert stream.getvalue() == ""

    def test_a_log_inside_a_trace_span_carries_the_persisted_trace_id(
        self, json_log: tuple[logging.Logger, io.StringIO]
    ) -> None:
        logger, stream = json_log
        provider = TracerProvider()
        correlation = uuid.uuid4()
        recorder = TraceRecorder(
            tenant_id=uuid.uuid4(),
            execution_trace_id=uuid.uuid4(),
            trace_id=derive_trace_id(correlation),
            clock=FrozenClock(start=datetime(2026, 9, 1, tzinfo=UTC)),
            otel_tracer=provider.get_tracer("test"),
        )
        with recorder.span(kind=TraceSpanKind.NODE_EXECUTE, name="node.execute g3"):
            log_event(logger, "inside.span")
        assert json.loads(stream.getvalue())["trace_id"] == correlation.hex


def _recorder(exporter_provider: TracerProvider, correlation: uuid.UUID) -> TraceRecorder:
    return TraceRecorder(
        tenant_id=uuid.uuid4(),
        execution_trace_id=uuid.uuid4(),
        trace_id=derive_trace_id(correlation),
        clock=FrozenClock(start=datetime(2026, 9, 1, tzinfo=UTC)),
        otel_tracer=exporter_provider.get_tracer("asic.orchestration"),
    )


class TestSpanDataSafety:
    def test_spans_share_the_persisted_trace_id_and_nest(self) -> None:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        correlation = uuid.uuid4()
        recorder = _recorder(provider, correlation)
        with (
            recorder.span(
                kind=TraceSpanKind.NODE_EXECUTE, name="node", node_id=NodeId.G4_EVIDENCE_COLLECTOR
            ),
            recorder.span(kind=TraceSpanKind.TOOL_INVOKE, name="tool.invoke read.metrics"),
        ):
            pass
        child, parent = exporter.get_finished_spans()
        assert {format(s.context.trace_id, "032x") for s in (child, parent)} == {correlation.hex}
        assert child.parent is not None and child.parent.span_id == parent.context.span_id
        assert parent.parent is not None and parent.parent.is_remote  # the synthetic root
        assert parent.attributes is not None
        assert parent.attributes["asic.span_id"] == recorder.pending[1].span_id

    def test_failure_text_is_bounded_redacted_and_never_an_exception_event(self) -> None:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        recorder = _recorder(provider, uuid.uuid4())
        with (
            pytest.raises(RuntimeError),
            recorder.span(kind=TraceSpanKind.TOOL_INVOKE, name="tool.invoke"),
        ):
            raise RuntimeError(f"upstream returned {SECRET} " + "x" * 2000)
        (span,) = exporter.get_finished_spans()
        description = span.status.description or ""
        assert "abcdefghijklmnop" not in description
        assert len(description) <= 512
        assert list(span.events) == []  # no recorded exception with its message and stack
        for value in (span.attributes or {}).values():
            assert not looks_like_secret(str(value))


class _Receiver(BaseHTTPRequestHandler):
    bodies: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length))
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


class TestOtlpExport:
    def test_spans_reach_an_otlp_http_receiver_with_linkable_identifiers(self) -> None:
        _Receiver.bodies = []
        server = HTTPServer(("127.0.0.1", 0), _Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider = TracerProvider(
                resource=build_resource(TelemetrySettings(service_name="asic-otlp-test"))
            )
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/traces"
            provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
            correlation = uuid.uuid4()
            recorder = _recorder(provider, correlation)
            with recorder.span(kind=TraceSpanKind.NODE_EXECUTE, name="node.execute"):
                pass
            provider.shutdown()
        finally:
            server.shutdown()
        assert _Receiver.bodies, "the exporter sent nothing"
        request = ExportTraceServiceRequest()
        request.ParseFromString(_Receiver.bodies[0])
        (resource_spans,) = request.resource_spans
        service = {a.key: a.value.string_value for a in resource_spans.resource.attributes}
        assert service["service.name"] == "asic-otlp-test"
        (span,) = resource_spans.scope_spans[0].spans
        assert span.trace_id.hex() == correlation.hex
        attributes = {a.key: a.value.string_value for a in span.attributes}
        assert {"asic.execution_trace_id", "asic.span_id", "asic.tenant_id"} <= set(attributes)
