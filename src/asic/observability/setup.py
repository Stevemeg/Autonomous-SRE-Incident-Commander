"""Process-level telemetry wiring: providers, views, exporters.

Called once by each entry point (API, workers, evaluation gate). It installs:

* a ``MeterProvider`` whose views come from :mod:`asic.observability.catalogue`: every
  catalogued instrument keeps only its allowlisted labels and gets explicit bucket
  boundaries; a label added at a call site without a catalogue entry is dropped by the SDK;
* a Prometheus reader, rendered by :func:`render_prometheus` for this application's own
  ``/metrics`` endpoint - unrelated to the Phase 10 Prometheus *adapter*, which queries a
  tenant's Prometheus as evidence;
* a ``TracerProvider`` with the service resource, exporting over OTLP/HTTP only when
  ``ASIC_OTEL_TRACES_EXPORTER=otlp`` (the endpoint comes from the standard
  ``OTEL_EXPORTER_OTLP_ENDPOINT`` / ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`` variables);
* the committed-record lifecycle listeners.

Global OpenTelemetry providers can be set only once per process, so this is idempotent: a
second call returns the handles from the first.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from opentelemetry import metrics as otel_metrics
from opentelemetry import trace as otel_trace
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader
from opentelemetry.sdk.metrics.view import (
    DropAggregation,
    ExplicitBucketHistogramAggregation,
    View,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from asic import __version__
from asic.domain.errors import IntegrationError
from asic.integrations.credentials import DEPLOYMENT_ENV_VAR
from asic.integrations.transport import validate_endpoint
from asic.observability import lifecycle
from asic.observability.catalogue import METRICS, InstrumentKind

TRACES_EXPORTER_ENV: Final[str] = "ASIC_OTEL_TRACES_EXPORTER"
SERVICE_NAME_ENV: Final[str] = "ASIC_SERVICE_NAME"
#: Resource attribute values are bounded to this set; anything else is reported as "other".
_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "test", "staging", "production", "prod"}
)


OTLP_ALLOW_INSECURE_ENV: Final[str] = "ASIC_OTLP_ALLOW_INSECURE"
_OTLP_DEFAULT_ENDPOINT: Final[str] = "http://localhost:4318"


def validate_otlp_endpoint(environ: Mapping[str, str] | None = None) -> str:
    """Validate the OTLP trace endpoint at startup (Phase 13 egress policy).

    The endpoint is operator configuration read from the standard OpenTelemetry variables.
    It must be ``https``, or plain ``http`` to loopback (a sidecar collector), or plain
    ``http`` to another host only when ``ASIC_OTLP_ALLOW_INSECURE`` is set explicitly - an
    in-cluster collector behind a service mesh that supplies mutual TLS. It may not carry
    user-info, a query or a fragment, and the shared egress host policy applies (no
    metadata, link-local or ambiguous numeric hosts). Trace bodies contain incident
    identifiers, so they are not sent in clear text across an untrusted network by accident.

    Raises:
        ValueError: the endpoint is unsafe. The URL is not echoed (it may embed a secret).
    """
    env = environ if environ is not None else os.environ
    url = (
        env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        or env.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or _OTLP_DEFAULT_ENDPOINT
    ).strip()
    insecure_ok = env.get(OTLP_ALLOW_INSECURE_ENV, "").strip().lower() in ("1", "true", "yes")
    try:
        endpoint = validate_endpoint(url, allow_loopback_http=True)
    except IntegrationError:
        # A non-loopback http endpoint is refused by the shared policy; permit it only with
        # the explicit opt-in, re-validating everything else against an https twin.
        parts = urlsplit(url)
        if parts.scheme.lower() == "http" and insecure_ok:
            try:
                validate_endpoint("https" + url[4:], allow_loopback_http=False)
            except IntegrationError:
                raise ValueError("the OTLP endpoint is not acceptable") from None
            return url
        raise ValueError(
            "the OTLP endpoint must be https, loopback http, or http with "
            f"{OTLP_ALLOW_INSECURE_ENV}=true"
        ) from None
    return f"{endpoint.scheme}://{endpoint.host}:{endpoint.port}{endpoint.base_path}"


@dataclass(frozen=True, slots=True)
class TelemetrySettings:
    service_name: str = "asic"
    deployment_environment: str = "development"
    traces_exporter: str = "none"  # none | otlp

    @classmethod
    def from_environment(cls, *, default_service: str = "asic") -> TelemetrySettings:
        environment = os.environ.get(DEPLOYMENT_ENV_VAR, "development").strip().lower()
        exporter = os.environ.get(TRACES_EXPORTER_ENV, "none").strip().lower()
        if exporter not in ("none", "otlp"):
            raise ValueError(f"{TRACES_EXPORTER_ENV} must be 'none' or 'otlp'")
        if exporter == "otlp":
            validate_otlp_endpoint()
        return cls(
            service_name=os.environ.get(SERVICE_NAME_ENV, default_service).strip()[:64]
            or default_service,
            deployment_environment=environment if environment in _ENVIRONMENTS else "other",
            traces_exporter=exporter,
        )


@dataclass(frozen=True, slots=True)
class Telemetry:
    settings: TelemetrySettings
    meter_provider: MeterProvider
    tracer_provider: TracerProvider


def build_views() -> list[View]:
    """One view per catalogued instrument: allowlisted labels, explicit buckets.

    The final wildcard view drops every instrument. The SDK applies its default view - every
    attribute kept - only to an instrument *no* view matches, so without it an instrument
    missing from the catalogue would be exported with whatever labels its call site passed.
    A catalogued instrument matches both its own view and the wildcard; the wildcard stream
    aggregates nothing, so only the catalogued stream is exported.
    """
    views: list[View] = []
    for spec in METRICS:
        aggregation = (
            ExplicitBucketHistogramAggregation(boundaries=spec.buckets)
            if spec.kind is InstrumentKind.HISTOGRAM and spec.buckets is not None
            else None
        )
        views.append(
            View(
                instrument_name=spec.name,
                attribute_keys=set(spec.labels),
                aggregation=aggregation,
            )
        )
    views.append(View(instrument_name="*", aggregation=DropAggregation()))
    return views


def build_resource(settings: TelemetrySettings) -> Resource:
    return Resource.create(
        {
            "service.name": settings.service_name,
            "service.version": __version__,
            "deployment.environment.name": settings.deployment_environment,
        }
    )


def build_meter_provider(
    settings: TelemetrySettings, readers: Sequence[MetricReader]
) -> MeterProvider:
    return MeterProvider(
        metric_readers=list(readers), resource=build_resource(settings), views=build_views()
    )


_lock = threading.Lock()
_configured: Telemetry | None = None


def configure_telemetry(
    settings: TelemetrySettings | None = None,
    *,
    extra_metric_readers: Sequence[MetricReader] = (),
    extra_span_processors: Sequence[SpanProcessor] = (),
) -> Telemetry:
    """Install global providers once. ``extra_*`` exist for tests and local tooling."""
    global _configured
    with _lock:
        if _configured is not None:
            return _configured
        resolved = settings or TelemetrySettings.from_environment()
        meter_provider = build_meter_provider(
            resolved, [PrometheusMetricReader(), *extra_metric_readers]
        )
        tracer_provider = TracerProvider(resource=build_resource(resolved))
        if resolved.traces_exporter == "otlp":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        for processor in extra_span_processors:
            tracer_provider.add_span_processor(processor)
        otel_metrics.set_meter_provider(meter_provider)
        otel_trace.set_tracer_provider(tracer_provider)
        lifecycle.install()
        _configured = Telemetry(resolved, meter_provider, tracer_provider)
        return _configured


def render_prometheus() -> tuple[bytes, str]:
    """The Prometheus text exposition of this process's metrics."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


__all__ = [
    "SERVICE_NAME_ENV",
    "TRACES_EXPORTER_ENV",
    "Telemetry",
    "TelemetrySettings",
    "build_meter_provider",
    "build_resource",
    "build_views",
    "configure_telemetry",
    "render_prometheus",
]
