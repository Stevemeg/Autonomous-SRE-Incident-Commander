"""Prometheus: bounded range reads for registered metrics.

There is no PromQL argument. ``metrics.query`` takes a metric *name from an enumeration*,
and this module owns one reviewed query template per name. Labels come from the resolved
scope (service, environment) and are inserted as escaped string literals; label *names*
come from connector settings with a strict identifier pattern. A caller - or a model -
therefore cannot select a different series, a different service or an arbitrary function.

Results are normalised to the same ``timestamp=value`` sample shape the rest of the system
already consumes. Non-finite samples (``NaN``, ``+Inf``) are dropped and counted rather than
coerced into numbers; more than one series is refused as ambiguous rather than merged.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from asic.domain.enums import IntegrationKind
from asic.integrations.base import (
    AdapterRuntime,
    authorization,
    base_headers,
    endpoint_for,
    label_name_setting,
    mapping,
    require_connector,
    require_window,
    resolve_secret,
    send_json,
    sequence,
    setting,
    string_escape,
)
from asic.integrations.transport import HttpRequest, malformed, path
from asic.tools.provider import InvocationContext

MAX_POINTS: Final[int] = 500
DEFAULT_STEP_SECONDS: Final[int] = 60
SOURCE: Final[str] = "prometheus"

#: One reviewed template per registered metric. ``{selector}`` is the only substitution.
_TEMPLATES: Final[dict[str, tuple[str, str]]] = {
    "http_request_duration_p95_seconds": (
        "histogram_quantile(0.95, sum by (le) "
        "(rate(http_request_duration_seconds_bucket{selector}[5m])))",
        "seconds",
    ),
    "http_request_duration_p50_seconds": (
        "histogram_quantile(0.5, sum by (le) "
        "(rate(http_request_duration_seconds_bucket{selector}[5m])))",
        "seconds",
    ),
    "http_requests_total": ("sum(rate(http_requests_total{selector}[5m]))", "requests_per_second"),
    "http_request_errors_total": (
        "sum(rate(http_request_errors_total{selector}[5m]))",
        "errors_per_second",
    ),
    "container_memory_working_set_bytes": (
        "sum(container_memory_working_set_bytes{selector_with_container})",
        "bytes",
    ),
    "container_cpu_usage_seconds_total": (
        "sum(rate(container_cpu_usage_seconds_total{selector_with_container}[5m]))",
        "cores",
    ),
}


def build_query(
    metric: str, *, service_label: str, environment_label: str, service: str, environment: str
) -> tuple[str, str]:
    """Compose the PromQL for one registered metric. Raises ``KeyError`` for any other."""
    template, unit = _TEMPLATES[metric]
    selector = (
        f'{{{service_label}="{string_escape(service)}",'
        f'{environment_label}="{string_escape(environment)}"}}'
    )
    with_container = selector[:-1] + ',container!=""}'
    query = template.replace("{selector_with_container}", with_container).replace(
        "{selector}", selector
    )
    return query, unit


class PrometheusAdapter:
    kind = IntegrationKind.PROMETHEUS

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def query_range(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        start, end = require_window(arguments)
        metric = str(arguments["metric"])
        service = str(arguments["service"])
        environment = str(arguments["environment"])
        if metric not in _TEMPLATES:
            raise malformed(f"metric {metric!r} has no reviewed query template")
        query, unit = build_query(
            metric,
            service_label=label_name_setting(connector, "service_label", "service"),
            environment_label=label_name_setting(connector, "environment_label", "environment"),
            service=service,
            environment=environment,
        )
        range_seconds = (end - start).total_seconds()
        requested = int(arguments.get("step_seconds") or DEFAULT_STEP_SECONDS)
        step = max(requested, math.ceil(range_seconds / (MAX_POINTS - 1)))

        headers = base_headers(context)
        scheme = setting(connector, "auth_scheme", pattern="bearer|basic|none", default="bearer")
        if scheme != "none":
            secret = resolve_secret(self._runtime, connector.credential_ref, purpose="read")
            headers.append(authorization(secret, scheme))
        request = HttpRequest(
            method="GET",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("api", "v1", "query_range"),
            query=(
                ("query", query),
                ("start", f"{start.timestamp():.3f}"),
                ("end", f"{end.timestamp():.3f}"),
                ("step", str(step)),
            ),
            headers=tuple(headers),
        )
        body = mapping(send_json(self._runtime, request, context), "prometheus response")
        if body.get("status") != "success":
            raise malformed("prometheus response status is not success")
        data = mapping(body.get("data"), "prometheus data")
        if data.get("resultType") != "matrix":
            raise malformed("prometheus result is not a matrix")
        result = sequence(data.get("result"), "prometheus result")
        if len(result) > 1:
            raise malformed(
                f"prometheus returned {len(result)} series for an aggregated query; "
                "refusing to choose between them"
            )
        samples: list[str] = []
        non_finite = 0
        if result:
            values = sequence(mapping(result[0], "series").get("values"), "series values")
            if len(values) > MAX_POINTS:
                raise malformed("prometheus returned more points than requested")
            for point in values:
                if not isinstance(point, list) or len(point) != 2:
                    raise malformed("prometheus sample is not a [timestamp, value] pair")
                timestamp, raw = point
                try:
                    stamp = datetime.fromtimestamp(float(timestamp), UTC)
                    value = float(raw)
                except (TypeError, ValueError, OverflowError, OSError) as exc:
                    raise malformed("prometheus sample is not numeric") from exc
                if not math.isfinite(value):
                    non_finite += 1
                    continue
                samples.append(f"{stamp.isoformat()}={value:.6f}")
        return {
            "samples": samples,
            "unit": unit,
            "source": SOURCE,
            "schema_version": 1,
            "series": metric,
            "environment": environment,
            "service": service,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "step_seconds": step,
            "non_finite_samples": non_finite,
        }


__all__ = ["MAX_POINTS", "SOURCE", "PrometheusAdapter", "build_query"]
