"""Loki: bounded log retrieval through a typed selector.

There is no LogQL argument. The stream selector is composed from the resolved service and
environment; the severity filter is a closed enumeration mapped to a regular expression
this module owns; the optional ``contains`` filter is a *literal* line filter, escaped as
a string literal so it can never become a pipeline stage.

Log text is untrusted content. It is bounded here (per line and in count), control
characters are removed, and it is returned as data. The broker scans it for injection
patterns and labels the result; nothing in a log line reaches an authorization decision,
because no authorization input accepts content from a tool result.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from asic.domain.enums import IntegrationKind
from asic.integrations.base import (
    AdapterRuntime,
    authorization,
    base_headers,
    display_text,
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

SOURCE: Final[str] = "loki"
DEFAULT_LIMIT: Final[int] = 100
MAX_LIMIT: Final[int] = 200
MAX_LINE_CHARS: Final[int] = 2000

_LEVELS: Final[tuple[str, ...]] = ("debug", "info", "warn", "error", "fatal")


def build_query(
    *,
    service_label: str,
    environment_label: str,
    level_label: str,
    service: str,
    environment: str,
    min_level: str | None,
    contains: str | None,
) -> str:
    matchers = [
        f'{service_label}="{string_escape(service)}"',
        f'{environment_label}="{string_escape(environment)}"',
    ]
    if min_level is not None:
        if min_level not in _LEVELS:
            raise KeyError(min_level)
        allowed = "|".join(_LEVELS[_LEVELS.index(min_level) :])
        matchers.append(f'{level_label}=~"{allowed}"')
    query = "{" + ",".join(matchers) + "}"
    if contains:
        query += f' |= "{string_escape(contains)}"'
    return query


def _instant(nanoseconds: int) -> str:
    """Render a Loki nanosecond timestamp, or refuse it as malformed.

    The value is a vendor-supplied integer of unbounded magnitude: ``fromtimestamp`` raises
    ``OverflowError`` past the platform's ``time_t``, ``OSError`` for values the C library
    rejects outright, and ``ValueError`` outside the representable year range. All three
    are properties of the response, so all three are malformed data rather than faults.
    """
    try:
        return datetime.fromtimestamp(nanoseconds / 1_000_000_000, UTC).isoformat()
    except (OverflowError, OSError, ValueError) as exc:
        raise malformed("loki timestamp is outside the representable range") from exc


class LokiAdapter:
    kind = IntegrationKind.LOKI

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def query_range(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        start, end = require_window(arguments)
        service = str(arguments["service"])
        environment = str(arguments["environment"])
        level_label = label_name_setting(connector, "level_label", "level")
        min_level = arguments.get("min_level")
        contains = arguments.get("contains")
        if isinstance(contains, str) and ("\n" in contains or "\r" in contains):
            raise malformed("contains filter must be a single line")
        limit = min(int(arguments.get("limit") or DEFAULT_LIMIT), MAX_LIMIT)
        query = build_query(
            service_label=label_name_setting(connector, "service_label", "service"),
            environment_label=label_name_setting(connector, "environment_label", "environment"),
            level_label=level_label,
            service=service,
            environment=environment,
            min_level=str(min_level) if min_level is not None else None,
            contains=str(contains) if contains else None,
        )
        headers = base_headers(context)
        org = connector.settings.get("org_id")
        if org is not None:
            headers.append(
                ("X-Scope-OrgID", setting(connector, "org_id", pattern=r"[A-Za-z0-9_.-]{1,64}"))
            )
        scheme = setting(connector, "auth_scheme", pattern="bearer|basic|none", default="bearer")
        if scheme != "none":
            secret = resolve_secret(self._runtime, connector.credential_ref, purpose="read")
            headers.append(authorization(secret, scheme))
        request = HttpRequest(
            method="GET",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("loki", "api", "v1", "query_range"),
            query=(
                ("query", query),
                ("start", str(int(start.timestamp() * 1_000_000_000))),
                ("end", str(int(end.timestamp() * 1_000_000_000))),
                ("limit", str(limit)),
                ("direction", "backward"),
            ),
            headers=tuple(headers),
        )
        body = mapping(send_json(self._runtime, request, context), "loki response")
        if body.get("status") != "success":
            raise malformed("loki response status is not success")
        data = mapping(body.get("data"), "loki data")
        if data.get("resultType") != "streams":
            raise malformed("loki result is not a stream list")
        entries: list[tuple[int, str, str]] = []
        for stream in sequence(data.get("result"), "loki result"):
            stream_map = mapping(stream, "loki stream")
            labels = mapping(stream_map.get("stream", {}), "loki stream labels")
            level = str(labels.get(level_label, "log")).upper()[:5]
            for value in sequence(stream_map.get("values"), "loki values"):
                if not isinstance(value, list) or len(value) < 2:
                    raise malformed("loki entry is not a [timestamp, line] pair")
                try:
                    stamp = int(value[0])
                except (TypeError, ValueError) as exc:
                    raise malformed("loki timestamp is not an integer") from exc
                if not isinstance(value[1], str):
                    raise malformed("loki line is not a string")
                entries.append((stamp, level, value[1]))
        if len(entries) > MAX_LIMIT * 4:
            raise malformed("loki returned far more entries than requested")
        # Deterministic order: oldest first, ties broken by content.
        entries.sort(key=lambda item: (item[0], item[2]))
        truncated = len(entries) >= limit
        selected = entries[-limit:]
        lines: list[str] = []
        for stamp, level, text in selected:
            clean = display_text(text, limit=MAX_LINE_CHARS)
            truncated = truncated or len(clean) < len(text.strip())
            moment = _instant(stamp)
            lines.append(f"{moment} {level:<5} {service} {clean}")
        return {
            "lines": lines,
            "truncated": truncated,
            "source": SOURCE,
            "schema_version": 1,
            "environment": environment,
            "service": service,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
        }


__all__ = ["MAX_LIMIT", "SOURCE", "LokiAdapter", "build_query"]
