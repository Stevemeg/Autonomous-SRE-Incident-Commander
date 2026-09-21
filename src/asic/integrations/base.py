"""Shared adapter mechanics: connector checks, credentials, JSON, text safety, windows."""

from __future__ import annotations

import base64
import json
import re
import ssl
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from asic.domain.clock import Clock
from asic.domain.enums import IntegrationFailureClass, IntegrationKind
from asic.domain.errors import CredentialUnavailable, IntegrationError, SchemaViolation
from asic.integrations.credentials import CredentialProvider, SecretValue
from asic.integrations.transport import (
    Endpoint,
    HttpRequest,
    HttpResponse,
    HttpTransport,
    malformed,
    raise_for_status,
    validate_endpoint,
)
from asic.tools.provider import ConnectorGrant, InvocationContext

#: Longest observation window any read adapter will query.
MAX_WINDOW_SECONDS: Final[int] = 6 * 3600

_LABEL_NAME: Final[re.Pattern[str]] = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}")
#: Every C0 and C1 control (newline, tab, ESC and NEL included), DEL, the Unicode line and
#: paragraph separators, and the invisible formatting characters that reorder or hide text
#: (zero-width, bidi embeddings/overrides/isolates, BOM). Display text is single-line and
#: visible: an embedded newline could masquerade as a separate observation line, and a bidi
#: override could make a rendered line read differently from what it contains.
_CONTROL: Final[re.Pattern[str]] = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]"
)


@dataclass(frozen=True, slots=True)
class AdapterRuntime:
    """What every adapter needs, injected once by composition."""

    transport: HttpTransport
    credentials: CredentialProvider
    clock: Clock
    #: Plain-http loopback endpoints are permitted only for local test servers.
    allow_loopback_http: bool = False


def configuration_error(message: str) -> IntegrationError:
    return IntegrationError(
        message,
        failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
        effect_not_applied=True,
    )


def require_connector(context: InvocationContext, kind: IntegrationKind) -> ConnectorGrant:
    connector = context.connector
    if connector is None or connector.kind is not kind:
        raise configuration_error(f"{kind.value} call reached an adapter without its connector")
    return connector


def endpoint_for(
    runtime: AdapterRuntime,
    connector: ConnectorGrant,
    *,
    default: str | None = None,
    allowed_host_suffixes: tuple[str, ...] = (),
) -> Endpoint:
    return validate_endpoint(
        connector.endpoint_url or default,
        allow_loopback_http=runtime.allow_loopback_http,
        allowed_host_suffixes=allowed_host_suffixes,
    )


def resolve_secret(runtime: AdapterRuntime, reference: str | None, *, purpose: str) -> SecretValue:
    if reference is None:
        raise configuration_error(f"connector has no {purpose} credential reference")
    try:
        return runtime.credentials.resolve(reference)
    except CredentialUnavailable as exc:
        raise IntegrationError(
            f"{purpose} credential is unavailable",
            failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
            effect_not_applied=True,
        ) from exc


def authorization(secret: SecretValue, scheme: str) -> tuple[str, str]:
    """Build the Authorization header. The secret enters only this header value."""
    if scheme == "bearer":
        return ("Authorization", f"Bearer {secret.reveal()}")
    if scheme == "basic":
        raw = secret.reveal()
        if ":" not in raw:
            raise configuration_error("basic credential must be 'user:token'")
        return ("Authorization", "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii"))
    raise configuration_error("unsupported authentication scheme")


def setting(
    connector: ConnectorGrant,
    name: str,
    *,
    pattern: str,
    default: str | None = None,
) -> str:
    value = connector.settings.get(name, default)
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise configuration_error(f"connector setting {name!r} is missing or invalid")
    return value


def label_name_setting(connector: ConnectorGrant, name: str, default: str) -> str:
    return setting(connector, name, pattern=_LABEL_NAME.pattern, default=default)


def base_headers(context: InvocationContext) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    if context.traceparent:
        headers.append(("traceparent", context.traceparent))
    return headers


def request_timeout(context: InvocationContext) -> float:
    """Leave headroom under the broker's own deadline so the adapter answers first."""
    return float(max(1, context.timeout_seconds - 2))


def send_json(
    runtime: AdapterRuntime,
    request: HttpRequest,
    context: InvocationContext,
    *,
    ssl_context: ssl.SSLContext | None = None,
    allow_empty: bool = False,
) -> Any:
    response: HttpResponse = runtime.transport.send(
        request, timeout_seconds=request_timeout(context), ssl_context=ssl_context
    )
    raise_for_status(request, response)
    if allow_empty and not response.body.strip():
        return None
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise malformed(
            f"{request.describe()}: response is not valid JSON", effectful=request.effectful
        ) from exc
    except RecursionError as exc:
        # A vendor body nested deeply enough to exhaust the interpreter's recursion limit.
        # Untrusted input decides how deep it goes, so this is a malformed *response*, not
        # a programming error, and must classify like one rather than unwind into the
        # kernel (where a write would lose its receipt entirely).
        raise malformed(
            f"{request.describe()}: response nesting exceeds the parser's limit",
            effectful=request.effectful,
        ) from exc


def json_body(value: Mapping[str, Any] | list[Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def display_text(value: object, *, limit: int) -> str:
    """Bound and neutralise untrusted text before it is placed in an outbound record.

    Control characters are removed, Unicode is normalised (so look-alike control sequences
    collapse), and the result is truncated. Destination-specific escaping (Slack mrkdwn,
    Markdown) is applied on top by each adapter.
    """
    text = unicodedata.normalize("NFKC", str(value))
    text = _CONTROL.sub(" ", text).strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."


def require_window(arguments: Mapping[str, Any]) -> tuple[datetime, datetime]:
    start = arguments.get("window_start")
    end = arguments.get("window_end")
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        raise SchemaViolation("an observation window is required")
    start, end = start.astimezone(UTC), end.astimezone(UTC)
    if end <= start:
        raise IntegrationError(
            "observation window is empty or reversed",
            failure_class=IntegrationFailureClass.INVALID_REQUEST,
            effect_not_applied=True,
        )
    if (end - start).total_seconds() > MAX_WINDOW_SECONDS:
        raise IntegrationError(
            f"observation window exceeds {MAX_WINDOW_SECONDS} seconds",
            failure_class=IntegrationFailureClass.INVALID_REQUEST,
            effect_not_applied=True,
        )
    return start, end


def ssl_context_for(runtime: AdapterRuntime, connector: ConnectorGrant) -> ssl.SSLContext | None:
    """A custom CA bundle, when the connector names one (typical for Kubernetes)."""
    reference = connector.settings.get("ca_certificate_ref")
    if reference is None:
        return None
    if not isinstance(reference, str):
        raise configuration_error("ca_certificate_ref must be a credential reference")
    pem = resolve_secret(runtime, reference, purpose="CA certificate").reveal()
    try:
        return ssl.create_default_context(cadata=pem)
    except (ssl.SSLError, ValueError) as exc:
        raise configuration_error("CA certificate is invalid") from exc


def string_escape(value: str) -> str:
    """Escape a value for a double-quoted PromQL/LogQL string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def mapping(value: Any, what: str, *, effectful: bool = False) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise malformed(f"{what} is not an object", effectful=effectful)
    return value


def sequence(value: Any, what: str, *, effectful: bool = False) -> list[Any]:
    if not isinstance(value, list):
        raise malformed(f"{what} is not a list", effectful=effectful)
    return value


__all__ = [
    "MAX_WINDOW_SECONDS",
    "AdapterRuntime",
    "authorization",
    "base_headers",
    "configuration_error",
    "display_text",
    "endpoint_for",
    "json_body",
    "label_name_setting",
    "mapping",
    "request_timeout",
    "require_connector",
    "require_window",
    "resolve_secret",
    "send_json",
    "sequence",
    "setting",
    "ssl_context_for",
    "string_escape",
]
