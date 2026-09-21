"""A narrow HTTP transport with explicit failure phases.

Why the standard library's ``http.client`` rather than a client SDK: the only thing this
layer must get exactly right is *which phase failed*. A connection that was refused never
reached the external system, so a write's effect is known not to have applied; a timeout
after the request was sent may have applied. Separating ``connect``, ``send`` and
``receive`` makes that distinction precise instead of inferred from an exception message,
and no runtime dependency is added (ADR-0026).

Structural limits, all enforced here rather than trusted to adapters:

* the endpoint comes from a validated connector row, never from a caller: ``https`` only,
  no user-info, no query or fragment; plain ``http`` only to a loopback host and only
  when composition explicitly permits it (local test servers), never in production;
* methods are a closed set, paths are composed by adapters from quoted segments;
* redirects are never followed - an endpoint that redirects is misconfigured, and following
  it would send credentials somewhere nobody approved;
* the response body is read to a byte ceiling and refused beyond it.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol
from urllib.parse import quote, urlencode, urlsplit

from asic.domain.enums import IntegrationFailureClass
from asic.domain.errors import IntegrationError, IntegrationUnknownOutcome

HttpMethod = Literal["GET", "POST", "PATCH", "PUT"]

USER_AGENT: Final[str] = "asic-incident-commander/0.10"
DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024

#: Headers an adapter may set. Anything else is refused at request construction.
_ALLOWED_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "accept",
        "authorization",
        "content-type",
        "traceparent",
        "x-scope-orgid",
        "x-atlassian-token",
    }
)


@dataclass(frozen=True, slots=True)
class Endpoint:
    scheme: Literal["http", "https"]
    host: str
    port: int
    base_path: str

    def origin_label(self) -> str:
        """A non-secret label for audit: scheme and host only."""
        return f"{self.scheme}://{self.host}"


def validate_endpoint(
    url: str | None,
    *,
    allow_loopback_http: bool,
    allowed_host_suffixes: Sequence[str] = (),
) -> Endpoint:
    """Parse and constrain a connector endpoint.

    Raises:
        IntegrationError: ``configuration_error``, effect not applied.
    """
    if not url or len(url) > 512:
        raise _config("connector endpoint is not configured")
    if _URL_FORBIDDEN_CHARS.search(url):
        raise _config("connector endpoint contains control, space or backslash characters")
    parts = urlsplit(url)
    if parts.username or parts.password or "@" in parts.netloc:
        raise _config("connector endpoint must not carry credentials")
    if parts.query or parts.fragment:
        raise _config("connector endpoint must not carry a query or fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise _config("connector endpoint has no host")
    check_egress_host(host)
    try:
        parts.port  # noqa: B018 - parsing the port validates its range
    except ValueError:
        raise _config("connector endpoint has an invalid port") from None
    scheme = parts.scheme.lower()
    loopback = _is_loopback(host)
    if scheme == "http":
        if not (allow_loopback_http and loopback):
            raise _config("connector endpoint must use https")
    elif scheme != "https":
        raise _config("connector endpoint must use https")
    if (
        allowed_host_suffixes
        and not loopback
        and not any(_host_matches(host, allowed) for allowed in allowed_host_suffixes)
    ):
        raise _config("connector endpoint host is not an approved host for this integration")
    port = parts.port or (443 if scheme == "https" else 80)
    base_path = parts.path.rstrip("/")
    return Endpoint(scheme=scheme, host=host, port=port, base_path=base_path)  # type: ignore[arg-type]


#: Control characters, space and backslash never belong in an administrator-configured URL;
#: different parsers disagree about them, which is how a URL is made to mean two things.
_URL_FORBIDDEN_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x20\x7f\\]")
_NUMERIC_HOST: Final[re.Pattern[str]] = re.compile(r"[0-9a-fx.]+", re.IGNORECASE)

#: Names of cloud instance-metadata services. Reaching one from a connector would hand out
#: the node's own credentials.
_METADATA_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_METADATA_IPV6: Final[frozenset[str]] = frozenset({"fd00:ec2::254"})


def check_egress_host(host: str) -> None:
    """Refuse hosts an administrator-configured endpoint must never target (SSRF policy).

    This is application-level hygiene, not a network boundary: it refuses link-local,
    unspecified and multicast addresses (which include the ``169.254.169.254`` metadata
    endpoint, also when written as an IPv4-mapped IPv6 address), instance-metadata host
    names, non-ASCII (IDN look-alike) hosts and ambiguous numeric hosts such as
    ``2852039166`` or ``0xA9FEA9FE`` that some resolvers expand to a dotted address.
    Private (RFC 1918) and loopback ranges are *allowed*: in-cluster and on-premises
    systems are legitimate connector targets. Constraining where a process may connect,
    and defeating DNS rebinding, belongs to network policy (Phase 14), not to this check.

    Raises:
        IntegrationError: ``configuration_error``, nothing sent.
    """
    if not host.isascii() or len(host) > 253:
        raise _config("connector endpoint host must be ASCII (use punycode) and bounded")
    if host in _METADATA_HOSTS or host in _METADATA_IPV6:
        raise _config("connector endpoint targets an instance-metadata service")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if _NUMERIC_HOST.fullmatch(host) and any(ch.isdigit() for ch in host):
            raise _config("connector endpoint host is an ambiguous numeric address") from None
        return
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_link_local or address.is_unspecified or address.is_multicast:
        raise _config("connector endpoint targets a link-local, unspecified or multicast address")


def _host_matches(host: str, allowed: str) -> bool:
    """``.example.com`` matches the domain and its subdomains; ``example.com`` only itself.

    A bare suffix comparison would accept ``evilexample.com``.
    """
    if allowed.startswith("."):
        return host == allowed[1:] or host.endswith(allowed)
    return host == allowed


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def path(*segments: str) -> str:
    """Compose a URL path from segments, each percent-encoded as a single segment."""
    return "/" + "/".join(quote(segment, safe="") for segment in segments)


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: HttpMethod
    endpoint: Endpoint
    path: str
    # ``repr=False`` on everything that can carry a credential or vendor payload: the
    # default dataclass repr would print the Authorization header and request body into any
    # exception message, log line or assertion that formats a request (Phase 13, F-16).
    query: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes | None = field(default=None, repr=False)
    #: True when the request can change external state. Governs unknown-outcome handling.
    effectful: bool = False
    #: Opaque header values (credentials) - never included in any rendering of the request.
    sensitive_headers: frozenset[str] = field(default_factory=lambda: frozenset({"authorization"}))

    def __post_init__(self) -> None:
        if self.method not in ("GET", "POST", "PATCH", "PUT"):
            raise ValueError(f"method {self.method!r} is not permitted")
        if not self.path.startswith("/") or "\n" in self.path or "\r" in self.path:
            raise ValueError("request path must be absolute and single-line")
        for name, value in self.headers:
            if name.lower() not in _ALLOWED_HEADERS:
                raise ValueError(f"header {name!r} is not permitted")
            if "\n" in value or "\r" in value:
                raise ValueError("header values must be single-line")

    def target(self) -> str:
        full = f"{self.endpoint.base_path}{self.path}"
        return f"{full}?{urlencode(self.query)}" if self.query else full

    def describe(self) -> str:
        """Safe for audit and logs: method, host and path only. No query, no headers."""
        return f"{self.method} {self.endpoint.origin_label()}{self.endpoint.base_path}{self.path}"


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


class HttpTransport(Protocol):
    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ssl_context: ssl.SSLContext | None = None,
    ) -> HttpResponse:
        """Send one request, or raise a classified integration failure."""


class HttpClientTransport:
    """The real transport. Connect, send and receive failures are classified separately."""

    __slots__ = ()

    def send(
        self,
        request: HttpRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ssl_context: ssl.SSLContext | None = None,
    ) -> HttpResponse:
        endpoint = request.endpoint
        timeout = max(0.1, float(timeout_seconds))
        connection: http.client.HTTPConnection
        if endpoint.scheme == "https":
            connection = http.client.HTTPSConnection(
                endpoint.host,
                endpoint.port,
                timeout=timeout,
                context=ssl_context or ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=timeout)
        try:
            # Phase 1 - connect. Nothing has reached the external system yet.
            try:
                connection.connect()
            except TimeoutError as exc:
                raise IntegrationError(
                    f"{request.describe()}: connect timed out",
                    failure_class=IntegrationFailureClass.TIMEOUT,
                    transient=True,
                    effect_not_applied=True,
                ) from exc
            except ssl.SSLError as exc:
                raise IntegrationError(
                    f"{request.describe()}: TLS verification failed",
                    failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
                    effect_not_applied=True,
                ) from exc
            except OSError as exc:
                raise IntegrationError(
                    f"{request.describe()}: connection failed",
                    failure_class=IntegrationFailureClass.TRANSIENT_UNAVAILABLE,
                    transient=True,
                    effect_not_applied=True,
                ) from exc

            headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
            headers.update(dict(request.headers))
            if request.body is not None:
                headers["Content-Length"] = str(len(request.body))
            # Phase 2 - send, and Phase 3 - receive. From here a write may have applied.
            try:
                connection.request(
                    request.method, request.target(), body=request.body, headers=headers
                )
                response = connection.getresponse()
                body = response.read(max_response_bytes + 1)
            except (TimeoutError, OSError, http.client.HTTPException) as exc:
                if request.effectful:
                    raise IntegrationUnknownOutcome(
                        f"{request.describe()}: no trustworthy response after sending"
                    ) from exc
                raise IntegrationError(
                    f"{request.describe()}: no response",
                    failure_class=IntegrationFailureClass.TIMEOUT,
                    transient=True,
                    effect_not_applied=True,
                ) from exc
            if len(body) > max_response_bytes:
                raise IntegrationError(
                    f"{request.describe()}: response exceeded {max_response_bytes} bytes",
                    failure_class=IntegrationFailureClass.MALFORMED_RESPONSE,
                    effect_not_applied=not request.effectful,
                )
            return HttpResponse(
                status=response.status,
                headers={k.lower(): v for k, v in response.getheaders()},
                body=body,
            )
        finally:
            connection.close()


def raise_for_status(request: HttpRequest, response: HttpResponse) -> None:
    """Classify a non-2xx status. Returns normally only for 2xx.

    Vendor error bodies are never copied into the message: they may echo request content
    or tokens, and the message is persisted.
    """
    status = response.status
    if 200 <= status < 300:
        return
    label = request.describe()
    if status in (401, 407):
        raise IntegrationError(
            f"{label}: unauthorized ({status})",
            failure_class=IntegrationFailureClass.UNAUTHORIZED,
            effect_not_applied=True,
            status_code=status,
        )
    if status == 403:
        raise IntegrationError(
            f"{label}: forbidden",
            failure_class=IntegrationFailureClass.FORBIDDEN,
            effect_not_applied=True,
            status_code=status,
        )
    if status == 404:
        raise IntegrationError(
            f"{label}: not found",
            failure_class=IntegrationFailureClass.NOT_FOUND,
            effect_not_applied=True,
            status_code=status,
        )
    if status == 409:
        raise IntegrationError(
            f"{label}: conflict",
            failure_class=IntegrationFailureClass.CONFLICT,
            effect_not_applied=True,
            status_code=status,
        )
    if status == 429:
        raise IntegrationError(
            f"{label}: rate limited",
            failure_class=IntegrationFailureClass.RATE_LIMITED,
            transient=True,
            effect_not_applied=True,
            retry_after_seconds=_retry_after(response.headers.get("retry-after")),
            status_code=status,
        )
    if 300 <= status < 400:
        raise IntegrationError(
            f"{label}: redirect ({status}) refused",
            failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
            effect_not_applied=True,
            status_code=status,
        )
    if 400 <= status < 500:
        raise IntegrationError(
            f"{label}: request rejected ({status})",
            failure_class=IntegrationFailureClass.INVALID_REQUEST,
            effect_not_applied=True,
            status_code=status,
        )
    # 5xx. For a read, a known-clean transient failure. For a write, the server may have
    # applied the effect before failing: never marked as not applied.
    raise IntegrationError(
        f"{label}: upstream unavailable ({status})",
        failure_class=IntegrationFailureClass.TRANSIENT_UNAVAILABLE,
        transient=not request.effectful,
        effect_not_applied=not request.effectful,
        status_code=status,
    )


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if 0 <= seconds <= 3600 else None


def _config(message: str) -> IntegrationError:
    return IntegrationError(
        message,
        failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
        effect_not_applied=True,
    )


def malformed(message: str, *, effectful: bool = False) -> IntegrationError:
    """A 2xx response whose content cannot be trusted."""
    return IntegrationError(
        message,
        failure_class=IntegrationFailureClass.MALFORMED_RESPONSE,
        effect_not_applied=not effectful,
    )


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "Endpoint",
    "HttpClientTransport",
    "HttpMethod",
    "HttpRequest",
    "HttpResponse",
    "HttpTransport",
    "check_egress_host",
    "malformed",
    "path",
    "raise_for_status",
    "validate_endpoint",
]
