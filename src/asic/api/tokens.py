"""Bearer-token verification: a production OIDC/JWKS verifier and an explicit dev verifier.

Phase 13 (ADR-0030). Authentication answers exactly one question - *who is this, and for
which tenant* - and never grants authority: permissions are reloaded from the database on
every request (:mod:`asic.api.auth`). This module therefore only verifies a token and
returns its claims.

Two verifiers exist and are deliberately not interchangeable:

* :class:`OidcJwksVerifier` - asymmetric signatures verified against an issuer's JWKS.
  This is the only verifier a production deployment may compose.
* :class:`Hs256DevelopmentVerifier` - a shared-secret verifier for local and test use. It
  declares ``is_development = True`` and composition refuses it in a production deployment.

Properties enforced here rather than trusted to a library default:

* the accepted algorithm set is explicit and asymmetric-only, so ``alg=none`` and the
  HS/RS confusion attack (an RSA public key used as an HMAC secret) are unrepresentable;
* the token's ``alg`` must also be compatible with the *type* of the selected key;
* ``kid`` is mandatory and must select exactly one key; duplicate ``kid`` values make the
  whole key set ambiguous and it is refused;
* ``jku``/``x5u``/``jwk`` headers (token-supplied key material or key location) are refused;
* issuer, audience, expiry and ``sub`` are required; ``nbf``/``iat`` are checked with a
  small, bounded clock-skew leeway;
* the JWKS fetch is bounded (HTTPS only outside loopback tests, no redirects, timeout,
  response-size ceiling, key-count ceiling) and the cache is bounded in age and size;
* every failure is a closed reason code. Token contents, key material and library
  exception text never appear in an error, a log line or a trace.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum, unique
from typing import Any, Final, Protocol

import jwt
from jwt import PyJWK
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    MissingRequiredClaimError,
)

from asic.domain.errors import DomainError, IntegrationError
from asic.integrations.transport import (
    HttpClientTransport,
    HttpRequest,
    HttpTransport,
    validate_endpoint,
)

#: A bearer token larger than this is refused before any parsing. Real OIDC access tokens
#: are well under 4 KiB; the ceiling bounds the CPU an unauthenticated caller can spend.
MAX_TOKEN_CHARS: Final[int] = 8192

#: Accepted clock skew between the issuer and this process, in seconds.
CLOCK_LEEWAY_SECONDS: Final[int] = 30

REQUIRED_CLAIMS: Final[tuple[str, ...]] = ("sub", "tenant_id", "iss", "aud", "exp")

#: Asymmetric algorithms this system will ever accept. HS* and ``none`` are absent on
#: purpose: they are not "disabled by configuration", they cannot be named.
PERMITTED_ASYMMETRIC_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}
)
DEFAULT_ALGORITHMS: Final[tuple[str, ...]] = ("RS256", "ES256")

_KEY_TYPE_FOR_ALGORITHM: Final[dict[str, str]] = {
    **dict.fromkeys(("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"), "RSA"),
    **dict.fromkeys(("ES256", "ES384"), "EC"),
}

_FORBIDDEN_HEADERS: Final[frozenset[str]] = frozenset({"jku", "x5u", "jwk", "x5c"})

#: JWKS fetch and cache bounds.
JWKS_MAX_RESPONSE_BYTES: Final[int] = 64 * 1024
JWKS_MAX_KEYS: Final[int] = 16
JWKS_TIMEOUT_SECONDS: Final[float] = 3.0
JWKS_CACHE_TTL_SECONDS: Final[float] = 300.0
#: An unknown ``kid`` triggers a refresh (key rotation), but never more often than this, so
#: a caller cannot turn bad tokens into a request flood against the identity provider.
JWKS_MIN_REFRESH_INTERVAL_SECONDS: Final[float] = 30.0
#: How long an expired cache may be served when the issuer is unreachable. Beyond this the
#: verifier fails closed rather than trusting keys nobody has confirmed recently.
JWKS_MAX_STALE_SECONDS: Final[float] = 600.0


@unique
class AuthMode(StrEnum):
    DEVELOPMENT_HS256 = "development_hs256"
    OIDC_JWKS = "oidc_jwks"


@unique
class RejectReason(StrEnum):
    """Closed vocabulary of verification failures. Safe to log and to count."""

    MALFORMED = "malformed"
    TOO_LARGE = "too_large"
    ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
    FORBIDDEN_HEADER = "forbidden_header"
    KEY_ID_MISSING = "key_id_missing"
    KEY_ID_UNKNOWN = "key_id_unknown"
    KEY_TYPE_MISMATCH = "key_type_mismatch"
    KEYS_UNAVAILABLE = "keys_unavailable"
    SIGNATURE = "signature_invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    ISSUER = "issuer_invalid"
    AUDIENCE = "audience_invalid"
    CLAIMS = "claims_invalid"


class TokenRejected(Exception):
    """Raised by a verifier. Carries only a closed reason code, never token content."""

    def __init__(self, reason: RejectReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class KeySetError(DomainError):
    """The JWKS could not be fetched or parsed into an unambiguous key set."""


class TokenVerifier(Protocol):
    @property
    def is_development(self) -> bool:
        """True for the shared-secret verifier. Production composition refuses it."""

    def verify(self, token: str) -> dict[str, Any]:
        """Return verified claims, or raise :class:`TokenRejected`."""


def _bounded(token: str) -> None:
    if not isinstance(token, str) or not token:
        raise TokenRejected(RejectReason.MALFORMED)
    if len(token) > MAX_TOKEN_CHARS:
        raise TokenRejected(RejectReason.TOO_LARGE)


def _translate(exc: Exception) -> TokenRejected:
    if isinstance(exc, ExpiredSignatureError):
        return TokenRejected(RejectReason.EXPIRED)
    if isinstance(exc, ImmatureSignatureError):
        return TokenRejected(RejectReason.NOT_YET_VALID)
    if isinstance(exc, InvalidIssuerError):
        return TokenRejected(RejectReason.ISSUER)
    if isinstance(exc, InvalidAudienceError):
        return TokenRejected(RejectReason.AUDIENCE)
    if isinstance(exc, InvalidSignatureError):
        return TokenRejected(RejectReason.SIGNATURE)
    if isinstance(exc, MissingRequiredClaimError):
        return TokenRejected(RejectReason.CLAIMS)
    return TokenRejected(RejectReason.MALFORMED)


class Hs256DevelopmentVerifier:
    """Shared-secret verifier for local development and tests only."""

    __slots__ = ("_audience", "_issuer", "_secret")

    def __init__(self, *, secret: str, issuer: str, audience: str) -> None:
        if not secret or len(secret) < 32:
            raise ValueError("the development signing secret must contain at least 32 characters")
        self._secret = secret
        self._issuer = issuer
        self._audience = audience

    @property
    def is_development(self) -> bool:
        return True

    def verify(self, token: str) -> dict[str, Any]:
        _bounded(token)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=self._issuer,
                audience=self._audience,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except Exception as exc:
            raise _translate(exc) from None
        return claims


@dataclass(frozen=True, slots=True)
class _KeySet:
    keys: Mapping[str, PyJWK]
    fetched_at: float


class JwksClient:
    """A bounded, rotation-aware JWKS cache.

    The endpoint is administrator configuration, never derived from a token. It goes
    through the same :func:`~asic.integrations.transport.validate_endpoint` policy as every
    connector: HTTPS only (plain HTTP to loopback only when a test explicitly allows it),
    no user-info, no query, no redirect following, bounded timeout and response size.
    """

    def __init__(
        self,
        url: str,
        *,
        allow_loopback_http: bool = False,
        transport: HttpTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = JWKS_CACHE_TTL_SECONDS,
        min_refresh_interval_seconds: float = JWKS_MIN_REFRESH_INTERVAL_SECONDS,
        max_stale_seconds: float = JWKS_MAX_STALE_SECONDS,
        timeout_seconds: float = JWKS_TIMEOUT_SECONDS,
        max_response_bytes: int = JWKS_MAX_RESPONSE_BYTES,
        allowed_algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    ) -> None:
        try:
            self._endpoint = validate_endpoint(url, allow_loopback_http=allow_loopback_http)
        except IntegrationError as exc:
            raise ValueError(f"invalid JWKS URL: {exc}") from None
        # The URL's path is the request path; the endpoint itself carries no base path.
        self._path = self._endpoint.base_path or "/"
        self._endpoint = replace(self._endpoint, base_path="")
        self._transport = transport or HttpClientTransport()
        self._clock = clock
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_interval_seconds
        self._max_stale = max_stale_seconds
        self._timeout = timeout_seconds
        self._max_bytes = max_response_bytes
        self._algorithms = frozenset(allowed_algorithms)
        self._keys: _KeySet | None = None
        self._last_attempt: float | None = None
        self._refreshing = False
        self._lock = threading.Lock()

    def key_for(self, kid: str) -> PyJWK:
        """Return the verification key for ``kid``, or raise :class:`TokenRejected`.

        Availability matters as much as correctness here: this sits on every authentication.
        The lock is held only to read and update state, **never across the network fetch**, so
        a slow issuer cannot stall requests whose keys are already cached. At most one thread
        refreshes at a time; while it does (or while refreshes are throttled) other callers are
        served the current key set - stale-while-revalidate, bounded by ``max_stale`` - and an
        unknown ``kid`` is simply refused.
        """
        now = self._clock()
        with self._lock:
            cached = self._keys
            if cached is not None and now - cached.fetched_at < self._ttl and kid in cached.keys:
                return cached.keys[kid]
            # Unknown kid, or an expired cache: refresh, but never more often than the
            # minimum interval (attempts are counted, so a failing issuer is not hammered).
            refresh = not self._refreshing and (
                self._last_attempt is None or now - self._last_attempt >= self._min_refresh
            )
            if refresh:
                self._last_attempt = now
                self._refreshing = True
        if refresh:
            fetched: _KeySet | None = None
            try:
                fetched = self._fetch(now)
            except KeySetError:
                fetched = None  # keep serving the last known-good set within the bound
            finally:
                with self._lock:
                    self._refreshing = False
                    if fetched is not None:
                        self._keys = fetched
                    elif self._keys is None or now - self._keys.fetched_at > self._max_stale:
                        self._keys = None
        with self._lock:
            current = self._keys
        if current is None or now - current.fetched_at > self._max_stale:
            raise TokenRejected(RejectReason.KEYS_UNAVAILABLE)
        if kid not in current.keys:
            raise TokenRejected(RejectReason.KEY_ID_UNKNOWN)
        return current.keys[kid]

    def _fetch(self, now: float) -> _KeySet:
        request = HttpRequest(method="GET", endpoint=self._endpoint, path=self._path)
        try:
            response = self._transport.send(
                request, timeout_seconds=self._timeout, max_response_bytes=self._max_bytes
            )
        except IntegrationError:
            raise KeySetError("jwks fetch failed") from None
        if response.status != 200:
            raise KeySetError("jwks endpoint did not return 200")
        try:
            document = json.loads(response.body)
        except (ValueError, UnicodeDecodeError):
            raise KeySetError("jwks is not JSON") from None
        return _KeySet(keys=self._parse(document), fetched_at=now)

    def _parse(self, document: object) -> dict[str, PyJWK]:
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise KeySetError("jwks has no key list")
        entries = document["keys"]
        if not entries or len(entries) > JWKS_MAX_KEYS:
            raise KeySetError("jwks key count is out of bounds")
        parsed: dict[str, PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise KeySetError("jwks entry is not an object")
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid or len(kid) > 128:
                raise KeySetError("jwks entry has no usable kid")
            if kid in parsed:
                # Two keys claiming one identity is ambiguous: refuse the whole set.
                raise KeySetError("jwks contains a duplicate kid")
            if entry.get("use", "sig") != "sig" or entry.get("kty") not in ("RSA", "EC"):
                # Encryption keys and unsupported types are ignored, not trusted for signing.
                continue
            try:
                parsed[kid] = PyJWK.from_dict(entry)
            except Exception:
                raise KeySetError("jwks entry is not a valid key") from None
        return parsed


class OidcJwksVerifier:
    """Asymmetric verifier bound to one issuer and one audience."""

    __slots__ = ("_algorithms", "_audience", "_issuer", "_keys")

    def __init__(
        self,
        *,
        keys: JwksClient,
        issuer: str,
        audience: str,
        algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    ) -> None:
        chosen = tuple(algorithms)
        if not chosen or not set(chosen) <= PERMITTED_ASYMMETRIC_ALGORITHMS:
            raise ValueError("accepted algorithms must be a non-empty asymmetric set")
        if not issuer or not audience:
            raise ValueError("issuer and audience are required for OIDC verification")
        self._keys = keys
        self._issuer = issuer
        self._audience = audience
        self._algorithms = frozenset(chosen)

    @property
    def is_development(self) -> bool:
        return False

    def verify(self, token: str) -> dict[str, Any]:
        _bounded(token)
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            raise TokenRejected(RejectReason.MALFORMED) from None
        if _FORBIDDEN_HEADERS & set(header):
            raise TokenRejected(RejectReason.FORBIDDEN_HEADER)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._algorithms:
            raise TokenRejected(RejectReason.ALGORITHM_NOT_ALLOWED)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenRejected(RejectReason.KEY_ID_MISSING)
        key = self._keys.key_for(kid)
        if key.key_type != _KEY_TYPE_FOR_ALGORITHM[alg]:
            raise TokenRejected(RejectReason.KEY_TYPE_MISMATCH)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=[alg],
                issuer=self._issuer,
                audience=self._audience,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except Exception as exc:
            raise _translate(exc) from None
        return claims


__all__ = [
    "CLOCK_LEEWAY_SECONDS",
    "DEFAULT_ALGORITHMS",
    "MAX_TOKEN_CHARS",
    "PERMITTED_ASYMMETRIC_ALGORITHMS",
    "AuthMode",
    "Hs256DevelopmentVerifier",
    "JwksClient",
    "KeySetError",
    "OidcJwksVerifier",
    "RejectReason",
    "TokenRejected",
    "TokenVerifier",
]
