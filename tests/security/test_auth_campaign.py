"""Phase 15 authentication campaign: token lifetime policy and boundary attacks.

``test_authentication.py`` (Phase 13) covers algorithm confusion, key handling, JWKS hardening,
rotation and leakage. This file adds what Phase 15 decided or widened:

* **P13-SEC-05, maximum token lifetime.** ``iat`` is required and ``exp - iat`` must not exceed
  the configured maximum (default 3600 s, platform range 300-5400 s). Both verifiers enforce it.
* **Claim boundary times** at exactly the clock-skew leeway.
* **Audience arrays**, **token size** at the exact ceiling, and **concurrent refresh** under an
  unknown-``kid`` storm while the issuer is slow.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from typing import Any

import jwt
import pytest

from asic.api.auth import ApiSettings, build_token_verifier
from asic.api.tokens import (
    CEILING_MAX_TOKEN_LIFETIME_SECONDS,
    CLOCK_LEEWAY_SECONDS,
    DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
    MAX_TOKEN_CHARS,
    MIN_MAX_TOKEN_LIFETIME_SECONDS,
    Hs256DevelopmentVerifier,
    JwksClient,
    OidcJwksVerifier,
    RejectReason,
    TokenRejected,
    validate_max_lifetime,
)
from tests.integrations.local_http import LocalHttpServer, Scripted, local_server
from tests.security.test_authentication import (
    AUDIENCE,
    ISSUER,
    Keys,
    jwks,
    reason,
    verifier_for,
)

pytestmark = pytest.mark.security

SECRET = "phase15-development-secret-of-sufficient-length"


@pytest.fixture
def idp() -> Iterator[LocalHttpServer]:
    with local_server() as server:
        yield server


def _lifetime_token(key: Keys, lifetime: float, **extra: Any) -> str:
    now = int(time.time())
    return key.sign({"iat": now, "exp": now + lifetime, **extra})


class TestMaximumTokenLifetime:
    def test_a_token_at_exactly_the_maximum_is_accepted(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = _lifetime_token(key, DEFAULT_MAX_TOKEN_LIFETIME_SECONDS)
        assert verifier_for(idp).verify(token)["sub"] == "alice"

    @pytest.mark.parametrize("excess", [1, 60, 86_400, 10 * 365 * 86_400])
    def test_a_longer_lived_token_is_refused(self, idp: LocalHttpServer, excess: int) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = _lifetime_token(key, DEFAULT_MAX_TOKEN_LIFETIME_SECONDS + excess)
        assert reason(verifier_for(idp), token) is RejectReason.LIFETIME

    def test_iat_is_required(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        assert reason(verifier_for(idp), key.sign({"iat": None})) is RejectReason.CLAIMS

    @pytest.mark.parametrize("iat", ["yesterday", True, [1], {"t": 1}])
    def test_a_non_numeric_iat_is_refused(self, idp: LocalHttpServer, iat: object) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign({"iat": iat})
        assert reason(verifier_for(idp), token) in {RejectReason.CLAIMS, RejectReason.MALFORMED}

    def test_expiry_not_after_issuance_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        now = int(time.time())
        for exp in (now, now - 5):
            token = key.sign({"iat": now, "exp": exp + 20})  # exp - iat = 20 or 15: fine
            assert verifier_for(idp).verify(token)
            token = key.sign({"iat": now + 10, "exp": exp + 10})  # exp <= iat
            assert reason(verifier_for(idp), token) is RejectReason.CLAIMS

    def test_backdated_iat_cannot_launder_a_long_lived_token(self, idp: LocalHttpServer) -> None:
        """A long-lived token stays long-lived however far back ``iat`` is placed."""
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        now = int(time.time())
        token = key.sign({"iat": now - 86_000, "exp": now + 600})
        assert reason(verifier_for(idp), token) is RejectReason.LIFETIME

    def test_a_future_iat_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        now = int(time.time())
        token = key.sign({"iat": now + 600, "exp": now + 900})
        assert reason(verifier_for(idp), token) is RejectReason.NOT_YET_VALID

    def test_a_configured_shorter_maximum_is_enforced(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        client = JwksClient(f"{idp.url}/jwks", allow_loopback_http=True)
        verifier = OidcJwksVerifier(
            keys=client, issuer=ISSUER, audience=AUDIENCE, max_lifetime_seconds=600
        )
        assert verifier.verify(_lifetime_token(key, 600))
        assert reason(verifier, _lifetime_token(key, 601)) is RejectReason.LIFETIME

    @pytest.mark.parametrize(
        "configured",
        [0, MIN_MAX_TOKEN_LIFETIME_SECONDS - 1, CEILING_MAX_TOKEN_LIFETIME_SECONDS + 1, True, 1.5],
    )
    def test_configured_maximum_outside_the_platform_bounds_is_fatal(
        self, configured: object
    ) -> None:
        with pytest.raises(ValueError):
            validate_max_lifetime(configured)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            Hs256DevelopmentVerifier(
                secret=SECRET,
                issuer="i",
                audience="a",
                max_lifetime_seconds=configured,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("value", ["abc", "299", "5401", "-1"])
    def test_environment_configuration_is_validated_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.delenv("ASIC_DEPLOYMENT_ENVIRONMENT", raising=False)
        monkeypatch.setenv("ASIC_AUTH_MODE", "development_hs256")
        monkeypatch.setenv("ASIC_JWT_SECRET", SECRET)
        monkeypatch.setenv("ASIC_JWT_MAX_LIFETIME_SECONDS", value)
        with pytest.raises(RuntimeError, match="ASIC_JWT_MAX_LIFETIME_SECONDS"):
            ApiSettings.from_environment()

    def test_environment_configuration_reaches_the_verifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ASIC_DEPLOYMENT_ENVIRONMENT", raising=False)
        monkeypatch.setenv("ASIC_AUTH_MODE", "development_hs256")
        monkeypatch.setenv("ASIC_JWT_SECRET", SECRET)
        monkeypatch.setenv("ASIC_JWT_MAX_LIFETIME_SECONDS", "900")
        settings = ApiSettings.from_environment()
        assert settings.jwt_max_lifetime_seconds == 900
        verifier = build_token_verifier(settings)
        now = int(time.time())
        base = {"sub": "a", "tenant_id": "t", "iss": settings.jwt_issuer}
        base["aud"] = settings.jwt_audience
        good = jwt.encode({**base, "iat": now, "exp": now + 900}, SECRET, algorithm="HS256")
        long = jwt.encode({**base, "iat": now, "exp": now + 901}, SECRET, algorithm="HS256")
        assert verifier.verify(good)
        with pytest.raises(TokenRejected) as info:
            verifier.verify(long)
        assert info.value.reason is RejectReason.LIFETIME

    def test_default_is_one_hour_when_unconfigured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ASIC_DEPLOYMENT_ENVIRONMENT", raising=False)
        monkeypatch.delenv("ASIC_JWT_MAX_LIFETIME_SECONDS", raising=False)
        monkeypatch.setenv("ASIC_AUTH_MODE", "development_hs256")
        monkeypatch.setenv("ASIC_JWT_SECRET", SECRET)
        assert ApiSettings.from_environment().jwt_max_lifetime_seconds == 3600


class TestClaimBoundaryTimes:
    def test_expiry_at_the_leeway_edge(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        now = int(time.time())
        inside = key.sign({"iat": now - 600, "exp": now - (CLOCK_LEEWAY_SECONDS - 5)})
        outside = key.sign({"iat": now - 600, "exp": now - (CLOCK_LEEWAY_SECONDS + 5)})
        assert verifier_for(idp).verify(inside)
        assert reason(verifier_for(idp), outside) is RejectReason.EXPIRED

    def test_not_before_at_the_leeway_edge(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        now = int(time.time())
        inside = key.sign({"nbf": now + (CLOCK_LEEWAY_SECONDS - 5)})
        outside = key.sign({"nbf": now + (CLOCK_LEEWAY_SECONDS + 5)})
        assert verifier_for(idp).verify(inside)
        assert reason(verifier_for(idp), outside) is RejectReason.NOT_YET_VALID


class TestAudienceAndSize:
    @pytest.mark.parametrize("aud", [["other"], [], "asic-other", ["ASIC-API"], 7])
    def test_audience_must_name_ours(self, idp: LocalHttpServer, aud: object) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        assert reason(verifier_for(idp), key.sign({"aud": aud})) in {
            RejectReason.AUDIENCE,
            RejectReason.CLAIMS,
            RejectReason.MALFORMED,
        }

    def test_size_ceiling_is_exact(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign()
        at_limit = token + "A" * (MAX_TOKEN_CHARS - len(token))
        assert len(at_limit) == MAX_TOKEN_CHARS
        # At the ceiling the token is parsed (and fails on its signature); one more character
        # is refused before any parsing.
        assert reason(verifier_for(idp), at_limit) is not RejectReason.TOO_LARGE
        assert reason(verifier_for(idp), at_limit + "A") is RejectReason.TOO_LARGE


class TestConcurrentRefresh:
    def test_an_unknown_kid_storm_under_a_slow_issuer_is_one_fetch(
        self, idp: LocalHttpServer
    ) -> None:
        """64 concurrent callers presenting an unknown ``kid`` while the issuer is slow: the
        issuer sees one fetch (not 64), and every caller returns promptly and closed."""
        good, rogue = Keys("k1"), Keys("k-unknown")
        slow = Scripted(body=jwks(good), delay=1.0)
        idp.route("GET", "/jwks", slow)
        verifier = verifier_for(idp)
        results: list[object] = []
        lock = threading.Lock()

        def attempt() -> None:
            try:
                verifier.verify(rogue.sign())
                outcome: object = "accepted"
            except TokenRejected as exc:
                outcome = exc.reason
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt) for _ in range(64)]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(results) == 64 and "accepted" not in results
        assert set(results) <= {RejectReason.KEY_ID_UNKNOWN, RejectReason.KEYS_UNAVAILABLE}
        assert len(idp.calls("GET", "/jwks")) == 1
        assert time.monotonic() - started < 5
