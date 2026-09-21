"""Phase 13 authentication attacks against the OIDC/JWKS verifier and its composition.

Runs against a deterministic loopback JWKS server (explicit test infrastructure). Nothing
here proves compatibility with a live identity provider; it proves the verifier's own
guarantees: explicit asymmetric algorithms, key selection by ``kid``, bounded and
rotation-aware key retrieval, fail-closed behaviour, and no token content in any failure.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from asic.api import ApiSettings, auth, create_app
from asic.api.tokens import (
    MAX_TOKEN_CHARS,
    AuthMode,
    Hs256DevelopmentVerifier,
    JwksClient,
    OidcJwksVerifier,
    RejectReason,
    TokenRejected,
)
from tests.integrations.local_http import LocalHttpServer, Scripted, local_server

pytestmark = pytest.mark.security

ISSUER = "https://idp.example.invalid/"
AUDIENCE = "asic-api"
TENANT = "0b1f6a5e-6a1d-4f6e-9d59-3a7f0d0c9e11"


class Keys:
    def __init__(self, kid: str, kind: str = "rsa") -> None:
        self.kid = kid
        self.kind = kind
        if kind == "rsa":
            self.private: Any = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.algorithm = "RS256"
            self.jwk = json.loads(RSAAlgorithm.to_jwk(self.private.public_key()))
        else:
            self.private = ec.generate_private_key(ec.SECP256R1())
            self.algorithm = "ES256"
            self.jwk = json.loads(ECAlgorithm.to_jwk(self.private.public_key()))
        self.jwk.update({"kid": kid, "use": "sig", "alg": self.algorithm})

    def sign(self, claims: dict[str, Any] | None = None, **headers: Any) -> str:
        return jwt.encode(
            claims_for(claims),
            self.private,
            algorithm=self.algorithm,
            headers={"kid": self.kid, **headers},
        )

    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def claims_for(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "sub": "alice",
        "tenant_id": TENANT,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
    }
    for key, value in (overrides or {}).items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def jwks(*keys: Keys) -> dict[str, Any]:
    return {"keys": [k.jwk for k in keys]}


@pytest.fixture
def idp() -> Iterator[LocalHttpServer]:
    with local_server() as server:
        yield server


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def verifier_for(
    server: LocalHttpServer, *, clock: FakeClock | None = None, **client_options: Any
) -> OidcJwksVerifier:
    client = JwksClient(
        f"{server.url}/jwks",
        allow_loopback_http=True,
        clock=clock or time.monotonic,
        **client_options,
    )
    return OidcJwksVerifier(keys=client, issuer=ISSUER, audience=AUDIENCE)


def reason(verifier: OidcJwksVerifier, token: str) -> RejectReason:
    with pytest.raises(TokenRejected) as info:
        verifier.verify(token)
    return info.value.reason


def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


class TestValidTokens:
    @pytest.mark.parametrize("kind", ["rsa", "ec"])
    def test_valid_signed_token_is_accepted(self, idp: LocalHttpServer, kind: str) -> None:
        key = Keys("k1", kind)
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        claims = verifier_for(idp).verify(key.sign())
        assert claims["sub"] == "alice"
        assert claims["tenant_id"] == TENANT

    def test_audience_list_containing_ours_is_accepted(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign({"aud": ["other", AUDIENCE]})
        assert verifier_for(idp).verify(token)["sub"] == "alice"


class TestClaimAttacks:
    @pytest.mark.parametrize(
        ("override", "expected"),
        [
            ({"exp": int(time.time()) - 3600}, RejectReason.EXPIRED),
            ({"nbf": int(time.time()) + 3600}, RejectReason.NOT_YET_VALID),
            ({"iss": "https://evil.example.invalid/"}, RejectReason.ISSUER),
            ({"aud": "someone-else"}, RejectReason.AUDIENCE),
            ({"aud": None}, RejectReason.CLAIMS),
            ({"sub": None}, RejectReason.CLAIMS),
            ({"tenant_id": None}, RejectReason.CLAIMS),
            ({"exp": None}, RejectReason.CLAIMS),
            ({"iss": None}, RejectReason.CLAIMS),
        ],
    )
    def test_invalid_claims_are_refused(
        self, idp: LocalHttpServer, override: dict[str, Any], expected: RejectReason
    ) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        assert reason(verifier_for(idp), key.sign(override)) is expected

    def test_issued_in_the_far_future_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign({"iat": int(time.time()) + 3600})
        assert reason(verifier_for(idp), token) is RejectReason.NOT_YET_VALID

    def test_small_clock_skew_is_tolerated(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign({"exp": int(time.time()) - 10})
        assert verifier_for(idp).verify(token)["sub"] == "alice"


class TestAlgorithmAndKeyAttacks:
    def test_invalid_signature_is_refused(self, idp: LocalHttpServer) -> None:
        trusted, attacker = Keys("k1"), Keys("k1")  # same kid, different private key
        idp.route("GET", "/jwks", Scripted(body=jwks(trusted)))
        assert reason(verifier_for(idp), attacker.sign()) is RejectReason.SIGNATURE

    def test_alg_none_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(claims_for())}."
        assert reason(verifier_for(idp), token) is RejectReason.ALGORITHM_NOT_ALLOWED

    def test_hmac_with_the_public_key_as_secret_is_refused(self, idp: LocalHttpServer) -> None:
        """The classic HS/RS confusion: sign HS256 using the RSA public key text."""
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        # PyJWT itself refuses to build this token, so forge it by hand as an attacker would.
        signing_input = f"{_b64({'alg': 'HS256', 'typ': 'JWT', 'kid': 'k1'})}.{_b64(claims_for())}"
        mac = hmac.new(key.public_pem(), signing_input.encode(), hashlib.sha256).digest()
        forged = f"{signing_input}.{base64.urlsafe_b64encode(mac).rstrip(b'=').decode()}"
        assert reason(verifier_for(idp), forged) is RejectReason.ALGORITHM_NOT_ALLOWED
        # No JWKS fetch was even needed to refuse it: algorithm policy comes first.
        assert idp.calls("GET", "/jwks") == []

    def test_algorithm_outside_the_configured_set_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = jwt.encode(claims_for(), key.private, algorithm="PS256", headers={"kid": "k1"})
        assert reason(verifier_for(idp), token) is RejectReason.ALGORITHM_NOT_ALLOWED

    def test_key_type_must_match_the_algorithm(self, idp: LocalHttpServer) -> None:
        ec_key = Keys("k1", "ec")
        idp.route("GET", "/jwks", Scripted(body=jwks(ec_key)))
        rsa_key = Keys("k1")  # same kid, but an RS256 token against an EC key
        assert reason(verifier_for(idp), rsa_key.sign()) is RejectReason.KEY_TYPE_MISMATCH

    def test_missing_key_id_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = jwt.encode(claims_for(), key.private, algorithm="RS256")
        assert reason(verifier_for(idp), token) is RejectReason.KEY_ID_MISSING

    def test_unknown_key_id_is_refused(self, idp: LocalHttpServer) -> None:
        idp.route("GET", "/jwks", Scripted(body=jwks(Keys("k1"))))
        assert reason(verifier_for(idp), Keys("other").sign()) is RejectReason.KEY_ID_UNKNOWN

    @pytest.mark.parametrize("header", ["jku", "x5u", "jwk"])
    def test_token_supplied_key_material_is_refused(
        self, idp: LocalHttpServer, header: str
    ) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign(**{header: "https://evil.example.invalid/keys"})
        assert reason(verifier_for(idp), token) is RejectReason.FORBIDDEN_HEADER

    @pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "....", "e30.e30."])
    def test_malformed_tokens_are_refused(self, idp: LocalHttpServer, token: str) -> None:
        idp.route("GET", "/jwks", Scripted(body=jwks(Keys("k1"))))
        assert reason(verifier_for(idp), token) in {
            RejectReason.MALFORMED,
            RejectReason.ALGORITHM_NOT_ALLOWED,
        }

    def test_enormous_token_is_refused_before_parsing(self, idp: LocalHttpServer) -> None:
        idp.route("GET", "/jwks", Scripted(body=jwks(Keys("k1"))))
        assert reason(verifier_for(idp), "a" * (MAX_TOKEN_CHARS + 1)) is RejectReason.TOO_LARGE
        assert idp.calls("GET", "/jwks") == []

    def test_asymmetric_only_algorithm_configuration(self) -> None:
        with local_server() as server:
            client = JwksClient(f"{server.url}/jwks", allow_loopback_http=True)
            for bad in (("HS256",), ("none",), ()):
                with pytest.raises(ValueError, match="asymmetric"):
                    OidcJwksVerifier(keys=client, issuer=ISSUER, audience=AUDIENCE, algorithms=bad)


class TestKeyRotationAndRevocation:
    def test_rotation_is_picked_up_on_an_unknown_kid(self, idp: LocalHttpServer) -> None:
        clock, old, new = FakeClock(), Keys("old"), Keys("new")
        idp.route("GET", "/jwks", Scripted(body=jwks(old)))
        verifier = verifier_for(idp, clock=clock)
        assert verifier.verify(old.sign())["sub"] == "alice"

        idp.route("GET", "/jwks", Scripted(body=jwks(old, new)))
        clock.now += 31  # past the minimum refresh interval
        assert verifier.verify(new.sign())["sub"] == "alice"

    def test_removed_key_is_refused_after_the_cache_expires(self, idp: LocalHttpServer) -> None:
        clock, old, new = FakeClock(), Keys("old"), Keys("new")
        idp.route("GET", "/jwks", Scripted(body=jwks(old, new)))
        verifier = verifier_for(idp, clock=clock)
        assert verifier.verify(old.sign())["sub"] == "alice"

        idp.route("GET", "/jwks", Scripted(body=jwks(new)))  # `old` revoked at the issuer
        clock.now += 301  # cache TTL elapsed
        assert reason(verifier, old.sign()) is RejectReason.KEY_ID_UNKNOWN
        assert verifier.verify(new.sign())["sub"] == "alice"

    def test_unknown_kid_spam_cannot_flood_the_issuer(self, idp: LocalHttpServer) -> None:
        clock = FakeClock()
        idp.route("GET", "/jwks", Scripted(body=jwks(Keys("k1"))))
        verifier = verifier_for(idp, clock=clock)
        for index in range(25):
            assert reason(verifier, Keys(f"junk-{index}").sign()) is RejectReason.KEY_ID_UNKNOWN
        assert len(idp.calls("GET", "/jwks")) == 1

    def test_revoked_key_outage_lag_is_bounded_by_the_documented_stale_window(
        self, idp: LocalHttpServer
    ) -> None:
        clock, old, replacement = FakeClock(), Keys("old"), Keys("replacement")
        idp.route("GET", "/jwks", Scripted(body=jwks(old, replacement)))
        verifier = verifier_for(idp, clock=clock)
        assert verifier.verify(old.sign())["sub"] == "alice"

        # The issuer removes `old`, then becomes unavailable before clients can refresh.
        # The normal cache remains authoritative before the 300-second TTL.
        idp.route("GET", "/jwks", Scripted(status=503))
        clock.now += 299
        assert verifier.verify(old.sign())["sub"] == "alice"

        # Refresh now fails, so the last-known-good key is served only within 600 seconds
        # of its original fetch. The exact stale boundary remains accepted...
        clock.now = 1600
        assert verifier.verify(old.sign())["sub"] == "alice"
        # ...and the first instant beyond it fails closed.
        clock.now = 1600.001
        assert reason(verifier, old.sign()) is RejectReason.KEYS_UNAVAILABLE


class TestJwksHardening:
    @pytest.mark.parametrize(
        "response",
        [
            Scripted(raw=b"not json"),
            Scripted(body={"nokeys": []}),
            Scripted(body={"keys": []}),
            Scripted(body={"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}]}),  # no kid
            Scripted(body={"keys": ["string"]}),
            Scripted(body={"keys": [{"kid": "k1", "kty": "RSA", "n": "!", "e": "!"}]}),
            Scripted(status=500),
        ],
    )
    def test_malformed_key_sets_fail_closed(self, idp: LocalHttpServer, response: Scripted) -> None:
        idp.route("GET", "/jwks", response)
        assert reason(verifier_for(idp), Keys("k1").sign()) is RejectReason.KEYS_UNAVAILABLE

    def test_duplicate_kid_makes_the_set_ambiguous(self, idp: LocalHttpServer) -> None:
        first, second = Keys("dup"), Keys("dup")
        idp.route("GET", "/jwks", Scripted(body=jwks(first, second)))
        assert reason(verifier_for(idp), first.sign()) is RejectReason.KEYS_UNAVAILABLE

    def test_too_many_keys_are_refused(self, idp: LocalHttpServer) -> None:
        keys = [Keys(f"k{i}", "ec") for i in range(17)]
        idp.route("GET", "/jwks", Scripted(body=jwks(*keys)))
        assert reason(verifier_for(idp), keys[0].sign()) is RejectReason.KEYS_UNAVAILABLE

    def test_oversized_response_is_refused(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        verifier = verifier_for(idp, max_response_bytes=64)
        assert reason(verifier, key.sign()) is RejectReason.KEYS_UNAVAILABLE

    def test_slow_issuer_times_out_and_fails_closed(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key), delay=1.5))
        verifier = verifier_for(idp, timeout_seconds=0.2)
        started = time.monotonic()
        assert reason(verifier, key.sign()) is RejectReason.KEYS_UNAVAILABLE
        assert time.monotonic() - started < 1.4

    def test_redirects_are_not_followed(self, idp: LocalHttpServer) -> None:
        idp.route(
            "GET", "/jwks", Scripted(status=302, headers={"Location": "http://127.0.0.1:1/x"})
        )
        assert reason(verifier_for(idp), Keys("k1").sign()) is RejectReason.KEYS_UNAVAILABLE

    def test_encryption_keys_are_never_used_for_verification(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        entry = dict(key.jwk, use="enc")
        idp.route("GET", "/jwks", Scripted(body={"keys": [entry]}))
        assert reason(verifier_for(idp), key.sign()) is RejectReason.KEY_ID_UNKNOWN

    @pytest.mark.parametrize(
        "url",
        [
            "http://idp.example.invalid/jwks",  # plain http, non-loopback
            "https://user:pw@idp.example.invalid/jwks",  # user-info
            "https://idp.example.invalid/jwks?x=1",  # query
            "ftp://idp.example.invalid/jwks",
            "",
        ],
    )
    def test_jwks_url_policy(self, url: str) -> None:
        with pytest.raises(ValueError, match="invalid JWKS URL"):
            JwksClient(url)

    def test_plain_http_to_loopback_needs_explicit_opt_in(self) -> None:
        with pytest.raises(ValueError, match="invalid JWKS URL"):
            JwksClient("http://127.0.0.1:9/jwks")


class TestNoLeakage:
    def test_failures_never_contain_token_or_key_material(self, idp: LocalHttpServer) -> None:
        key = Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        token = key.sign({"exp": int(time.time()) - 3600})
        signature = token.split(".")[2]
        verifier = verifier_for(idp)
        with pytest.raises(TokenRejected) as info:
            verifier.verify(token)
        rendered = f"{info.value!s} {info.value!r} {info.value.__cause__!r}"
        assert token not in rendered and signature not in rendered
        assert info.value.__suppress_context__ is True

    def test_http_response_and_logs_carry_only_a_closed_reason(
        self, asic_log_records: list[logging.LogRecord]
    ) -> None:
        secret = "phase13-dev-signing-secret-not-production-0000"
        settings = ApiSettings(jwt_secret=secret, jwt_issuer=ISSUER, jwt_audience=AUDIENCE)
        app = create_app(settings=settings, factory=lambda: None)  # type: ignore[arg-type,return-value]
        from fastapi.testclient import TestClient

        bad = jwt.encode(claims_for({"aud": "wrong"}), secret, algorithm="HS256")
        response = TestClient(app).get(
            "/api/v1/incidents", headers={"Authorization": f"Bearer {bad}"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == {
            "code": "invalid_token",
            "message": "authentication failed",
        }
        assert bad not in response.text
        logged = " ".join(f"{r.getMessage()} {r.__dict__}" for r in asic_log_records)
        assert "audience_invalid" in logged
        assert bad not in logged and secret not in logged


class TestProductionComposition:
    def test_production_refuses_the_development_verifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        settings = ApiSettings(jwt_secret="x" * 40)
        with pytest.raises(RuntimeError, match="cannot run in production"):
            auth.build_token_verifier(settings)
        with pytest.raises(RuntimeError, match="cannot run in production"):
            create_app(settings=settings, factory=lambda: None)  # type: ignore[arg-type,return-value]

    def test_production_defaults_to_oidc_and_requires_its_configuration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        monkeypatch.setenv("ASIC_JWT_SECRET", "s" * 40)  # must not be a way in
        for name in (
            "ASIC_AUTH_MODE",
            "ASIC_JWT_ISSUER",
            "ASIC_JWT_AUDIENCE",
            "ASIC_OIDC_JWKS_URL",
        ):
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(RuntimeError, match="OIDC mode requires"):
            ApiSettings.from_environment()

    def test_a_shared_secret_in_the_environment_cannot_downgrade_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        monkeypatch.setenv("ASIC_AUTH_MODE", "development_hs256")
        monkeypatch.setenv("ASIC_JWT_SECRET", "s" * 40)
        settings = ApiSettings.from_environment()
        with pytest.raises(RuntimeError, match="cannot run in production"):
            auth.build_token_verifier(settings)

    def test_production_refuses_plain_http_jwks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        settings = ApiSettings(
            auth_mode=AuthMode.OIDC_JWKS,
            oidc_jwks_url="http://127.0.0.1:9/jwks",
            oidc_allow_loopback_http=True,
        )
        with pytest.raises(RuntimeError, match="plain-HTTP JWKS"):
            auth.build_token_verifier(settings)
        with pytest.raises(ValueError, match="invalid JWKS URL"):
            plain_http = "http://" + "idp.invalid" + "/keys"
            auth.build_token_verifier(
                ApiSettings(auth_mode=AuthMode.OIDC_JWKS, oidc_jwks_url=plain_http)
            )

    def test_production_composes_the_oidc_verifier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        verifier = auth.build_token_verifier(
            ApiSettings(
                auth_mode=AuthMode.OIDC_JWKS,
                oidc_jwks_url="https://idp.example.invalid/.well-known/jwks.json",
                jwt_issuer=ISSUER,
                jwt_audience=AUDIENCE,
            )
        )
        assert isinstance(verifier, OidcJwksVerifier)
        assert verifier.is_development is False

    def test_development_verifier_declares_itself_and_rejects_short_secrets(self) -> None:
        with pytest.raises(ValueError, match="at least 32"):
            Hs256DevelopmentVerifier(secret="short", issuer=ISSUER, audience=AUDIENCE)
        assert Hs256DevelopmentVerifier(
            secret="s" * 32, issuer=ISSUER, audience=AUDIENCE
        ).is_development


class TestRefreshDoesNotStallAuthentication:
    def test_a_slow_issuer_refresh_never_blocks_callers_holding_a_cached_key(
        self, idp: LocalHttpServer
    ) -> None:
        import threading

        clock, key = FakeClock(), Keys("k1")
        idp.route("GET", "/jwks", Scripted(body=jwks(key)))
        verifier = verifier_for(idp, clock=clock, timeout_seconds=3.0)
        assert verifier.verify(key.sign())["sub"] == "alice"  # prime the cache

        idp.route("GET", "/jwks", Scripted(body=jwks(key), delay=1.5))
        clock.now += 301  # TTL elapsed: the next caller must refresh, slowly
        refresher = threading.Thread(target=lambda: verifier.verify(key.sign()))
        refresher.start()
        time.sleep(0.3)  # the refresh is now in flight, waiting on the issuer
        started = time.monotonic()
        claims = verifier.verify(key.sign())  # served from the stale-but-bounded cache
        assert time.monotonic() - started < 0.5
        assert claims["sub"] == "alice"
        refresher.join(5)
        assert len(idp.calls("GET", "/jwks")) == 2  # one refresh, not one per caller
