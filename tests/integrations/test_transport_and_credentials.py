"""Transport failure phases, endpoint constraints and credential containment (UNIT + LOCAL)."""

from __future__ import annotations

import pickle
import socket

import pytest

from asic.domain.clock import FrozenClock
from asic.domain.enums import IntegrationFailureClass
from asic.domain.errors import CredentialUnavailable, IntegrationError, IntegrationUnknownOutcome
from asic.integrations.composition import (
    CompositionRefused,
    compose_live_providers,
    compose_local_integration_test_providers,
)
from asic.integrations.credentials import (
    EnvironmentCredentialProvider,
    SecretValue,
    StaticCredentialProvider,
)
from asic.integrations.transport import (
    HttpClientTransport,
    HttpRequest,
    HttpResponse,
    path,
    raise_for_status,
    validate_endpoint,
)
from tests.integrations.conftest import NOW, SECRETS
from tests.integrations.local_http import LocalHttpServer, Scripted


class TestEndpointValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "ftp://example.com",
            "https://user:pass@example.com",
            "https://example.com/?q=1",
            "https://example.com/#frag",
            "",
            None,
        ],
    )
    def test_unsafe_endpoints_are_configuration_errors(self, url: str | None) -> None:
        with pytest.raises(IntegrationError) as refused:
            validate_endpoint(url, allow_loopback_http=True)
        assert refused.value.failure_class is IntegrationFailureClass.CONFIGURATION_ERROR
        assert refused.value.effect_not_applied

    def test_plain_http_only_to_loopback_and_only_when_permitted(self) -> None:
        assert validate_endpoint("http://127.0.0.1:9", allow_loopback_http=True).scheme == "http"
        with pytest.raises(IntegrationError):
            validate_endpoint("http://127.0.0.1:9", allow_loopback_http=False)
        with pytest.raises(IntegrationError):
            validate_endpoint("http://10.0.0.1", allow_loopback_http=True)

    @pytest.mark.parametrize(
        ("host", "allowed", "accepted"),
        [
            ("slack.com", (".slack.com",), True),
            ("api.slack.com", (".slack.com",), True),
            ("evilslack.com", (".slack.com",), False),
            ("slack.com.evil.io", (".slack.com",), False),
            ("events.pagerduty.com", ("events.pagerduty.com",), True),
            ("xevents.pagerduty.com", ("events.pagerduty.com",), False),
        ],
    )
    def test_host_allowlist_is_exact_or_dot_suffix(
        self, host: str, allowed: tuple[str, ...], accepted: bool
    ) -> None:
        if accepted:
            validate_endpoint(
                f"https://{host}", allow_loopback_http=False, allowed_host_suffixes=allowed
            )
        else:
            with pytest.raises(IntegrationError):
                validate_endpoint(
                    f"https://{host}", allow_loopback_http=False, allowed_host_suffixes=allowed
                )

    def test_path_segments_cannot_traverse_or_inject(self) -> None:
        assert path("api", "../../admin", "x?y=1") == "/api/..%2F..%2Fadmin/x%3Fy%3D1"


class TestRequestConstruction:
    def test_headers_are_allowlisted_and_single_line(self) -> None:
        endpoint = validate_endpoint("https://example.com", allow_loopback_http=False)
        with pytest.raises(ValueError, match="not permitted"):
            HttpRequest(method="GET", endpoint=endpoint, path="/", headers=(("Host", "evil"),))
        with pytest.raises(ValueError, match="single-line"):
            HttpRequest(
                method="GET",
                endpoint=endpoint,
                path="/",
                headers=(("traceparent", "x\r\nAuthorization: stolen"),),
            )
        with pytest.raises(ValueError, match="not permitted"):
            HttpRequest(method="DELETE", endpoint=endpoint, path="/")  # type: ignore[arg-type]

    def test_description_never_contains_query_or_credentials(self) -> None:
        endpoint = validate_endpoint("https://example.com/base", allow_loopback_http=False)
        request = HttpRequest(
            method="GET",
            endpoint=endpoint,
            path="/api",
            query=(("query", "secret-looking"),),
            headers=(("Authorization", "Bearer abc"),),
        )
        assert request.describe() == "GET https://example.com/base/api"


class TestStatusClassification:
    @pytest.mark.parametrize(
        ("status", "failure_class", "transient", "not_applied"),
        [
            (401, IntegrationFailureClass.UNAUTHORIZED, False, True),
            (403, IntegrationFailureClass.FORBIDDEN, False, True),
            (404, IntegrationFailureClass.NOT_FOUND, False, True),
            (409, IntegrationFailureClass.CONFLICT, False, True),
            (422, IntegrationFailureClass.INVALID_REQUEST, False, True),
            (429, IntegrationFailureClass.RATE_LIMITED, True, True),
            (302, IntegrationFailureClass.CONFIGURATION_ERROR, False, True),
            (503, IntegrationFailureClass.TRANSIENT_UNAVAILABLE, True, True),
        ],
    )
    def test_read_statuses(
        self,
        status: int,
        failure_class: IntegrationFailureClass,
        transient: bool,
        not_applied: bool,
    ) -> None:
        endpoint = validate_endpoint("https://example.com", allow_loopback_http=False)
        request = HttpRequest(method="GET", endpoint=endpoint, path="/")
        with pytest.raises(IntegrationError) as failed:
            raise_for_status(
                request,
                HttpResponse(status=status, headers={"retry-after": "7"}, body=b'{"token":"x"}'),
            )
        assert failed.value.failure_class is failure_class
        assert failed.value.transient is transient
        assert failed.value.effect_not_applied is not_applied
        assert "token" not in str(failed.value)

    def test_a_write_5xx_is_never_marked_not_applied_or_transient(self) -> None:
        endpoint = validate_endpoint("https://example.com", allow_loopback_http=False)
        request = HttpRequest(method="POST", endpoint=endpoint, path="/", effectful=True)
        with pytest.raises(IntegrationError) as failed:
            raise_for_status(request, HttpResponse(status=500, headers={}, body=b""))
        assert not failed.value.effect_not_applied
        assert not failed.value.transient

    def test_retry_after_is_parsed_and_bounded(self) -> None:
        endpoint = validate_endpoint("https://example.com", allow_loopback_http=False)
        request = HttpRequest(method="GET", endpoint=endpoint, path="/")
        for header, expected in (("12", 12.0), ("-1", None), ("soon", None), ("99999", None)):
            with pytest.raises(IntegrationError) as failed:
                raise_for_status(
                    request, HttpResponse(status=429, headers={"retry-after": header}, body=b"")
                )
            assert failed.value.retry_after_seconds == expected


class TestTransportPhases:
    def _request(
        self, server: LocalHttpServer, *, effectful: bool, method: str = "GET"
    ) -> HttpRequest:
        return HttpRequest(
            method=method,  # type: ignore[arg-type]
            endpoint=validate_endpoint(server.url, allow_loopback_http=True),
            path="/probe",
            body=b"{}" if method != "GET" else None,
            effectful=effectful,
        )

    def test_connection_refused_is_known_not_applied(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        request = HttpRequest(
            method="POST",
            endpoint=validate_endpoint(f"http://127.0.0.1:{port}", allow_loopback_http=True),
            path="/",
            effectful=True,
        )
        with pytest.raises(IntegrationError) as failed:
            HttpClientTransport().send(request, timeout_seconds=2)
        assert failed.value.effect_not_applied
        assert failed.value.transient

    def test_a_write_that_times_out_after_sending_is_an_unknown_outcome(
        self, server: LocalHttpServer
    ) -> None:
        server.route("POST", "/probe", Scripted(delay=2.0, body={}))
        with pytest.raises(IntegrationUnknownOutcome):
            HttpClientTransport().send(
                self._request(server, effectful=True, method="POST"), timeout_seconds=0.5
            )
        assert len(server.calls("POST", "/probe")) == 1

    def test_a_read_that_times_out_is_a_clean_transient_timeout(
        self, server: LocalHttpServer
    ) -> None:
        server.route("GET", "/probe", Scripted(delay=2.0, body={}))
        with pytest.raises(IntegrationError) as failed:
            HttpClientTransport().send(self._request(server, effectful=False), timeout_seconds=0.5)
        assert failed.value.failure_class is IntegrationFailureClass.TIMEOUT
        assert failed.value.transient and failed.value.effect_not_applied

    def test_a_dropped_connection_after_a_write_is_unknown(self, server: LocalHttpServer) -> None:
        server.route("POST", "/probe", Scripted(drop=True))
        with pytest.raises(IntegrationUnknownOutcome):
            HttpClientTransport().send(
                self._request(server, effectful=True, method="POST"), timeout_seconds=2
            )

    def test_oversized_responses_are_refused(self, server: LocalHttpServer) -> None:
        server.route("GET", "/probe", Scripted(raw=b"x" * 2048))
        with pytest.raises(IntegrationError) as failed:
            HttpClientTransport().send(
                self._request(server, effectful=False), timeout_seconds=2, max_response_bytes=1024
            )
        assert failed.value.failure_class is IntegrationFailureClass.MALFORMED_RESPONSE

    def test_redirects_are_not_followed(self, server: LocalHttpServer) -> None:
        server.route(
            "GET", "/probe", Scripted(status=302, headers={"Location": "http://127.0.0.1:1/x"})
        )
        response = HttpClientTransport().send(
            self._request(server, effectful=False), timeout_seconds=2
        )
        assert response.status == 302
        assert len(server.requests) == 1


class TestCredentials:
    def test_a_secret_value_never_renders_or_serialises(self) -> None:
        secret = SecretValue("super-secret-value")
        assert "super-secret" not in repr(secret)
        assert "super-secret" not in str(secret)
        assert "super-secret" not in f"{secret}"
        with pytest.raises(TypeError):
            pickle.dumps(secret)
        assert secret.reveal() == "super-secret-value"

    def test_environment_provider_fails_closed_without_a_fallback(self) -> None:
        provider = EnvironmentCredentialProvider(environ={})
        with pytest.raises(CredentialUnavailable) as missing:
            provider.resolve("asic/read/prometheus")
        assert "asic/read/prometheus" in str(missing.value)
        resolved = EnvironmentCredentialProvider(
            environ={"ASIC_SECRET_ASIC_READ_PROMETHEUS": "value-1"}
        ).resolve("asic/read/prometheus")
        assert resolved.reveal() == "value-1"
        assert not provider.is_test_infrastructure

    def test_mounted_secrets_resolve_and_cannot_escape_the_directory(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        target = tmp_path / "asic" / "read"
        target.mkdir(parents=True)
        (target / "loki").write_text("mounted-secret\n", encoding="utf-8")
        provider = EnvironmentCredentialProvider(environ={"ASIC_SECRETS_DIR": str(tmp_path)})
        assert provider.resolve("asic/read/loki").reveal() == "mounted-secret"
        for reference in ("asic/../etc/passwd", "../x", "asic/read/../../x", "ASIC/READ"):
            with pytest.raises(CredentialUnavailable):
                provider.resolve(reference)

    def test_static_test_credentials_are_refused_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
        with pytest.raises(CredentialUnavailable):
            StaticCredentialProvider(SECRETS)
        with pytest.raises(CompositionRefused):
            compose_local_integration_test_providers(
                credentials=EnvironmentCredentialProvider(environ={}),
                clock=FrozenClock(start=NOW),
            )


class TestComposition:
    def test_live_composition_refuses_test_credentials(self) -> None:
        with pytest.raises(CompositionRefused):
            compose_live_providers(
                credentials=StaticCredentialProvider(SECRETS), clock=FrozenClock(start=NOW)
            )

    def test_live_composition_contains_no_simulator(self) -> None:
        from asic.simulators.provider import SimulatorProvider
        from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, scenario

        composed = compose_live_providers(
            credentials=EnvironmentCredentialProvider(environ={}), clock=FrozenClock(start=NOW)
        )
        assert composed.mode.value == "live" and not composed.is_test_infrastructure
        assert all(p.kind.value == "native" for p in composed.providers)
        with pytest.raises(CompositionRefused):
            compose_live_providers(
                credentials=EnvironmentCredentialProvider(environ={}),
                clock=FrozenClock(start=NOW),
                extra_native=[
                    SimulatorProvider(scenario(PRIMARY_SCENARIO_ID), clock=FrozenClock(start=NOW))
                ],
            )

    def test_local_test_composition_is_labelled_test_infrastructure(self) -> None:
        composed = compose_local_integration_test_providers(
            credentials=StaticCredentialProvider(SECRETS), clock=FrozenClock(start=NOW)
        )
        assert composed.is_test_infrastructure
