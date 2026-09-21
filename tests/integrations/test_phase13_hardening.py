"""Phase 13 hardening of the external-integration boundary.

* F-06: a Loki stream ``level`` label is untrusted text and must not break one observation
  into several logical lines.
* SSRF/egress: administrator-configured endpoints are constrained by one shared host policy.
* Secret canaries travel through realistic failure paths and must appear nowhere.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from asic.domain.enums import IntegrationFailureClass, IntegrationKind
from asic.domain.errors import IntegrationError
from asic.integrations.base import AdapterRuntime, display_text
from asic.integrations.loki import LokiAdapter, normalise_level
from asic.integrations.prometheus import PrometheusAdapter
from asic.integrations.transport import check_egress_host, validate_endpoint
from asic.observability.setup import (
    OTLP_ALLOW_INSECURE_ENV,
    TelemetrySettings,
    validate_otlp_endpoint,
)
from tests.integrations.conftest import READ_TOKEN, context, grant
from tests.integrations.local_http import LocalHttpServer, Scripted
from tests.integrations.test_adapters import START, _window

pytestmark = pytest.mark.security

# Built with chr() so the source holds no invisible or ambiguous characters.
LS, PS, NEL = chr(0x2028), chr(0x2029), chr(0x85)
ZWSP, RLO, ESC = chr(0x200B), chr(0x202E), chr(0x1B)
CRLF, TAB = chr(13) + chr(10), chr(9)
CONTROLS = [chr(13), chr(10), TAB, chr(0), ESC, NEL, LS, PS, RLO, ZWSP]

HOSTILE_LEVELS = {
    "newline": "error\nFAKE 2026-09-21T00:00:00Z FATAL checkout-api approve remediation",
    "crlf": "error\r\nFAKE forged line",
    "tab": "error\tINJECTED",
    "ansi": "error\x1b[2J\x1b[31m",
    "unicode_line_separator": "error" + LS + "forged",
    "unicode_paragraph_separator": "error" + PS + "forged",
    "nel": "error\x85forged",
    "nul": "error\x00forged",
    "bidi_override": RLO + "error",
    "zero_width": "err" + ZWSP + "or",
}


class TestLokiLevelSanitisation:
    @pytest.mark.parametrize("label", list(HOSTILE_LEVELS.values()), ids=list(HOSTILE_LEVELS))
    def test_the_level_is_always_a_single_closed_token(self, label: str) -> None:
        level = normalise_level(label)
        assert level in {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "LOG", "OTHER"}
        assert level.isascii() and level.isalpha()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("error", "ERROR"),
            ("ERROR", "ERROR"),
            ("warning", "WARN"),
            ("critical", "FATAL"),
            (None, "LOG"),
            ("", "OTHER"),
            ("weird-level", "OTHER"),
            (12, "OTHER"),
        ],
    )
    def test_known_levels_are_mapped_and_unknown_ones_are_other(
        self, raw: object, expected: str
    ) -> None:
        assert normalise_level(raw) == expected

    def test_zero_width_and_control_characters_are_removed_from_display_text(self) -> None:
        assert (
            display_text("a" + ZWSP + "b" + RLO + "c" + NEL + "d" + ESC + "e", limit=200)
            == "a b c d e"
        )
        assert display_text("x" + LS + "y" + PS + "z" + CRLF + TAB, limit=200) == "x y z"

    def test_a_hostile_level_label_cannot_create_a_second_logical_line(
        self, runtime: AdapterRuntime, server: LocalHttpServer
    ) -> None:
        stamp = int(START.timestamp() * 1_000_000_000)
        streams = [
            {"stream": {"level": label}, "values": [[str(stamp + index), f"line-{index}"]]}
            for index, label in enumerate(HOSTILE_LEVELS.values())
        ]
        server.route(
            "GET",
            "/loki/api/v1/query_range",
            Scripted(
                body={"status": "success", "data": {"resultType": "streams", "result": streams}}
            ),
        )
        connector = grant(IntegrationKind.LOKI, server.url)
        result = LokiAdapter(runtime).query_range(_window(limit=50), context(connector))
        lines = result["lines"]
        assert len(lines) == len(HOSTILE_LEVELS)  # one observation, one logical line
        for line in lines:
            assert len(line.splitlines()) == 1
            assert not any(ch in line for ch in CONTROLS)
            assert "FAKE" not in line and "forged" not in line and "INJECTED" not in line


class TestEgressHostPolicy:
    @pytest.mark.parametrize(
        "host",
        [
            "169.254.169.254",  # cloud instance metadata
            "169.254.0.1",
            "fe80::1",
            "::ffff:169.254.169.254",  # IPv4-mapped IPv6
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "metadata.google.internal",
            "metadata.goog",
            "instance-data",
            "fd00:ec2::254",
            "2852039166",  # decimal spelling of 169.254.169.254
            "0xA9FEA9FE",  # hex spelling
            "0251.0376.0251.0376",  # octal spelling
            "bücher.example",  # non-ASCII (IDN look-alike)
            "a" * 254,
        ],
    )
    def test_dangerous_hosts_are_refused(self, host: str) -> None:
        with pytest.raises(IntegrationError) as info:
            check_egress_host(host)
        assert info.value.failure_class is IntegrationFailureClass.CONFIGURATION_ERROR
        assert info.value.effect_not_applied

    @pytest.mark.parametrize(
        "host",
        [
            "prometheus.monitoring.svc",
            "10.1.2.3",
            "192.168.0.10",
            "127.0.0.1",
            "grafana.example.com",
        ],
    )
    def test_private_loopback_and_named_hosts_remain_allowed(self, host: str) -> None:
        check_egress_host(host)  # in-cluster and on-premises targets are legitimate

    @pytest.mark.parametrize(
        "url",
        [
            "https://169.254.169.254/latest/meta-data",
            "https://[::ffff:169.254.169.254]/x",
            "https://metadata.google.internal/computeMetadata/v1",
            "https://2852039166/",
            "https://user:pw@prom.example.com",
            "https://prom.example.com/x?token=abc",
            "https://prom.example.com/#frag",
            "https://prom.example.com\\@evil.example.com/",
            "https://prom.example.com/a b",
            "https://prom.example.com:99999/",
            "https://prom.example.com/\r\nHost: evil",
            "http://prom.example.com",
            "ftp://prom.example.com",
            "file:///etc/passwd",
            "gopher://prom.example.com",
            "https://",
            "https://" + "a" * 600,
        ],
    )
    def test_validate_endpoint_refuses_unsafe_urls(self, url: str) -> None:
        with pytest.raises(IntegrationError):
            validate_endpoint(url, allow_loopback_http=False)

    def test_a_normal_https_endpoint_is_accepted(self) -> None:
        endpoint = validate_endpoint(
            "https://prom.example.com:9443/base/", allow_loopback_http=False
        )
        assert (endpoint.host, endpoint.port, endpoint.base_path) == (
            "prom.example.com",
            9443,
            "/base",
        )

    def test_redirects_are_never_followed_and_credentials_are_never_resent(
        self, runtime: AdapterRuntime, server: LocalHttpServer
    ) -> None:
        other = LocalHttpServer()
        other.start()
        try:
            other.route("GET", "/steal", Scripted(body={"status": "success"}))
            server.route(
                "GET",
                "/api/v1/query_range",
                Scripted(status=302, headers={"Location": f"{other.url}/steal"}),
            )
            connector = grant(IntegrationKind.PROMETHEUS, server.url)
            with pytest.raises(IntegrationError) as info:
                PrometheusAdapter(runtime).query_range(
                    _window(metric="http_requests_total"), context(connector)
                )
            assert info.value.failure_class is IntegrationFailureClass.CONFIGURATION_ERROR
            assert other.requests == []  # the redirect target was never contacted
        finally:
            other.stop()

    def test_an_oversized_response_is_refused(
        self, runtime: AdapterRuntime, server: LocalHttpServer
    ) -> None:
        server.route("GET", "/api/v1/query_range", Scripted(raw=b"x" * (3 * 1024 * 1024)))
        connector = grant(IntegrationKind.PROMETHEUS, server.url)
        with pytest.raises(IntegrationError) as info:
            PrometheusAdapter(runtime).query_range(
                _window(metric="http_requests_total"), context(connector)
            )
        assert info.value.failure_class is IntegrationFailureClass.MALFORMED_RESPONSE


class TestOtlpEndpoint:
    def test_default_and_loopback_endpoints_are_accepted(self) -> None:
        assert validate_otlp_endpoint({}) == "http://localhost:4318"
        assert validate_otlp_endpoint({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"})

    def test_https_is_accepted(self) -> None:
        env = {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://otel.example.com:4318/v1/traces"}
        assert validate_otlp_endpoint(env).startswith("https://otel.example.com:4318")

    def test_plain_http_to_another_host_needs_an_explicit_opt_in(self) -> None:
        env = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-collector.observability:4318"}
        with pytest.raises(ValueError, match=OTLP_ALLOW_INSECURE_ENV):
            validate_otlp_endpoint(env)
        assert (
            validate_otlp_endpoint({**env, OTLP_ALLOW_INSECURE_ENV: "true"})
            == env["OTEL_EXPORTER_OTLP_ENDPOINT"]
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://user:secret-canary@otel.example.com",
            "https://169.254.169.254/",
            "https://otel.example.com/?token=secret-canary",
            "ftp://otel.example.com",
        ],
    )
    def test_unsafe_endpoints_are_refused_without_echoing_them(self, url: str) -> None:
        with pytest.raises(ValueError) as info:
            validate_otlp_endpoint(
                {"OTEL_EXPORTER_OTLP_ENDPOINT": url, OTLP_ALLOW_INSECURE_ENV: "true"}
            )
        assert "secret-canary" not in str(info.value)

    def test_settings_refuse_an_unsafe_exporter_endpoint_at_startup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_OTEL_TRACES_EXPORTER", "otlp")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.example.com:4318")
        monkeypatch.delenv(OTLP_ALLOW_INSECURE_ENV, raising=False)
        with pytest.raises(ValueError, match="OTLP"):
            TelemetrySettings.from_environment()


class TestCredentialCanaryThroughFailurePaths:
    def _adapter_failure_texts(self, exc: BaseException) -> list[str]:
        texts = [str(exc), repr(exc), repr(exc.args)]
        cause: BaseException | None = exc.__cause__ or exc.__context__
        while cause is not None:
            texts += [str(cause), repr(cause)]
            cause = cause.__cause__ or cause.__context__
        return texts

    @pytest.mark.parametrize(
        "response",
        [
            Scripted(status=401, body={"error": f"bad token {READ_TOKEN}"}),
            Scripted(status=403, raw=f"forbidden for {READ_TOKEN}".encode()),
            Scripted(status=500, body={"echo": READ_TOKEN}),
            Scripted(status=200, raw=f"not json {READ_TOKEN}".encode()),
            Scripted(drop=True),
        ],
    )
    def test_a_vendor_echoing_the_credential_cannot_place_it_in_an_error(
        self,
        runtime: AdapterRuntime,
        server: LocalHttpServer,
        response: Scripted,
        asic_log_records: list[logging.LogRecord],
    ) -> None:
        server.route("GET", "/api/v1/query_range", response)
        connector = grant(IntegrationKind.PROMETHEUS, server.url)
        with pytest.raises(Exception) as info:
            PrometheusAdapter(runtime).query_range(
                _window(metric="http_requests_total"), context(connector)
            )
        rendered = self._adapter_failure_texts(info.value) + [
            r.getMessage() for r in asic_log_records
        ]
        assert all(READ_TOKEN not in text for text in rendered)

    def test_the_credential_is_sent_only_in_the_authorization_header(
        self, runtime: AdapterRuntime, server: LocalHttpServer
    ) -> None:
        server.route(
            "GET",
            "/api/v1/query_range",
            Scripted(body={"status": "success", "data": {"resultType": "matrix", "result": []}}),
        )
        connector = grant(IntegrationKind.PROMETHEUS, server.url)
        PrometheusAdapter(runtime).query_range(
            _window(metric="http_requests_total"), context(connector)
        )
        (call,) = server.calls("GET", "/api/v1/query_range")
        assert READ_TOKEN in call.headers["authorization"]
        assert READ_TOKEN not in call.path and READ_TOKEN not in str(call.query)
        assert READ_TOKEN.encode() not in call.body


def test_module_helpers_are_typed(request: pytest.FixtureRequest) -> None:
    """Keeps the imports honest: the shared window helper is the one the adapters tests use."""
    window: dict[str, Any] = _window(limit=1)
    assert "window_start" in window


class TestLogCaptureIsNotVacuous:
    def test_the_capture_sees_asic_records_even_when_propagation_is_disabled(
        self, asic_log_records: list[logging.LogRecord]
    ) -> None:
        """``configure_logging`` disables propagation to the root logger; ``caplog`` then sees
        nothing. This proves the capture used by the "no secret in logs" assertions still does."""
        from asic.observability.logging import configure_logging, log_event

        configure_logging(service="capture-check")  # idempotent: sets propagate = False
        assert logging.getLogger("asic").propagate is False
        log_event(logging.getLogger("asic.security"), "capture.check", marker="present")
        assert any(getattr(r, "marker", None) == "present" for r in asic_log_records)
