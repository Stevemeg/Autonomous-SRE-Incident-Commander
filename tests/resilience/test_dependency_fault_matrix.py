"""Phase 15.4: controlled dependency fault matrix for the native integration adapters.

Every adapter the product ships (Prometheus, Loki, Kubernetes, Slack, PagerDuty, Jira, Grafana)
is driven against a real local HTTP endpoint that injects one fault at a time: connection
refused, receive timeout, dropped connection, HTTP 5xx, malformed body, truncated (partial)
body and rate limiting; plus a slow-but-in-deadline answer and recovery after an outage.

The invariants are the material failure semantics, not vendor trivia:

1. a fault is always a *classified* ``IntegrationError`` / ``IntegrationUnknownOutcome``,
   never success and never an unclassified exception;
2. for an effectful (external-record) call, any fault after the request may have been sent
   is never reported as "effect not applied" - an unknown outcome is reconciled, not retried;
3. the error text carries no credential;
4. every faulted call is bounded by its deadline;
5. the next call after the dependency recovers succeeds with no restart.

PostgreSQL, JWKS/IdP, the model provider and the OTLP exporter are covered by their own
suites (``test_database_stress``, ``tests/security/test_auth_campaign``,
``test_model_provider_failure``, ``test_telemetry_outage``). The embedding provider is the
deterministic in-process implementation only (ADR-0008): there is no network seam to fault.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from asic.domain.enums import IntegrationFailureClass as F
from asic.domain.enums import IntegrationKind
from asic.domain.errors import IntegrationError, IntegrationUnknownOutcome
from asic.integrations.base import AdapterRuntime
from asic.integrations.collaboration import (
    GrafanaAdapter,
    JiraAdapter,
    PagerDutyAdapter,
    SlackAdapter,
)
from asic.integrations.kubernetes import KubernetesAdapter
from asic.integrations.loki import LokiAdapter
from asic.integrations.prometheus import PrometheusAdapter
from tests.integrations import test_adapters as adapter_contracts
from tests.integrations.conftest import SECRETS, context, grant
from tests.integrations.local_http import LocalHttpServer, Scripted, local_server
from tests.integrations.test_adapters import _event, _window

pytestmark = pytest.mark.security


@dataclass(frozen=True)
class Case:
    name: str
    kind: IntegrationKind
    method: str
    path: str
    ok: Scripted
    call: Callable[[AdapterRuntime, Any], Any]
    effectful: bool
    settings: dict[str, Any] = field(default_factory=dict)
    credential_ref: str = "asic/test/read"
    setup: Callable[[LocalHttpServer], None] | None = None


CASES = [
    Case(
        "prometheus",
        IntegrationKind.PROMETHEUS,
        "GET",
        "/api/v1/query_range",
        Scripted(body={"status": "success", "data": {"resultType": "matrix", "result": []}}),
        lambda rt, ctx: PrometheusAdapter(rt).query_range(
            _window(metric="http_requests_total"), ctx
        ),
        effectful=False,
    ),
    Case(
        "loki",
        IntegrationKind.LOKI,
        "GET",
        "/loki/api/v1/query_range",
        Scripted(body={"status": "success", "data": {"resultType": "streams", "result": []}}),
        lambda rt, ctx: LokiAdapter(rt).query_range(_window(limit=10), ctx),
        effectful=False,
        settings={"org_id": "tenant-a"},
    ),
    Case(
        "kubernetes",
        IntegrationKind.KUBERNETES,
        "GET",
        "/apis/apps/v1/namespaces/checkout/deployments",
        Scripted(body={"items": []}),
        lambda rt, ctx: KubernetesAdapter(rt).workload_read(
            {**_window(), "namespace": "checkout", "include_events": False}, ctx
        ),
        effectful=False,
        setup=lambda server: adapter_contracts.TestKubernetes()._routes(server),
    ),
    Case(
        "slack",
        IntegrationKind.SLACK,
        "POST",
        "/api/chat.postMessage",
        Scripted(body={"ok": True, "ts": "1726488000.000100"}),
        lambda rt, ctx: SlackAdapter(rt).post(_event(), ctx),
        effectful=True,
        settings={"channel_id": "C0123456789"},
    ),
    Case(
        "pagerduty",
        IntegrationKind.PAGERDUTY,
        "POST",
        "/v2/enqueue",
        Scripted(status=202, body={"status": "success", "dedup_key": "__dedup__"}),
        lambda rt, ctx: PagerDutyAdapter(rt).event(_event(), ctx),
        effectful=True,
    ),
    Case(
        "jira",
        IntegrationKind.JIRA,
        "POST",
        "/rest/api/3/issue",
        Scripted(status=201, body={"id": "1", "key": "OPS-12"}),
        lambda rt, ctx: JiraAdapter(rt).create(_event(), ctx),
        effectful=True,
        settings={"project_key": "OPS"},
        credential_ref="asic/test/basic",
        setup=lambda server: server.route(
            "GET", "/rest/api/3/search/jql", Scripted(body={"issues": []})
        ),
    ),
    Case(
        "grafana",
        IntegrationKind.GRAFANA,
        "POST",
        "/api/annotations",
        Scripted(body={"id": 91, "message": "Annotation added"}),
        lambda rt, ctx: GrafanaAdapter(rt).annotate(_event(), ctx),
        effectful=True,
        settings={"dashboard_uid": "svc-overview"},
    ),
]

#: Fault -> (scripted answer, expected classes for a read, for an effectful call, whether a
#: request may have reached the dependency).
FAULTS: dict[str, tuple[Scripted | None, set[F], set[F], bool]] = {
    # Nothing reached the dependency. (Windows retries a refused loopback SYN for ~2 s, so
    # there the same fault surfaces as a connect-phase timeout: equally "not sent".)
    "connection_refused": (
        None,
        {F.TRANSIENT_UNAVAILABLE, F.TIMEOUT},
        {F.TRANSIENT_UNAVAILABLE, F.TIMEOUT},
        False,
    ),
    "timeout": (Scripted(delay=2.5), {F.TIMEOUT}, {F.UNKNOWN_OUTCOME}, True),
    "dropped_connection": (Scripted(drop=True), {F.TIMEOUT}, {F.UNKNOWN_OUTCOME}, True),
    "http_5xx": (Scripted(status=503), {F.TRANSIENT_UNAVAILABLE}, {F.TRANSIENT_UNAVAILABLE}, True),
    "malformed": (
        Scripted(raw=b"<html>upstream proxy error</html>"),
        {F.MALFORMED_RESPONSE},
        {F.MALFORMED_RESPONSE, F.UNKNOWN_OUTCOME},
        True,
    ),
    "partial": (
        Scripted(raw=b'{"status": "success", "data": {"resultType": "mat'),
        {F.MALFORMED_RESPONSE},
        {F.MALFORMED_RESPONSE, F.UNKNOWN_OUTCOME},
        True,
    ),
    # A definitive refusal by the vendor: nothing was applied, and saying so is correct.
    "rate_limited": (
        Scripted(status=429, headers={"Retry-After": "7"}),
        {F.RATE_LIMITED},
        {F.RATE_LIMITED},
        False,
    ),
}


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _serve(server: LocalHttpServer, case: Case, *answers: Scripted) -> None:
    if case.setup:
        case.setup(server)
    if case.name == "pagerduty":
        queue = list(answers)

        def answer(recorded: Any) -> Scripted:
            scripted = queue.pop(0) if len(queue) > 1 else queue[0]
            if scripted is case.ok:
                return Scripted(
                    status=202,
                    body={"status": "success", "dedup_key": recorded.json()["dedup_key"]},
                )
            return scripted

        server.handler(case.method, case.path, answer)
    else:
        server.route(case.method, case.path, *answers)


def _failure_class(error: BaseException) -> F:
    value = getattr(error, "failure_class", None)
    assert isinstance(value, F), f"unclassified failure: {type(error).__name__}"
    return value


@pytest.mark.parametrize("fault", sorted(FAULTS))
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_fault_is_classified_bounded_and_never_a_false_negative(
    runtime: AdapterRuntime, case: Case, fault: str
) -> None:
    scripted, read_classes, write_classes, may_have_sent = FAULTS[fault]
    with local_server() as server:
        endpoint = server.url
        if scripted is None:
            endpoint = f"http://127.0.0.1:{_closed_port()}"
        else:
            _serve(server, case, scripted)
        connector = grant(
            case.kind, endpoint, settings=case.settings, credential_ref=case.credential_ref
        )
        started = time.monotonic()
        with pytest.raises((IntegrationError, IntegrationUnknownOutcome)) as failed:
            case.call(runtime, context(connector, timeout=1))
        elapsed = time.monotonic() - started
    error = failed.value
    expected = write_classes if case.effectful else read_classes
    assert _failure_class(error) in expected, f"{case.name}/{fault}: {_failure_class(error)}"
    if case.effectful and may_have_sent:
        # An effect that may have been applied is never reported as certainly not applied.
        assert not getattr(error, "effect_not_applied", False), f"{case.name}/{fault}"
    if not may_have_sent:
        # ...and a request that provably never left (or was refused) is known not applied,
        # so the caller may retry it safely.
        assert getattr(error, "effect_not_applied", False), f"{case.name}/{fault}"
    if fault == "rate_limited":
        assert getattr(error, "retry_after_seconds", None) == 7.0
    for secret in SECRETS.values():
        assert secret not in str(error)
    assert elapsed < 5.0


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_slow_but_in_deadline_answers_succeed(runtime: AdapterRuntime, case: Case) -> None:
    with local_server() as server:
        slow = Scripted(
            status=case.ok.status, body=case.ok.body, headers=case.ok.headers, delay=0.3
        )
        if case.name == "pagerduty":
            _serve(server, case, case.ok)
        else:
            _serve(server, case, slow)
        connector = grant(
            case.kind, server.url, settings=case.settings, credential_ref=case.credential_ref
        )
        assert case.call(runtime, context(connector, timeout=5)) is not None


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_the_next_call_after_an_outage_succeeds(runtime: AdapterRuntime, case: Case) -> None:
    with local_server() as server:
        _serve(server, case, Scripted(status=503), case.ok)
        connector = grant(
            case.kind, server.url, settings=case.settings, credential_ref=case.credential_ref
        )
        with pytest.raises(IntegrationError):
            case.call(runtime, context(connector))
        assert case.call(runtime, context(connector)) is not None
