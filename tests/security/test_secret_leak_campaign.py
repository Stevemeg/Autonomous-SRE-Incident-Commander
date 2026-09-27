"""Phase 15.21: secret-leak campaign with canary credentials through every entry point.

Canary credentials - each realistically shaped (JWT, DSN with password, ``PGPASSWORD``, API
key, cloud access key, chat token) and each carrying a unique ``CANARY`` marker - are pushed in
through: the Authorization header, query parameters, JSON bodies, a vendor's error response, a
model provider's exception, a Kubernetes adapter failure, a tool's output, a retrieved
document, an evaluation-gate failure and deployment (kubectl) diagnostics.

Every sink an operator or attacker could read is then searched for the marker: raw
``LogRecord`` attributes, formatted JSON log lines, exported span attributes and events,
persisted trace spans, the Prometheus exposition, audit records, API error bodies, the
evaluation report and deployment diagnostics. Redaction is a backup layer (the primary controls
are typed and structural - see SECRETS_POLICY.md); this campaign checks the combination.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from scripts import deploy_release
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.db.models import (
    AuditRecord,
    IncidentEvent,
    InvestigationStep,
    ToolExecution,
    TraceSpan,
    WorkflowCheckpoint,
    WorkflowRun,
)
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import IntegrationKind
from asic.domain.errors import IntegrationError, ModelProviderError
from asic.evaluation import gate
from asic.integrations.base import AdapterRuntime
from asic.integrations.collaboration import SlackAdapter
from asic.integrations.kubernetes import KubernetesAdapter
from asic.llm.deterministic import DeterministicModelProvider
from asic.observability.logging import JsonFormatter
from asic.observability.setup import render_prometheus
from asic.orchestration.kernel import InvestigationKernel
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, SimulatedResponse, scenario
from asic.tools.capability import CapabilityResolver
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.integrations.conftest import context, grant
from tests.integrations.local_http import Scripted, local_server
from tests.integrations.test_adapters import _event, _window
from tests.kernel_fixtures import build_fixture

pytestmark = [pytest.mark.postgres, pytest.mark.security]

# The JWT and API-key canaries are assembled at runtime so no token-shaped literal sits in the
# source for secret scanners (gitleaks) to report; the values are synthetic either way.
CANARIES = {
    "jwt": ".".join(
        ("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJDQU5BUlktSldUIn0", "Q0FOQVJZLUpXVC1TSUdOQVRVUkU")
    ),
    "dsn": "postgresql://owner:CANARYDSN7c1q@db.internal:5432/asic",  # hygiene: synthetic-secret-fixture
    "pgpassword": "PGPASSWORD=CANARYPG9b2xyz",
    "api_key": "sk-" + "CANARYAPIKEY0123456789abcd",
    "aws": "AKIACANARY1234567890",  # hygiene: synthetic-secret-fixture
    "slack": "xoxb-CANARY-1234567890-abcdefghij",  # hygiene: synthetic-secret-fixture
}
MARKERS = (
    "CANARYDSN7c1q",
    "CANARYPG9b2xyz",
    "CANARYAPIKEY",
    "AKIACANARY",
    "xoxb-CANARY",
    "Q0FOQVJZLUpXVC1TSUdOQVRVUkU",  # the JWT's signature segment
)
ALL = " ".join(CANARIES.values())


def _leaks(text: str) -> list[str]:
    return [marker for marker in MARKERS if marker in text]


def _record_text(record: logging.LogRecord) -> str:
    return json.dumps({k: str(v) for k, v in vars(record).items()}) + JsonFormatter(
        service="leak-campaign"
    ).format(record)


class Probe:
    """Collects every sink after the flows have run."""

    def __init__(self, records: list[logging.LogRecord], spans: Any) -> None:
        self.records, self.spans = records, spans
        self.api_bodies: list[str] = []
        self.extra: list[str] = []

    def assert_clean(self, engine: Engine, tenant_id: uuid.UUID | None = None) -> None:
        for record in self.records:
            assert not _leaks(_record_text(record)), ("log", record.getMessage(), record.__dict__)
        for span in self.spans.get_finished_spans():
            rendered = json.dumps(
                {
                    "name": span.name,
                    "attributes": {k: str(v) for k, v in (span.attributes or {}).items()},
                    "events": [
                        {e.name: {k: str(v) for k, v in (e.attributes or {}).items()}}
                        for e in span.events
                    ],
                    "status": str(span.status.description),
                }
            )
            assert not _leaks(rendered), ("span", span.name, rendered[:500])
        assert not _leaks(render_prometheus()[0].decode()), "metrics"
        for body in self.api_bodies:
            assert not _leaks(body), ("api", body[:300])
        for text in self.extra:
            assert not _leaks(text), ("other", text[:300])
        if tenant_id is not None:
            factory = sessionmaker(engine)
            with factory() as session:
                bind_tenant(session, tenant_id)
                for model in (
                    AuditRecord,
                    TraceSpan,
                    WorkflowCheckpoint,
                    WorkflowRun,
                    InvestigationStep,
                    IncidentEvent,
                    ToolExecution,
                ):
                    for row in session.scalars(
                        sa.select(model).where(model.tenant_id == tenant_id)
                    ):
                        rendered = json.dumps(
                            {c.name: str(getattr(row, c.key)) for c in model.__table__.columns}
                        )
                        found = _leaks(rendered)
                        columns = [
                            c.name
                            for c in model.__table__.columns
                            if _leaks(str(getattr(row, c.key)))
                        ]
                        assert not found, (model.__name__, columns, found)


@pytest.fixture
def probe(asic_log_records: list[logging.LogRecord], spans: Any) -> Probe:
    return Probe(asic_log_records, spans)


def test_api_entry_points(app_engine: Engine, owner_engine: Engine, probe: Probe) -> None:
    factory: Callable[[], Session] = sessionmaker(app_engine, expire_on_commit=False)
    with Session(owner_engine, expire_on_commit=False, autoflush=False) as arranging:
        fixture = build_fixture(arranging, slug=f"leak-api-{uuid.uuid4().hex[:8]}")
        arranging.commit()
        subject = f"leak-{uuid.uuid4().hex[:6]}"
        _principal(arranging, fixture, "responder", subject)
    client = TestClient(create_app(settings=SETTINGS, factory=factory))
    good = {"Authorization": f"Bearer {_token(fixture.tenant_id, subject)}"}
    responses = [
        client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {CANARIES['jwt']}"}),
        client.get("/api/v1/incidents", headers={"Authorization": f"Basic {CANARIES['api_key']}"}),
        client.get(
            "/api/v1/incidents",
            params={"token": CANARIES["api_key"], "dsn": CANARIES["dsn"]},
            headers=good,
        ),
        client.get(f"/api/v1/incidents/{CANARIES['aws']}", headers=good),
        # A wrong-typed field containing canaries: the 422 must not echo the input.
        client.post(
            f"/api/v1/incidents/{fixture.incident.id}/annotate",
            headers={**good, "Idempotency-Key": f"leak-{uuid.uuid4().hex}"},
            json={"justification": {"password": CANARIES["pgpassword"], "k": ALL}},
        ),
        client.post(
            f"/api/v1/incidents/{fixture.incident.id}/annotate",
            headers={**good, "Idempotency-Key": f"leak-{uuid.uuid4().hex}"},
            json={"justification": "ok", CANARIES["slack"]: CANARIES["dsn"]},
        ),
    ]
    assert [r.status_code for r in responses] == [401, 401, 200, 422, 422, 422]
    probe.api_bodies.extend(r.text for r in responses)
    probe.assert_clean(app_engine, fixture.tenant_id)


def test_vendor_and_kubernetes_failures(runtime: AdapterRuntime, probe: Probe) -> None:
    with local_server() as server:
        server.route(
            "POST",
            "/api/chat.postMessage",
            Scripted(status=500, body={"error": ALL, "echo": {"Authorization": CANARIES["jwt"]}}),
        )
        server.route(
            "GET",
            "/apis/apps/v1/namespaces/checkout/deployments",
            Scripted(status=403, body={"message": f"forbidden: token {CANARIES['jwt']} {ALL}"}),
        )
        for call in (
            lambda: SlackAdapter(runtime).post(
                _event(summary=ALL),
                context(grant(IntegrationKind.SLACK, server.url, settings={"channel_id": "C01"})),
            ),
            lambda: KubernetesAdapter(runtime).workload_read(
                {**_window(), "namespace": "checkout", "include_events": False},
                context(grant(IntegrationKind.KUBERNETES, server.url)),
            ),
        ):
            with pytest.raises(IntegrationError) as failed:
                call()
            probe.extra.append(str(failed.value) + repr(failed.value))
    probe.extra.append(deploy_release.bounded(f"kubectl apply failed: {ALL} {CANARIES['dsn']}"))
    probe.assert_clean(None)  # type: ignore[arg-type]


class LeakyModel:
    """A model provider whose failure message quotes secrets (vendor SDKs do this)."""

    def __init__(self, delegate: DeterministicModelProvider) -> None:
        self.delegate, self.calls = delegate, 0

    @property
    def provider_name(self) -> str:
        return self.delegate.provider_name

    @property
    def model_id(self) -> str:
        return self.delegate.model_id

    def estimate(self, request: Any) -> Any:
        return self.delegate.estimate(request)

    def complete(self, request: Any) -> Any:
        self.calls += 1
        if self.calls >= 3:
            raise ModelProviderError(
                f"upstream 401 for key {CANARIES['api_key']} via {CANARIES['dsn']}"
            )
        return self.delegate.complete(request)


def test_provider_exception_tool_output_and_retrieved_text(
    app_engine: Engine, resolver: CapabilityResolver, probe: Probe
) -> None:
    factory: Callable[[], Session] = sessionmaker(
        app_engine, expire_on_commit=False, autoflush=False
    )
    base = scenario(PRIMARY_SCENARIO_ID)
    service = base.service
    responses = dict(base.responses)
    logs_builder = responses[f"read.logs|{service}"].builder
    assert logs_builder is not None

    def leaky_logs(ctx: Any) -> Any:
        result = dict(logs_builder(ctx))
        result["lines"] = [f"{ctx.at(0.6).isoformat()} config dump {ALL}", *result["lines"]]
        return result

    responses[f"read.logs|{service}"] = SimulatedResponse(builder=leaky_logs)
    from dataclasses import replace

    case = replace(base, responses=responses)
    with factory() as arranging, arranging.begin():
        fixture = build_fixture(
            arranging, slug=f"leak-run-{uuid.uuid4().hex[:8]}", service_name=service
        )
    clock = FrozenClock(start=fixture.incident.opened_at)
    outcome = InvestigationKernel(
        session_factory=factory,
        resolver=resolver,
        providers=[SimulatorProvider(case, clock=clock)],
        model=LeakyModel(DeterministicModelProvider(case)),
        clock=clock,
        budget_policy=case.budget,
    ).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
    )
    assert outcome.terminated
    probe.assert_clean(app_engine, fixture.tenant_id)


def test_evaluation_gate_failure_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Any, probe: Probe
) -> None:
    class Exploding:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError(
                f"could not connect using {CANARIES['dsn']} {CANARIES['pgpassword']}"
            )

    monkeypatch.setattr(gate, "EvaluationHarness", Exploding)
    monkeypatch.setattr(gate, "configure_telemetry", lambda *_a, **_k: None)
    output = tmp_path / "report.json"
    code = gate.main(
        [
            "--database-url",
            "postgresql://x/y",
            "--admin-database-url",
            "postgresql://x/y",
            "--output",
            str(output),
        ]
    )
    assert code == 2
    captured = capsys.readouterr()
    probe.extra.extend([output.read_text("utf-8"), captured.out, captured.err])
    probe.assert_clean(None)  # type: ignore[arg-type]
