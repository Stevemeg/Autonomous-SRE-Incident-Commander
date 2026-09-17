"""INTEGRATION / SIMULATOR: telemetry emitted by real runs against PostgreSQL.

Covers committed-only lifecycle metrics (commit, rollback, savepoints), readiness and
dependency degradation, the exposition's cardinality policy after real workflows, and the
trace -> incident -> evaluation linkage.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import ApiSettings, create_app
from asic.db.models import Environment, ExecutionTrace, Incident, Tenant, WorkflowRun
from asic.db.session import bind_tenant
from asic.domain.enums import ExecutionMode, IncidentSeverity, IncidentStatus, TenantStatus
from asic.evaluation.harness import EvaluationHarness, HarnessConfig, SuiteOutcome
from asic.observability.catalogue import BY_NAME, FORBIDDEN_LABEL_KEYS, METRICS
from asic.observability.health import EXPECTED_SCHEMA_REVISION, check_database
from asic.observability.redaction import looks_like_secret
from asic.observability.setup import Telemetry
from tests.observability.conftest import sample

pytestmark = pytest.mark.postgres

REPO = Path(__file__).resolve().parents[2]
SETTINGS = ApiSettings(
    jwt_secret="phase12-test-signing-secret-not-production", metrics_enabled=True
)
IDENTIFIER = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-|\b[0-9a-f]{16,}\b", re.IGNORECASE)


def _factory(engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


# ------------------------------------------------------------------ committed-only facts


@pytest.fixture
def world(owner_engine: Engine) -> tuple[uuid.UUID, uuid.UUID]:
    with Session(owner_engine) as session, session.begin():
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=f"obs-{uuid.uuid4().hex[:10]}",
            display_name="observability",
            status=TenantStatus.ACTIVE,
        )
        session.add(tenant)
        session.flush()
        bind_tenant(session, tenant.id)
        environment = Environment(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="obs",
            display_name="obs",
            is_production=False,
        )
        session.add(environment)
        return tenant.id, environment.id


def _incident(
    tenant_id: uuid.UUID, environment_id: uuid.UUID, severity: IncidentSeverity
) -> Incident:
    return Incident(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        reference=f"OBS-{uuid.uuid4().hex[:8]}",
        title="observability probe",
        environment_id=environment_id,
        status=IncidentStatus.DETECTED,
        severity=severity,
        opened_at=datetime.now(UTC),
    )


class TestCommittedLifecycleFacts:
    SEVERITY = IncidentSeverity.SEV4

    def _opened(self) -> float:
        return sample("asic_incidents_opened_total", severity=self.SEVERITY.value)

    def test_only_committed_writes_are_counted(
        self, telemetry: Telemetry, app_engine: Engine, world: tuple[uuid.UUID, uuid.UUID]
    ) -> None:
        tenant_id, environment_id = world
        before = self._opened()

        with Session(app_engine) as session, session.begin():
            bind_tenant(session, tenant_id)
            session.add(_incident(tenant_id, environment_id, self.SEVERITY))
        assert self._opened() - before == 1

        session = Session(app_engine)
        session.begin()
        bind_tenant(session, tenant_id)
        session.add(_incident(tenant_id, environment_id, self.SEVERITY))
        session.flush()  # written to the database, then undone
        session.rollback()
        session.close()
        assert self._opened() - before == 1

        with Session(app_engine) as session, session.begin():
            bind_tenant(session, tenant_id)
            savepoint = session.begin_nested()
            session.add(_incident(tenant_id, environment_id, self.SEVERITY))
            session.flush()
            savepoint.rollback()
            released = session.begin_nested()
            session.add(_incident(tenant_id, environment_id, self.SEVERITY))
            session.flush()
            released.commit()
        assert self._opened() - before == 2

        session = Session(app_engine)
        session.begin()
        bind_tenant(session, tenant_id)
        released = session.begin_nested()
        session.add(_incident(tenant_id, environment_id, self.SEVERITY))
        session.flush()
        released.commit()  # a released savepoint is still undone by its enclosing rollback
        session.rollback()
        session.close()
        assert self._opened() - before == 2

    def test_status_transitions_are_counted_by_new_status(
        self, telemetry: Telemetry, app_engine: Engine, world: tuple[uuid.UUID, uuid.UUID]
    ) -> None:
        tenant_id, environment_id = world
        before = sample("asic_incident_transitions_total", to_status="acknowledged")
        with Session(app_engine) as session, session.begin():
            bind_tenant(session, tenant_id)
            incident = _incident(tenant_id, environment_id, self.SEVERITY)
            incident_id = incident.id
            session.add(incident)
        with Session(app_engine) as session, session.begin():
            bind_tenant(session, tenant_id)
            row = session.get(Incident, incident_id)
            assert row is not None
            row.status = IncidentStatus.ACKNOWLEDGED
        assert sample("asic_incident_transitions_total", to_status="acknowledged") - before == 1


# ------------------------------------------------------------------------ health


class TestHealth:
    def test_expected_revision_is_the_migration_head(self) -> None:
        config = Config(str(REPO / "alembic.ini"))
        config.set_main_option("script_location", str(REPO / "migrations"))
        assert ScriptDirectory.from_config(config).get_current_head() == EXPECTED_SCHEMA_REVISION

    def test_ready_when_the_database_answers_at_the_expected_revision(
        self, telemetry: Telemetry, app_engine: Engine
    ) -> None:
        client = TestClient(create_app(settings=SETTINGS, factory=_factory(app_engine)))
        assert client.get("/livez").status_code == 200
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["dependencies"]["database"] == {
            "status": "up",
            "detail": "ok",
            "critical": True,
        }
        assert sample("asic_dependency_up", dependency="database") == 1.0

    def test_a_schema_mismatch_is_degraded_and_not_ready(self, app_engine: Engine) -> None:
        check = check_database(_factory(app_engine), expected_revision="0000_not_this_one")
        assert (check.status.value, check.detail) == ("degraded", "schema_revision_mismatch")

    def test_an_unreachable_database_is_not_ready_and_discloses_nothing(
        self, telemetry: Telemetry, database_url: str
    ) -> None:
        unreachable = sa.engine.make_url(database_url).set(host="127.0.0.1", port=1)
        engine = sa.create_engine(unreachable, connect_args={"connect_timeout": 2})
        try:
            client = TestClient(create_app(settings=SETTINGS, factory=_factory(engine)))
            assert client.get("/livez").status_code == 200  # liveness never touches the database
            response = client.get("/readyz")
            assert response.status_code == 503
            body = response.text
            assert response.json()["dependencies"]["database"]["detail"] == "unreachable"
            assert "127.0.0.1" not in body and "password" not in body.lower()
            assert sample("asic_dependency_up", dependency="database") == 0.0
        finally:
            engine.dispose()
        # Restore the gauge for anything that reads it later in the session.
        check_database(_factory(sa.create_engine(database_url)))

    def test_metrics_endpoint_is_off_unless_enabled(self, app_engine: Engine) -> None:
        disabled = ApiSettings(jwt_secret=SETTINGS.jwt_secret)
        client = TestClient(create_app(settings=disabled, factory=_factory(app_engine)))
        assert client.get("/metrics").status_code == 404


# ------------------------------------------------------- exposition and trace linkage


@pytest.fixture(scope="module")
def evaluated(
    telemetry: Telemetry,
    span_exporter: InMemorySpanExporter,
    owner_engine: Engine,
    app_engine: Engine,
) -> tuple[SuiteOutcome, list[object]]:
    span_exporter.clear()
    harness = EvaluationHarness(
        admin_factory=_factory(owner_engine), app_factory=_factory(app_engine)
    )
    outcome = harness.run(
        HarnessConfig(
            tenant_slug=f"obs-ev-{uuid.uuid4().hex[:8]}",
            keys=("EV-INV-005", "EV-INV-009", "EV-REM-002", "EV-COR-001", "EV-SEC-002"),
            mode=ExecutionMode.SIMULATOR,
            baseline="none",
        )
    )
    finished = list(span_exporter.get_finished_spans())
    span_exporter.clear()
    return outcome, finished


class TestExpositionAndLinkage:
    def test_exposition_respects_the_label_policy_after_real_workflows(
        self, evaluated: tuple[SuiteOutcome, list[object]], app_engine: Engine
    ) -> None:
        outcome, _ = evaluated
        assert outcome.status == "passed"
        client = TestClient(create_app(settings=SETTINGS, factory=_factory(app_engine)))
        client.get("/readyz")
        client.get(f"/api/v1/incidents/{uuid.uuid4()}")  # unauthenticated: a 401 with a route
        response = client.get("/metrics")
        assert response.status_code == 200
        families = {
            family.name: family
            for family in text_string_to_metric_families(response.text)
            if family.name.startswith("asic_")
        }
        by_family = {spec.prometheus_name.removesuffix("_total"): spec for spec in METRICS}
        for name, family in families.items():
            spec = by_family.get(name)
            assert spec is not None, f"{name} is exported but not catalogued"
            for item in family.samples:
                keys = set(item.labels) - {
                    "le",
                    "otel_scope_name",
                    "otel_scope_version",
                    "otel_scope_schema_url",
                }
                assert keys <= spec.labels, (
                    f"{item.name} has uncatalogued labels {keys - spec.labels}"
                )
                assert not keys & FORBIDDEN_LABEL_KEYS
                for key in keys:
                    value = item.labels[key]
                    assert not IDENTIFIER.search(value), (
                        f"{item.name}{{{key}={value!r}}} looks like an id"
                    )
                    assert not looks_like_secret(value)

        # The workflows really produced lifecycle, broker, model and evaluation series.
        for required in (
            "asic_incidents_opened",
            "asic_workflow_runs_started",
            "asic_remediation_policy_decisions",
            "asic_remediation_approvals",
            "asic_remediation_verifications",
            "asic_llm_usage_tokens",
            "asic_llm_usage_cost_usd",
            "asic_evaluation_suite_runs",
            "asic_evaluation_results",
            "asic_tool_invocations",
            "asic_integration_calls",
            "asic_node_duration_seconds",
            "asic_api_requests",
            "asic_api_request_duration_seconds",
            "asic_dependency_up",
            "asic_knowledge_retrievals",
        ):
            assert required in families, f"{required} was not exported"
        routes = {s.labels.get("route") for s in families["asic_api_requests"].samples}
        assert "/api/v1/incidents/{incident_id}" in routes
        assert not any(r and IDENTIFIER.search(r) for r in routes)

    def test_traces_link_incident_workflow_and_evaluation(
        self, evaluated: tuple[SuiteOutcome, list[object]], owner_engine: Engine
    ) -> None:
        outcome, finished = evaluated
        spans = list(finished)
        scenario_spans = {
            s.attributes["asic.evaluation.scenario"]: s  # type: ignore[attr-defined]
            for s in spans
            if s.name == "evaluation.scenario"  # type: ignore[attr-defined]
        }
        suite_spans = [s for s in spans if s.name == "evaluation.suite"]  # type: ignore[attr-defined]
        assert len(suite_spans) == 1
        assert suite_spans[0].attributes["asic.evaluation.suite_run_id"] == str(
            outcome.suite_run_id
        )  # type: ignore[attr-defined]

        report = {s["key"]: s for s in outcome.report["scenarios"]}
        for key in ("EV-INV-009", "EV-REM-002"):
            trace_id = report[key]["trace_id"]
            assert trace_id and re.fullmatch(r"[0-9a-f]{32}", trace_id)
            assert scenario_spans[key].attributes["asic.evaluated_trace_id"] == trace_id  # type: ignore[attr-defined]
            with Session(owner_engine) as session:
                trace = session.scalars(
                    sa.select(ExecutionTrace).where(ExecutionTrace.trace_id == trace_id)
                ).one()
                run = session.get(WorkflowRun, trace.workflow_run_id)
                assert run is not None and run.incident_id == trace.incident_id
            product = [
                s
                for s in spans
                if (s.attributes or {}).get("asic.execution_trace_id") == str(trace.id)  # type: ignore[attr-defined]
            ]
            assert product, f"no exported product spans for {key}"
            assert {format(s.context.trace_id, "032x") for s in product} == {trace_id}  # type: ignore[attr-defined]

    def test_exported_spans_carry_no_secrets_prompts_or_injected_content(
        self, evaluated: tuple[SuiteOutcome, list[object]]
    ) -> None:
        _, finished = evaluated
        assert finished
        for span in finished:
            texts = [str(v) for v in (span.attributes or {}).values()]  # type: ignore[attr-defined]
            texts.append(span.status.description or "")  # type: ignore[attr-defined]
            assert not list(span.events)  # type: ignore[attr-defined]
            for text in texts:
                assert not looks_like_secret(text)
                # EV-INV-005's hostile log line must never reach telemetry.
                assert "ignore all previous instructions" not in text.lower()
                assert "## Operational data" not in text  # no rendered prompt bodies
            assert "asic.prompt_text" not in (span.attributes or {})  # type: ignore[attr-defined]

    def test_every_catalogued_counter_name_is_unique_after_translation(self) -> None:
        names = [spec.prometheus_name for spec in METRICS]
        assert len(names) == len(set(names))
        assert set(BY_NAME) == {spec.name for spec in METRICS}
