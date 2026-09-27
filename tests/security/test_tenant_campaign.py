"""Phase 15.17: tenant adversarial campaign, schema-wide, as the real non-owner application role.

Tenant B is populated through the real product paths - a full autonomous remediation to
``resolved`` (investigation, evidence, hypotheses, policy decision, action, tool executions,
verification, audit, checkpoints, traces), a governed knowledge ingestion and an idempotent API
call. Then, bound to an unrelated tenant A under the unprivileged application role, *every*
tenant-scoped table in the model registry is attacked:

* read B's rows (filtered and unfiltered) - nothing is visible;
* update B's rows - nothing is reachable (or the table is not updatable at all);
* delete B's rows - the role holds no DELETE anywhere;
* insert a copy of a B row still labelled B - refused by row-level security;
* insert a copy relabelled A but still pointing at B's parent rows - refused by the composite
  tenant foreign keys (a cross-tenant reference cannot be written at all).

The API is attacked the same way: every B object id guessed on every GET route, B incidents
controlled, forged pagination cursors pointing into B, and a connector identity of B used to
ingest into A. Nothing crosses.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import Callable
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.db.base import Base
from asic.db.models import (
    EvaluationSuiteRun,
    Incident,
    RemediationAction,
    ToolExecution,
)
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    IncidentStatus,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    RiskTier,
    TrustClass,
)
from asic.knowledge.contracts import ImportActor, ImportContext, SourceAccessPolicy, SourceDocument
from asic.knowledge.embedding import DeterministicEmbeddingProvider, EmbeddingService
from asic.knowledge.ingestion import KnowledgeIngestionService
from asic.simulators.scenarios import scenario
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry
from tests.api.test_auth import SETTINGS, _bind_connector, _principal, _token
from tests.kernel_fixtures import CLOCK_START, build_fixture
from tests.orchestration.test_remediation import (
    _remediation_scenario,
    _resume_remediation,
    _run_remediation,
)
from tests.remediation_fixtures import escalate_to_accepted_hypothesis

pytestmark = [pytest.mark.postgres, pytest.mark.security]

TENANT_TABLES = [table for table in Base.metadata.sorted_tables if "tenant_id" in table.c]


class Worlds:
    """Tenant B populated through real flows; tenant A empty apart from its fixture."""

    def __init__(
        self,
        app_engine: Engine,
        owner_engine: Engine,
        resolver: CapabilityResolver,
        remediation_resolver: CapabilityResolver,
    ) -> None:
        self.factory: Callable[[], Session] = sessionmaker(
            app_engine, expire_on_commit=False, autoflush=False
        )
        clock = FrozenClock(start=CLOCK_START)
        with self.factory() as session, session.begin():
            self.b = build_fixture(session, slug=f"victim-{uuid.uuid4().hex[:8]}")
            self.b.environment.is_production = False  # autonomous R1 path, no human needed
        with self.factory() as session, session.begin():
            self.a = build_fixture(session, slug=f"attacker-{uuid.uuid4().hex[:8]}")
        hypothesis = escalate_to_accepted_hypothesis(
            self.factory, resolver, clock, self.b, scenario("SC-0001-checkout-latency-after-deploy")
        )
        outcome = _run_remediation(
            self.factory, remediation_resolver, clock, self.b, hypothesis, _remediation_scenario()
        )
        clock.advance(90)
        outcome = _resume_remediation(self.factory, remediation_resolver, clock, self.b, outcome)
        assert outcome.incident_status is IncidentStatus.RESOLVED
        KnowledgeIngestionService(
            self.factory, EmbeddingService(DeterministicEmbeddingProvider()), clock=clock
        ).ingest(
            ImportContext(
                tenant_id=self.b.tenant_id,
                provider="git",
                source_ref="victim/runbook.md",
                policy=SourceAccessPolicy(
                    document_type=KnowledgeDocumentType.RUNBOOK,
                    trust_class=TrustClass.OFFICIAL_RUNBOOK,
                    service_ids=(self.b.service.id,),
                    environment_ids=(self.b.environment.id,),
                ),
                actor=ImportActor(actor_type=ActorType.SYSTEM, actor_id="connector:git"),
            ),
            SourceDocument(
                title="Victim runbook",
                body=b"# Private runbook\n\nConfidential remediation steps.\n",
                content_format=KnowledgeContentFormat.MARKDOWN,
            ),
        )
        with Session(owner_engine, expire_on_commit=False, autoflush=False) as arranging:
            self.b_subject, self.a_subject = (
                f"b-{uuid.uuid4().hex[:6]}",
                f"a-{uuid.uuid4().hex[:6]}",
            )
            _principal(arranging, self.b, "platform_admin", self.b_subject, environment_id=None)
            _principal(arranging, self.a, "platform_admin", self.a_subject, environment_id=None)
            _principal(
                arranging, self.a, "system_operator", f"{self.a_subject}-op", environment_id=None
            )
            _bind_connector(arranging, self.b, connector_id="victim-alerts")
        self.client = TestClient(create_app(settings=SETTINGS, factory=self.factory))
        self.a_headers = {"Authorization": f"Bearer {_token(self.a.tenant_id, self.a_subject)}"}
        b_headers = {
            "Authorization": f"Bearer {_token(self.b.tenant_id, self.b_subject)}",
            "Idempotency-Key": f"victim-{uuid.uuid4().hex}",
        }
        annotated = self.client.post(
            f"/api/v1/incidents/{self.b.incident.id}/annotate",
            headers=b_headers,
            json={"justification": "victim's private note"},
        )
        assert annotated.status_code == 200


@pytest.fixture(scope="module")
def worlds(app_engine: Engine, owner_engine: Engine) -> Worlds:
    return Worlds(
        app_engine,
        owner_engine,
        CapabilityResolver(ToolRegistry.read_only()),
        CapabilityResolver(ToolRegistry.remediation_full(), max_risk_tier=RiskTier.R2),
    )


CAMPAIGN_ROLE = "asic_campaign_app"
CAMPAIGN_PASSWORD = "asic-campaign-role-local-only"


@pytest.fixture(scope="module")
def pure_app_engine(owner_engine: Engine, database_url: str) -> Any:
    """A login role holding exactly ``asic_app``'s privileges and nothing else.

    The shared test login role carries test-only INSERT/UPDATE/DELETE grants so fixtures can
    arrange data; attacking with it would test the fixture's privileges, not production's.
    """
    with owner_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{CAMPAIGN_ROLE}') THEN
                        CREATE ROLE {CAMPAIGN_ROLE} LOGIN PASSWORD '{CAMPAIGN_PASSWORD}'
                            NOSUPERUSER NOBYPASSRLS NOINHERIT IN ROLE asic_app;
                    END IF;
                END
                $$;
                """
            )
        )
        direct = conn.scalar(
            sa.text("SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = :r"),
            {"r": CAMPAIGN_ROLE},
        )
        assert direct == 0, "the campaign role must hold no grant of its own"
    url = (
        sa.engine.make_url(database_url)
        .set(username=CAMPAIGN_ROLE, password=CAMPAIGN_PASSWORD)
        .render_as_string(hide_password=False)
    )
    engine = sa.create_engine(url, future=True)
    with engine.connect() as connection:
        # NOINHERIT: act as the application role exactly, as the runtime does.
        connection.execute(sa.text("SET ROLE asic_app"))
    yield engine
    engine.dispose()


def _owner_rows(
    owner_engine: Engine, table: sa.Table, tenant_id: uuid.UUID
) -> list[dict[str, Any]]:
    with owner_engine.connect() as connection:
        return [
            dict(row._mapping)
            for row in connection.execute(
                sa.select(table).where(table.c.tenant_id == tenant_id).limit(1)
            )
        ]


def _sqlstate(error: BaseException) -> str | None:
    return getattr(getattr(error, "orig", None), "pgcode", None)


def test_every_tenant_table_is_closed_to_another_tenant(
    worlds: Worlds, pure_app_engine: Engine, owner_engine: Engine
) -> None:
    populated = 0
    with pure_app_engine.connect() as connection:
        connection.execute(sa.text("SET ROLE asic_app"))
        connection.commit()
        for table in TENANT_TABLES:
            victim_rows = _owner_rows(owner_engine, table, worlds.b.tenant_id)
            populated += bool(victim_rows)
            transaction = connection.begin()
            try:
                connection.execute(
                    sa.text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": str(worlds.a.tenant_id)},
                )
                # READ: filtered and unfiltered, B is invisible.
                visible_b = connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.tenant_id == worlds.b.tenant_id)
                )
                assert visible_b == 0, f"{table.name}: {visible_b} rows of B visible to A"
                foreign = connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.tenant_id != worlds.a.tenant_id)
                )
                assert foreign == 0, f"{table.name}: foreign rows visible"

                # UPDATE: nothing of B is reachable (or the table is append-only / read-only).
                savepoint = connection.begin_nested()
                try:
                    result = connection.execute(
                        sa.update(table)
                        .where(table.c.tenant_id == worlds.b.tenant_id)
                        .values(tenant_id=worlds.a.tenant_id)
                    )
                    assert result.rowcount == 0, f"{table.name}: updated B rows"
                    savepoint.commit()
                except sa.exc.DBAPIError as error:
                    savepoint.rollback()
                    assert _sqlstate(error) == "42501", (table.name, _sqlstate(error))

                # DELETE: the application role holds no DELETE at all.
                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        sa.delete(table).where(table.c.tenant_id == worlds.b.tenant_id)
                    )
                    savepoint.commit()
                    pytest.fail(f"{table.name}: DELETE was permitted")
                except sa.exc.DBAPIError as error:
                    savepoint.rollback()
                    assert _sqlstate(error) == "42501", (table.name, _sqlstate(error))

                if victim_rows:
                    row = dict(victim_rows[0])
                    if "id" in table.c:
                        row["id"] = uuid.uuid4()
                    # INSERT still labelled B: row-level security refuses it.
                    savepoint = connection.begin_nested()
                    try:
                        connection.execute(sa.insert(table).values(**row))
                        savepoint.commit()
                        pytest.fail(f"{table.name}: inserted a row labelled with tenant B")
                    except sa.exc.DBAPIError as error:
                        savepoint.rollback()
                        assert _sqlstate(error) in ("42501", "23505", "23514"), (
                            table.name,
                            _sqlstate(error),
                        )
                    # INSERT relabelled A but still referencing B's parents: the composite
                    # tenant foreign keys make the cross-tenant reference unwritable.
                    tenant_fks = [
                        fk
                        for fk in table.foreign_key_constraints
                        if "tenant_id" in fk.column_keys and len(fk.column_keys) > 1
                    ]
                    references_b = [
                        fk
                        for fk in tenant_fks
                        if all(row.get(c) is not None for c in fk.column_keys if c != "tenant_id")
                    ]
                    if references_b:
                        row["tenant_id"] = worlds.a.tenant_id
                        savepoint = connection.begin_nested()
                        try:
                            connection.execute(sa.insert(table).values(**row))
                            savepoint.commit()
                            pytest.fail(f"{table.name}: wrote a reference into tenant B")
                        except sa.exc.DBAPIError as error:
                            savepoint.rollback()
                            assert _sqlstate(error) in ("23503", "42501", "23505", "23514"), (
                                table.name,
                                _sqlstate(error),
                            )
            finally:
                transaction.rollback()
    # Non-vacuous: the real flows populated most of the schema for the victim tenant.
    assert populated >= 30, f"only {populated} tables populated for the victim"


def _b_ids(worlds: Worlds) -> dict[str, uuid.UUID]:
    with worlds.factory() as session:
        bind_tenant(session, worlds.b.tenant_id)
        action = session.scalars(
            sa.select(RemediationAction.id).where(RemediationAction.tenant_id == worlds.b.tenant_id)
        ).first()
        execution = session.scalars(
            sa.select(ToolExecution.id).where(ToolExecution.tenant_id == worlds.b.tenant_id)
        ).first()
    assert action is not None and execution is not None
    return {"incident": worlds.b.incident.id, "action": action, "execution": execution}


def test_guessing_another_tenants_object_ids_on_every_route_finds_nothing(
    worlds: Worlds,
) -> None:
    ids = _b_ids(worlds)
    incident, action = ids["incident"], ids["action"]
    routes = [
        f"/api/v1/incidents/{incident}",
        f"/api/v1/incidents/{incident}/timeline",
        f"/api/v1/incidents/{incident}/evidence",
        f"/api/v1/incidents/{incident}/hypotheses",
        f"/api/v1/incidents/{incident}/actions",
        f"/api/v1/incidents/{incident}/trace",
        f"/api/v1/approvals/{action}",
        f"/api/v1/evaluation/suite-runs/{uuid.uuid4()}",
    ]
    for route in routes:
        response = worlds.client.get(route, headers=worlds.a_headers)
        assert response.status_code in (403, 404), (route, response.status_code)
        assert str(incident) not in response.text or response.status_code == 404
    for control in ("escalate", "cancel", "annotate"):
        response = worlds.client.post(
            f"/api/v1/incidents/{incident}/{control}",
            headers={**worlds.a_headers, "Idempotency-Key": f"attack-{uuid.uuid4().hex}"},
            json={"justification": "cross-tenant control attempt"},
        )
        assert response.status_code in (403, 404), (control, response.status_code)
    # Tenant-wide listings return only A's own objects.
    for listing in ("/api/v1/incidents", "/api/v1/approvals/pending", "/api/v1/admin/audit"):
        response = worlds.client.get(listing, headers=worlds.a_headers)
        assert response.status_code == 200, listing
        assert str(incident) not in response.text and str(worlds.b.tenant_id) not in response.text


def test_forged_cursors_cannot_page_into_another_tenant(worlds: Worlds) -> None:
    incident = _b_ids(worlds)["incident"]
    forged = base64.urlsafe_b64encode(str(incident).encode()).decode().rstrip("=")
    for route in ("/api/v1/incidents", f"/api/v1/incidents/{worlds.a.incident.id}/timeline"):
        response = worlds.client.get(route, params={"cursor": forged}, headers=worlds.a_headers)
        assert response.status_code in (200, 400), route
        assert str(incident) not in response.text
        assert str(worlds.b.tenant_id) not in response.text


def test_a_victims_connector_identity_cannot_ingest_into_the_attacker(worlds: Worlds) -> None:
    token = _token(
        worlds.a.tenant_id,
        f"{worlds.a_subject}-op",
        connector_id="victim-alerts",  # bound in tenant B only
        source="simulator",
        service_id=str(worlds.a.service.id),
        environment_id=str(worlds.a.environment.id),
    )
    response = worlds.client.post(
        "/api/v1/ingest/alerts",
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": f"x-{uuid.uuid4().hex}"},
        json={
            "schema_version": 1,
            "source_event_id": "cross-tenant",
            "fingerprint": "x",
            "severity": "high",
            "state": "firing",
            "title": "cross tenant",
            "started_at": "2026-09-14T12:00:00Z",
            "observed_at": "2026-09-14T12:00:01Z",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "connector_scope_denied"
    # And B's own objects never became visible to A through the attempt.
    with worlds.factory() as session:
        bind_tenant(session, worlds.a.tenant_id)
        assert session.get(Incident, worlds.b.incident.id) is None
        assert (
            session.scalar(
                sa.select(sa.func.count())
                .select_from(EvaluationSuiteRun)
                .where(EvaluationSuiteRun.tenant_id == worlds.b.tenant_id)
            )
            == 0
        )
