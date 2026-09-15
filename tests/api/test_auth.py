"""Authentication, tenancy, authorization and durable mutation tests for Phase 9."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any, cast

import jwt
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from tests.kernel_fixtures import Fixture, build_fixture
from tests.orchestration.test_remediation import _remediation_scenario, _run_remediation
from tests.orchestration.test_remediation_security import _prepared

from asic.api import ApiSettings, create_app
from asic.db.models import Environment, IncidentEvent, Role, User, UserRoleAssignment
from asic.db.models.remediation import RemediationAction
from asic.db.session import bind_tenant
from asic.domain.enums import IncidentStatus, UserStatus

pytestmark = pytest.mark.postgres

SECRET = "phase9-test-signing-secret-is-not-production"
SETTINGS = ApiSettings(jwt_secret=SECRET, rate_limit_per_minute=100)


@pytest.fixture
def api_factory(app_engine: object) -> Callable[[], Session]:
    return sessionmaker(bind=app_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def api_arranger(owner_engine: object) -> Session:
    session = Session(bind=owner_engine, expire_on_commit=False, autoflush=False)
    try:
        yield session
    finally:
        session.close()


def _token(tenant_id: uuid.UUID, subject: str, **claims: object) -> str:
    payload: dict[str, object] = {
        "sub": subject,
        "tenant_id": str(tenant_id),
        "iss": SETTINGS.jwt_issuer,
        "aud": SETTINGS.jwt_audience,
        "exp": int(time.time()) + 300,
        **claims,
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _principal(
    session: Session,
    fixture: Fixture,
    role_key: str,
    subject: str,
    *,
    environment_id: object = Ellipsis,
) -> User:
    bind_tenant(session, fixture.tenant_id)
    user = User(
        id=uuid.uuid4(),
        tenant_id=fixture.tenant_id,
        external_idp_subject=subject,
        email=f"{subject}@example.invalid",
        display_name=subject,
        status=UserStatus.ACTIVE,
    )
    session.add(user)
    session.flush()
    role = session.scalar(sa.select(Role).where(Role.key == role_key))
    assert role is not None
    session.add(
        UserRoleAssignment(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant_id,
            user_id=user.id,
            role_id=role.id,
            environment_id=(
                fixture.environment.id
                if environment_id is Ellipsis
                else cast(uuid.UUID | None, environment_id)
            ),
        )
    )
    session.commit()
    return user


@pytest.fixture
def worlds(api_arranger: Session) -> tuple[Fixture, Fixture]:
    first = build_fixture(api_arranger, slug=f"api-a-{uuid.uuid4().hex[:8]}")
    second = build_fixture(api_arranger, slug=f"api-b-{uuid.uuid4().hex[:8]}")
    api_arranger.commit()
    return first, second


def test_incident_api_derives_tenant_and_environment_from_current_grant(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, other = worlds
    _principal(api_arranger, own, "viewer", "viewer-a")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'viewer-a')}"}

    listing = client.get("/api/v1/incidents", headers=headers)
    assert listing.status_code == 200
    assert [row["id"] for row in listing.json()["items"]] == [str(own.incident.id)]
    assert client.get(f"/api/v1/incidents/{other.incident.id}", headers=headers).status_code == 404


def test_jwt_role_claim_cannot_create_authority(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    bind_tenant(api_arranger, own.tenant_id)
    user = User(
        id=uuid.uuid4(),
        tenant_id=own.tenant_id,
        external_idp_subject="claim-only",
        email="claim-only@example.invalid",
        display_name="claim-only",
        status=UserStatus.ACTIVE,
    )
    api_arranger.add(user)
    api_arranger.commit()
    token = _token(own.tenant_id, "claim-only", role="platform_admin")
    response = TestClient(create_app(settings=SETTINGS, factory=api_factory)).get(
        "/api/v1/incidents", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403  # the untrusted role claim is never interpreted


def test_expired_and_unknown_tokens_fail_closed(
    api_factory: Callable[[], Session], worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    expired = _token(own.tenant_id, "nobody", exp=int(time.time()) - 1)
    assert (
        client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {expired}"}).status_code
        == 401
    )
    assert client.get("/api/v1/incidents").status_code == 401


def test_incident_control_is_authorized_and_durably_idempotent(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "responder", "responder-a")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {
        "Authorization": f"Bearer {_token(own.tenant_id, 'responder-a')}",
        "Idempotency-Key": "incident-escalation-0001",
    }
    body = {"justification": "Operator escalation after customer impact confirmation."}

    first = client.post(f"/api/v1/incidents/{own.incident.id}/escalate", headers=headers, json=body)
    replay = client.post(
        f"/api/v1/incidents/{own.incident.id}/escalate", headers=headers, json=body
    )
    assert first.status_code == replay.status_code == 200
    assert first.json() == replay.json()
    assert first.json()["status"] == IncidentStatus.ESCALATED.value

    conflict = client.post(
        f"/api/v1/incidents/{own.incident.id}/escalate",
        headers=headers,
        json={"justification": "A materially different request."},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "idempotency_conflict"


def test_viewer_cannot_mutate_incident(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "viewer", "viewer-control")
    response = TestClient(create_app(settings=SETTINGS, factory=api_factory)).post(
        f"/api/v1/incidents/{own.incident.id}/escalate",
        headers={
            "Authorization": f"Bearer {_token(own.tenant_id, 'viewer-control')}",
            "Idempotency-Key": "viewer-cannot-control",
        },
        json={"justification": "Should not be authorized."},
    )
    assert response.status_code == 403


def test_surfaces_are_independently_authorized(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "viewer", "surface-viewer")
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'surface-viewer')}"}
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    assert client.get("/api/v1/incidents", headers=headers).status_code == 200
    assert client.get("/api/v1/approvals/pending", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/tools", headers=headers).status_code == 403
    assert client.get("/api/v1/evaluation/runs", headers=headers).status_code == 403
    assert client.post("/api/v1/ingest/alerts", headers=headers).status_code == 403


def test_authenticated_ingestion_uses_only_signed_connector_scope(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "system_operator", "connector-a")
    token = _token(
        own.tenant_id,
        "connector-a",
        connector_id="synthetic-connector",
        source="simulator",
        service_id=str(own.service.id),
        environment_id=str(own.environment.id),
    )
    response = TestClient(create_app(settings=SETTINGS, factory=api_factory)).post(
        "/api/v1/ingest/alerts",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "connector-delivery-0001",
        },
        json={
            "schema_version": 1,
            "source_event_id": "api-alert-1",
            "fingerprint": "api-fingerprint",
            "severity": "high",
            "state": "firing",
            "title": "API ingestion smoke alert",
            "started_at": "2026-09-14T12:00:00Z",
            "observed_at": "2026-09-14T12:00:01Z",
        },
    )
    assert response.status_code == 200
    assert response.json()["outcome"] in {"accepted", "duplicate"}


def test_correlation_id_is_validated_and_returned() -> None:
    client = TestClient(create_app(settings=SETTINGS, factory=lambda: Session()))
    assert client.get("/healthz", headers={"X-Correlation-ID": "not-a-uuid"}).status_code == 400
    correlation_id = str(uuid.uuid4())
    response = client.get("/healthz", headers={"X-Correlation-ID": correlation_id})
    assert response.headers["X-Correlation-ID"] == correlation_id


def test_idempotency_replay_does_not_bypass_current_revocation(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    user = _principal(api_arranger, own, "responder", "revoked-replay")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {
        "Authorization": f"Bearer {_token(own.tenant_id, 'revoked-replay')}",
        "Idempotency-Key": "revocation-replay-0001",
    }
    body = {"justification": "Initial authorized escalation."}
    first = client.post(f"/api/v1/incidents/{own.incident.id}/escalate", headers=headers, json=body)
    assert first.status_code == 200
    bind_tenant(api_arranger, own.tenant_id)
    before = api_arranger.scalar(
        sa.select(sa.func.count())
        .select_from(IncidentEvent)
        .where(IncidentEvent.incident_id == own.incident.id)
    )
    api_arranger.execute(sa.delete(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id))
    api_arranger.commit()
    replay = client.post(
        f"/api/v1/incidents/{own.incident.id}/escalate", headers=headers, json=body
    )
    # Once the final grant is removed the resource is deliberately non-discoverable.
    assert replay.status_code == 404
    bind_tenant(api_arranger, own.tenant_id)
    after = api_arranger.scalar(
        sa.select(sa.func.count())
        .select_from(IncidentEvent)
        .where(IncidentEvent.incident_id == own.incident.id)
    )
    assert after == before


def test_approval_replay_does_not_bypass_current_revocation(
    api_factory: Callable[[], Session],
    api_arranger: Session,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        api_arranger,
        api_factory,
        resolver,
        clock,
        f"api-approval-replay-{uuid.uuid4().hex[:8]}",
        True,
    )
    outcome = _run_remediation(
        api_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    action = api_arranger.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    )
    assert action is not None
    user = _principal(api_arranger, fixture, "sre_approver", "revoked-approval-replay")
    headers = {
        "Authorization": f"Bearer {_token(fixture.tenant_id, 'revoked-approval-replay')}",
        "Idempotency-Key": "approval-revocation-replay-0001",
    }
    body = {
        "decision": "approved",
        "action_version_hash": action.action_version_hash,
        "justification": "Reviewed exact frozen action.",
    }
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    first = client.post(f"/api/v1/approvals/{action.id}/decide", headers=headers, json=body)
    assert first.status_code == 200
    bind_tenant(api_arranger, fixture.tenant_id)
    api_arranger.execute(sa.delete(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id))
    api_arranger.commit()
    replay = client.post(f"/api/v1/approvals/{action.id}/decide", headers=headers, json=body)
    assert replay.status_code == 403


def test_environment_scoped_ingestion_cannot_widen_to_production(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    bind_tenant(api_arranger, own.tenant_id)
    staging = Environment(
        id=uuid.uuid4(),
        tenant_id=own.tenant_id,
        name="staging",
        display_name="Staging",
        is_production=False,
    )
    api_arranger.add(staging)
    api_arranger.flush()
    _principal(
        api_arranger,
        own,
        "system_operator",
        "staging-connector",
        environment_id=staging.id,
    )
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    payload = {
        "schema_version": 1,
        "source_event_id": "scope-alert-1",
        "fingerprint": "scope-fingerprint",
        "severity": "high",
        "state": "firing",
        "title": "Environment authorization probe",
        "started_at": "2026-09-14T12:00:00Z",
        "observed_at": "2026-09-14T12:00:01Z",
    }

    def token(environment_id: uuid.UUID) -> str:
        return _token(
            own.tenant_id,
            "staging-connector",
            connector_id="scoped-connector",
            source="simulator",
            service_id=str(own.service.id),
            environment_id=str(environment_id),
        )

    production = client.post(
        "/api/v1/ingest/alerts",
        headers={
            "Authorization": f"Bearer {token(own.environment.id)}",
            "Idempotency-Key": "prod-with-stage-grant",
        },
        json=payload,
    )
    assert production.status_code == 403
    staging_response = client.post(
        "/api/v1/ingest/alerts",
        headers={
            "Authorization": f"Bearer {token(staging.id)}",
            "Idempotency-Key": "stage-with-stage-grant",
        },
        json={**payload, "source_event_id": "scope-alert-2"},
    )
    assert staging_response.status_code == 200


def test_administration_requires_a_tenant_wide_grant(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "platform_admin", "scoped-admin")
    _principal(
        api_arranger,
        own,
        "platform_admin",
        "tenant-admin",
        environment_id=None,
    )
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    assert (
        client.get(
            "/api/v1/admin/services",
            headers={"Authorization": f"Bearer {_token(own.tenant_id, 'scoped-admin')}"},
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/v1/admin/services",
            headers={"Authorization": f"Bearer {_token(own.tenant_id, 'tenant-admin')}"},
        ).status_code
        == 200
    )
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'tenant-admin')}"}
    first_page = client.get("/api/v1/admin/tools?limit=1", headers=headers)
    assert first_page.status_code == 200
    first_body = first_page.json()
    assert len(first_body["items"]) == 1
    assert first_body["next_cursor"]
    second_page = client.get(
        f"/api/v1/admin/tools?limit=1&cursor={first_body['next_cursor']}", headers=headers
    )
    assert second_page.status_code == 200
    assert second_page.json()["items"][0]["id"] != first_body["items"][0]["id"]


def test_annotation_is_authorized_idempotent_and_durable(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "responder", "annotator")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {
        "Authorization": f"Bearer {_token(own.tenant_id, 'annotator')}",
        "Idempotency-Key": "incident-annotation-0001",
    }
    body = {"justification": "Customer impact confirmed by the on-call operator."}
    first = client.post(f"/api/v1/incidents/{own.incident.id}/annotate", headers=headers, json=body)
    replay = client.post(
        f"/api/v1/incidents/{own.incident.id}/annotate", headers=headers, json=body
    )
    assert first.status_code == replay.status_code == 200
    assert first.json() == replay.json()
    bind_tenant(api_arranger, own.tenant_id)
    assert (
        api_arranger.scalar(
            sa.select(sa.func.count())
            .select_from(IncidentEvent)
            .where(
                IncidentEvent.incident_id == own.incident.id,
                IncidentEvent.event_type == "incident.annotated",
            )
        )
        == 1
    )
