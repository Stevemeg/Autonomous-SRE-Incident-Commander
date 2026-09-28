"""Phase 16 closure routes: remediation requests, human resolution and postmortem reads.

The remediation request is the deployed product's only way to start the remediation graph, so
it is tested for authorization, tenancy, idempotency and every refusal it owns. It confers no
execution authority: whether anything runs is still decided by G7 and G8 in the worker.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import Fixture, build_fixture

from asic.api import create_app
from asic.db.models import Hypothesis, Incident, RemediationRequest
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import IncidentStatus
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.kernel import InvestigationKernel
from asic.postmortem.author import PostmortemAuthor
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import scenario
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry

pytestmark = pytest.mark.postgres

PRIMARY = "SC-0001-checkout-latency-after-deploy"


@pytest.fixture
def api_factory(app_engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=app_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def api_arranger(owner_engine: Engine) -> Iterator[Session]:
    session = Session(bind=owner_engine, expire_on_commit=False, autoflush=False)
    try:
        yield session
    finally:
        session.close()


def _escalated(api_factory: Callable[[], Session], arranger: Session, slug: str) -> Fixture:
    """A world whose incident a real investigation escalated with an actionable hypothesis."""
    fixture = build_fixture(arranger, slug=f"{slug}-{uuid.uuid4().hex[:8]}")
    arranger.commit()
    selected = scenario(PRIMARY)
    clock = FrozenClock(start=fixture.incident.opened_at)
    outcome = InvestigationKernel(
        session_factory=api_factory,
        resolver=CapabilityResolver(ToolRegistry.read_only()),
        providers=[SimulatorProvider(selected, clock=clock)],
        model=DeterministicModelProvider(selected),
        clock=clock,
        budget_policy=selected.budget,
    ).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
    )
    assert outcome.incident_status is IncidentStatus.ESCALATED
    return fixture


def _hypothesis(session: Session, fixture: Fixture) -> uuid.UUID:
    session.expire_all()
    bind_tenant(session, fixture.tenant_id)
    value = session.scalar(
        sa.select(Hypothesis.id)
        .where(Hypothesis.incident_id == fixture.incident.id)
        .order_by(Hypothesis.rank)
        .limit(1)
    )
    session.rollback()
    assert value is not None
    return value


def _headers(fixture: Fixture, subject: str, key: str | None = None) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token(fixture.tenant_id, subject)}",
        "Idempotency-Key": key or uuid.uuid4().hex,
    }


def test_a_responder_requests_remediation_and_the_request_is_durable_and_idempotent(
    api_factory: Callable[[], Session], api_arranger: Session
) -> None:
    fixture = _escalated(api_factory, api_arranger, "p16-req")
    hypothesis_id = _hypothesis(api_arranger, fixture)
    _principal(api_arranger, fixture, "responder", "p16-responder")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    path = f"/api/v1/incidents/{fixture.incident.id}/remediation-requests"
    body = {
        "hypothesis_id": str(hypothesis_id),
        "service_id": str(fixture.service.id),
        "justification": "Deployment evidence matches the rollback runbook; request remediation.",
    }
    headers = _headers(fixture, "p16-responder", "p16-remediation-request-0001")

    first = client.post(path, headers=headers, json=body)
    replay = client.post(path, headers=headers, json=body)
    assert first.status_code == replay.status_code == 202, first.text
    assert first.json() == replay.json()
    assert first.json()["status"] == "pending"
    assert first.json()["incident_status"] == IncidentStatus.INVESTIGATING.value

    api_arranger.expire_all()
    bind_tenant(api_arranger, fixture.tenant_id)
    rows = list(
        api_arranger.scalars(
            sa.select(RemediationRequest).where(
                RemediationRequest.incident_id == fixture.incident.id
            )
        )
    )
    assert len(rows) == 1
    incident = api_arranger.get(Incident, fixture.incident.id)
    assert incident is not None and incident.status is IncidentStatus.INVESTIGATING
    api_arranger.rollback()

    again = client.post(path, headers=_headers(fixture, "p16-responder"), json=body)
    assert again.status_code == 409
    assert again.json()["detail"]["code"] == "request_pending"


def test_remediation_request_refusals(
    api_factory: Callable[[], Session], api_arranger: Session
) -> None:
    fixture = _escalated(api_factory, api_arranger, "p16-refuse")
    other = build_fixture(api_arranger, slug=f"p16-other-{uuid.uuid4().hex[:8]}")
    api_arranger.commit()
    hypothesis_id = _hypothesis(api_arranger, fixture)
    _principal(api_arranger, fixture, "viewer", "p16-viewer")
    _principal(api_arranger, fixture, "responder", "p16-responder-2")
    _principal(api_arranger, other, "responder", "p16-foreign")
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    path = f"/api/v1/incidents/{fixture.incident.id}/remediation-requests"
    body = {
        "hypothesis_id": str(hypothesis_id),
        "service_id": str(fixture.service.id),
        "justification": "request",
    }

    viewer = client.post(path, headers=_headers(fixture, "p16-viewer"), json=body)
    assert viewer.status_code == 403
    foreign = client.post(path, headers=_headers(other, "p16-foreign"), json=body)
    assert foreign.status_code == 404  # another tenant's incident does not exist for it
    unknown = client.post(
        path,
        headers=_headers(fixture, "p16-responder-2"),
        json={**body, "hypothesis_id": str(uuid.uuid4())},
    )
    assert unknown.json()["detail"]["code"] == "invalid_hypothesis"
    wrong_service = client.post(
        path,
        headers=_headers(fixture, "p16-responder-2"),
        json={**body, "service_id": str(uuid.uuid4())},
    )
    assert wrong_service.json()["detail"]["code"] == "invalid_service"
    extra = client.post(
        path,
        headers=_headers(fixture, "p16-responder-2"),
        json={**body, "approved": True},
    )
    assert extra.status_code == 422  # no field can smuggle an approval


def test_a_responder_can_resolve_and_the_postmortem_is_readable_only_in_its_tenant(
    api_factory: Callable[[], Session], api_arranger: Session
) -> None:
    fixture = _escalated(api_factory, api_arranger, "p16-resolve")
    other = build_fixture(api_arranger, slug=f"p16-pm-other-{uuid.uuid4().hex[:8]}")
    api_arranger.commit()
    _principal(api_arranger, fixture, "responder", "p16-resolver")
    _principal(api_arranger, other, "platform_admin", "p16-other-admin", environment_id=None)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))

    resolved = client.post(
        f"/api/v1/incidents/{fixture.incident.id}/resolve",
        headers=_headers(fixture, "p16-resolver"),
        json={"justification": "Rolled back by hand; error rate is back to baseline."},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == IncidentStatus.RESOLVED.value

    outcome = PostmortemAuthor(
        session_factory=api_factory, model=DeterministicModelProvider(scenario(PRIMARY))
    ).draft(tenant_id=fixture.tenant_id, incident_id=fixture.incident.id)
    assert outcome.outcome == "created"

    listing = client.get(
        f"/api/v1/incidents/{fixture.incident.id}/postmortems",
        headers=_headers(fixture, "p16-resolver"),
    )
    assert listing.status_code == 200
    (draft,) = listing.json()["items"]
    assert draft["status"] == "draft" and draft["review_required"] is True
    assert draft["resolution_basis"] == "human_declared"
    assert draft["citations"]

    foreign = client.get(
        f"/api/v1/incidents/{fixture.incident.id}/postmortems",
        headers=_headers(other, "p16-other-admin"),
    )
    assert foreign.status_code == 404
