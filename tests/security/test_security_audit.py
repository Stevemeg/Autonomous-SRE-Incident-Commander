"""Phase 13 security audit evidence: what is recorded, for whom, and what can never change.

Authentication failures happen before a tenant is known, so they cannot be tenant-bound
durable rows; they are structured log events with a closed reason code (see
``test_authentication.py``). Authorization denials are different: the principal and tenant
are known, so a denied state change or a denied tenant-wide read is a durable, tenant-bound,
append-only audit record - while ordinary denied reads are deliberately *not* recorded, so a
caller cannot fill the audit trail by probing.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from asic.api import create_app
from asic.db.models import AuditRecord
from asic.db.session import bind_tenant
from asic.domain.enums import ActorType, AuditEventType
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import Fixture

pytestmark = [pytest.mark.security, pytest.mark.postgres]


def _denials(arranger: Session, fixture: Fixture) -> list[AuditRecord]:
    bind_tenant(arranger, fixture.tenant_id)
    arranger.expire_all()
    return list(
        arranger.scalars(
            sa.select(AuditRecord).where(
                AuditRecord.tenant_id == fixture.tenant_id,
                AuditRecord.event_type == AuditEventType.AUTHORIZATION_DENIED,
            )
        )
    )


def test_a_denied_state_change_is_a_durable_attributed_record(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    user = _principal(api_arranger, own, "viewer", "denied-writer", environment_id=None)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    correlation = str(uuid.uuid4())
    token = _token(own.tenant_id, "denied-writer")
    response = client.post(
        f"/api/v1/incidents/{own.incident.id}/annotate",
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "denied-writer-key-0001",
            "X-Correlation-ID": correlation,
        },
        json={"justification": "attempt without incident.control"},
    )
    assert response.status_code == 403
    assert "incident.control" not in response.text  # the body never names the permission
    (record,) = _denials(api_arranger, own)
    assert record.tenant_id == own.tenant_id
    assert record.actor_type is ActorType.HUMAN and record.actor_id == str(user.id)
    assert record.outcome == "denied"
    assert record.target_type == "permission" and record.target_id == "incident.control"
    assert str(record.correlation_id) == correlation
    assert record.payload_redacted == {
        "method": "POST",
        "route": "/api/v1/incidents/{incident_id}/annotate",
        "authority_source": "rbac",
    }
    rendered = str(record.payload_redacted) + str(record.target_id)
    assert token not in rendered and "attempt without" not in rendered  # no token, no body


def test_a_denied_tenant_wide_read_is_recorded(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    _principal(api_arranger, own, "viewer", "denied-reader", environment_id=None)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'denied-reader')}"}
    assert client.get("/api/v1/admin/audit", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/tools", headers=headers).status_code == 403
    targets = sorted(r.target_id or "" for r in _denials(api_arranger, own))
    assert targets == ["administration.read", "audit.read"]


def test_an_ordinary_denied_read_is_not_audited_so_probing_cannot_flood_the_trail(
    api_factory: Callable[[], Session], api_arranger: Session, worlds: tuple[Fixture, Fixture]
) -> None:
    own, _ = worlds
    # Valid, provisioned, but holding no role at all.
    from asic.db.models import User
    from asic.domain.enums import UserStatus

    bind_tenant(api_arranger, own.tenant_id)
    api_arranger.add(
        User(
            id=uuid.uuid4(),
            tenant_id=own.tenant_id,
            external_idp_subject="roleless",
            email="roleless@example.invalid",
            display_name="roleless",
            status=UserStatus.ACTIVE,
        )
    )
    api_arranger.commit()
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'roleless')}"}
    for _ in range(5):
        assert client.get("/api/v1/incidents", headers=headers).status_code == 403
    assert _denials(api_arranger, own) == []


def test_an_audit_write_failure_can_never_turn_a_denial_into_an_allow(
    api_factory: Callable[[], Session],
    api_arranger: Session,
    worlds: tuple[Fixture, Fixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asic.observability.audit import AuditWriter

    own, _ = worlds
    _principal(api_arranger, own, "viewer", "audit-down", environment_id=None)

    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(AuditWriter, "record", broken)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    response = client.get(
        "/api/v1/admin/audit",
        headers={"Authorization": f"Bearer {_token(own.tenant_id, 'audit-down')}"},
    )
    assert response.status_code == 403


def test_a_tenants_audit_records_are_invisible_to_another_tenant(
    api_factory: Callable[[], Session],
    api_arranger: Session,
    app_engine: object,
    worlds: tuple[Fixture, Fixture],
) -> None:
    own, other = worlds
    _principal(api_arranger, own, "viewer", "cross-audit", environment_id=None)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'cross-audit')}"}
    assert client.get("/api/v1/admin/audit", headers=headers).status_code == 403
    assert len(_denials(api_arranger, own)) == 1
    # Through the unprivileged application role, bound to the *other* tenant.
    with Session(bind=app_engine) as session:  # type: ignore[arg-type]
        bind_tenant(session, other.tenant_id)
        visible = session.scalar(
            sa.select(sa.func.count())
            .select_from(AuditRecord)
            .where(AuditRecord.event_type == AuditEventType.AUTHORIZATION_DENIED)
        )
        assert visible == 0


@pytest.mark.parametrize("statement", ["update", "delete"])
def test_the_application_role_cannot_rewrite_or_erase_audit_history(
    statement: str, app_session: Session
) -> None:
    from tests.conftest import make_tenant

    tenant = make_tenant(app_session, f"audit-{uuid.uuid4().hex[:8]}")
    bind_tenant(app_session, tenant.id)
    app_session.add(
        AuditRecord(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            event_type=AuditEventType.AUTHORIZATION_DENIED,
            actor_type=ActorType.HUMAN,
            actor_id="x",
            outcome="denied",
            payload_redacted={},
        )
    )
    app_session.flush()
    change = (
        sa.update(AuditRecord).values(outcome="allowed")
        if statement == "update"
        else sa.delete(AuditRecord)
    )
    with pytest.raises(ProgrammingError, match="permission denied"):
        app_session.execute(change)
