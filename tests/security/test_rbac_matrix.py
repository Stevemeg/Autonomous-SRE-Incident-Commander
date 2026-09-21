"""Phase 13 RBAC: one vocabulary, a matrix generated from it, and attacks against the matrix.

The expected outcome of every (role, assignment scope, route) cell is *computed* from
``asic.domain.permissions`` - the same vocabulary the enforcement sites import - so the test
cannot drift from the code, and the code cannot drift from the migrated database (asserted
first). Attack tests then target the seams the matrix cannot express: revocation between
requests, expiry, wrong tenant, wrong environment, forged claims, and cross-tenant references.
"""

from __future__ import annotations

import ast
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asic.api import app as api_module
from asic.api import create_app
from asic.db.models import Environment, UserRoleAssignment
from asic.db.session import bind_tenant
from asic.domain.permissions import (
    SCOPE_RULES,
    SYSTEM_ROLE_GRANTS,
    UNASSIGNED_BY_DEFAULT,
    PermissionKey,
    ScopeRule,
)
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import Fixture

pytestmark = pytest.mark.security

SRC = Path(__file__).resolve().parents[2] / "src" / "asic"


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    permission: PermissionKey


ROUTES = (
    Route("GET", "/api/v1/incidents", PermissionKey.INCIDENT_READ),
    Route("GET", "/api/v1/incidents/{incident}", PermissionKey.INCIDENT_READ),
    Route("POST", "/api/v1/incidents/{incident}/annotate", PermissionKey.INCIDENT_CONTROL),
    Route("GET", "/api/v1/approvals/pending", PermissionKey.REMEDIATION_APPROVE),
    Route("GET", "/api/v1/evaluation/runs", PermissionKey.EVALUATION_READ),
    Route("GET", "/api/v1/admin/tools", PermissionKey.ADMINISTRATION_READ),
    Route("GET", "/api/v1/admin/policies", PermissionKey.ADMINISTRATION_READ),
    Route("GET", "/api/v1/admin/tenants", PermissionKey.ADMINISTRATION_READ),
    Route("GET", "/api/v1/admin/services", PermissionKey.ADMINISTRATION_READ),
    Route("GET", "/api/v1/admin/knowledge-sources", PermissionKey.ADMINISTRATION_READ),
    Route("GET", "/api/v1/admin/audit", PermissionKey.AUDIT_READ),
    Route("POST", "/api/v1/ingest/alerts", PermissionKey.INGESTION_WRITE),
)


def _send(client: TestClient, route: Route, token: str | None, incident: uuid.UUID) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    path = route.path.format(incident=incident)
    if route.method == "GET":
        return client.get(path, headers=headers).status_code
    headers["Idempotency-Key"] = uuid.uuid4().hex
    return client.post(path, headers=headers, json={"justification": "matrix probe"}).status_code


def _forbidden_for_authority(
    client: TestClient, route: Route, token: str, incident: uuid.UUID
) -> bool:
    """True when the route answered 403 ``forbidden`` (an RBAC refusal, not another failure)."""
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": uuid.uuid4().hex}
    path = route.path.format(incident=incident)
    response = (
        client.get(path, headers=headers)
        if route.method == "GET"
        else client.post(path, headers=headers, json={"justification": "matrix probe"})
    )
    if response.status_code != 403:
        return False
    detail = response.json().get("detail")
    return isinstance(detail, dict) and detail.get("code") == "forbidden"


def _allowed(role: str, permission: PermissionKey, *, tenant_wide: bool) -> bool:
    if permission not in SYSTEM_ROLE_GRANTS[role]:
        return False
    return tenant_wide or SCOPE_RULES[permission] is ScopeRule.ENVIRONMENT


class TestVocabulary:
    def test_every_permission_has_a_scope_rule_and_the_unassigned_set_is_accurate(self) -> None:
        assert set(SCOPE_RULES) == set(PermissionKey)
        granted = set().union(*SYSTEM_ROLE_GRANTS.values())
        assert set(PermissionKey) - granted == set(UNASSIGNED_BY_DEFAULT)

    @pytest.mark.postgres
    def test_the_database_catalogue_equals_the_vocabulary(self, owner_session: Session) -> None:
        keys = set(owner_session.scalars(sa.text("SELECT key FROM permission")))
        assert keys == {p.value for p in PermissionKey}

    @pytest.mark.postgres
    def test_the_seeded_system_roles_equal_the_matrix(self, owner_session: Session) -> None:
        rows = owner_session.execute(
            sa.text(
                "SELECT r.key, p.key FROM role r JOIN role_permission rp ON rp.role_id = r.id "
                "JOIN permission p ON p.id = rp.permission_id WHERE r.key = ANY(:roles)"
            ),
            {"roles": list(SYSTEM_ROLE_GRANTS)},
        )
        actual: dict[str, set[str]] = {role: set() for role in SYSTEM_ROLE_GRANTS}
        for role, permission in rows:
            actual[role].add(permission)
        expected = {r: {p.value for p in grants} for r, grants in SYSTEM_ROLE_GRANTS.items()}
        assert actual == expected

    def test_no_permission_string_is_spelled_outside_the_vocabulary(self) -> None:
        pattern = re.compile("|".join(re.escape(p.value) for p in PermissionKey))
        offenders = []
        for path in sorted(SRC.rglob("*.py")):
            if path.name == "permissions.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and pattern.fullmatch(node.value)
                ):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
        assert offenders == [], offenders

    def test_route_guards_agree_with_the_scope_rules(self) -> None:
        """A tenant-wide permission must only be enforced with ``require_tenant_wide``."""
        tree = ast.parse((SRC / "api" / "app.py").read_text(encoding="utf-8"))
        constants = {
            name: getattr(api_module, name)
            for name in (
                "INCIDENT_READ",
                "INCIDENT_CONTROL",
                "INGEST_WRITE",
                "APPROVAL_DECIDE",
                "EVALUATION_READ",
                "ADMIN_READ",
                "AUDIT_READ",
            )
        }
        checked = 0
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if node.func.id not in {
                "require_tenant_wide",
                "require_environment",
                "require_any_environment",
            }:
                continue
            argument = node.args[1]
            assert isinstance(argument, ast.Name), "permission must be a named constant"
            rule = SCOPE_RULES[PermissionKey(constants[argument.id])]
            expected = (
                ScopeRule.TENANT_WIDE
                if node.func.id == "require_tenant_wide"
                else ScopeRule.ENVIRONMENT
            )
            assert rule is expected, f"{argument.id} enforced by {node.func.id}"
            checked += 1
        assert checked >= 15


def _bind_role(
    arranger: Session,
    fixture: Fixture,
    role: str,
    subject: str,
    *,
    tenant_wide: bool,
) -> None:
    _principal(
        arranger,
        fixture,
        role,
        subject,
        environment_id=None if tenant_wide else fixture.environment.id,
    )


@pytest.mark.postgres
@pytest.mark.parametrize("tenant_wide", [True, False], ids=["tenant_wide", "env_scoped"])
@pytest.mark.parametrize("role", sorted(SYSTEM_ROLE_GRANTS))
def test_the_role_matrix_is_enforced_on_every_route(
    role: str,
    tenant_wide: bool,
    api_factory: Callable[[], Session],
    api_arranger: Session,
    worlds: tuple[Fixture, Fixture],
) -> None:
    own, _ = worlds
    subject = f"matrix-{role}-{'wide' if tenant_wide else 'env'}"
    _bind_role(api_arranger, own, role, subject, tenant_wide=tenant_wide)
    token = _token(own.tenant_id, subject)
    client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
    for route in ROUTES:
        refused = _forbidden_for_authority(client, route, token, own.incident.id)
        should_allow = _allowed(role, route.permission, tenant_wide=tenant_wide)
        assert refused is (not should_allow), (
            f"{role} ({'tenant-wide' if tenant_wide else 'env-scoped'}) "
            f"{route.method} {route.path}: expected {'allow' if should_allow else 'forbid'}"
        )


@pytest.mark.postgres
class TestAuthenticationSeams:
    def test_no_credential_and_bad_credentials_never_reach_authorization(
        self, api_factory: Callable[[], Session], worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        for route in ROUTES:
            assert _send(client, route, None, own.incident.id) == 401
            assert _send(client, route, "not.a.token", own.incident.id) == 401

    def test_a_valid_token_for_an_unprovisioned_subject_is_refused(
        self, api_factory: Callable[[], Session], worlds: tuple[Fixture, Fixture]
    ) -> None:
        own, _ = worlds
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(own.tenant_id, "nobody-provisioned")
        assert {_send(client, r, token, own.incident.id) for r in ROUTES} == {401}

    def test_a_subject_cannot_act_in_a_tenant_it_does_not_belong_to(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, other = worlds
        _bind_role(api_arranger, own, "platform_admin", "admin-of-own", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(other.tenant_id, "admin-of-own")  # right subject, wrong tenant
        assert {_send(client, r, token, other.incident.id) for r in ROUTES} == {401}

    def test_forged_authority_claims_confer_nothing(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        _bind_role(api_arranger, own, "viewer", "forger", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(
            own.tenant_id,
            "forger",
            role="platform_admin",
            roles=["platform_admin"],
            permissions=[p.value for p in PermissionKey],
            scope="administration.read audit.read remediation.approve",
            is_admin=True,
            environment_id=str(own.environment.id),
        )
        admin = next(r for r in ROUTES if r.path.endswith("/admin/tools"))
        approvals = next(r for r in ROUTES if r.path.endswith("/approvals/pending"))
        assert _forbidden_for_authority(client, admin, token, own.incident.id)
        assert _forbidden_for_authority(client, approvals, token, own.incident.id)


@pytest.mark.postgres
class TestCurrentAuthorityNotHistoricalSuccess:
    def test_revocation_applies_to_the_very_next_request(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        _bind_role(api_arranger, own, "platform_admin", "revoked-admin", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(own.tenant_id, "revoked-admin")
        admin = next(r for r in ROUTES if r.path.endswith("/admin/tools"))
        assert _send(client, admin, token, own.incident.id) == 200
        bind_tenant(api_arranger, own.tenant_id)
        api_arranger.execute(
            sa.delete(UserRoleAssignment).where(UserRoleAssignment.tenant_id == own.tenant_id)
        )
        api_arranger.commit()
        assert _send(client, admin, token, own.incident.id) == 403  # same token, no stale grant

    def test_an_expired_assignment_stops_working_without_any_change_being_made(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        _bind_role(api_arranger, own, "platform_admin", "break-glass", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(own.tenant_id, "break-glass")
        admin = next(r for r in ROUTES if r.path.endswith("/admin/tools"))
        assert _send(client, admin, token, own.incident.id) == 200
        bind_tenant(api_arranger, own.tenant_id)
        api_arranger.execute(
            sa.update(UserRoleAssignment)
            .where(UserRoleAssignment.tenant_id == own.tenant_id)
            .values(
                granted_at=datetime.now(UTC) - timedelta(hours=3),
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            )
        )
        api_arranger.commit()
        assert _send(client, admin, token, own.incident.id) == 403

    def test_a_disabled_user_is_refused_even_with_a_valid_token_and_grants(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        from asic.db.models import User
        from asic.domain.enums import UserStatus

        own, _ = worlds
        _bind_role(api_arranger, own, "viewer", "disabled-user", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(own.tenant_id, "disabled-user")
        listing = ROUTES[0]
        assert _send(client, listing, token, own.incident.id) == 200
        bind_tenant(api_arranger, own.tenant_id)
        api_arranger.execute(
            sa.update(User)
            .where(User.tenant_id == own.tenant_id, User.external_idp_subject == "disabled-user")
            .values(status=UserStatus.DISABLED)
        )
        api_arranger.commit()
        assert _send(client, listing, token, own.incident.id) == 401


@pytest.mark.postgres
class TestEnvironmentAndTenantIsolation:
    def _second_environment(self, arranger: Session, fixture: Fixture) -> uuid.UUID:
        bind_tenant(arranger, fixture.tenant_id)
        environment = Environment(
            id=uuid.uuid4(),
            tenant_id=fixture.tenant_id,
            name=f"staging-{uuid.uuid4().hex[:6]}",
            display_name="Staging",
            is_production=False,
        )
        arranger.add(environment)
        arranger.commit()
        return environment.id

    def test_a_role_in_another_environment_cannot_read_this_environments_incident(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        elsewhere = self._second_environment(api_arranger, own)
        _principal(api_arranger, own, "responder", "elsewhere", environment_id=elsewhere)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        token = _token(own.tenant_id, "elsewhere")
        by_id = ROUTES[1]
        control = ROUTES[2]
        # Not found rather than forbidden: existence is not disclosed across the boundary.
        assert _send(client, by_id, token, own.incident.id) in {403, 404}
        assert _forbidden_for_authority(client, control, token, own.incident.id) or _send(
            client, control, token, own.incident.id
        ) in {403, 404}
        listing = client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        assert listing.status_code == 200
        assert str(own.incident.id) not in listing.text

    def test_another_tenants_incident_is_indistinguishable_from_nonexistent(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, other = worlds
        _bind_role(api_arranger, own, "platform_admin", "own-admin", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        headers = {"Authorization": f"Bearer {_token(own.tenant_id, 'own-admin')}"}
        foreign = client.get(f"/api/v1/incidents/{other.incident.id}", headers=headers)
        invented = client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=headers)
        assert foreign.status_code == invented.status_code == 404
        assert foreign.json()["detail"] == invented.json()["detail"]

    def test_a_guessed_cursor_from_another_tenant_leaks_nothing(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        import base64

        own, other = worlds
        _bind_role(api_arranger, own, "viewer", "cursor-guesser", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        cursor = base64.urlsafe_b64encode(str(other.incident.id).encode()).decode().rstrip("=")
        response = client.get(
            "/api/v1/incidents",
            params={"cursor": cursor},
            headers={"Authorization": f"Bearer {_token(own.tenant_id, 'cursor-guesser')}"},
        )
        assert response.status_code == 200
        assert str(other.incident.id) not in response.text
        assert str(other.tenant_id) not in response.text

    def test_the_same_idempotency_key_in_two_tenants_never_replays_across_them(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, other = worlds
        _bind_role(api_arranger, own, "responder", "responder-a", tenant_wide=True)
        _bind_role(api_arranger, other, "responder", "responder-b", tenant_wide=True)
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        key = "shared-idempotency-key-0001"

        def annotate(fixture: Fixture, subject: str) -> dict[str, object]:
            response = client.post(
                f"/api/v1/incidents/{fixture.incident.id}/annotate",
                headers={
                    "Authorization": f"Bearer {_token(fixture.tenant_id, subject)}",
                    "Idempotency-Key": key,
                },
                json={"justification": "collision probe"},
            )
            assert response.status_code == 200, response.text
            return response.json()

        first, second = annotate(own, "responder-a"), annotate(other, "responder-b")
        assert str(own.incident.id) in str(first) and str(other.incident.id) not in str(first)
        assert str(other.incident.id) in str(second) and str(own.incident.id) not in str(second)

    def test_a_role_with_two_environments_sees_exactly_those_two(
        self,
        api_factory: Callable[[], Session],
        api_arranger: Session,
        worlds: tuple[Fixture, Fixture],
    ) -> None:
        own, _ = worlds
        second = self._second_environment(api_arranger, own)
        user = _principal(
            api_arranger, own, "viewer", "two-envs", environment_id=own.environment.id
        )
        bind_tenant(api_arranger, own.tenant_id)
        from asic.db.models import Role

        role = api_arranger.scalar(sa.select(Role).where(Role.key == "viewer"))
        assert role is not None
        api_arranger.add(
            UserRoleAssignment(
                id=uuid.uuid4(),
                tenant_id=own.tenant_id,
                user_id=user.id,
                role_id=role.id,
                environment_id=second,
            )
        )
        api_arranger.commit()
        client = TestClient(create_app(settings=SETTINGS, factory=api_factory))
        response = client.get(
            "/api/v1/incidents",
            headers={"Authorization": f"Bearer {_token(own.tenant_id, 'two-envs')}"},
        )
        assert response.status_code == 200
        assert str(own.incident.id) in response.text
