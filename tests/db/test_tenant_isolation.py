"""Tenant isolation and row-level security.

These are the tests the whole tenancy design exists to pass. The valuable assertions are
adversarial: they *try* to read and write across the boundary and assert failure.

The property being demonstrated is that isolation does not depend on the application
remembering to write ``WHERE tenant_id = ...``. Every behavioural test here issues a query
with **no tenant predicate at all** and relies on the database to filter or refuse.

All behavioural tests run on ``app_session`` - the unprivileged application role. Running
them as the owner would prove nothing, because the bootstrap owner is typically a
superuser and superusers bypass row-level security regardless of ``FORCE``.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from asic.db.models import GLOBAL_TABLES, Incident, Service, tenant_scoped_tables
from asic.db.session import (
    TENANT_SETTING,
    TenantContext,
    bind_tenant,
    clear_tenant,
    current_tenant,
    require_tenant,
    tenant_scope,
)
from asic.domain.errors import TenantContextMismatch, TenantContextMissing
from tests.conftest import make_environment, make_incident, make_service, make_tenant

pytestmark = pytest.mark.postgres


class TestRlsCoverage:
    """Schema-level coverage. Introspection only, so the owner connection is fine here."""

    def test_every_tenant_scoped_table_has_rls_enabled_and_forced(
        self, owner_session: Session
    ) -> None:
        rows = owner_session.execute(
            sa.text(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind = 'r'
                """
            )
        ).all()
        state = {name: (enabled, forced) for name, enabled, forced in rows}

        for table in sorted(tenant_scoped_tables()):
            enabled, forced = state[table]
            assert enabled, f"{table} is tenant-scoped but RLS is not enabled"
            assert forced, f"{table} has RLS enabled but not FORCED"

    def test_every_tenant_scoped_table_has_an_isolation_policy(
        self, owner_session: Session
    ) -> None:
        protected = set(
            owner_session.execute(
                sa.text(
                    "SELECT tablename FROM pg_policies "
                    "WHERE schemaname = 'public' AND policyname = 'tenant_isolation'"
                )
            ).scalars()
        )
        missing = tenant_scoped_tables() - protected
        assert missing == set(), f"no tenant_isolation policy on: {sorted(missing)}"

    def test_policies_constrain_writes_as_well_as_reads(self, owner_session: Session) -> None:
        """A USING clause without WITH CHECK would let a session insert rows for another
        tenant even though it could not read them back."""
        rows = owner_session.execute(
            sa.text(
                "SELECT tablename, qual, with_check FROM pg_policies "
                "WHERE schemaname = 'public' AND policyname = 'tenant_isolation'"
            )
        ).all()
        for table, qual, with_check in rows:
            assert qual is not None, f"{table} policy has no USING clause"
            assert with_check is not None, f"{table} policy has no WITH CHECK clause"

    def test_global_tables_are_deliberately_unprotected(self, owner_session: Session) -> None:
        unprotected = set(
            owner_session.execute(
                sa.text(
                    """
                    SELECT c.relname FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relkind = 'r'
                      AND NOT c.relrowsecurity
                    """
                )
            ).scalars()
        )
        assert unprotected == GLOBAL_TABLES


class TestFailClosed:
    """With no tenant bound the database must show nothing, not everything."""

    def test_reads_return_nothing_without_a_tenant_context(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        make_incident(app_session, tenant, env)
        clear_tenant(app_session)

        visible = app_session.execute(sa.select(sa.func.count()).select_from(Incident)).scalar_one()
        assert visible == 0, "an unbound session must see no rows, not all rows"

    def test_writes_are_refused_without_a_tenant_context(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        clear_tenant(app_session)

        with pytest.raises(ProgrammingError, match="row-level security"):
            make_incident(app_session, tenant, env)

    def test_require_tenant_fails_loudly_rather_than_returning_nothing(
        self, app_session: Session
    ) -> None:
        clear_tenant(app_session)
        with pytest.raises(TenantContextMissing, match="no tenant bound"):
            require_tenant(app_session)

    def test_empty_setting_is_treated_as_unbound(self, app_session: Session) -> None:
        app_session.execute(sa.text("SELECT set_config(:s, '', true)"), {"s": TENANT_SETTING})
        assert current_tenant(app_session) is None


class TestCrossTenantReads:
    def test_a_bound_tenant_sees_only_its_own_rows(self, app_session: Session) -> None:
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, acme.id)
        acme_env = make_environment(app_session, acme)
        make_incident(app_session, acme, acme_env, reference="INC-ACME")
        clear_tenant(app_session)

        bind_tenant(app_session, globex.id)
        globex_env = make_environment(app_session, globex)
        make_incident(app_session, globex, globex_env, reference="INC-GLOBEX")

        # Deliberately no tenant predicate: the database must do the filtering.
        visible = list(app_session.execute(sa.select(Incident.reference)).scalars())
        assert visible == ["INC-GLOBEX"]

    def test_targeting_another_tenants_row_by_primary_key_returns_nothing(
        self, app_session: Session
    ) -> None:
        """Knowing the id is not enough; the policy still applies."""
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, acme.id)
        acme_env = make_environment(app_session, acme)
        secret = make_incident(app_session, acme, acme_env, reference="INC-SECRET")
        secret_id = secret.id
        app_session.expunge_all()
        clear_tenant(app_session)

        bind_tenant(app_session, globex.id)
        found = app_session.execute(
            sa.select(Incident).where(Incident.id == secret_id)
        ).scalar_one_or_none()
        assert found is None

    @pytest.mark.parametrize("model", [Incident, Service])
    def test_aggregates_do_not_leak_counts_across_tenants(
        self, app_session: Session, model: type
    ) -> None:
        """A count is a disclosure too."""
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, acme.id)
        acme_env = make_environment(app_session, acme)
        make_service(app_session, acme, "acme-svc")
        make_incident(app_session, acme, acme_env)
        clear_tenant(app_session)

        bind_tenant(app_session, globex.id)
        count = app_session.execute(sa.select(sa.func.count()).select_from(model)).scalar_one()
        assert count == 0


class TestCrossTenantWrites:
    def test_cannot_insert_a_row_for_another_tenant(self, app_session: Session) -> None:
        """The WITH CHECK half of the policy. Without it, a session could write rows it
        cannot read - a silent one-way data injection."""
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, globex.id)
        globex_env = make_environment(app_session, globex)
        clear_tenant(app_session)

        bind_tenant(app_session, acme.id)
        app_session.add(
            Incident(
                id=uuid.uuid4(),
                tenant_id=globex.id,  # not the bound tenant
                reference="INC-INJECTED",
                title="injected",
                environment_id=globex_env.id,
            )
        )
        with pytest.raises(ProgrammingError, match="row-level security"):
            app_session.flush()

    def test_update_cannot_reach_another_tenants_row(self, app_session: Session) -> None:
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, acme.id)
        acme_env = make_environment(app_session, acme)
        target = make_incident(app_session, acme, acme_env, reference="INC-TARGET")
        target_id = target.id
        app_session.expunge_all()
        clear_tenant(app_session)

        bind_tenant(app_session, globex.id)
        result = app_session.execute(
            sa.update(Incident).where(Incident.id == target_id).values(title="tampered")
        )
        assert result.rowcount == 0, "an update must not reach another tenant's row"

    def test_delete_cannot_reach_another_tenants_row(self, app_session: Session) -> None:
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, acme.id)
        acme_env = make_environment(app_session, acme)
        target = make_incident(app_session, acme, acme_env)
        target_id = target.id
        app_session.expunge_all()
        clear_tenant(app_session)

        bind_tenant(app_session, globex.id)
        result = app_session.execute(sa.delete(Incident).where(Incident.id == target_id))
        assert result.rowcount == 0


class TestCompositeForeignKeys:
    """The second isolation layer: a cross-tenant *reference* is structurally impossible."""

    def test_cannot_reference_another_tenants_environment(self, app_session: Session) -> None:
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")

        bind_tenant(app_session, globex.id)
        globex_env = make_environment(app_session, globex)
        clear_tenant(app_session)

        bind_tenant(app_session, acme.id)
        # RLS is satisfied - tenant_id is acme's - but the composite foreign key
        # (tenant_id, environment_id) cannot match a row belonging to globex.
        app_session.add(
            Incident(
                id=uuid.uuid4(),
                tenant_id=acme.id,
                reference="INC-XREF",
                title="cross-tenant reference attempt",
                environment_id=globex_env.id,
            )
        )
        with pytest.raises(sa.exc.IntegrityError):
            app_session.flush()


class TestApplicationRolePrivileges:
    def test_the_test_role_is_not_privileged(self, app_session: Session) -> None:
        """Guards every other assertion in this module: a superuser or a BYPASSRLS role
        would sail through all of them."""
        privileged = app_session.execute(
            sa.text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).scalar_one()
        assert not privileged

    def test_global_catalogues_are_read_only_to_the_application(self, app_session: Session) -> None:
        """A tenant-facing path must not be able to register a tool or invent a role.

        ``INSERT`` is granted to the *test* role as a fixture convenience; ``UPDATE`` and
        ``DELETE`` are revoked from ``asic_app`` itself and are what this asserts.
        """
        for table in ("tool_definition", "role", "permission"):
            can_update = app_session.execute(
                sa.text("SELECT has_table_privilege(current_user, :t, 'UPDATE')"),
                {"t": table},
            ).scalar_one()
            can_delete = app_session.execute(
                sa.text("SELECT has_table_privilege(current_user, :t, 'DELETE')"),
                {"t": table},
            ).scalar_one()
            assert not can_update, f"application role may UPDATE the {table} catalogue"
            assert not can_delete, f"application role may DELETE from the {table} catalogue"


class TestTenantScopeContextManager:
    def test_scope_binds_and_releases(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        with tenant_scope(app_session, tenant.id) as ctx:
            assert isinstance(ctx, TenantContext)
            assert current_tenant(app_session) == tenant.id
        assert current_tenant(app_session) is None

    def test_rebinding_to_a_different_tenant_is_refused(self, app_session: Session) -> None:
        """Switching tenant mid-transaction is almost always a bug."""
        acme = make_tenant(app_session, "acme")
        globex = make_tenant(app_session, "globex")
        with (
            tenant_scope(app_session, acme.id),
            pytest.raises(TenantContextMismatch),
            tenant_scope(app_session, globex.id),
        ):
            pass

    def test_nesting_the_same_tenant_is_permitted(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        with tenant_scope(app_session, tenant.id), tenant_scope(app_session, tenant.id):
            assert current_tenant(app_session) == tenant.id


class TestCacheAndJobPropagation:
    """Tenancy must survive the boundary between a request and the work it schedules."""

    def test_cache_keys_are_namespaced_by_tenant(self) -> None:
        acme = TenantContext(tenant_id=uuid.uuid4())
        globex = TenantContext(tenant_id=uuid.uuid4())
        assert acme.cache_key("incident", "42") != globex.cache_key("incident", "42")
        assert acme.cache_key("incident", "42").startswith(f"t:{acme.tenant_id}:")

    def test_job_envelope_carries_the_tenant(self) -> None:
        ctx = TenantContext(tenant_id=uuid.uuid4())
        envelope = ctx.job_envelope({"incident_id": "abc"})
        assert envelope["tenant_id"] == str(ctx.tenant_id)
        assert envelope["payload"] == {"incident_id": "abc"}

    def test_job_payload_cannot_smuggle_its_own_tenant(self) -> None:
        ctx = TenantContext(tenant_id=uuid.uuid4())
        with pytest.raises(ValueError, match="must not carry its own tenant_id"):
            ctx.job_envelope({"tenant_id": "someone-else"})
