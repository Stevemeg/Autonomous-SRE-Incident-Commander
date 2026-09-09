"""Tenant isolation: application role, tenant-context function, row-level security.

This is the migration that makes tenant isolation a property of the *database* rather than
a property of every query someone remembers to write correctly.

Three mechanisms, applied together:

1. **A separate application role.** ``asic_app`` is not the table owner and does not hold
   ``BYPASSRLS``. Migrations run as the owner; the application runs as ``asic_app``.

2. **``FORCE ROW LEVEL SECURITY``.** ``ENABLE`` alone exempts the table owner, which would
   make every test that runs as the owner pass vacuously while production leaked. ``FORCE``
   subjects the owner too, so what the tests exercise is what production enforces.

3. **A fail-closed policy.** The policy compares ``tenant_id`` against
   ``app.current_tenant_id()``. With no tenant bound, that function returns ``NULL``, the
   comparison is ``NULL``, and **no rows are visible or writable**. Forgetting to bind a
   tenant produces an empty result set, never a cross-tenant read.

``WITH CHECK`` matters as much as ``USING``: without it a session could *insert* rows
belonging to another tenant even though it could not read them back.

Append-only tables additionally have ``UPDATE`` and ``DELETE`` revoked from the application
role, so history cannot be rewritten by application code at all.

Revision ID: 0003_tenant_isolation_rls
Revises: 0002_domain_schema
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from asic.db.models import GLOBAL_TABLES

revision: str = "0003_tenant_isolation_rls"
down_revision: str | None = "0002_domain_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The role the application connects as. Created without LOGIN: an environment grants it
#: to a concrete login role and sets that role's password out of band, so no credential
#: appears in a migration.
APP_ROLE = "asic_app"

#: Read-only role for platform-level audit access across tenants. Created here so the
#: grant exists; it is deliberately *not* given BYPASSRLS by this migration - an
#: environment that needs cross-tenant audit reads grants that explicitly and records why.
AUDITOR_ROLE = "asic_auditor"

POLICY_NAME = "tenant_isolation"

#: The tenant-scoped tables **as they existed when this migration was authored**.
#:
#: An earlier draft derived this list from the live model registry. That is wrong for a
#: migration, and subtly so: adding a tenant-scoped table in a later phase would silently
#: change what this migration does, so a fresh ``upgrade head`` would try to enable
#: row-level security on a table that migration 0002 has not created yet. A migration must
#: describe the schema at its own point in history.
#:
#: Coverage of *current* models is asserted elsewhere - the RLS coverage test compares the
#: live database against ``tenant_scoped_tables()``, so a new tenant-scoped table without
#: its own protecting migration still fails the build.
TENANT_TABLES: tuple[str, ...] = (
    "alert",
    "app_user",
    "approval",
    "audit_record",
    "environment",
    "evaluation_run",
    "evaluation_scenario",
    "evidence",
    "execution_trace",
    "hypothesis",
    "hypothesis_evidence",
    "incident",
    "incident_event",
    "investigation_step",
    "knowledge_chunk",
    "knowledge_document",
    "memory_entry",
    "memory_promotion",
    "policy_decision",
    "postmortem",
    "remediation_action",
    "service",
    "service_dependency",
    "tenant_tool_grant",
    "timeline_event",
    "tool_execution",
    "trace_span",
    "user_role_assignment",
    "verification",
    "workflow_run",
)

#: Append-only tables as of this migration, for the same reason.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "approval",
    "audit_record",
    "behaviour_version",
    "evidence",
    "incident_event",
    "policy_decision",
    "tool_execution",
    "trace_span",
    "verification",
)


def _sorted_tenant_tables() -> list[str]:
    return sorted(TENANT_TABLES)


def upgrade() -> None:
    # ------------------------------------------------------------------ roles
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} NOLOGIN NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AUDITOR_ROLE}') THEN
                CREATE ROLE {AUDITOR_ROLE} NOLOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        """
    )

    # ------------------------------------------- tenant context accessor
    # SECURITY: this function is the single definition of "which tenant am I". It is
    # STABLE (not IMMUTABLE) because the setting can change between statements, and it
    # returns NULL rather than raising when unset so that RLS denies rather than errors.
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.current_tenant_id()
        RETURNS uuid
        LANGUAGE sql
        STABLE
        AS $$
            SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA app TO {APP_ROLE}, {AUDITOR_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO {APP_ROLE}, {AUDITOR_ROLE}")

    # ------------------------------------------------------------- base grants
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}, {AUDITOR_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {AUDITOR_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")

    # The platform-owned catalogues are read-only to the application: a tenant-facing code
    # path must not be able to register a tool, invent a role, or add a permission.
    for table in sorted(GLOBAL_TABLES - {"alembic_version"}):
        op.execute(f"REVOKE INSERT, UPDATE, DELETE ON {table} FROM {APP_ROLE}")

    # ------------------------------------------------------ row-level security
    for table in _sorted_tenant_tables():
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE is the load-bearing half: without it the owner bypasses the policy and
        # every owner-connected test passes while production leaks.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {POLICY_NAME} ON {table}
                USING (tenant_id = app.current_tenant_id())
                WITH CHECK (tenant_id = app.current_tenant_id())
            """
        )

    # --------------------------------------------------------- append-only tables
    # History cannot be rewritten by application code. The owner retains the ability so
    # that retention purges and lawful erasure remain possible as deliberate operations.
    for table in sorted(APPEND_ONLY_TABLES):
        op.execute(f"REVOKE UPDATE, DELETE ON {table} FROM {APP_ROLE}")


def downgrade() -> None:
    for table in sorted(APPEND_ONLY_TABLES):
        op.execute(f"GRANT UPDATE, DELETE ON {table} TO {APP_ROLE}")

    for table in _sorted_tenant_tables():
        op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP FUNCTION IF EXISTS app.current_tenant_id()")
    op.execute("DROP SCHEMA IF EXISTS app")

    # Roles are not dropped: they may own grants in other databases in the same cluster,
    # and dropping a role that still holds privileges fails in a way that is confusing to
    # diagnose mid-downgrade.
