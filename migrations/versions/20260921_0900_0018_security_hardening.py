"""Phase 13 security hardening: trace-id integrity, connector referential integrity, grants.

Self-contained (ADR-0018). Three independent changes, each closing a finding from the
Phases 10-12 audit or the Phase 13 privilege inventory:

* **F-11 - trace identity.** ``execution_trace.trace_id`` is a W3C trace id: 32 lowercase
  hex characters, not all zero. The application validates at the boundary
  (``asic.observability.trace_ids``); this CHECK makes the database refuse anything else.
  It is added ``NOT VALID`` and validated in the same step *only if no historical row
  violates it*: a pre-existing malformed row must not make the upgrade fail, and must not
  be silently rewritten either - the constraint still governs every new or updated row,
  and the application refuses to build a trace context from a malformed persisted id.
* **F-13 - connector referential integrity.** ``connector_scope_binding`` names a connector
  by ``connector_id`` with no relational link to ``integration_connector``. A composite,
  tenant-carrying foreign key (``ON DELETE RESTRICT``) makes a binding to a nonexistent -
  or another tenant's - connector structurally impossible, and refuses to delete a
  connector while authority history still references it. Same ``NOT VALID``-then-validate
  treatment for pre-existing orphan rows.
* **Least privilege.** The privilege inventory found the application role holding
  ``DELETE`` on eighteen tables although no runtime code path deletes anything, write
  access to ``alembic_version`` (the readiness signal), and write access to identity, role
  assignment, tool-grant and scope-catalogue tables that the runtime only reads. Those
  grants are revoked. Cascading foreign-key deletes are executed by the referential
  integrity triggers with the table owner's rights and are unaffected.

Revision ID: 0018_security_hardening
Revises: 0017_evaluation_harness
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0018_security_hardening"
down_revision: str | None = "0017_evaluation_harness"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "asic_app"

TRACE_CHECK = "ck_execution_trace_trace_id_is_w3c_trace_id"
BINDING_FK = "fk_connector_scope_binding_connector"

#: Provisioned by the owner/administrative path, read by the runtime.
READ_ONLY_FOR_RUNTIME: tuple[str, ...] = (
    "app_user",
    "environment",
    "service",
    "service_dependency",
    "tenant_tool_grant",
    "user_role_assignment",
)


def upgrade() -> None:
    # ---------------------------------------------------------------- F-11
    op.execute(
        f"""
        ALTER TABLE execution_trace ADD CONSTRAINT {TRACE_CHECK}
            CHECK (trace_id ~ '^[0-9a-f]{{32}}$' AND trace_id <> repeat('0', 32)) NOT VALID
        """
    )
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM execution_trace
                WHERE NOT (trace_id ~ '^[0-9a-f]{{32}}$' AND trace_id <> repeat('0', 32))
            ) THEN
                ALTER TABLE execution_trace VALIDATE CONSTRAINT {TRACE_CHECK};
            ELSE
                RAISE NOTICE 'execution_trace holds malformed trace ids; {TRACE_CHECK} left '
                    'NOT VALID (enforced for new and updated rows only)';
            END IF;
        END
        $$;
        """
    )

    # ---------------------------------------------------------------- F-13
    op.execute(
        f"""
        ALTER TABLE connector_scope_binding ADD CONSTRAINT {BINDING_FK}
            FOREIGN KEY (tenant_id, connector_id)
            REFERENCES integration_connector (tenant_id, connector_id)
            ON DELETE RESTRICT NOT VALID
        """
    )
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM connector_scope_binding b
                WHERE NOT EXISTS (
                    SELECT 1 FROM integration_connector c
                    WHERE c.tenant_id = b.tenant_id AND c.connector_id = b.connector_id
                )
            ) THEN
                ALTER TABLE connector_scope_binding VALIDATE CONSTRAINT {BINDING_FK};
            ELSE
                RAISE NOTICE 'connector_scope_binding holds orphan bindings; {BINDING_FK} left '
                    'NOT VALID (enforced for new and updated rows only)';
            END IF;
        END
        $$;
        """
    )

    # ------------------------------------------------------------ privileges
    # No runtime path issues DELETE (verified by tests/security/test_least_privilege.py);
    # history is retired by an owner-run lifecycle job, never by the application role.
    op.execute(f"REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM {APP_ROLE}")
    op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM {APP_ROLE}")
    for table in READ_ONLY_FOR_RUNTIME:
        op.execute(f"REVOKE INSERT, UPDATE ON {table} FROM {APP_ROLE}")


def downgrade() -> None:
    for table in READ_ONLY_FOR_RUNTIME:
        op.execute(f"GRANT INSERT, UPDATE ON {table} TO {APP_ROLE}")
    op.execute(f"GRANT INSERT, UPDATE, DELETE ON alembic_version TO {APP_ROLE}")
    # DELETE is restored only on the tables that held it before this revision.
    for table in (
        "alert",
        "app_user",
        "environment",
        "execution_trace",
        "hypothesis",
        "hypothesis_evidence",
        "incident",
        "investigation_dispatch",
        "investigation_step",
        "postmortem",
        "remediation_action",
        "service",
        "service_dependency",
        "tenant_tool_grant",
        "timeline_event",
        "user_role_assignment",
        "workflow_run",
    ):
        op.execute(f"GRANT DELETE ON {table} TO {APP_ROLE}")

    op.execute(f"ALTER TABLE connector_scope_binding DROP CONSTRAINT IF EXISTS {BINDING_FK}")
    op.execute(f"ALTER TABLE execution_trace DROP CONSTRAINT IF EXISTS {TRACE_CHECK}")
