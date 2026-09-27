"""Phase 15 retention lifecycle executor: a separate maintenance role and durable receipts.

NFR-SEC-14 requires data-retention controls. Phase 13 built classification, tenant policy,
holds and a dry-run planner and left the runtime unable to delete anything. This revision adds
the smallest safe executor boundary, for the one class the planner ever makes time-eligible:
the API idempotency replay cache (``api_idempotency_record``).

* ``asic_maintenance`` - a separate ``NOLOGIN NOBYPASSRLS`` role. A deployment grants it to a
  maintenance login that is never mounted into API pods. It may read and delete idempotency
  records, read tenant policy, and write receipts - nothing else. Row-level security still
  applies to it (the ``tenant_isolation`` policies are ``TO PUBLIC``): it acts one tenant at a
  time, bound exactly like the application.
* ``retention_run`` - append-only, tenant-scoped, RLS-protected receipts written in the same
  transaction as each deletion batch. The runtime may read them; nobody may change them.

The application role gains nothing: it still holds no ``DELETE`` anywhere.

Revision ID: 0019_retention_maintenance
Revises: 0018_security_hardening
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_retention_maintenance"
down_revision: str | None = "0018_security_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

MAINTENANCE_ROLE = "asic_maintenance"
TABLE = "retention_run"


def upgrade() -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MAINTENANCE_ROLE}') THEN
                CREATE ROLE {MAINTENANCE_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB
                    NOCREATEROLE;
            END IF;
        END
        $$;
        """
    )
    op.create_table(
        TABLE,
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("execution_id", sa.UUID(), nullable=False),
        sa.Column("retention_class", sa.String(length=64), nullable=False),
        sa.Column("table_name", sa.String(length=64), nullable=False),
        sa.Column("policy_days", sa.Integer(), nullable=True),
        sa.Column("cutoff", sa.DateTime(timezone=True), nullable=True),
        sa.Column("held", sa.Boolean(), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("batch_limit", sa.Integer(), nullable=False),
        sa.Column("eligible_rows", sa.Integer(), nullable=False),
        sa.Column("deleted_rows", sa.Integer(), nullable=False),
        sa.Column("executed_by", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "NOT dry_run OR deleted_rows = 0", name=op.f("ck_retention_run_dry_run_deletes_nothing")
        ),
        sa.CheckConstraint(
            "NOT held OR deleted_rows = 0", name=op.f("ck_retention_run_held_deletes_nothing")
        ),
        sa.CheckConstraint(
            "batch_limit BETWEEN 1 AND 10000", name=op.f("ck_retention_run_batch_limit_bounded")
        ),
        sa.CheckConstraint(
            "deleted_rows <= batch_limit", name=op.f("ck_retention_run_deleted_within_batch")
        ),
        sa.CheckConstraint(
            "deleted_rows >= 0 AND eligible_rows >= 0",
            name=op.f("ck_retention_run_counts_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name=op.f("fk_retention_run_tenant_id_tenant"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retention_run")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_retention_run_tenant_id_id"),
    )
    op.create_index(
        "ix_retention_run_execution", TABLE, ["tenant_id", "execution_id"], unique=False
    )
    op.create_index(op.f("ix_retention_run_tenant_id"), TABLE, ["tenant_id"], unique=False)

    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {TABLE} "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    # Receipts are evidence: the runtime and the auditor read them, only maintenance writes.
    op.execute(f"GRANT SELECT ON {TABLE} TO asic_app")
    op.execute(f"GRANT SELECT ON {TABLE} TO asic_auditor")

    op.execute(f"GRANT USAGE ON SCHEMA app TO {MAINTENANCE_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION app.current_tenant_id() TO {MAINTENANCE_ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {MAINTENANCE_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON {TABLE} TO {MAINTENANCE_ROLE}")
    op.execute(f"GRANT SELECT, DELETE ON api_idempotency_record TO {MAINTENANCE_ROLE}")
    op.execute(f"GRANT SELECT (id, slug, status, retention_policy) ON tenant TO {MAINTENANCE_ROLE}")


def downgrade() -> None:
    # Receipts are protected evidence: refuse to drop them once any exist.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM {TABLE}) THEN
                RAISE EXCEPTION 'retention_run holds receipts; refusing to discard them';
            END IF;
        END
        $$;
        """
    )
    op.execute(f"REVOKE ALL ON api_idempotency_record FROM {MAINTENANCE_ROLE}")
    op.execute(f"REVOKE ALL ON tenant FROM {MAINTENANCE_ROLE}")
    op.execute(f"REVOKE ALL ON FUNCTION app.current_tenant_id() FROM {MAINTENANCE_ROLE}")
    op.execute(f"REVOKE ALL ON SCHEMA app FROM {MAINTENANCE_ROLE}")
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {MAINTENANCE_ROLE}")
    op.drop_index(op.f("ix_retention_run_tenant_id"), table_name=TABLE)
    op.drop_index("ix_retention_run_execution", table_name=TABLE)
    op.drop_table(TABLE)
    # The role is cluster-wide and may be granted to a deployment's login; it is left in place
    # (with no privileges) rather than dropped from under that login.
