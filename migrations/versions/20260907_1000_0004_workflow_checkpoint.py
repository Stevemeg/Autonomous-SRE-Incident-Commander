"""Durable orchestration checkpoints.

Adds ``workflow_checkpoint`` and protects it in the same migration that creates it. That
pairing is deliberate: a tenant-scoped table that exists for even one migration without
row-level security is a table an application bug could read across tenants, and "we will
add the policy in the next migration" is how that window opens.

The table's justification is recorded in ADR-0015. In short: ``workflow_run.checkpoint_ref``
can only name the latest checkpoint, which is enough to resume and not enough to diagnose a
resume - the operation most likely to go wrong and hardest to reproduce afterwards.

Revision ID: 0004_workflow_checkpoint
Revises: 0003_tenant_isolation_rls
Create Date: 2026-09-07
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_workflow_checkpoint"
down_revision: str | None = "0003_tenant_isolation_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "workflow_checkpoint"
APP_ROLE = "asic_app"
AUDITOR_ROLE = "asic_auditor"
POLICY_NAME = "tenant_isolation"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("workflow_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("after_node", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.String(length=32), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "durable_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "budget_consumed",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("behaviour_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "taken_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "reason IN ('run_started', 'node_boundary', 'terminal', 'suspended')",
            name=op.f("ck_workflow_checkpoint_known_checkpoint_reason"),
        ),
        sa.CheckConstraint(
            "length(state_digest) = 64",
            name=op.f("ck_workflow_checkpoint_state_digest_is_sha256"),
        ),
        sa.CheckConstraint(
            "sequence >= 1", name=op.f("ck_workflow_checkpoint_sequence_starts_at_one")
        ),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            name="fk_workflow_checkpoint_behaviour_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incident.tenant_id", "incident.id"],
            name="fk_workflow_checkpoint_incident",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "workflow_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            name="fk_workflow_checkpoint_workflow_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name=op.f("fk_workflow_checkpoint_tenant_id_tenant"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_checkpoint")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_workflow_checkpoint_tenant_id_id")),
        sa.UniqueConstraint(
            "tenant_id",
            "workflow_run_id",
            "sequence",
            name="uq_workflow_checkpoint_sequence",
        ),
    )
    op.create_index(op.f("ix_workflow_checkpoint_tenant_id"), TABLE, ["tenant_id"], unique=False)
    op.create_index(
        "ix_workflow_checkpoint_run",
        TABLE,
        ["tenant_id", "workflow_run_id", "sequence"],
        unique=False,
    )

    # Grants, then isolation, in the same migration that created the table.
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {TABLE} TO {AUDITOR_ROLE}")

    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
    # FORCE, because ENABLE alone exempts the table owner - and in a standard container
    # image the owner is a superuser, which bypasses row-level security regardless.
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {POLICY_NAME} ON {TABLE}
            USING (tenant_id = app.current_tenant_id())
            WITH CHECK (tenant_id = app.current_tenant_id())
        """
    )

    # Append-only: a checkpoint that could be edited would let a resume be pointed at a
    # state the run was never in.
    op.execute(f"REVOKE UPDATE, DELETE ON {TABLE} FROM {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {TABLE}")
    op.drop_index("ix_workflow_checkpoint_run", table_name=TABLE)
    op.drop_index(op.f("ix_workflow_checkpoint_tenant_id"), table_name=TABLE)
    op.drop_table(TABLE)
