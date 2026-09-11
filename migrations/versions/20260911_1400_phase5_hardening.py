"""Phase 5 ingestion hardening

Revision ID: 0007_phase5_hardening
Revises: 0006_telemetry_ingestion
Create Date: 2026-09-11 14:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_phase5_hardening"
down_revision: str | None = "0006_telemetry_ingestion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
TENANT_TABLES = ("incident_reopen_candidate",)


def upgrade() -> None:
    op.drop_constraint(op.f("ck_signal_receipt_known_outcome"), "signal_receipt", type_="check")
    op.create_check_constraint(
        op.f("ck_signal_receipt_known_outcome"),
        "signal_receipt",
        "outcome IN ('accepted', 'rejected', 'retryable', 'stale', 'unchanged')",
    )
    op.add_column(
        "investigation_dispatch",
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        "status IN ('pending', 'terminal')",
    )
    op.create_table(
        "incident_reopen_candidate",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("receipt_id", sa.UUID(), nullable=False),
        sa.Column(
            "requested_severity",
            postgresql.ENUM(
                "sev1",
                "sev2",
                "sev3",
                "sev4",
                name="incident_severity",
                native_enum=True,
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "alert_id"],
            ["alert.tenant_id", "alert.id"],
            name="fk_reopen_candidate_alert",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incident.tenant_id", "incident.id"],
            name="fk_reopen_candidate_incident",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "receipt_id"],
            ["signal_receipt.tenant_id", "signal_receipt.id"],
            name="fk_reopen_candidate_receipt",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name=op.f("fk_incident_reopen_candidate_tenant_id_tenant"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_reopen_candidate")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_incident_reopen_candidate_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_reopen_candidate_receipt"),
    )
    op.create_index(
        op.f("ix_incident_reopen_candidate_tenant_id"),
        "incident_reopen_candidate",
        ["tenant_id"],
        unique=False,
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON incident_reopen_candidate TO asic_app")
    op.execute("GRANT SELECT ON incident_reopen_candidate TO asic_auditor")
    op.execute("ALTER TABLE incident_reopen_candidate ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE incident_reopen_candidate FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON incident_reopen_candidate "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute("REVOKE UPDATE, DELETE ON incident_reopen_candidate FROM asic_app")


def downgrade() -> None:
    op.execute("SET LOCAL row_security = off")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM incident_reopen_candidate)
           OR EXISTS (SELECT 1 FROM signal_receipt WHERE outcome = 'retryable')
           OR EXISTS (SELECT 1 FROM investigation_dispatch WHERE status = 'terminal')
        THEN RAISE EXCEPTION 'Phase 5 hardening history exists; downgrade refused'; END IF;
        END $$""")
    op.drop_index(
        op.f("ix_incident_reopen_candidate_tenant_id"),
        table_name="incident_reopen_candidate",
    )
    op.drop_table("incident_reopen_candidate")
    op.drop_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        type_="check",
    )
    op.drop_column("investigation_dispatch", "status")
    op.drop_constraint(op.f("ck_signal_receipt_known_outcome"), "signal_receipt", type_="check")
    op.create_check_constraint(
        op.f("ck_signal_receipt_known_outcome"),
        "signal_receipt",
        "outcome IN ('accepted', 'rejected', 'stale', 'unchanged')",
    )
