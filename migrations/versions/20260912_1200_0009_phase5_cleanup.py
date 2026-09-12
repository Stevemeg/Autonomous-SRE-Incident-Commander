"""Deferred Phase 5 ingestion corrections.

Adds an explicit successful dispatch state and a database backstop allowing at most one
open reopen-review obligation per tenant/incident/alert. Existing duplicate candidates are
retained and marked superseded; no history is deleted.

Revision ID: 0009_phase5_cleanup
Revises: 0008_knowledge_memory
Create Date: 2026-09-12 12:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_phase5_cleanup"
down_revision: str | None = "0008_knowledge_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        "status IN ('pending', 'completed', 'terminal')",
    )

    op.add_column(
        "incident_reopen_candidate",
        sa.Column("status", sa.String(length=16), nullable=True),
    )
    op.execute(
        """
        WITH ranked AS (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY tenant_id, incident_id, alert_id
                       ORDER BY created_at, id
                   ) AS candidate_rank
            FROM incident_reopen_candidate
        )
        UPDATE incident_reopen_candidate AS candidate
        SET status = CASE WHEN ranked.candidate_rank = 1 THEN 'open' ELSE 'superseded' END
        FROM ranked
        WHERE candidate.id = ranked.id
        """
    )
    op.alter_column(
        "incident_reopen_candidate",
        "status",
        existing_type=sa.String(length=16),
        nullable=False,
        server_default=sa.text("'open'"),
    )
    op.create_check_constraint(
        op.f("ck_incident_reopen_candidate_known_status"),
        "incident_reopen_candidate",
        "status IN ('open', 'superseded')",
    )
    op.create_index(
        "uq_reopen_candidate_open_incident_alert",
        "incident_reopen_candidate",
        ["tenant_id", "incident_id", "alert_id"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM incident_reopen_candidate)
               OR EXISTS (
                   SELECT 1 FROM investigation_dispatch WHERE status = 'completed'
               ) THEN
                RAISE EXCEPTION
                    'refusing to discard Phase 5 cleanup state while retained history exists';
            END IF;
        END
        $$
        """
    )
    op.drop_index(
        "uq_reopen_candidate_open_incident_alert",
        table_name="incident_reopen_candidate",
        postgresql_where=sa.text("status = 'open'"),
    )
    op.drop_constraint(
        op.f("ck_incident_reopen_candidate_known_status"),
        "incident_reopen_candidate",
        type_="check",
    )
    op.drop_column("incident_reopen_candidate", "status")

    op.drop_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_investigation_dispatch_known_status"),
        "investigation_dispatch",
        "status IN ('pending', 'terminal')",
    )
