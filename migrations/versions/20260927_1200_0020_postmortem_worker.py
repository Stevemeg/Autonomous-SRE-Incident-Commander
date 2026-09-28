"""Phase 16 closure: versioned postmortem drafts (G11) and the worker's remediation handoff.

``postmortem`` existed since 0002 as a single row per incident that no code path wrote. The
G11 postmortem author needs:

* **versions** - one draft per (incident, source fingerprint); a changed record set is a new
  version, never an edit (``uq_postmortem_version``, ``uq_postmortem_fingerprint``);
* **structure** - sections of cited claims, the uncertainty list, generation metadata and the
  grounding-validation outcome, so a reviewer can check every claim against its record;
* **draft-only authority** - the table becomes append-only (the runtime loses ``UPDATE``) and a
  check constraint refuses any row that is not an unreviewed ``draft`` with
  ``review_required``. No automated path can publish; a future review workflow must change this
  constraint in its own migration.

``remediation_request`` is the durable handoff from a responder to the deployed worker. It is
tenant-scoped with FORCE row-level security and composite tenant foreign keys like every other
tenant table, and the runtime role may insert and update it but never delete it.

The existing ``postmortem`` table has never been written by any released code path. Rather
than invent values for rows it cannot interpret, the upgrade refuses to run if any exist.

Revision ID: 0020_postmortem_worker
Revises: 0019_retention_maintenance
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020_postmortem_worker"
down_revision: str | None = "0019_retention_maintenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "asic_app"
AUDITOR_ROLE = "asic_auditor"
REQUEST = "remediation_request"
#: Tenant-scoped tables this migration creates and protects (pinned, never derived).
TENANT_TABLES = (REQUEST,)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM postmortem) THEN
                RAISE EXCEPTION 'postmortem holds rows written before 0020; refusing to '
                    'reinterpret them as versioned drafts';
            END IF;
        END
        $$;
        """
    )
    op.drop_constraint("uq_postmortem_incident", "postmortem", type_="unique")
    op.add_column("postmortem", sa.Column("version", sa.Integer(), nullable=False))
    op.add_column(
        "postmortem", sa.Column("source_fingerprint", sa.String(length=64), nullable=False)
    )
    op.add_column(
        "postmortem",
        sa.Column("sections", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.add_column(
        "postmortem",
        sa.Column(
            "uncertainties",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("postmortem", sa.Column("resolution_basis", sa.String(length=32), nullable=False))
    op.add_column(
        "postmortem",
        sa.Column("generation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.add_column(
        "postmortem",
        sa.Column("validation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    )
    op.add_column(
        "postmortem",
        sa.Column("review_required", sa.Boolean(), server_default=sa.text("true"), nullable=False),
    )
    op.create_unique_constraint(
        "uq_postmortem_version", "postmortem", ["tenant_id", "incident_id", "version"]
    )
    op.create_unique_constraint(
        "uq_postmortem_fingerprint",
        "postmortem",
        ["tenant_id", "incident_id", "source_fingerprint"],
    )
    for name, condition in (
        (
            "unreviewed_drafts_only",
            "status = 'draft' AND review_required AND reviewed_by_user_id IS NULL "
            "AND reviewed_at IS NULL",
        ),
        ("version_positive", "version >= 1"),
        (
            "known_resolution_basis",
            "resolution_basis IN ('independently_verified', 'human_declared')",
        ),
        (
            "cites_at_least_one_record",
            "jsonb_typeof(citations) = 'array' AND jsonb_array_length(citations) > 0",
        ),
        ("sections_is_object", "jsonb_typeof(sections) = 'object'"),
        ("uncertainties_is_array", "jsonb_typeof(uncertainties) = 'array'"),
    ):
        op.create_check_constraint(op.f(f"ck_postmortem_{name}"), "postmortem", condition)
    # Append-only: a draft is evidence of what was generated from what. Nobody edits it.
    op.execute(f"REVOKE UPDATE, DELETE ON postmortem FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON postmortem TO {APP_ROLE}")

    op.create_table(
        REQUEST,
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("hypothesis_id", sa.UUID(), nullable=False),
        sa.Column("service_id", sa.UUID(), nullable=False),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'pending'"), nullable=False
        ),
        sa.Column("workflow_run_id", sa.UUID(), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'started', 'rejected')",
            name=op.f("ck_remediation_request_known_status"),
        ),
        sa.CheckConstraint(
            "(status = 'started') = (workflow_run_id IS NOT NULL)",
            name=op.f("ck_remediation_request_started_request_names_run"),
        ),
        sa.CheckConstraint(
            "status <> 'rejected' OR last_error IS NOT NULL",
            name=op.f("ck_remediation_request_rejection_has_reason"),
        ),
        sa.CheckConstraint(
            "attempts >= 0", name=op.f("ck_remediation_request_attempts_nonnegative")
        ),
        sa.CheckConstraint(
            "char_length(justification) BETWEEN 1 AND 2000",
            name=op.f("ck_remediation_request_justification_bounded"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name=op.f("fk_remediation_request_tenant_id_tenant"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incident.tenant_id", "incident.id"],
            name="fk_remediation_request_incident",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "hypothesis_id"],
            ["hypothesis.tenant_id", "hypothesis.id"],
            name="fk_remediation_request_hypothesis",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_id"],
            ["service.tenant_id", "service.id"],
            name="fk_remediation_request_service",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "requested_by_user_id"],
            ["app_user.tenant_id", "app_user.id"],
            name="fk_remediation_request_requester",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "workflow_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            name="fk_remediation_request_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_remediation_request")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_remediation_request_tenant_id_id"),
    )
    op.create_index(
        "uq_remediation_request_pending_incident",
        REQUEST,
        ["tenant_id", "incident_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index("ix_remediation_request_status", REQUEST, ["tenant_id", "status"])
    op.create_index(op.f("ix_remediation_request_tenant_id"), REQUEST, ["tenant_id"])

    op.execute(f"ALTER TABLE {REQUEST} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {REQUEST} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {REQUEST} "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {REQUEST} TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {REQUEST} TO {AUDITOR_ROLE}")


def downgrade() -> None:
    # Drafts and requests are evidence of what was generated and who asked for what.
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM postmortem) OR EXISTS (SELECT 1 FROM {REQUEST}) THEN
                RAISE EXCEPTION 'postmortem drafts or remediation requests exist; refusing to '
                    'discard them';
            END IF;
        END
        $$;
        """
    )
    op.drop_index(op.f("ix_remediation_request_tenant_id"), table_name=REQUEST)
    op.drop_index("ix_remediation_request_status", table_name=REQUEST)
    op.drop_index("uq_remediation_request_pending_incident", table_name=REQUEST)
    op.drop_table(REQUEST)

    op.execute(f"GRANT UPDATE ON postmortem TO {APP_ROLE}")
    for name in (
        "uncertainties_is_array",
        "sections_is_object",
        "cites_at_least_one_record",
        "known_resolution_basis",
        "version_positive",
        "unreviewed_drafts_only",
    ):
        op.drop_constraint(op.f(f"ck_postmortem_{name}"), "postmortem", type_="check")
    op.drop_constraint("uq_postmortem_fingerprint", "postmortem", type_="unique")
    op.drop_constraint("uq_postmortem_version", "postmortem", type_="unique")
    for column in (
        "review_required",
        "validation",
        "generation",
        "resolution_basis",
        "uncertainties",
        "sections",
        "source_fingerprint",
        "version",
    ):
        op.drop_column("postmortem", column)
    op.create_unique_constraint(
        "uq_postmortem_incident", "postmortem", ["tenant_id", "incident_id"]
    )
