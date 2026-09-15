"""Bind verified memory lineage and make completed model attempts immutable."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0015_verified_memory_ledger"
down_revision: str | None = "0014_pre_phase10_safety"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LINEAGE_COLUMNS: tuple[str, ...] = (
    "remediation_baseline_id",
    "post_action_read_execution_id",
    "profile_id",
    "profile_version",
    "observed_metric",
    "observed_value",
    "observed_at",
    "observation_source_provider",
    "observation_source_capability",
    "observation_provenance_hash",
)


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_tool_execution_tenant_id_id_action",
        "tool_execution",
        ["tenant_id", "id", "remediation_action_id"],
    )
    op.create_unique_constraint(
        "uq_remediation_baseline_tenant_id_id_action",
        "remediation_baseline",
        ["tenant_id", "id", "remediation_action_id"],
    )
    op.drop_constraint(
        "fk_remediation_baseline_read_execution",
        "remediation_baseline",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_remediation_baseline_read_execution",
        "remediation_baseline",
        "tool_execution",
        ["tenant_id", "read_execution_id", "remediation_action_id"],
        ["tenant_id", "id", "remediation_action_id"],
        ondelete="RESTRICT",
    )
    op.add_column("verification", sa.Column("remediation_baseline_id", pg.UUID(), nullable=True))
    op.add_column(
        "verification", sa.Column("post_action_read_execution_id", pg.UUID(), nullable=True)
    )
    op.add_column("verification", sa.Column("profile_id", sa.String(128), nullable=True))
    op.add_column("verification", sa.Column("profile_version", sa.Integer(), nullable=True))
    op.add_column("verification", sa.Column("observed_metric", sa.String(128), nullable=True))
    op.add_column("verification", sa.Column("observed_value", sa.Numeric(18, 6), nullable=True))
    op.add_column(
        "verification", sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "verification", sa.Column("observation_source_provider", sa.String(128), nullable=True)
    )
    op.add_column(
        "verification", sa.Column("observation_source_capability", sa.String(128), nullable=True)
    )
    op.add_column(
        "verification", sa.Column("observation_provenance_hash", sa.String(64), nullable=True)
    )
    op.create_foreign_key(
        "fk_verification_baseline",
        "verification",
        "remediation_baseline",
        ["tenant_id", "remediation_baseline_id", "remediation_action_id"],
        ["tenant_id", "id", "remediation_action_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_verification_post_read_execution",
        "verification",
        "tool_execution",
        ["tenant_id", "post_action_read_execution_id", "remediation_action_id"],
        ["tenant_id", "id", "remediation_action_id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "trusted_lineage_all_or_none",
        "verification",
        "((remediation_baseline_id IS NULL) AND "
        "(post_action_read_execution_id IS NULL) AND (profile_id IS NULL) AND "
        "(profile_version IS NULL) AND (observed_metric IS NULL) AND "
        "(observed_value IS NULL) AND (observed_at IS NULL) AND "
        "(observation_source_provider IS NULL) AND "
        "(observation_source_capability IS NULL) AND "
        "(observation_provenance_hash IS NULL)) OR "
        "((remediation_baseline_id IS NOT NULL) AND "
        "(post_action_read_execution_id IS NOT NULL) AND (profile_id IS NOT NULL) AND "
        "(profile_version IS NOT NULL) AND (profile_version > 0) AND "
        "(observed_metric IS NOT NULL) AND (observed_value IS NOT NULL) AND "
        "(observed_at IS NOT NULL) AND (observation_source_provider IS NOT NULL) AND "
        "(observation_source_capability IS NOT NULL) AND "
        "(observation_provenance_hash IS NOT NULL))",
    )
    op.create_unique_constraint(
        "uq_verification_post_read_execution",
        "verification",
        ["tenant_id", "post_action_read_execution_id"],
    )
    op.create_index(
        "ix_verification_baseline", "verification", ["tenant_id", "remediation_baseline_id"]
    )
    op.create_index(
        "ix_verification_post_read",
        "verification",
        ["tenant_id", "post_action_read_execution_id"],
    )

    # Table-level UPDATE from 0014 was intentionally broad enough to settle a row, but it
    # also allowed completed replay evidence to be rewritten. Narrow the privilege to the
    # six settlement fields and enforce the one legal transition in the database.
    op.execute("REVOKE UPDATE ON model_call_reservation FROM asic_app")
    op.execute(
        "GRANT UPDATE (actual_input_tokens, actual_output_tokens, actual_cost_usd, "
        "response, status, updated_at) ON model_call_reservation TO asic_app"
    )
    op.execute(
        r"""
        CREATE FUNCTION app.enforce_model_call_reservation_transition()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'reserved'
                    OR NEW.response IS NOT NULL
                    OR NEW.actual_input_tokens IS NOT NULL
                    OR NEW.actual_output_tokens IS NOT NULL
                    OR NEW.actual_cost_usd IS NOT NULL
                THEN
                    RAISE EXCEPTION 'model-call reservations must begin reserved and unsettled'
                        USING ERRCODE = '42501';
                END IF;
                RETURN NEW;
            END IF;
            IF OLD.status <> 'reserved' THEN
                RAISE EXCEPTION 'completed model-call reservations are immutable'
                    USING ERRCODE = '42501';
            END IF;
            IF NEW.status <> 'completed' THEN
                RAISE EXCEPTION 'model-call reservation may only transition reserved to completed'
                    USING ERRCODE = '42501';
            END IF;
            IF NEW.id IS DISTINCT FROM OLD.id
                OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id
                OR NEW.invocation_key IS DISTINCT FROM OLD.invocation_key
                OR NEW.node_id IS DISTINCT FROM OLD.node_id
                OR NEW.reserved_tokens IS DISTINCT FROM OLD.reserved_tokens
                OR NEW.reserved_cost_usd IS DISTINCT FROM OLD.reserved_cost_usd
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
            THEN
                RAISE EXCEPTION 'model-call reservation identity and bounds are immutable'
                    USING ERRCODE = '42501';
            END IF;
            IF OLD.response IS NOT NULL
                OR OLD.actual_input_tokens IS NOT NULL
                OR OLD.actual_output_tokens IS NOT NULL
                OR OLD.actual_cost_usd IS NOT NULL
            THEN
                RAISE EXCEPTION 'reserved model-call row already contains settlement data'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER enforce_model_call_reservation_transition "
        "BEFORE INSERT OR UPDATE ON model_call_reservation FOR EACH ROW "
        "EXECUTE FUNCTION app.enforce_model_call_reservation_transition()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS enforce_model_call_reservation_transition ON model_call_reservation"
    )
    op.execute("DROP FUNCTION IF EXISTS app.enforce_model_call_reservation_transition()")
    op.execute(
        "REVOKE UPDATE (actual_input_tokens, actual_output_tokens, actual_cost_usd, "
        "response, status, updated_at) ON model_call_reservation FROM asic_app"
    )
    op.execute("GRANT UPDATE ON model_call_reservation TO asic_app")

    op.drop_index("ix_verification_post_read", table_name="verification")
    op.drop_index("ix_verification_baseline", table_name="verification")
    op.drop_constraint("uq_verification_post_read_execution", "verification", type_="unique")
    op.drop_constraint("trusted_lineage_all_or_none", "verification", type_="check")
    op.drop_constraint("fk_verification_post_read_execution", "verification", type_="foreignkey")
    op.drop_constraint("fk_verification_baseline", "verification", type_="foreignkey")
    for column in reversed(_LINEAGE_COLUMNS):
        op.drop_column("verification", column)
    op.drop_constraint(
        "fk_remediation_baseline_read_execution",
        "remediation_baseline",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_remediation_baseline_read_execution",
        "remediation_baseline",
        "tool_execution",
        ["tenant_id", "read_execution_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.drop_constraint(
        "uq_remediation_baseline_tenant_id_id_action",
        "remediation_baseline",
        type_="unique",
    )
    op.drop_constraint("uq_tool_execution_tenant_id_id_action", "tool_execution", type_="unique")
