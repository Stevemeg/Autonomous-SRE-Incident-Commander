"""Bind verification evidence, model budgets and connector ingestion scope."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0014_pre_phase10_safety"
down_revision: str | None = "0013_audit_corrections"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES: tuple[str, ...] = (
    "connector_scope_binding",
    "model_call_reservation",
    "remediation_baseline",
)


def _tenant_identity(table: str) -> tuple[sa.UniqueConstraint, sa.ForeignKeyConstraint]:
    return (
        sa.UniqueConstraint("tenant_id", "id", name=f"uq_{table}_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenant.id"], ondelete="RESTRICT", name=f"fk_{table}_tenant"
        ),
    )


def _protect(table: str, privileges: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute(f"GRANT {privileges} ON {table} TO asic_app")


def upgrade() -> None:
    op.create_table(
        "connector_scope_binding",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", sa.String(255), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("service_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        *_tenant_identity("connector_scope_binding"),
        sa.PrimaryKeyConstraint("id", name="pk_connector_scope_binding"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_id"],
            ["service.tenant_id", "service.id"],
            ondelete="CASCADE",
            name="fk_connector_binding_service",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "environment_id"],
            ["environment.tenant_id", "environment.id"],
            ondelete="CASCADE",
            name="fk_connector_binding_environment",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "connector_id",
            "source",
            "service_id",
            "environment_id",
            name="uq_connector_scope_binding_tuple",
        ),
        sa.CheckConstraint(
            "(is_enabled AND revoked_at IS NULL) OR (NOT is_enabled)",
            name="ck_connector_scope_binding_enabled_binding_not_revoked",
        ),
    )
    op.create_index(
        "ix_connector_scope_binding_lookup",
        "connector_scope_binding",
        ["tenant_id", "connector_id", "source", "service_id", "environment_id", "is_enabled"],
    )
    op.create_index(
        "ix_connector_scope_binding_tenant_id", "connector_scope_binding", ["tenant_id"]
    )
    _protect("connector_scope_binding", "SELECT")

    op.create_table(
        "model_call_reservation",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("workflow_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("invocation_key", sa.String(255), nullable=False),
        sa.Column("node_id", pg.ENUM(name="node_id", create_type=False), nullable=False),
        sa.Column("reserved_tokens", sa.Integer(), nullable=False),
        sa.Column("reserved_cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("actual_input_tokens", sa.Integer(), nullable=True),
        sa.Column("actual_output_tokens", sa.Integer(), nullable=True),
        sa.Column("actual_cost_usd", sa.Numeric(12, 6), nullable=True),
        sa.Column("response", pg.JSONB(), nullable=True),
        sa.Column("status", sa.String(16), server_default=sa.text("'reserved'"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        *_tenant_identity("model_call_reservation"),
        sa.PrimaryKeyConstraint("id", name="pk_model_call_reservation"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "workflow_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            ondelete="CASCADE",
            name="fk_model_call_reservation_run",
        ),
        sa.UniqueConstraint(
            "tenant_id", "workflow_run_id", "invocation_key", name="uq_model_call_reservation"
        ),
        sa.CheckConstraint(
            "reserved_tokens >= 0", name="ck_model_call_reservation_reserved_tokens_non_negative"
        ),
        sa.CheckConstraint(
            "reserved_cost_usd >= 0", name="ck_model_call_reservation_reserved_cost_non_negative"
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'completed')", name="ck_model_call_reservation_status_known"
        ),
        sa.CheckConstraint(
            "(status = 'completed') = (response IS NOT NULL)",
            name="ck_model_call_reservation_completed_has_response",
        ),
        sa.CheckConstraint(
            "status <> 'completed' OR "
            "(actual_input_tokens IS NOT NULL AND actual_input_tokens >= 0 "
            "AND actual_output_tokens IS NOT NULL AND actual_output_tokens >= 0 "
            "AND actual_input_tokens + actual_output_tokens <= reserved_tokens "
            "AND actual_cost_usd IS NOT NULL AND actual_cost_usd >= 0 "
            "AND actual_cost_usd <= reserved_cost_usd)",
            name="ck_model_call_reservation_completed_usage_within_reservation",
        ),
    )
    op.create_index(
        "ix_model_call_reservation_run",
        "model_call_reservation",
        ["tenant_id", "workflow_run_id", "created_at"],
    )
    op.create_index("ix_model_call_reservation_tenant_id", "model_call_reservation", ["tenant_id"])
    _protect("model_call_reservation", "SELECT, INSERT, UPDATE")
    op.execute("REVOKE DELETE, TRUNCATE ON model_call_reservation FROM asic_app")

    op.create_table(
        "remediation_baseline",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("remediation_target_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("remediation_action_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("service_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("criteria_hash", sa.String(64), nullable=False),
        sa.Column("metric", sa.String(128), nullable=False),
        sa.Column("source_capability", sa.String(128), nullable=False),
        sa.Column("source_provider", sa.String(128), nullable=False),
        sa.Column("read_execution_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_value", sa.Numeric(18, 6), nullable=False),
        sa.Column("provenance_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        *_tenant_identity("remediation_baseline"),
        sa.PrimaryKeyConstraint("id", name="pk_remediation_baseline"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incident.tenant_id", "incident.id"],
            ondelete="CASCADE",
            name="fk_remediation_baseline_incident",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "remediation_target_id"],
            ["remediation_target.tenant_id", "remediation_target.id"],
            ondelete="RESTRICT",
            name="fk_remediation_baseline_target",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "remediation_action_id"],
            ["remediation_action.tenant_id", "remediation_action.id"],
            ondelete="CASCADE",
            name="fk_remediation_baseline_action",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_id"],
            ["service.tenant_id", "service.id"],
            ondelete="CASCADE",
            name="fk_remediation_baseline_service",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "environment_id"],
            ["environment.tenant_id", "environment.id"],
            ondelete="CASCADE",
            name="fk_remediation_baseline_environment",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "read_execution_id"],
            ["tool_execution.tenant_id", "tool_execution.id"],
            ondelete="RESTRICT",
            name="fk_remediation_baseline_read_execution",
        ),
        sa.UniqueConstraint(
            "tenant_id", "remediation_action_id", name="uq_remediation_baseline_action"
        ),
        sa.CheckConstraint(
            "profile_version > 0", name="ck_remediation_baseline_profile_version_positive"
        ),
        sa.CheckConstraint(
            "observed_at <= captured_at", name="ck_remediation_baseline_observed_before_capture"
        ),
    )
    op.create_index(
        "ix_remediation_baseline_target",
        "remediation_baseline",
        ["tenant_id", "remediation_target_id"],
    )
    op.create_index("ix_remediation_baseline_tenant_id", "remediation_baseline", ["tenant_id"])
    _protect("remediation_baseline", "SELECT, INSERT")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON remediation_baseline FROM asic_app")


def downgrade() -> None:
    op.drop_table("remediation_baseline")
    op.drop_table("model_call_reservation")
    op.drop_table("connector_scope_binding")
