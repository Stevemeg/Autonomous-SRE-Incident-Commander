"""Freeze remediation targets and add explicit knowledge lifecycle authority."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0013_audit_corrections"
down_revision: str | None = "0012_phase9_api_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Pinned historical declaration used by the migration-history coverage guard. Never derive
# this from the live model registry: this migration owns exactly this tenant-scoped table.
TENANT_TABLES: tuple[str, ...] = ("remediation_target",)


def upgrade() -> None:
    op.execute("ALTER TYPE incident_event_type ADD VALUE IF NOT EXISTS 'incident.annotated'")
    op.create_table(
        "remediation_target",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("workflow_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("investigation_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("hypothesis_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("service_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("resolved_permission_scope", pg.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_remediation_target"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_remediation_target_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "workflow_run_id", name="uq_remediation_target_run"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_remediation_target_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "workflow_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            ondelete="CASCADE",
            name="fk_remediation_target_run",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incident.tenant_id", "incident.id"],
            ondelete="CASCADE",
            name="fk_remediation_target_incident",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "investigation_run_id"],
            ["workflow_run.tenant_id", "workflow_run.id"],
            ondelete="RESTRICT",
            name="fk_remediation_target_investigation_run",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "hypothesis_id"],
            ["hypothesis.tenant_id", "hypothesis.id"],
            ondelete="RESTRICT",
            name="fk_remediation_target_hypothesis",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "service_id"],
            ["service.tenant_id", "service.id"],
            ondelete="RESTRICT",
            name="fk_remediation_target_service",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "environment_id"],
            ["environment.tenant_id", "environment.id"],
            ondelete="RESTRICT",
            name="fk_remediation_target_environment",
        ),
    )
    op.create_index("ix_remediation_target_tenant_id", "remediation_target", ["tenant_id"])
    op.create_index(
        "ix_remediation_target_incident", "remediation_target", ["tenant_id", "incident_id"]
    )
    op.execute("ALTER TABLE remediation_target ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE remediation_target FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON remediation_target USING (tenant_id = app.current_tenant_id()) WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute("GRANT SELECT, INSERT ON remediation_target TO asic_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON remediation_target FROM asic_app")

    op.add_column(
        "remediation_action",
        sa.Column("remediation_target_id", pg.UUID(as_uuid=True), nullable=True),
    )
    op.execute(
        """INSERT INTO remediation_target
        (tenant_id, workflow_run_id, incident_id, investigation_run_id, hypothesis_id,
         service_id, environment_id, resolved_permission_scope)
        SELECT a.tenant_id, a.workflow_run_id, a.incident_id, h.workflow_run_id,
               a.hypothesis_id, s.id, i.environment_id, a.permission_scope
          FROM remediation_action a
          JOIN hypothesis h ON h.tenant_id = a.tenant_id AND h.id = a.hypothesis_id
          JOIN incident i ON i.tenant_id = a.tenant_id AND i.id = a.incident_id
          JOIN service s ON s.tenant_id = a.tenant_id
                        AND s.name = a.permission_scope->>'service'
        ON CONFLICT (tenant_id, workflow_run_id) DO NOTHING"""
    )
    op.execute(
        """UPDATE remediation_action a SET remediation_target_id = t.id
             FROM remediation_target t
            WHERE t.tenant_id = a.tenant_id AND t.workflow_run_id = a.workflow_run_id"""
    )
    op.alter_column("remediation_action", "remediation_target_id", nullable=False)
    op.create_foreign_key(
        "fk_remediation_action_target",
        "remediation_action",
        "remediation_target",
        ["tenant_id", "remediation_target_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )

    op.execute(
        "INSERT INTO permission (id, key, description, resource, action) VALUES (gen_random_uuid(), 'knowledge.source.lifecycle.manage', 'Revoke or delete governed knowledge sources and versions.', 'knowledge_source', 'lifecycle') ON CONFLICT (key) DO NOTHING"
    )
    op.execute(
        "INSERT INTO role_permission (role_id, permission_id) SELECT r.id, p.id FROM role r CROSS JOIN permission p WHERE r.key = 'platform_admin' AND p.key = 'knowledge.source.lifecycle.manage' ON CONFLICT DO NOTHING"
    )


def downgrade() -> None:
    # PostgreSQL enum labels are intentionally retained on downgrade. Removing one safely
    # requires rewriting every dependent column; the older application simply never emits it.
    op.execute(
        "DELETE FROM role_permission WHERE permission_id IN (SELECT id FROM permission WHERE key = 'knowledge.source.lifecycle.manage')"
    )
    op.execute("DELETE FROM permission WHERE key = 'knowledge.source.lifecycle.manage'")
    op.drop_constraint("fk_remediation_action_target", "remediation_action", type_="foreignkey")
    op.drop_column("remediation_action", "remediation_target_id")
    op.drop_table("remediation_target")
