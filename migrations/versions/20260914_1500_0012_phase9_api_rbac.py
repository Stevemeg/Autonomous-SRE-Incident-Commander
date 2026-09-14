"""Phase 9 API permission and system-role catalogue.

Revision ID: 0012_phase9_api_rbac
Revises: 0011_remediation_safety
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0012_phase9_api_rbac"
down_revision: str | None = "0011_remediation_safety"
branch_labels: str | None = None
depends_on: str | None = None

TENANT_TABLES = ("api_idempotency_record",)

PERMISSIONS = (
    ("incident.read", "Read tenant incidents and their governed artefacts.", "incident", "read"),
    (
        "incident.control",
        "Apply approved human incident lifecycle controls.",
        "incident",
        "control",
    ),
    ("ingestion.write", "Access the authenticated ingestion surface.", "ingestion", "write"),
    (
        "evaluation.read",
        "Access the separately authorized evaluation surface.",
        "evaluation",
        "read",
    ),
    (
        "administration.read",
        "Read governed tenant and platform configuration.",
        "administration",
        "read",
    ),
    ("audit.read", "Read the tenant immutable audit stream.", "audit_record", "read"),
)

ROLES = (
    ("viewer", "Viewer", "Read tenant incident-command data."),
    ("responder", "Responder", "Read and control incidents in assigned environments."),
    ("sre_approver", "SRE approver", "Approve bounded remediation through risk tier R2."),
    ("senior_approver", "Senior approver", "Senior bounded-remediation approver."),
    ("platform_admin", "Platform administrator", "Read governed platform configuration."),
    ("security_auditor", "Security auditor", "Read tenant incident and audit records."),
    (
        "system_operator",
        "System operator",
        "Operate authenticated ingestion and evaluation surfaces.",
    ),
)

GRANTS = {
    "viewer": ("incident.read",),
    "responder": ("incident.read", "incident.control"),
    "sre_approver": ("incident.read", "incident.control", "remediation.approve"),
    "senior_approver": ("incident.read", "incident.control", "remediation.approve"),
    "platform_admin": (
        "incident.read",
        "incident.control",
        "remediation.approve",
        "administration.read",
        "audit.read",
    ),
    "security_auditor": ("incident.read", "audit.read"),
    "system_operator": ("incident.read", "ingestion.write", "evaluation.read"),
}


def upgrade() -> None:
    op.create_table(
        "api_idempotency_record",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("principal_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("response_body", pg.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "length(request_digest) = 64", name="ck_api_idempotency_record_request_digest_is_sha256"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name="fk_api_idempotency_record_tenant_id_tenant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_idempotency_record"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_api_idempotency_record_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "principal_id", "idempotency_key", name="uq_api_idempotency_principal_key"
        ),
    )
    op.create_index("ix_api_idempotency_record_tenant_id", "api_idempotency_record", ["tenant_id"])
    op.create_index(
        "ix_api_idempotency_created", "api_idempotency_record", ["tenant_id", "created_at"]
    )
    op.execute("ALTER TABLE api_idempotency_record ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE api_idempotency_record FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON api_idempotency_record USING (tenant_id = app.current_tenant_id()) WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute("GRANT SELECT, INSERT ON api_idempotency_record TO asic_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON api_idempotency_record FROM asic_app")
    for key, description, resource, action in PERMISSIONS:
        op.execute(
            "INSERT INTO permission (id, key, description, resource, action) VALUES "
            f"(gen_random_uuid(), '{key}', '{description}', '{resource}', '{action}') "
            "ON CONFLICT (key) DO NOTHING"
        )
    for key, display_name, description in ROLES:
        op.execute(
            "INSERT INTO role (id, key, display_name, description, is_system) VALUES "
            f"(gen_random_uuid(), '{key}', '{display_name}', '{description}', true) "
            "ON CONFLICT (key) DO NOTHING"
        )
    for role, permissions in GRANTS.items():
        for permission in permissions:
            op.execute(
                "INSERT INTO role_permission (role_id, permission_id) "
                f"SELECT r.id, p.id FROM role r CROSS JOIN permission p "
                f"WHERE r.key = '{role}' AND p.key = '{permission}' "
                "ON CONFLICT DO NOTHING"
            )


def downgrade() -> None:
    role_keys = ", ".join(f"'{key}'" for key, _, _ in ROLES)
    permission_keys = ", ".join(f"'{key}'" for key, _, _, _ in PERMISSIONS)
    op.execute(
        f"DELETE FROM role_permission WHERE role_id IN (SELECT id FROM role WHERE key IN ({role_keys}))"
    )
    op.execute(f"DELETE FROM role WHERE key IN ({role_keys})")
    op.execute(f"DELETE FROM permission WHERE key IN ({permission_keys})")
    op.drop_table("api_idempotency_record")
