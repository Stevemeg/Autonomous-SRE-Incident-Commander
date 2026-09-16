"""External integrations: effect classes, tenant connectors and the external-record catalogue.

Self-contained (ADR-0018): every row and schema literal below is frozen here rather than
derived from the live catalogue module, so this revision creates the same database on the
day it was written and on any later day.

What this revision establishes, and why each piece is in the database rather than code:

* ``tool_effect_class`` on ``tool_definition`` and ``tool_execution``. An execution's class
  is *derived by trigger from its definition* and a caller-supplied class that disagrees
  is refused, so an external record cannot be recorded as a read, nor a mutation as an
  external record.
* An external record (message, page, ticket, annotation) is the only non-read effect that
  may execute without a remediation action, and only when requested by the deterministic
  S2 notification service.
* ``integration_connector`` holds each tenant's endpoint and credential *reference* per
  environment. The application role may read it and nothing else.
* Execution rows gain ``connector_id``, a normalised ``failure_class`` and an
  ``external_reference`` for audit reconstruction.

Revision ID: 0016_external_integrations
Revises: 0015_verified_memory_ledger
"""

from __future__ import annotations

import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0016_external_integrations"
down_revision: str | None = "0015_verified_memory_ledger"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES: tuple[str, ...] = ("integration_connector",)

EFFECT_CLASSES: tuple[str, ...] = ("read", "infrastructure_mutation", "external_record")
INTEGRATION_KINDS: tuple[str, ...] = (
    "prometheus",
    "loki",
    "kubernetes",
    "slack",
    "teams",
    "pagerduty",
    "jira",
    "grafana",
)
FAILURE_CLASSES: tuple[str, ...] = (
    "unauthorized",
    "forbidden",
    "not_found",
    "conflict",
    "rate_limited",
    "timeout",
    "transient_unavailable",
    "malformed_response",
    "invalid_request",
    "scope_denied",
    "configuration_error",
    "unknown_outcome",
)

_REFERENCE_PATTERN = "^asic/[a-z0-9][a-z0-9/_.-]{0,200}$"

#: Frozen at this revision. Identical for every external-record tool.
_EVENT_INPUT_SCHEMA: dict[str, object] = {
    "environment": {
        "description": "Environment name resolved from the incident.",
        "kind": "bounded_string",
        "max_length": 32,
        "pattern": "[a-z][a-z0-9_-]{0,31}",
        "required": True,
        "scope_resolved": True,
    },
    "event_id": {
        "description": "Deterministic digest of the incident transition being announced.",
        "kind": "bounded_string",
        "max_length": 64,
        "pattern": "[0-9a-f]{64}",
        "required": True,
        "scope_resolved": False,
    },
    "event_type": {
        "allowed_values": [
            "incident_opened",
            "incident_escalated",
            "incident_resolved",
            "approval_requested",
            "remediation_executed",
            "verification_completed",
        ],
        "description": "Which lifecycle transition this record announces.",
        "kind": "enum",
        "max_length": 253,
        "required": True,
        "scope_resolved": False,
    },
    "incident_reference": {
        "description": "The incident's human reference, e.g. INC-0042.",
        "kind": "bounded_string",
        "max_length": 40,
        "pattern": "[A-Za-z][A-Za-z0-9-]{0,39}",
        "required": True,
        "scope_resolved": False,
    },
    "service": {
        "description": "Service resolved from the incident's affected services.",
        "kind": "bounded_string",
        "max_length": 253,
        "pattern": "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
        "required": True,
        "scope_resolved": True,
    },
    "severity": {
        "allowed_values": ["sev1", "sev2", "sev3", "sev4"],
        "description": "Incident severity.",
        "kind": "enum",
        "max_length": 253,
        "required": True,
        "scope_resolved": False,
    },
    "status": {
        "description": "Incident lifecycle status at the time of the event.",
        "kind": "bounded_string",
        "max_length": 32,
        "pattern": "[a-z][a-z_]{0,31}",
        "required": True,
        "scope_resolved": False,
    },
    "summary": {
        "description": (
            "Bounded summary rendered by S2 from records. Treated as untrusted display text "
            "by every adapter: escaped, never interpreted."
        ),
        "kind": "bounded_string",
        "max_length": 300,
        "required": True,
        "scope_resolved": False,
    },
    "tenant_id": {
        "description": "Owning tenant. Resolved from the bound session, never supplied.",
        "kind": "uuid",
        "required": True,
        "scope_resolved": True,
    },
}

_RECORD_OUTPUT_SCHEMA: dict[str, object] = {
    "created": {"kind": "boolean", "required": True},
    "external_reference": {"kind": "bounded_string", "required": True},
    "schema_version": {"kind": "integer", "required": True},
    "source": {"kind": "bounded_string", "required": True},
}

#: (name, capability, description, timeout_seconds) - frozen at this revision.
_RECORD_TOOLS: tuple[tuple[str, str, str, int], ...] = (
    (
        "grafana.annotation.create",
        "write.grafana_annotation",
        "Annotate the tenant's configured service dashboard with an incident lifecycle event.",
        20,
    ),
    (
        "jira.issue.comment",
        "write.jira_comment",
        "Append a structured status comment to the incident's own Jira issue.",
        30,
    ),
    (
        "jira.issue.create",
        "write.jira_issue",
        "Create, or find the already-created, Jira issue for one incident (label-deduplicated).",
        30,
    ),
    (
        "pagerduty.event",
        "write.pagerduty_event",
        "Send a PagerDuty Events API v2 trigger/acknowledge/resolve derived from the internal "
        "incident status. PagerDuty state never drives internal incident state.",
        20,
    ),
    (
        "slack.post",
        "notify.slack_channel",
        "Post a templated incident update to the tenant's configured Slack channel.",
        20,
    ),
    (
        "teams.post",
        "notify.teams_channel",
        "Post a templated incident card to the tenant's configured Microsoft Teams workflow.",
        20,
    ),
)


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def upgrade() -> None:
    bind = op.get_bind()
    for name, values in (
        ("tool_effect_class", EFFECT_CLASSES),
        ("integration_kind", INTEGRATION_KINDS),
        ("integration_failure_class", FAILURE_CLASSES),
    ):
        pg.ENUM(*values, name=name).create(bind, checkfirst=False)

    effect = pg.ENUM(*EFFECT_CLASSES, name="tool_effect_class", create_type=False)

    # --------------------------------------------------------------- tool_definition
    op.add_column("tool_definition", sa.Column("effect_class", effect, nullable=True))
    op.execute(
        "UPDATE tool_definition SET effect_class = CASE WHEN risk_tier = 'ro' "
        "THEN 'read'::tool_effect_class ELSE 'infrastructure_mutation'::tool_effect_class END"
    )
    op.alter_column("tool_definition", "effect_class", nullable=False)
    op.drop_constraint("write_tool_declares_rollback", "tool_definition", type_="check")
    op.create_check_constraint(
        "write_tool_declares_rollback",
        "tool_definition",
        "risk_tier = 'ro' OR effect_class = 'external_record' OR rollback_tool_name IS NOT NULL",
    )
    op.create_check_constraint(
        "read_effect_matches_tier",
        "tool_definition",
        "(risk_tier = 'ro') = (effect_class = 'read')",
    )
    op.create_check_constraint(
        "external_record_is_low_risk_without_rollback",
        "tool_definition",
        "effect_class <> 'external_record' OR "
        "(risk_tier = 'r1' AND rollback_tool_name IS NULL AND settling_seconds = 0)",
    )

    # ---------------------------------------------------------------- tool_execution
    op.add_column("tool_execution", sa.Column("effect_class", effect, nullable=True))
    op.execute(
        "UPDATE tool_execution SET effect_class = CASE WHEN risk_tier = 'ro' "
        "THEN 'read'::tool_effect_class ELSE 'infrastructure_mutation'::tool_effect_class END"
    )
    op.alter_column("tool_execution", "effect_class", nullable=False)
    op.add_column("tool_execution", sa.Column("connector_id", sa.String(255), nullable=True))
    op.add_column(
        "tool_execution",
        sa.Column(
            "failure_class",
            pg.ENUM(*FAILURE_CLASSES, name="integration_failure_class", create_type=False),
            nullable=True,
        ),
    )
    op.add_column("tool_execution", sa.Column("external_reference", sa.String(255), nullable=True))
    op.drop_constraint("write_execution_requires_action", "tool_execution", type_="check")
    op.create_check_constraint(
        "write_execution_requires_action",
        "tool_execution",
        "risk_tier = 'ro' OR effect_class = 'external_record' OR remediation_action_id IS NOT NULL",
    )
    op.create_check_constraint(
        "external_record_from_notification_service",
        "tool_execution",
        "effect_class <> 'external_record' OR (remediation_action_id IS NULL "
        "AND requested_by_node = 's2_notification_service')",
    )
    op.create_check_constraint(
        "succeeded_has_no_failure_class",
        "tool_execution",
        "(outcome IS DISTINCT FROM 'succeeded') OR failure_class IS NULL",
    )
    # Invoker rights with a fully qualified table: a session search_path (or a temporary
    # table named tool_definition) cannot change which definition the class comes from.
    op.execute(
        r"""
        CREATE FUNCTION app.derive_tool_execution_effect_class()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            defined public.tool_effect_class;
        BEGIN
            SELECT d.effect_class INTO defined
            FROM public.tool_definition AS d
            WHERE d.id = NEW.tool_definition_id;
            IF defined IS NULL THEN
                RETURN NEW;  -- the foreign key refuses the row
            END IF;
            IF NEW.effect_class IS NULL THEN
                NEW.effect_class := defined;
            ELSIF NEW.effect_class <> defined THEN
                RAISE EXCEPTION 'tool execution effect class must match its definition'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER derive_tool_execution_effect_class "
        "BEFORE INSERT ON tool_execution FOR EACH ROW "
        "EXECUTE FUNCTION app.derive_tool_execution_effect_class()"
    )

    # --------------------------------------------------------- integration_connector
    op.create_table(
        "integration_connector",
        sa.Column(
            "id", pg.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", sa.String(255), nullable=False),
        sa.Column(
            "kind",
            pg.ENUM(*INTEGRATION_KINDS, name="integration_kind", create_type=False),
            nullable=False,
        ),
        sa.Column("environment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_url", sa.String(512), nullable=True),
        sa.Column("credential_ref", sa.String(255), nullable=True),
        sa.Column("write_credential_ref", sa.String(255), nullable=True),
        sa.Column("settings", pg.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_integration_connector"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_integration_connector_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_integration_connector_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "environment_id"],
            ["environment.tenant_id", "environment.id"],
            ondelete="CASCADE",
            name="fk_integration_connector_environment",
        ),
        sa.UniqueConstraint("tenant_id", "connector_id", name="uq_integration_connector_id"),
        sa.CheckConstraint(
            "(is_enabled AND revoked_at IS NULL) OR (NOT is_enabled)",
            name="enabled_connector_not_revoked",
        ),
        sa.CheckConstraint(
            f"credential_ref IS NULL OR credential_ref ~ '{_REFERENCE_PATTERN}'",
            name="credential_ref_is_reference",
        ),
        sa.CheckConstraint(
            f"write_credential_ref IS NULL OR write_credential_ref ~ '{_REFERENCE_PATTERN}'",
            name="write_credential_ref_is_reference",
        ),
        sa.CheckConstraint(
            "write_credential_ref IS NULL OR write_credential_ref IS DISTINCT FROM credential_ref",
            name="write_credential_separate_from_read",
        ),
        sa.CheckConstraint(
            "endpoint_url IS NULL OR endpoint_url ~ '^https?://[^\\s@]+$'",
            name="endpoint_url_has_no_userinfo",
        ),
        sa.CheckConstraint(
            "connector_id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'",
            name="connector_id_format",
        ),
    )
    op.create_index("ix_integration_connector_tenant_id", "integration_connector", ["tenant_id"])
    op.create_index(
        "uq_integration_connector_active_kind",
        "integration_connector",
        ["tenant_id", "environment_id", "kind"],
        unique=True,
        postgresql_where=sa.text("is_enabled"),
    )
    op.execute("ALTER TABLE integration_connector ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE integration_connector FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON integration_connector "
        "USING (tenant_id = app.current_tenant_id()) "
        "WITH CHECK (tenant_id = app.current_tenant_id())"
    )
    op.execute("GRANT SELECT ON integration_connector TO asic_app")

    # -------------------------------------------------- external-record tool catalogue
    input_schema = json.dumps(_EVENT_INPUT_SCHEMA, sort_keys=True)
    output_schema = json.dumps(_RECORD_OUTPUT_SCHEMA, sort_keys=True)
    scope_template = json.dumps(
        {
            "environment": "from_incident_context",
            "service": "from_incident_context",
            "tenant_id": "from_incident_context",
        },
        sort_keys=True,
    )
    audit = json.dumps({"required_events": ["tool.executed"]}, sort_keys=True)
    for name, capability, description, timeout in _RECORD_TOOLS:
        op.execute(
            f"""
            INSERT INTO tool_definition (
                id, name, version, major_version, capability, description,
                provider_kind, risk_tier, effect_class, input_schema, output_schema,
                permission_scope_template, timeout_seconds, settling_seconds,
                is_idempotent, idempotency_key_fields, retry_policy, preconditions,
                rollback_tool_name, audit_requirements, credential_ref, is_enabled
            ) VALUES (
                gen_random_uuid(), {_q(name)}, '1.0.0', 1, {_q(capability)},
                {_q(description)}, 'native'::tool_provider_kind, 'r1'::risk_tier,
                'external_record'::tool_effect_class, {_q(input_schema)}::jsonb,
                {_q(output_schema)}::jsonb, {_q(scope_template)}::jsonb, {timeout}, 0,
                true, ARRAY['tenant_id', 'environment', 'service', 'event_id']::varchar[],
                '{{}}'::jsonb, '{{}}'::varchar[], NULL, {_q(audit)}::jsonb, NULL, true
            )
            """
        )


def downgrade() -> None:
    """Reverse 0016.

    Refused, by design, on a database that has sent any external record: the seeded
    definitions are referenced ``ON DELETE RESTRICT`` by their execution history, which
    must stay interpretable (the same rule as migration 0005's downgrade).
    """
    names = ", ".join(_q(name) for name, _capability, _description, _timeout in _RECORD_TOOLS)
    op.execute(f"DELETE FROM tool_definition WHERE name IN ({names}) AND version = '1.0.0'")

    op.drop_index("uq_integration_connector_active_kind", table_name="integration_connector")
    op.drop_index("ix_integration_connector_tenant_id", table_name="integration_connector")
    op.drop_table("integration_connector")

    op.execute("DROP TRIGGER IF EXISTS derive_tool_execution_effect_class ON tool_execution")
    op.execute("DROP FUNCTION IF EXISTS app.derive_tool_execution_effect_class()")
    op.drop_constraint("succeeded_has_no_failure_class", "tool_execution", type_="check")
    op.drop_constraint("external_record_from_notification_service", "tool_execution", type_="check")
    op.drop_constraint("write_execution_requires_action", "tool_execution", type_="check")
    op.create_check_constraint(
        "write_execution_requires_action",
        "tool_execution",
        "risk_tier = 'ro' OR remediation_action_id IS NOT NULL",
    )
    op.drop_column("tool_execution", "external_reference")
    op.drop_column("tool_execution", "failure_class")
    op.drop_column("tool_execution", "connector_id")
    op.drop_column("tool_execution", "effect_class")

    op.drop_constraint(
        "external_record_is_low_risk_without_rollback", "tool_definition", type_="check"
    )
    op.drop_constraint("read_effect_matches_tier", "tool_definition", type_="check")
    op.drop_constraint("write_tool_declares_rollback", "tool_definition", type_="check")
    op.create_check_constraint(
        "write_tool_declares_rollback",
        "tool_definition",
        "risk_tier = 'ro' OR rollback_tool_name IS NOT NULL",
    )
    op.drop_column("tool_definition", "effect_class")

    bind = op.get_bind()
    for name in ("integration_failure_class", "integration_kind", "tool_effect_class"):
        pg.ENUM(name=name).drop(bind, checkfirst=False)
