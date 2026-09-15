"""Tool registry and execution records.

``tool_definition`` is a **global** table: the catalogue is platform-owned and reviewed
like code. A tenant that could define its own tool risk tiers could widen its own
authority, which is exactly what the capability model exists to prevent. Tenants receive
capability through ``tenant_tool_grant`` instead.

Two things this schema deliberately does not have:

* **No free-form command column.** There is no ``command``, ``script``, ``manifest`` or
  ``raw_query`` field on any table here. Tool arguments are validated against
  ``input_schema``, and that schema is checked against
  :data:`asic.domain.safety.FORBIDDEN_EXECUTION_FIELDS` before a definition is accepted.
* **No credential column.** ``credential_ref`` names a secret in the secret manager; the
  secret itself never enters the database.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import (
    Base,
    CreatedAtMixin,
    TenantScoped,
    TimestampMixin,
    enum_column,
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import (
    ActorType,
    NodeId,
    RiskTier,
    ToolExecutionOutcome,
    ToolProviderKind,
)
from asic.domain.idempotency import KEY_LENGTH


class ToolDefinition(Base, TimestampMixin):
    """A registered capability. Global, versioned, reviewed in migrations.

    Every field master specification section 7 requires a tool to declare is a column
    here: name and version, capability, input and output schema, permission scope, risk,
    timeout, retry and idempotency behaviour, and audit requirements.
    """

    __tablename__ = "tool_definition"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Stable identifier: ``k8s.deployment.rollback``.
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    #: Semver. Proposals bind to major.minor; a major bump requires re-proposal.
    version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    major_version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: ``<verb>.<resource-class>``, e.g. ``mutate.k8s_deployment``.
    capability: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)

    provider_kind: Mapped[ToolProviderKind] = mapped_column(
        enum_column(ToolProviderKind, "tool_provider_kind"),
        nullable=False,
        default=ToolProviderKind.NATIVE,
    )
    risk_tier: Mapped[RiskTier] = mapped_column(enum_column(RiskTier, "risk_tier"), nullable=False)

    #: Typed argument schema. Validated on insert against the forbidden-field list.
    input_schema: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    output_schema: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Template describing how scope is *resolved* (from service ownership, from incident
    #: context). Never supplied by a caller.
    permission_scope_template: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    timeout_seconds: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: Delay before verification may judge the effect, so success cannot be declared early.
    settling_seconds: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    is_idempotent: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    #: Which argument names compose the idempotency key for this tool's effect.
    idempotency_key_fields: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )
    retry_policy: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    preconditions: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(128)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )
    #: Name of the tool that undoes this one. A write tool without a rollback cannot be R1.
    rollback_tool_name: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)

    audit_requirements: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Name of the credential in the secret manager. Never the credential itself.
    credential_ref: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    is_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )
    deprecated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        sa.UniqueConstraint("name", "version", name="uq_tool_definition_name_version"),
        # SI-5: destructive actions are not expressible. A capability the system cannot
        # name is safer than one it is instructed not to use.
        sa.CheckConstraint("risk_tier <> 'r3'", name="no_destructive_tool_registered"),
        # A write tool must declare how to undo itself.
        sa.CheckConstraint(
            "risk_tier = 'ro' OR rollback_tool_name IS NOT NULL",
            name="write_tool_declares_rollback",
        ),
        # A read-only tool must not carry a settling delay or rollback: it changes nothing.
        sa.CheckConstraint(
            "risk_tier <> 'ro' OR (rollback_tool_name IS NULL AND settling_seconds = 0)",
            name="read_only_tool_has_no_effect_metadata",
        ),
        # Retry is only safe where the descriptor declares idempotence.
        sa.CheckConstraint(
            "risk_tier = 'ro' OR is_idempotent OR retry_policy = '{}'::jsonb",
            name="non_idempotent_write_declares_no_retry",
        ),
        sa.CheckConstraint("timeout_seconds > 0 AND timeout_seconds <= 3600", name="timeout_range"),
        sa.CheckConstraint("settling_seconds >= 0", name="settling_non_negative"),
        sa.CheckConstraint("major_version >= 0", name="major_version_non_negative"),
        sa.Index("ix_tool_definition_capability", "capability"),
        sa.Index("ix_tool_definition_enabled", "name", postgresql_where=sa.text("is_enabled")),
    )


class TenantToolGrant(Base, TenantScoped, TimestampMixin):
    """Which registered tools a tenant may use, and within what bounds.

    This is the table the capability *menu* is resolved from. A model is only ever offered
    capabilities that already exist here for its tenant and environment; it does not
    request capability and receive a verdict.
    """

    __tablename__ = "tenant_tool_grant"

    id: Mapped[uuid.UUID] = uuid_pk()
    tool_definition_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: ``NULL`` grants across every environment in the tenant.
    environment_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    is_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )
    #: Tenant-level narrowing of the tool's scope template. Narrowing only: the broker
    #: takes the intersection of tool scope and grant scope.
    scope_overrides: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Whether this tenant requires approval even where the platform default would not.
    require_approval_override: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)
    #: Blast-radius ceiling for this tenant, e.g. max pods affected per action.
    blast_radius_limits: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        *tenant_identity_constraints("tenant_tool_grant"),
        sa.ForeignKeyConstraint(
            ["tool_definition_id"],
            ["tool_definition.id"],
            ondelete="CASCADE",
            name="fk_tenant_tool_grant_tool_definition",
        ),
        tenant_fk(
            "environment_id",
            "environment",
            ondelete="CASCADE",
            name="fk_tenant_tool_grant_environment",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "tool_definition_id",
            "environment_id",
            name="uq_tenant_tool_grant",
            postgresql_nulls_not_distinct=True,
        ),
        sa.Index("ix_tenant_tool_grant_lookup", "tenant_id", "environment_id", "is_enabled"),
    )


class ToolExecution(Base, TenantScoped, CreatedAtMixin):
    """One invocation through the tool broker. Append-only.

    The broker is the sole egress point, so this table is the complete record of every
    interaction with an external system. "Unaudited action" is not a reachable state
    because there is no other path out.

    ``arguments_redacted`` is named for what it is: arguments with secret material and
    personal data removed *before* the row is constructed, not filtered on read.
    """

    __tablename__ = "tool_execution"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    investigation_step_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    remediation_action_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    tool_definition_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: Denormalised so an execution record stays readable if a definition is later
    #: deprecated. History must remain interpretable without joining to current config.
    tool_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    capability: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    risk_tier: Mapped[RiskTier] = mapped_column(enum_column(RiskTier, "risk_tier"), nullable=False)

    #: The scope actually resolved for this call, after intersecting tool, grant and
    #: incident context.
    resolved_scope: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Business-identifier key. Unique per tenant, so a duplicate effect collides.
    idempotency_key: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    #: The node that requested the call, for attribution. Not a credential holder.
    requested_by_node: Mapped[NodeId | None] = mapped_column(
        enum_column(NodeId, "node_id"), nullable=True
    )

    attempt: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("1"))
    outcome: Mapped[ToolExecutionOutcome | None] = mapped_column(
        enum_column(ToolExecutionOutcome, "tool_execution_outcome"), nullable=True
    )
    #: What actually changed, as observed. For read tools, a result summary.
    observed_effect: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    failure_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("tool_execution"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_tool_execution_incident"),
        tenant_fk(
            "investigation_step_id",
            "investigation_step",
            ondelete="SET NULL",
            name="fk_tool_execution_investigation_step",
        ),
        sa.ForeignKeyConstraint(
            ["tool_definition_id"],
            ["tool_definition.id"],
            ondelete="RESTRICT",
            name="fk_tool_execution_tool_definition",
        ),
        # One effect per idempotency key per tenant. This is the constraint that makes a
        # double-applied remediation impossible rather than unlikely.
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_tool_execution_idempotency"),
        # Enables downstream evidence rows to bind a read execution to the exact
        # remediation action structurally, rather than trusting a copied action id.
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            "remediation_action_id",
            name="uq_tool_execution_tenant_id_id_action",
        ),
        sa.CheckConstraint("attempt >= 1", name="attempt_starts_at_one"),
        sa.CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="duration_non_negative"),
        sa.CheckConstraint(
            "(outcome IS NULL) OR (outcome <> 'unknown') OR (failure_reason IS NOT NULL)",
            name="unknown_outcome_has_reason",
        ),
        # A non-read-only execution must belong to a remediation action, which is what
        # forces it through the policy gate.
        sa.CheckConstraint(
            "risk_tier = 'ro' OR remediation_action_id IS NOT NULL",
            name="write_execution_requires_action",
        ),
        sa.Index("ix_tool_execution_incident", "tenant_id", "incident_id"),
        sa.Index("ix_tool_execution_action", "tenant_id", "remediation_action_id"),
        sa.Index("ix_tool_execution_correlation", "tenant_id", "correlation_id"),
        sa.Index("ix_tool_execution_started", "tenant_id", "started_at"),
    )
