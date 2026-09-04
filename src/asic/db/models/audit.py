"""Immutable audit records.

Every action the Phase 3 brief section E names produces a row here: authentication and
authorization decisions, tool authorization, tool execution, remediation planning,
approval requests and decisions, remediation execution, verification, policy decisions,
and configuration or security changes.

Three properties make this table an audit log rather than an application log:

* **Append-only.** The migration revokes ``UPDATE`` and ``DELETE`` from the application
  role. A row cannot be edited to say something else happened.
* **Written at the chokepoint.** The tool broker is the sole egress, and it emits
  unconditionally, so "an action happened with no audit record" is not reachable.
* **Redacted at construction.** Secrets and personal data are removed *before* the row is
  built, never filtered on read.

Retention is longer than for operational data (seven years by default), and survives
tenant deletion with tenant content redacted - the erasure obligation and the audit
obligation are both real, and this is where they are reconciled.
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
    enum_column,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import ActorType, AuditEventType, RiskTier


class AuditRecord(Base, TenantScoped, CreatedAtMixin):
    """One immutable audit entry.

    Foreign keys here are deliberately *soft* - plain UUID columns rather than enforced
    references. An audit record must outlive the thing it describes: when an incident is
    purged under the retention policy, the audit trail of the decisions taken during it
    must remain. A hard foreign key with ``ON DELETE CASCADE`` would delete exactly the
    evidence a later investigation needs, and ``RESTRICT`` would block the purge entirely.
    """

    __tablename__ = "audit_record"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    event_type: Mapped[AuditEventType] = mapped_column(
        enum_column(AuditEventType, "audit_event_type"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    #: User id, node id, or service name. Free-form because actors are heterogeneous.
    actor_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    #: Source address of a human action, for authentication forensics.
    actor_ip: Mapped[str | None] = mapped_column(pg.INET, nullable=True)

    # -- soft references, intentionally unenforced (see class docstring) -------------
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    remediation_action_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    approval_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    #: What was acted on: ``tool_definition``, ``incident``, ``tenant_tool_grant``.
    target_type: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)

    #: For authorization events: the verdict and the rule that produced it.
    outcome: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    policy_rule_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    risk_tier: Mapped[RiskTier | None] = mapped_column(
        enum_column(RiskTier, "risk_tier"), nullable=True
    )
    #: Redacted before construction. Never contains secret material (SEC-I6).
    payload_redacted: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    #: When this record becomes eligible for deletion. Longer than operational retention.
    retain_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("audit_record"),
        sa.CheckConstraint(
            "outcome IN ('allowed', 'denied', 'succeeded', 'failed', 'requested',"
            " 'expired', 'invalidated', 'recorded')",
            name="known_outcome",
        ),
        sa.Index("ix_audit_record_tenant_time", "tenant_id", "occurred_at"),
        sa.Index("ix_audit_record_event_type", "tenant_id", "event_type", "occurred_at"),
        sa.Index("ix_audit_record_actor", "tenant_id", "actor_id", "occurred_at"),
        sa.Index("ix_audit_record_incident", "tenant_id", "incident_id"),
        sa.Index("ix_audit_record_action", "tenant_id", "remediation_action_id"),
        sa.Index("ix_audit_record_correlation", "tenant_id", "correlation_id"),
    )
