"""Immutable delivery decisions and a durable, tenant-bound investigation handoff."""

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
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import IncidentSeverity


class SignalReceipt(Base, TenantScoped, CreatedAtMixin):
    __tablename__ = "signal_receipt"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    delivery_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    content_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    raw_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True))
    service_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True))
    environment_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True))
    kind: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    outcome: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    envelope: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    decision: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    observed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        *tenant_identity_constraints("signal_receipt"),
        tenant_fk("alert_id", "alert", ondelete="RESTRICT", name="fk_signal_receipt_alert"),
        tenant_fk(
            "incident_id", "incident", ondelete="RESTRICT", name="fk_signal_receipt_incident"
        ),
        tenant_fk("service_id", "service", ondelete="RESTRICT", name="fk_signal_receipt_service"),
        tenant_fk(
            "environment_id",
            "environment",
            ondelete="RESTRICT",
            name="fk_signal_receipt_environment",
        ),
        sa.UniqueConstraint("tenant_id", "delivery_key", name="uq_signal_receipt_delivery"),
        sa.CheckConstraint("kind IN ('alert', 'change', 'invalid')", name="known_kind"),
        sa.CheckConstraint(
            "outcome IN ('accepted', 'rejected', 'retryable', 'stale', 'unchanged')",
            name="known_outcome",
        ),
        sa.Index(
            "ix_signal_receipt_changes", "tenant_id", "environment_id", "service_id", "observed_at"
        ),
    )


class InvestigationDispatch(Base, TenantScoped, CreatedAtMixin):
    __tablename__ = "investigation_dispatch"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    event_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True))
    attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("0"))
    last_error: Mapped[str | None] = mapped_column(sa.String(64))
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, server_default=sa.text("'pending'")
    )

    __table_args__ = (
        *tenant_identity_constraints("investigation_dispatch"),
        tenant_fk(
            "incident_id",
            "incident",
            ondelete="RESTRICT",
            name="fk_investigation_dispatch_incident",
        ),
        tenant_fk(
            "event_id",
            "incident_event",
            ondelete="RESTRICT",
            name="fk_investigation_dispatch_event",
        ),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="RESTRICT",
            name="fk_investigation_dispatch_run",
        ),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_investigation_dispatch_incident"),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_investigation_dispatch_event"),
        sa.CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        sa.CheckConstraint("status IN ('pending', 'terminal')", name="known_status"),
    )


class IncidentReopenCandidate(Base, TenantScoped, CreatedAtMixin):
    """Append-only request for human review of a signal after terminal disposition."""

    __tablename__ = "incident_reopen_candidate"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    receipt_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    requested_severity: Mapped[IncidentSeverity] = mapped_column(
        enum_column(IncidentSeverity, "incident_severity"), nullable=False
    )
    reason: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("incident_reopen_candidate"),
        tenant_fk(
            "incident_id", "incident", ondelete="RESTRICT", name="fk_reopen_candidate_incident"
        ),
        tenant_fk("alert_id", "alert", ondelete="RESTRICT", name="fk_reopen_candidate_alert"),
        tenant_fk(
            "receipt_id", "signal_receipt", ondelete="RESTRICT", name="fk_reopen_candidate_receipt"
        ),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_reopen_candidate_receipt"),
    )
