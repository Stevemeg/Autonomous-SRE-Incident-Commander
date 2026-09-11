"""Incident core: alerts, incidents, the append-only event log, and derived projections.

The design rule that governs this module (DM-2): **the event log is the system of record.**
``incident.status`` is a materialised projection of it, kept on the row because deriving it
on every read would be unaffordable, and reconciled by
:func:`asic.db.projections.recompute_incident_status`. The test suite asserts the two never
disagree.

``timeline_event`` is likewise derived. Both are written only by the projection code, never
by a node, and never by a model.
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
    AlertSeverity,
    AlertStatus,
    EventCategory,
    IncidentEventType,
    IncidentSeverity,
    IncidentStatus,
    ProvenanceLabel,
    TerminationReason,
    TimelineCategory,
    WorkflowRunStatus,
)
from asic.domain.idempotency import KEY_LENGTH


class Alert(Base, TenantScoped, TimestampMixin):
    """A normalised alert occurrence.

    Deduplication is a database guarantee, not an application habit: the unique key on
    ``(tenant_id, idempotency_key)`` makes a redelivered alert collide. Alertmanager and
    PagerDuty both re-deliver until acknowledged, so this is the common path, not an edge
    case.

    ``annotations`` and ``labels`` come from outside our boundary and are therefore
    untrusted. They are recorded verbatim for evidence, and carry ``RETRIEVED`` provenance
    wherever they reach a reasoning path.
    """

    __tablename__ = "alert"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Which upstream system delivered it: ``alertmanager``, ``pagerduty``.
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: The upstream's own grouping identity for this alert.
    source_fingerprint: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    #: Derived from (tenant, source, fingerprint, started_at). See
    #: :func:`asic.domain.idempotency.alert_key`.
    idempotency_key: Mapped[str] = mapped_column(sa.String(KEY_LENGTH), nullable=False)

    service_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    severity: Mapped[AlertSeverity] = mapped_column(
        enum_column(AlertSeverity, "alert_severity"), nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"), nullable=False, default=AlertStatus.RECEIVED
    )
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Untrusted: upstream label set.
    labels: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Untrusted: free text written by whoever authored the alert rule, and a known
    #: prompt-injection vector. Never placed in an instruction position.
    annotations: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    #: Populated only when ``status = dead_lettered``. Never dropped silently (FR-ING-05).
    rejection_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    # Nullable for historical Phase 3/4 rows. Processing status retains its meaning.
    source_state: Mapped[str | None] = mapped_column(sa.String(16))
    source_observed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    source_digest: Mapped[str | None] = mapped_column(sa.String(64))
    correlation_category: Mapped[str | None] = mapped_column(sa.String(255))

    __table_args__ = (
        *tenant_identity_constraints("alert"),
        tenant_fk("service_id", "service", ondelete="RESTRICT", name="fk_alert_service"),
        tenant_fk(
            "environment_id", "environment", ondelete="RESTRICT", name="fk_alert_environment"
        ),
        tenant_fk("incident_id", "incident", ondelete="SET NULL", name="fk_alert_incident"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_alert_idempotency"),
        sa.CheckConstraint("source_state IN ('firing', 'resolved')", name="known_source_state"),
        sa.CheckConstraint(
            "(status <> 'dead_lettered') OR (rejection_reason IS NOT NULL)",
            name="dead_letter_has_reason",
        ),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= started_at", name="resolved_after_started"
        ),
        sa.Index("ix_alert_tenant_incident", "tenant_id", "incident_id"),
        sa.Index("ix_alert_tenant_started", "tenant_id", "started_at"),
        # Correlation window lookup: unattached alerts for a service, newest first.
        sa.Index(
            "ix_alert_correlation_window",
            "tenant_id",
            "service_id",
            "started_at",
            postgresql_where=sa.text("incident_id IS NULL"),
        ),
    )


class Incident(Base, TenantScoped, TimestampMixin):
    """A correlated incident and the subject of a durable workflow.

    ``status`` carries an optimistic lock. Two writers legitimately race here - the
    orchestrator advancing the workflow and a human escalating - and last-write-wins would
    silently discard one of those decisions.
    """

    __tablename__ = "incident"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Short human reference, unique per tenant: ``INC-0042``.
    reference: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    status: Mapped[IncidentStatus] = mapped_column(
        enum_column(IncidentStatus, "incident_status"),
        nullable=False,
        default=IncidentStatus.DETECTED,
    )
    severity: Mapped[IncidentSeverity] = mapped_column(
        enum_column(IncidentSeverity, "incident_severity"),
        nullable=False,
        default=IncidentSeverity.SEV3,
    )
    #: Recorded only on entry to a terminal state. Master specification section 5 requires
    #: that a run never stop without recording why.
    termination_reason: Mapped[TerminationReason | None] = mapped_column(
        enum_column(TerminationReason, "termination_reason"), nullable=True
    )

    opened_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    terminated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    #: Gapless per-incident event counter. Incremented under the incident row lock in the
    #: same transaction as the event insert, which is what makes a missing event
    #: detectable rather than merely absent.
    event_sequence_high_water: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )

    #: Optimistic concurrency token, managed by SQLAlchemy.
    version_id: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    # RUF012: SQLAlchemy's declarative convention. It cannot be a ClassVar because
    # DeclarativeBase declares it as an instance variable.
    __mapper_args__ = {"version_id_col": version_id}  # noqa: RUF012

    __table_args__ = (
        *tenant_identity_constraints("incident"),
        tenant_fk(
            "environment_id", "environment", ondelete="RESTRICT", name="fk_incident_environment"
        ),
        sa.UniqueConstraint("tenant_id", "reference", name="uq_incident_tenant_id_reference"),
        sa.CheckConstraint(
            "(status IN ('resolved', 'failed', 'escalated', 'uncertain'))"
            " = (terminated_at IS NOT NULL)",
            name="terminal_status_has_terminated_at",
        ),
        sa.CheckConstraint(
            "terminated_at IS NULL OR termination_reason IS NOT NULL",
            name="terminated_has_reason",
        ),
        sa.CheckConstraint("event_sequence_high_water >= 0", name="sequence_non_negative"),
        sa.Index("ix_incident_tenant_status", "tenant_id", "status"),
        sa.Index("ix_incident_tenant_opened", "tenant_id", "opened_at"),
        # Open-incident lookup during correlation: the hot path on every alert.
        sa.Index(
            "ix_incident_open",
            "tenant_id",
            "environment_id",
            "opened_at",
            postgresql_where=sa.text("terminated_at IS NULL"),
        ),
    )


class IncidentEvent(Base, TenantScoped, CreatedAtMixin):
    """Immutable, append-only record of everything that happened to an incident.

    This table is the system of record. It is never updated and never deleted within the
    retention period; the migration revokes ``UPDATE`` and ``DELETE`` from the application
    role so that an accidental write fails at the database rather than corrupting history.
    """

    __tablename__ = "incident_event"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Gapless, starting at 1, ordered within the incident.
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    event_type: Mapped[IncidentEventType] = mapped_column(
        enum_column(IncidentEventType, "incident_event_type"), nullable=False
    )
    category: Mapped[EventCategory] = mapped_column(
        enum_column(EventCategory, "event_category"), nullable=False
    )
    #: The concrete emitter: ``alertmanager``, ``g3_investigation_planner``.
    source: Mapped[str] = mapped_column(sa.String(128), nullable=False)

    #: When it actually happened. May precede ``created_at`` for external events.
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    #: Links every artefact of one run together (FR-OBS-04).
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: The event that caused this one, where a causal parent exists.
    causation_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    #: User id for a human actor, node id for an agent actor, service name for the system.
    actor_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    provenance: Mapped[ProvenanceLabel] = mapped_column(
        enum_column(ProvenanceLabel, "provenance_label"), nullable=False
    )

    payload_schema_version: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("1")
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Present for events that can be delivered more than once. ``NULL`` for events that
    #: are legitimately repeatable, which is why the unique index below is partial.
    idempotency_key: Mapped[str | None] = mapped_column(sa.String(KEY_LENGTH), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("incident_event"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_incident_event_incident"),
        sa.UniqueConstraint(
            "tenant_id", "incident_id", "sequence", name="uq_incident_event_sequence"
        ),
        sa.Index(
            "uq_incident_event_idempotency",
            "tenant_id",
            "idempotency_key",
            unique=True,
            postgresql_where=sa.text("idempotency_key IS NOT NULL"),
        ),
        sa.CheckConstraint("sequence >= 1", name="sequence_starts_at_one"),
        sa.CheckConstraint("payload_schema_version >= 1", name="schema_version_positive"),
        # External content may never carry authority-bearing provenance (SEC-I4). The
        # application enforces this too; the database is the backstop.
        sa.CheckConstraint(
            "category <> 'external' OR provenance NOT IN ('system', 'human')",
            name="external_events_are_not_authoritative",
        ),
        sa.Index("ix_incident_event_stream", "tenant_id", "incident_id", "sequence"),
        sa.Index("ix_incident_event_correlation", "tenant_id", "correlation_id"),
        sa.Index("ix_incident_event_type_time", "tenant_id", "event_type", "occurred_at"),
    )


class TimelineEvent(Base, TenantScoped, CreatedAtMixin):
    """Derived, human-readable projection of :class:`IncidentEvent`.

    Every row cites the event it was derived from. Nothing writes here except the
    projection: a timeline that could be hand-authored would be a compliance artifact
    nobody could trust.
    """

    __tablename__ = "timeline_event"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Mirrors the source event's sequence, so the timeline orders identically.
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    category: Mapped[TimelineCategory] = mapped_column(
        enum_column(TimelineCategory, "timeline_category"), nullable=False
    )
    summary: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: The event this entry was projected from. NOT NULL: a timeline entry with no source
    #: is exactly the fabrication this design exists to prevent (INV-3).
    source_event_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Optional deep link to the evidence behind the entry.
    source_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    #: Version of the projection logic that produced this row, so a projection change is
    #: detectable and the timeline can be rebuilt.
    projection_version: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("1")
    )

    __table_args__ = (
        *tenant_identity_constraints("timeline_event"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_timeline_event_incident"),
        tenant_fk(
            "source_event_id",
            "incident_event",
            ondelete="CASCADE",
            name="fk_timeline_event_source_event",
        ),
        sa.UniqueConstraint("tenant_id", "source_event_id", name="uq_timeline_event_source_event"),
        sa.Index("ix_timeline_event_stream", "tenant_id", "incident_id", "sequence"),
    )


class WorkflowRun(Base, TenantScoped, TimestampMixin):
    """One durable orchestration run of an incident.

    The lease columns are how split-brain is prevented. Two orchestrators believing they
    own the same incident would double-execute remediation, which is the worst failure
    this system can produce. A worker may only advance a run whose lease it holds and has
    not allowed to expire.

    The run id is stable across resumes; ``resumed_count`` records how many times it came
    back, which is a reliability signal worth keeping.
    """

    __tablename__ = "workflow_run"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    behaviour_version_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    status: Mapped[WorkflowRunStatus] = mapped_column(
        enum_column(WorkflowRunStatus, "workflow_run_status"),
        nullable=False,
        default=WorkflowRunStatus.RUNNING,
    )
    #: Opaque reference to the orchestrator's checkpoint for this run.
    checkpoint_ref: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    resumed_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )

    #: Worker currently holding the lease, and until when. A worker whose lease expired
    #: must stop rather than assume it still owns the run.
    lease_owner: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    #: Budget ledger: consumed iterations, tool calls, tokens and cost for this run.
    budget_consumed: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    termination_reason: Mapped[TerminationReason | None] = mapped_column(
        enum_column(TerminationReason, "termination_reason"), nullable=True
    )

    __table_args__ = (
        *tenant_identity_constraints("workflow_run"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_workflow_run_incident"),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            ondelete="RESTRICT",
            name="fk_workflow_run_behaviour_version",
        ),
        # At most one live run per incident. A second concurrent run is the split-brain
        # this constraint exists to make impossible.
        sa.Index(
            "uq_workflow_run_active",
            "tenant_id",
            "incident_id",
            unique=True,
            postgresql_where=sa.text("status IN ('running', 'suspended')"),
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL)", name="lease_fields_together"
        ),
        sa.CheckConstraint("resumed_count >= 0", name="resumed_count_non_negative"),
        sa.Index("ix_workflow_run_lease", "status", "lease_expires_at"),
    )
