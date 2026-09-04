"""Investigation: planner steps, evidence, hypotheses and their evidence links.

Two invariants from the architecture package are enforced here as database constraints
rather than as application habits:

* **INV-4** - every evidence row references the tool execution that produced it. Evidence
  cannot be conjured; it is always the recorded result of an actual query.
* **INV-5** - a hypothesis cites evidence through a foreign-keyed junction table, so a
  citation to a non-existent evidence record cannot be persisted at all. Hallucinated
  citation becomes an impossible state rather than a scoring problem.
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
    EvidenceDomain,
    EvidenceRelation,
    HypothesisStatus,
    InvestigationStepStatus,
    NodeId,
    ProvenanceLabel,
)


class InvestigationStep(Base, TenantScoped, TimestampMixin):
    """One planner-selected evidence-gathering step.

    Records the *decision*, not just the result: which information gap was declared, why
    this step was chosen to close it, and what budget remained. Without that, tool-call
    efficiency can be measured but never diagnosed, and the step cannot be replayed.
    """

    __tablename__ = "investigation_step"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Ordinal within the incident's investigation loop.
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    #: The gap the planner declared before choosing this step.
    gap_declared: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Which Evidence Collector strategy was selected.
    domain: Mapped[EvidenceDomain] = mapped_column(
        enum_column(EvidenceDomain, "evidence_domain"), nullable=False
    )
    #: Planner rationale, retained for replay and for diagnosing redundant collection.
    rationale: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[InvestigationStepStatus] = mapped_column(
        enum_column(InvestigationStepStatus, "investigation_step_status"),
        nullable=False,
        default=InvestigationStepStatus.PLANNED,
    )
    #: Set when the step completed with reduced coverage because an adapter degraded.
    degradation_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    budget_before: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    budget_after: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("investigation_step"),
        tenant_fk(
            "incident_id", "incident", ondelete="CASCADE", name="fk_investigation_step_incident"
        ),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="CASCADE",
            name="fk_investigation_step_workflow_run",
        ),
        sa.UniqueConstraint(
            "tenant_id", "incident_id", "sequence", name="uq_investigation_step_sequence"
        ),
        sa.CheckConstraint("sequence >= 1", name="sequence_starts_at_one"),
        sa.CheckConstraint(
            "(status <> 'degraded') OR (degradation_reason IS NOT NULL)",
            name="degraded_has_reason",
        ),
        sa.Index("ix_investigation_step_incident", "tenant_id", "incident_id", "sequence"),
    )


class Evidence(Base, TenantScoped, CreatedAtMixin):
    """One recorded piece of evidence, with the provenance that makes it usable.

    Append-only. Evidence is a factual record of what a query returned at a point in time;
    editing it later would invalidate every hypothesis that cited it.

    ``tool_execution_id`` is NOT NULL by design (INV-4). There is no code path that
    produces evidence without a corresponding recorded query.
    """

    __tablename__ = "evidence"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    investigation_step_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    #: The execution that produced this evidence. Not nullable: see INV-4.
    tool_execution_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    domain: Mapped[EvidenceDomain] = mapped_column(
        enum_column(EvidenceDomain, "evidence_domain"), nullable=False
    )
    #: ``VERIFIED_FACT`` for tool results, ``RETRIEVED`` for knowledge-base content.
    #: Never ``SYSTEM`` or ``HUMAN``: evidence does not confer authority (SEC-I4).
    provenance: Mapped[ProvenanceLabel] = mapped_column(
        enum_column(ProvenanceLabel, "provenance_label"), nullable=False
    )
    #: The content itself. Sensitivity: CUSTOMER_CONTENT - log excerpts and runbook text
    #: subject to the tenant's retention policy.
    content: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Everything a human needs to re-derive this independently: the query issued, the
    #: time window, the source system and its identifiers (FR-EVD-02).
    citation: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Window and sample-size coverage relative to the declared gap. 0.0 - 1.0.
    quality_score: Mapped[float | None] = mapped_column(sa.Numeric(4, 3), nullable=True)
    gathered_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    #: Set when injection patterns were detected in retrieved content. A signal, recorded
    #: for evidence; the structural defence is that this content cannot reach the gate.
    injection_flagged: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("false")
    )

    __table_args__ = (
        *tenant_identity_constraints("evidence"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_evidence_incident"),
        tenant_fk(
            "investigation_step_id",
            "investigation_step",
            ondelete="SET NULL",
            name="fk_evidence_investigation_step",
        ),
        tenant_fk(
            "tool_execution_id",
            "tool_execution",
            ondelete="RESTRICT",
            name="fk_evidence_tool_execution",
        ),
        sa.CheckConstraint(
            "provenance IN ('verified_fact', 'retrieved')",
            name="evidence_provenance_is_not_authoritative",
        ),
        sa.CheckConstraint(
            "quality_score IS NULL OR (quality_score >= 0 AND quality_score <= 1)",
            name="quality_score_range",
        ),
        sa.Index("ix_evidence_incident", "tenant_id", "incident_id"),
        sa.Index("ix_evidence_incident_domain", "tenant_id", "incident_id", "domain"),
        sa.Index("ix_evidence_tool_execution", "tenant_id", "tool_execution_id"),
    )


class Hypothesis(Base, TenantScoped, TimestampMixin):
    """A ranked candidate root cause.

    ``confidence_basis`` is not decoration. Master specification section 9 requires
    confidence to be reported with what produced it - evidence count, evidence quality,
    presence of contradiction - so that calibration is measurable rather than a number the
    model chose.
    """

    __tablename__ = "hypothesis"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: 1 is the highest-ranked candidate.
    rank: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: Coarse cause classification used as the evaluation label (``bad_deployment``,
    #: ``dependency_outage``, ``resource_exhaustion``).
    root_cause_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Optional pointer to the specific implicated object, e.g. ``deploy:847``.
    root_cause_ref: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    statement: Mapped[str] = mapped_column(sa.Text, nullable=False)

    confidence: Mapped[float] = mapped_column(sa.Numeric(4, 3), nullable=False)
    confidence_basis: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    status: Mapped[HypothesisStatus] = mapped_column(
        enum_column(HypothesisStatus, "hypothesis_status"),
        nullable=False,
        default=HypothesisStatus.PROPOSED,
    )
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    #: Gaps the hypothesis itself declares it cannot yet close.
    remaining_gaps: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    #: Which node produced it. Always a model-backed node, recorded for evaluation.
    produced_by_node: Mapped[NodeId] = mapped_column(enum_column(NodeId, "node_id"), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("hypothesis"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_hypothesis_incident"),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="CASCADE",
            name="fk_hypothesis_workflow_run",
        ),
        tenant_fk(
            "superseded_by_id",
            "hypothesis",
            ondelete="SET NULL",
            name="fk_hypothesis_superseded_by",
        ),
        sa.CheckConstraint("rank >= 1", name="rank_starts_at_one"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        sa.CheckConstraint("superseded_by_id <> id", name="no_self_supersede"),
        sa.CheckConstraint(
            "(status <> 'superseded') OR (superseded_by_id IS NOT NULL)",
            name="superseded_names_successor",
        ),
        sa.Index("ix_hypothesis_incident_rank", "tenant_id", "incident_id", "rank"),
        sa.Index("ix_hypothesis_incident_status", "tenant_id", "incident_id", "status"),
    )


class HypothesisEvidence(Base, TenantScoped, CreatedAtMixin):
    """Link between a hypothesis and the evidence that supports or contradicts it.

    Counter-evidence is a first-class row, not an afterthought: master specification
    section 3 requires hypotheses to carry counter-evidence, and a schema that could only
    express support would make that impossible to satisfy honestly.

    The foreign key to ``evidence`` is what enforces INV-5.
    """

    __tablename__ = "hypothesis_evidence"

    id: Mapped[uuid.UUID] = uuid_pk()
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    evidence_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    relation: Mapped[EvidenceRelation] = mapped_column(
        enum_column(EvidenceRelation, "evidence_relation"), nullable=False
    )
    #: Relative contribution of this evidence to the hypothesis's confidence.
    weight: Mapped[float | None] = mapped_column(sa.Numeric(4, 3), nullable=True)
    #: Why this evidence bears on this hypothesis.
    rationale: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("hypothesis_evidence"),
        tenant_fk(
            "hypothesis_id",
            "hypothesis",
            ondelete="CASCADE",
            name="fk_hypothesis_evidence_hypothesis",
        ),
        tenant_fk(
            "evidence_id", "evidence", ondelete="RESTRICT", name="fk_hypothesis_evidence_evidence"
        ),
        sa.UniqueConstraint(
            "tenant_id", "hypothesis_id", "evidence_id", name="uq_hypothesis_evidence_link"
        ),
        sa.CheckConstraint("weight IS NULL OR (weight >= 0 AND weight <= 1)", name="weight_range"),
        sa.Index("ix_hypothesis_evidence_hypothesis", "tenant_id", "hypothesis_id"),
        sa.Index("ix_hypothesis_evidence_evidence", "tenant_id", "evidence_id"),
    )
