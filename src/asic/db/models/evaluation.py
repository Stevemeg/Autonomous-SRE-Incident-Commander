"""Behaviour versioning, evaluation records and structured execution traces.

The evaluation harness is not built in this phase. What is built is the **persistence
model it will consume**, because the trace schema constrains how every future node is
written: a node that does not emit a span cannot be evaluated, and retrofitting emission
means rewriting the node.

The design commitment from the architecture package (PR-5) is that one trace schema serves
operations, replay and evaluation. That is why :class:`ExecutionTrace` carries an optional
``evaluation_run_id`` rather than there being a separate evaluation trace table: a
production incident becomes an evaluation case without transformation.
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
    EvaluationRunVerdict,
    EvaluationScenarioClass,
    NodeId,
    SpanStatus,
    TerminationReason,
    TraceSpanKind,
)


class BehaviourVersion(Base, CreatedAtMixin):
    """The versioned tuple that determines how the system behaves. Global and immutable.

    Master specification section 10 requires prompt, model, retriever and agent-policy
    changes to be treated as versioned behaviour changes. This row is that version. Every
    workflow run and every evaluation run references one, which is what makes "never
    silently modify production behaviour" checkable rather than aspirational.
    """

    __tablename__ = "behaviour_version"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Human-readable label, e.g. ``2026.09.04-1``.
    label: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    code_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    prompt_set_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Model identifiers per node, e.g. ``{"g5_hypothesis_engine": "..."}``.
    model_ids: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    retriever_config_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    tool_registry_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    judge_set_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    #: Digest over the whole tuple, so two identical configurations collide instead of
    #: producing two "different" versions that are actually the same behaviour.
    fingerprint: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("fingerprint", name="uq_behaviour_version_fingerprint"),
        sa.UniqueConstraint("label", name="uq_behaviour_version_label"),
    )


class ExecutionTrace(Base, TenantScoped, TimestampMixin):
    """Run-level trace header.

    One row per workflow run (production) or per evaluation run (harness). The seeds and
    fixture references are what make L2 deterministic replay possible: without the frozen
    clock and seed, a replay is a re-run, not a reproduction.
    """

    __tablename__ = "execution_trace"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Production trace. Exactly one of this and ``evaluation_run_id`` is set.
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    #: Harness trace.
    evaluation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    behaviour_version_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: W3C trace id, so the row joins to whatever the collector received.
    trace_id: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: Replay determinism inputs.
    clock_start: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    random_seed: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    fixture_refs: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    termination_reason: Mapped[TerminationReason | None] = mapped_column(
        enum_column(TerminationReason, "termination_reason"), nullable=True
    )
    #: Roll-up of cost and effort for the whole run.
    total_tokens: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    total_cost_usd: Mapped[float | None] = mapped_column(sa.Numeric(12, 6), nullable=True)
    total_tool_calls: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("execution_trace"),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="CASCADE",
            name="fk_execution_trace_workflow_run",
        ),
        tenant_fk(
            "evaluation_run_id",
            "evaluation_run",
            ondelete="CASCADE",
            name="fk_execution_trace_evaluation_run",
        ),
        tenant_fk(
            "incident_id", "incident", ondelete="CASCADE", name="fk_execution_trace_incident"
        ),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            ondelete="RESTRICT",
            name="fk_execution_trace_behaviour_version",
        ),
        sa.UniqueConstraint("tenant_id", "trace_id", name="uq_execution_trace_trace_id"),
        # A trace belongs to exactly one kind of run. Both set, or neither, is a bug in
        # whatever created it.
        sa.CheckConstraint(
            "(workflow_run_id IS NOT NULL) <> (evaluation_run_id IS NOT NULL)",
            name="trace_belongs_to_exactly_one_run",
        ),
        sa.CheckConstraint("total_tokens IS NULL OR total_tokens >= 0", name="tokens_non_negative"),
        sa.CheckConstraint(
            "total_cost_usd IS NULL OR total_cost_usd >= 0", name="cost_non_negative"
        ),
        sa.Index("ix_execution_trace_incident", "tenant_id", "incident_id"),
        sa.Index("ix_execution_trace_behaviour", "tenant_id", "behaviour_version_id"),
    )


class TraceSpan(Base, TenantScoped, CreatedAtMixin):
    """One span within a trace, with its parent link.

    Append-only. This is the table the evaluation harness reads to score a run, and the
    table an operator reads to understand what a node decided and why.

    **No secrets, prompts or raw credentials.** Prompts are referenced by version and
    hash, never inlined: inlining them inflates the table, and risks writing untrusted
    retrieved content and personal data into telemetry that has a different retention
    policy from the incident record.
    """

    __tablename__ = "trace_span"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    execution_trace_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: W3C span id, and the parent that makes the tree.
    span_id: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    parent_span_id: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)

    kind: Mapped[TraceSpanKind] = mapped_column(
        enum_column(TraceSpanKind, "trace_span_kind"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[SpanStatus] = mapped_column(
        enum_column(SpanStatus, "span_status"), nullable=False, default=SpanStatus.UNSET
    )

    #: Which node emitted it, and at what version - both needed to attribute a regression.
    node_id: Mapped[NodeId | None] = mapped_column(enum_column(NodeId, "node_id"), nullable=True)
    node_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    #: References rather than content: evidence ids, tool execution ids, input digests.
    input_refs: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    evidence_refs: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=sa.text("'{}'::uuid[]")
    )
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )

    #: Model call metadata. Provider and model id, token counts, cost - never prompt text.
    model_metadata: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    prompt_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    input_tokens: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(sa.Numeric(12, 6), nullable=True)

    #: What the node decided, and the alternatives it weighed. Recording the alternatives
    #: is what makes tool-call efficiency diagnosable rather than merely measurable.
    decision: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    confidence: Mapped[float | None] = mapped_column(sa.Numeric(4, 3), nullable=True)
    #: Budget remaining on entry, so a termination is explicable after the fact.
    budget_snapshot: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    failure_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    termination_reason: Mapped[TerminationReason | None] = mapped_column(
        enum_column(TerminationReason, "termination_reason"), nullable=True
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    __table_args__ = (
        *tenant_identity_constraints("trace_span"),
        tenant_fk(
            "execution_trace_id",
            "execution_trace",
            ondelete="CASCADE",
            name="fk_trace_span_execution_trace",
        ),
        tenant_fk(
            "tool_execution_id",
            "tool_execution",
            ondelete="SET NULL",
            name="fk_trace_span_tool_execution",
        ),
        sa.UniqueConstraint(
            "tenant_id", "execution_trace_id", "span_id", name="uq_trace_span_span_id"
        ),
        sa.CheckConstraint("span_id <> parent_span_id", name="no_self_parent"),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        sa.CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="duration_non_negative"),
        sa.CheckConstraint(
            "(status <> 'error') OR (failure_reason IS NOT NULL)", name="error_has_reason"
        ),
        sa.Index("ix_trace_span_trace", "tenant_id", "execution_trace_id", "started_at"),
        sa.Index("ix_trace_span_parent", "tenant_id", "execution_trace_id", "parent_span_id"),
        sa.Index("ix_trace_span_node", "tenant_id", "node_id", "kind"),
    )


class EvaluationScenario(Base, TenantScoped, TimestampMixin):
    """A versioned evaluation case with its expected outcomes.

    Versioned because changing a scenario invalidates cross-version comparison: a score
    that improved because the target moved is not an improvement.
    """

    __tablename__ = "evaluation_scenario"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Stable human key, e.g. ``SC-0007``.
    key: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("1"))
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    scenario_class: Mapped[EvaluationScenarioClass] = mapped_column(
        enum_column(EvaluationScenarioClass, "evaluation_scenario_class"), nullable=False
    )
    difficulty: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    tags: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )

    #: Frozen inputs: fixtures, clock, seed, alert payloads.
    fixture_refs: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    input_refs: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Expected correlation, evidence, RCA, remediation safety and termination labels.
    expected_labels: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)

    review_state: Mapped[str] = mapped_column(
        sa.String(32), nullable=False, server_default=sa.text("'draft'")
    )
    labelled_by: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    labelled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("evaluation_scenario"),
        sa.UniqueConstraint("tenant_id", "key", "version", name="uq_evaluation_scenario_version"),
        sa.CheckConstraint("version >= 1", name="version_starts_at_one"),
        sa.Index("ix_evaluation_scenario_class", "tenant_id", "scenario_class"),
    )


class EvaluationRun(Base, TenantScoped, TimestampMixin):
    """One scored execution of one scenario against one behaviour version.

    Immutable once complete. The scenario *version* is denormalised onto the run so a
    historical result stays interpretable after the scenario is revised.
    """

    __tablename__ = "evaluation_run"

    id: Mapped[uuid.UUID] = uuid_pk()
    evaluation_scenario_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    scenario_version: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    behaviour_version_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: Which repetition this is, for establishing the noise band. Model output varies even
    #: at temperature zero, so a single run is not a measurement.
    repetition_index: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("0")
    )
    verdict: Mapped[EvaluationRunVerdict | None] = mapped_column(
        enum_column(EvaluationRunVerdict, "evaluation_run_verdict"), nullable=True
    )
    #: Per-metric scores. Absent metrics are absent, never zero: an unmeasured metric
    #: reported as zero is an invented result.
    metrics: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Judge versions used, so a judge change forces re-baselining.
    judge_versions: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )
    #: Populated when judges disagreed beyond tolerance. Not averaged away.
    disagreement: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("evaluation_run"),
        tenant_fk(
            "evaluation_scenario_id",
            "evaluation_scenario",
            ondelete="RESTRICT",
            name="fk_evaluation_run_scenario",
        ),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            ondelete="RESTRICT",
            name="fk_evaluation_run_behaviour_version",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "evaluation_scenario_id",
            "scenario_version",
            "behaviour_version_id",
            "repetition_index",
            name="uq_evaluation_run_repetition",
        ),
        sa.CheckConstraint("repetition_index >= 0", name="repetition_non_negative"),
        sa.CheckConstraint("scenario_version >= 1", name="scenario_version_positive"),
        sa.Index("ix_evaluation_run_behaviour", "tenant_id", "behaviour_version_id"),
        sa.Index("ix_evaluation_run_scenario", "tenant_id", "evaluation_scenario_id"),
    )
