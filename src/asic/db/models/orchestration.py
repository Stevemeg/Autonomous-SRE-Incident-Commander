"""Durable orchestration checkpoints.

The one table Phase 4 adds, and the reasoning for adding it rather than reusing something
existing is recorded in ADR-0015.

``workflow_run`` already carries a ``checkpoint_ref``, but a single reference can only ever
name the latest checkpoint. That is enough to resume and not enough to *diagnose* a resume,
which is the operation most likely to go wrong and hardest to reproduce afterwards. An
append-only sequence of checkpoints gives the run a recoverable history: which node the run
was at, what it had gathered, what the budget looked like, and how many times it came back.

What a checkpoint holds is deliberately small. Durable domain records - evidence, steps,
hypotheses, tool executions - are the system of record, and the resume path rebuilds working
state from them. The checkpoint carries only the *ephemeral remainder*: the phase, the open
gaps, the last planner decision and the budget ledger. A checkpoint containing copies of
evidence would be a second source of truth, and the two would diverge the first time a
resume landed mid-write.
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
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)


class WorkflowCheckpoint(Base, TenantScoped, CreatedAtMixin):
    """One durable checkpoint of one workflow run. Append-only.

    Written inside the same transaction as the node's durable effects, so a checkpoint can
    never describe work that was rolled back, and work can never be committed without the
    checkpoint that records where the run had got to.
    """

    __tablename__ = "workflow_checkpoint"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    #: Monotonic within a run, so gaps are detectable exactly as they are on the event log.
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: The graph node that had just completed. ``None`` for the checkpoint taken at start.
    after_node: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    #: Why the checkpoint was taken: ``node_boundary``, ``run_started``, ``terminal``.
    reason: Mapped[str] = mapped_column(sa.String(32), nullable=False)

    #: The ephemeral remainder of the graph state. References and scalars only; no evidence
    #: content, no model messages, no credentials.
    state: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    #: Digest over ``state``, so a tampered or truncated checkpoint is detectable rather
    #: than silently resumed from.
    state_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    #: Counts of the durable rows that existed when the checkpoint was taken. The resume
    #: path compares them with what it actually finds; a mismatch means rows were written
    #: after the checkpoint and before the crash, which the resume must account for.
    durable_counts: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    budget_consumed: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    #: Which behaviour version produced it, so a resume under a changed deployment is
    #: visible rather than silent.
    behaviour_version_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    taken_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        *tenant_identity_constraints("workflow_checkpoint"),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="CASCADE",
            name="fk_workflow_checkpoint_workflow_run",
        ),
        tenant_fk(
            "incident_id",
            "incident",
            ondelete="CASCADE",
            name="fk_workflow_checkpoint_incident",
        ),
        sa.ForeignKeyConstraint(
            ["behaviour_version_id"],
            ["behaviour_version.id"],
            ondelete="RESTRICT",
            name="fk_workflow_checkpoint_behaviour_version",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "workflow_run_id",
            "sequence",
            name="uq_workflow_checkpoint_sequence",
        ),
        sa.CheckConstraint("sequence >= 1", name="sequence_starts_at_one"),
        sa.CheckConstraint(
            "reason IN ('run_started', 'node_boundary', 'terminal', 'suspended')",
            name="known_checkpoint_reason",
        ),
        sa.CheckConstraint("length(state_digest) = 64", name="state_digest_is_sha256"),
        sa.Index(
            "ix_workflow_checkpoint_run",
            "tenant_id",
            "workflow_run_id",
            "sequence",
        ),
    )
