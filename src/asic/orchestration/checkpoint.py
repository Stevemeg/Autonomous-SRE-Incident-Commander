"""Checkpointing, and the resume that rebuilds working state from durable rows.

ADR-0002 chose LangGraph with PostgreSQL persistence and required that the safety-critical
durability guarantees be implemented in our own code, independent of the engine. ADR-0015
records the consequence: this module owns checkpointing rather than delegating to a
framework checkpointer.

The guarantee this module actually provides, stated exactly:

    **At-least-once node execution, with effect-level idempotency.**

Not exactly-once. A process can die after an adapter has answered and before the
transaction commits, and a resumed run will call that adapter again. What cannot happen is
a *duplicated effect*: the tool broker keys every execution on the effect's business
identity, so the second call collides with the first record instead of applying twice. For
the read-only catalogue an extra call is merely wasted budget; the mechanism matters
because it is the same one that will guard writes.

The resume path deliberately does **not** trust the checkpoint's copy of the working state
for anything the durable rows can answer. Evidence, steps and hypotheses are re-read from
their tables, and the checkpoint supplies only the ephemeral remainder - the phase, the open
gaps, the last planner decision, the budget ledger. If the two disagree about how many rows
exist, the durable rows win and the divergence is recorded, because the durable rows are
what actually happened.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.state import (
    BudgetSnapshot,
    EvidenceRef,
    GraphState,
    HypothesisRef,
    InvestigationObjective,
    PlannerDecisionRef,
    ReflectionDecisionRef,
    RunIdentity,
    StepRef,
    TraceContext,
)
from asic.db.models.incident import WorkflowRun
from asic.db.models.investigation import Evidence, Hypothesis, HypothesisEvidence, InvestigationStep
from asic.db.models.orchestration import WorkflowCheckpoint
from asic.domain.budget import BudgetState
from asic.domain.clock import Clock
from asic.domain.enums import EvidenceRelation, InvestigationPhase
from asic.observability import metrics

#: Reasons a checkpoint is taken. Matches the ``ck_workflow_checkpoint_known_reason``
#: constraint; naming them here means a caller cannot invent one and find out at INSERT.
CHECKPOINT_REASONS: Final[frozenset[str]] = frozenset(
    {"run_started", "node_boundary", "terminal", "suspended"}
)

#: State keys the checkpoint carries. Everything else in :class:`GraphState` is either
#: immutable run identity (recomputed on resume) or derivable from durable rows.
_EPHEMERAL_KEYS: Final[tuple[str, ...]] = (
    "phase",
    "iteration",
    "resumed_count",
    "open_gaps",
    "covered_domains",
    "degraded_domains",
    "capability_menu",
    "last_decision",
    "reflection_decision",
    "budget",
    "budget_refusal",
    "pending_approval",
    "terminated",
    "termination_reason",
    "termination_rule_id",
    "terminal_incident_status",
)


def digest_state(state: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical rendering of a checkpoint's state."""
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def serialise(state: GraphState) -> dict[str, Any]:
    """Render the ephemeral remainder of ``state`` as JSON-safe data."""
    payload: dict[str, Any] = {}
    for key in _EPHEMERAL_KEYS:
        if key not in state:
            continue
        value = state[key]  # type: ignore[literal-required]
        if hasattr(value, "model_dump"):
            payload[key] = value.model_dump(mode="json")
        elif isinstance(value, InvestigationPhase):
            payload[key] = value.value
        else:
            payload[key] = value
    return payload


@dataclass(frozen=True, slots=True)
class DurableCounts:
    """How many durable rows a run had produced when a checkpoint was taken."""

    steps: int
    evidence: int
    hypotheses: int

    def to_dict(self) -> dict[str, int]:
        return {"steps": self.steps, "evidence": self.evidence, "hypotheses": self.hypotheses}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DurableCounts:
        return cls(
            steps=int(raw.get("steps", 0)),
            evidence=int(raw.get("evidence", 0)),
            hypotheses=int(raw.get("hypotheses", 0)),
        )


def count_durable(session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID) -> DurableCounts:
    def _count(model: Any, column: Any) -> int:
        return int(
            session.execute(
                sa.select(sa.func.count())
                .select_from(model)
                .where(model.tenant_id == tenant_id, column == run_id)
            ).scalar_one()
        )

    return DurableCounts(
        steps=_count(InvestigationStep, InvestigationStep.workflow_run_id),
        evidence=int(
            session.execute(
                sa.select(sa.func.count())
                .select_from(Evidence)
                .join(
                    InvestigationStep,
                    sa.and_(
                        InvestigationStep.id == Evidence.investigation_step_id,
                        InvestigationStep.tenant_id == Evidence.tenant_id,
                    ),
                )
                .where(
                    Evidence.tenant_id == tenant_id,
                    InvestigationStep.workflow_run_id == run_id,
                )
            ).scalar_one()
        ),
        hypotheses=_count(Hypothesis, Hypothesis.workflow_run_id),
    )


class CheckpointStore:
    """Writes and reads a run's checkpoints."""

    __slots__ = ("_clock",)

    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock

    def write(
        self,
        session: Session,
        *,
        state: GraphState,
        reason: str,
        after_node: str | None,
        budget: BudgetState,
    ) -> WorkflowCheckpoint:
        """Append one checkpoint. Must be called in the node's own transaction.

        Raises:
            ValueError: on an unknown reason, before the database refuses it, so the error
                names the vocabulary rather than a constraint.
        """
        if reason not in CHECKPOINT_REASONS:
            raise ValueError(
                f"checkpoint reason {reason!r} is not one of {sorted(CHECKPOINT_REASONS)}"
            )
        identity = state["identity"]
        tenant_id = uuid.UUID(identity.tenant_id)
        run_id = uuid.UUID(identity.workflow_run_id)

        # Serialise on the run row, not on an aggregate: PostgreSQL refuses FOR UPDATE
        # alongside an aggregate, and locking the run is the correct granularity anyway -
        # exactly one worker holds the lease, so exactly one may append a checkpoint.
        session.execute(
            sa.select(WorkflowRun.id)
            .where(WorkflowRun.tenant_id == tenant_id, WorkflowRun.id == run_id)
            .with_for_update()
        ).scalar_one()
        high_water = session.execute(
            sa.select(sa.func.coalesce(sa.func.max(WorkflowCheckpoint.sequence), 0)).where(
                WorkflowCheckpoint.tenant_id == tenant_id,
                WorkflowCheckpoint.workflow_run_id == run_id,
            )
        ).scalar_one()

        payload = serialise(state)
        checkpoint = WorkflowCheckpoint(
            tenant_id=tenant_id,
            workflow_run_id=run_id,
            incident_id=uuid.UUID(identity.incident_id),
            sequence=int(high_water) + 1,
            after_node=after_node,
            reason=reason,
            state=payload,
            state_digest=digest_state(payload),
            durable_counts=count_durable(session, tenant_id=tenant_id, run_id=run_id).to_dict(),
            budget_consumed=budget.to_dict(),
            behaviour_version_id=uuid.UUID(identity.behaviour_version_id),
            correlation_id=uuid.UUID(state["trace"].correlation_id),
            taken_at=self._clock.now(),
        )
        session.add(checkpoint)
        session.flush()
        metrics.checkpoints_total.add(1, {"reason": reason})
        return checkpoint

    @staticmethod
    def latest(
        session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID
    ) -> WorkflowCheckpoint | None:
        return session.execute(
            sa.select(WorkflowCheckpoint)
            .where(
                WorkflowCheckpoint.tenant_id == tenant_id,
                WorkflowCheckpoint.workflow_run_id == run_id,
            )
            .order_by(WorkflowCheckpoint.sequence.desc())
            .limit(1)
        ).scalar_one_or_none()

    @staticmethod
    def sequence_gaps(session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID) -> list[int]:
        """Missing checkpoint sequence numbers. A gap means a checkpoint was lost."""
        sequences = list(
            session.execute(
                sa.select(WorkflowCheckpoint.sequence)
                .where(
                    WorkflowCheckpoint.tenant_id == tenant_id,
                    WorkflowCheckpoint.workflow_run_id == run_id,
                )
                .order_by(WorkflowCheckpoint.sequence)
            ).scalars()
        )
        if not sequences:
            return []
        present = set(sequences)
        return [n for n in range(1, sequences[-1] + 1) if n not in present]


class CheckpointIntegrityError(RuntimeError):
    """A checkpoint could not be trusted enough to resume from."""


@dataclass(frozen=True, slots=True)
class RehydrationReport:
    """What the resume found, and how it differed from what the checkpoint expected."""

    checkpoint_sequence: int
    expected: DurableCounts
    observed: DurableCounts

    @property
    def diverged(self) -> bool:
        return self.expected != self.observed

    def describe(self) -> str:
        return (
            f"checkpoint {self.checkpoint_sequence} expected "
            f"{self.expected.to_dict()} and the database holds {self.observed.to_dict()}"
        )


def rehydrate(
    session: Session,
    *,
    checkpoint: WorkflowCheckpoint,
    identity: RunIdentity,
    trace: TraceContext,
    objective: InvestigationObjective,
) -> tuple[GraphState, RehydrationReport]:
    """Rebuild working state: durable rows for facts, the checkpoint for the remainder.

    Raises:
        CheckpointIntegrityError: if the stored digest does not match the stored state. A
            checkpoint that has been truncated or altered is not resumed from; the correct
            response is to dead-letter the run for inspection, not to guess at the missing
            part.
    """
    stored = dict(checkpoint.state or {})
    if digest_state(stored) != checkpoint.state_digest:
        raise CheckpointIntegrityError(
            f"checkpoint {checkpoint.id} fails its own digest; the stored state has been "
            "altered or truncated since it was written and will not be resumed from"
        )

    tenant_id = uuid.UUID(identity.tenant_id)
    run_id = uuid.UUID(identity.workflow_run_id)

    steps = _load_steps(session, tenant_id=tenant_id, run_id=run_id)
    evidence = _load_evidence(session, tenant_id=tenant_id, run_id=run_id)
    hypotheses = _load_hypotheses(session, tenant_id=tenant_id, run_id=run_id)

    observed = DurableCounts(steps=len(steps), evidence=len(evidence), hypotheses=len(hypotheses))
    report = RehydrationReport(
        checkpoint_sequence=checkpoint.sequence,
        expected=DurableCounts.from_dict(checkpoint.durable_counts or {}),
        observed=observed,
    )

    budget_raw = stored.get("budget") or {}
    state: GraphState = {
        "identity": identity,
        "trace": trace,
        "objective": objective,
        "phase": InvestigationPhase(stored.get("phase", InvestigationPhase.PLANNING.value)),
        "iteration": int(stored.get("iteration", 0)),
        "resumed_count": int(stored.get("resumed_count", 0)) + 1,
        "evidence": evidence,
        "steps": steps,
        "hypotheses": hypotheses,
        "failures": [],
        "open_gaps": list(stored.get("open_gaps", [])),
        "covered_domains": sorted({s.domain.value for s in steps}),
        "degraded_domains": list(stored.get("degraded_domains", [])),
        "capability_menu": list(stored.get("capability_menu", [])),
        "last_decision": (
            PlannerDecisionRef.model_validate(stored["last_decision"])
            if stored.get("last_decision")
            else None
        ),
        "reflection_decision": (
            ReflectionDecisionRef.model_validate(stored["reflection_decision"])
            if stored.get("reflection_decision")
            else None
        ),
        "budget": (
            BudgetSnapshot.model_validate(budget_raw)
            if budget_raw
            else BudgetSnapshot(consumed={}, remaining={})
        ),
        "budget_refusal": stored.get("budget_refusal"),
        "pending_approval": None,
        "terminated": bool(stored.get("terminated", False)),
        "termination_reason": stored.get("termination_reason"),
        "termination_rule_id": stored.get("termination_rule_id"),
        "terminal_incident_status": stored.get("terminal_incident_status"),
    }
    metrics.resumes_total.add(1, {"diverged": str(report.diverged).lower()})
    return state, report


def _load_steps(session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID) -> list[StepRef]:
    rows = list(
        session.execute(
            sa.select(InvestigationStep)
            .where(
                InvestigationStep.tenant_id == tenant_id,
                InvestigationStep.workflow_run_id == run_id,
            )
            .order_by(InvestigationStep.sequence)
        ).scalars()
    )
    counts: dict[uuid.UUID, int] = {
        step_id: int(count)
        for step_id, count in session.execute(
            sa.select(Evidence.investigation_step_id, sa.func.count())
            .where(
                Evidence.tenant_id == tenant_id,
                Evidence.investigation_step_id.is_not(None),
            )
            .group_by(Evidence.investigation_step_id)
        ).all()
        if step_id is not None
    }
    return [
        StepRef(
            step_id=str(row.id),
            sequence=row.sequence,
            domain=row.domain,
            gap=row.gap_declared,
            status=row.status,
            evidence_count=counts.get(row.id, 0),
            degradation_reason=row.degradation_reason,
        )
        for row in rows
    ]


def _load_evidence(
    session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> list[EvidenceRef]:
    rows = list(
        session.execute(
            sa.select(Evidence)
            .join(
                InvestigationStep,
                sa.and_(
                    InvestigationStep.id == Evidence.investigation_step_id,
                    InvestigationStep.tenant_id == Evidence.tenant_id,
                ),
            )
            .where(
                Evidence.tenant_id == tenant_id,
                InvestigationStep.workflow_run_id == run_id,
            )
            .order_by(Evidence.gathered_at, Evidence.id)
        ).scalars()
    )
    return [
        EvidenceRef(
            evidence_id=str(row.id),
            tool_execution_id=str(row.tool_execution_id),
            domain=row.domain,
            provenance=row.provenance,
            headline=str((row.content or {}).get("headline", ""))[:240],
            content_digest=str((row.citation or {}).get("content_digest", "")),
            quality_score=float(row.quality_score or 0.0),
            injection_flagged=bool(row.injection_flagged),
        )
        for row in rows
    ]


def _load_hypotheses(
    session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> list[HypothesisRef]:
    rows = list(
        session.execute(
            sa.select(Hypothesis)
            .where(Hypothesis.tenant_id == tenant_id, Hypothesis.workflow_run_id == run_id)
            .order_by(Hypothesis.rank)
        ).scalars()
    )
    links = list(
        session.execute(
            sa.select(HypothesisEvidence.hypothesis_id, HypothesisEvidence.relation).where(
                HypothesisEvidence.tenant_id == tenant_id
            )
        ).all()
    )
    supporting: dict[uuid.UUID, int] = {}
    contradicting: dict[uuid.UUID, int] = {}
    for hypothesis_id, relation in links:
        target = supporting if relation is EvidenceRelation.SUPPORTS else contradicting
        target[hypothesis_id] = target.get(hypothesis_id, 0) + 1

    return [
        HypothesisRef(
            hypothesis_id=str(row.id),
            rank=row.rank,
            root_cause_class=row.root_cause_class,
            confidence=float(row.confidence),
            status=row.status,
            supporting_evidence_count=supporting.get(row.id, 0),
            contradicting_evidence_count=contradicting.get(row.id, 0),
            remaining_gaps=tuple(str(gap) for gap in (row.remaining_gaps or [])),
        )
        for row in rows
    ]


__all__ = [
    "CHECKPOINT_REASONS",
    "CheckpointIntegrityError",
    "CheckpointStore",
    "DurableCounts",
    "RehydrationReport",
    "count_durable",
    "digest_state",
    "rehydrate",
    "serialise",
]
