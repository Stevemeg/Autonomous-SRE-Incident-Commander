"""The canonical orchestration graph state.

Four kinds of state exist in this system and confusing them is the failure this module is
designed to prevent:

======================  ==========================================================
Kind                    Where it lives, and who may write it
======================  ==========================================================
**Durable domain**      PostgreSQL rows - ``incident``, ``investigation_step``,
                        ``evidence``, ``hypothesis``, ``tool_execution``. The
                        system of record. Written by nodes through the
                        persistence layer.
**Ephemeral graph**     :class:`GraphState`, below. Working state for one pass of
                        the graph. Rebuilt from durable rows on resume.
**Execution trace**     ``execution_trace`` / ``trace_span``. Append-only record
                        of what happened, for operators and evaluation.
**Audit**               ``audit_record``. Append-only record of decisions that
                        carry authority.
======================  ==========================================================

:class:`GraphState` therefore carries **references and scalars, never payloads**. An
evidence reference names an id, a domain, a quality score and a one-line headline; the log
lines themselves stay in ``evidence.content`` where they are tenant-scoped, retention-bound
and out of the checkpoint. This is not only a size concern:

* a checkpoint containing copies of evidence becomes a **second source of truth**, and the
  two diverge the first time a resume replays a partial write;
* untrusted operational content in the checkpoint spreads customer log data into a store
  with a different retention policy;
* model messages accumulated in state are the classic way an agent's context - and cost -
  grows without bound.

There is consequently no ``messages`` key here, and no field capable of holding a
credential, a prompt, or a raw tool response.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from asic.domain.enums import (
    EvidenceDomain,
    EvidenceFailureCategory,
    HypothesisStatus,
    InvestigationPhase,
    InvestigationStepStatus,
    NodeId,
    PlannerAction,
    ProvenanceLabel,
    ReflectionAction,
)

#: Longest headline retained in graph state for one piece of evidence. Enough for an
#: operator or a planner to tell two findings apart; far too short to be a copy of the
#: content.
HEADLINE_MAX_CHARS = 240


class _Frozen(BaseModel):
    """Immutable, strictly-validated base for every reference model in the state."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class EvidenceRef(_Frozen):
    """A pointer to one persisted evidence row.

    ``content_digest`` lets a resumed run detect that the referenced row changed without
    carrying the content, and ``injection_flagged`` travels with the reference so a
    downstream node does not have to re-read the row to know the content was suspicious.
    """

    evidence_id: str
    tool_execution_id: str
    domain: EvidenceDomain
    provenance: ProvenanceLabel
    headline: str = Field(max_length=HEADLINE_MAX_CHARS)
    content_digest: str
    quality_score: float = Field(ge=0.0, le=1.0)
    injection_flagged: bool = False


class StepRef(_Frozen):
    """A pointer to one persisted investigation step."""

    step_id: str
    sequence: int = Field(ge=1)
    domain: EvidenceDomain
    gap: str
    status: InvestigationStepStatus
    evidence_count: int = Field(ge=0)
    degradation_reason: str | None = None


class HypothesisRef(_Frozen):
    """A pointer to one persisted hypothesis, with the numbers routing depends on."""

    hypothesis_id: str
    rank: int = Field(ge=1)
    root_cause_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus
    supporting_evidence_count: int = Field(ge=0)
    contradicting_evidence_count: int = Field(ge=0)
    remaining_gaps: tuple[str, ...] = ()


class CandidateTask(_Frozen):
    """One option the planner weighed but did not necessarily choose.

    Recorded because ``docs/architecture/observability.md`` section 3.1 requires every
    decision span to carry the alternatives considered: without them, tool-call efficiency
    can be measured but never diagnosed.
    """

    domain: EvidenceDomain
    gap: str
    expected_gain: float = Field(ge=0.0, le=1.0)


class PlannerDecisionRef(_Frozen):
    """What the last planning step decided, and why."""

    action: PlannerAction
    gap: str
    rationale: str
    domain: EvidenceDomain | None = None
    expected_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    candidates: tuple[CandidateTask, ...] = ()
    #: Set when the deterministic guards overrode the model's choice - redundant
    #: collection, an ungranted capability, an exhausted budget.
    overridden_reason: str | None = None


class ReflectionDecisionRef(_Frozen):
    """What one bounded-reflection step decided, and why.

    Produced by the hypothesis engine's structured output and then passed through
    :func:`asic.orchestration.reflection.decide_reflection`, which is what makes ``action``
    here the *validated* decision rather than the model's raw proposal: ``overridden_reason``
    is set whenever the two differ, on exactly the same principle as
    :class:`PlannerDecisionRef.overridden_reason`.
    """

    action: ReflectionAction
    rationale: str
    #: The hypothesis a ``revise_hypothesis`` or ``collect_counter_evidence`` decision
    #: concerns. Checked against this run's persisted hypotheses before it is trusted;
    #: never a hypothesis id from anywhere else.
    target_hypothesis_id: str | None = None
    #: The information gap a non-terminal decision names. Folded into ``open_gaps`` so the
    #: next planning step sees it like any other gap.
    gap: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    #: Set when the deterministic guards in ``reflection.py`` overrode the model's proposed
    #: action - an unknown target id, a missing gap, or a terminal claim the evidence does
    #: not support.
    overridden_reason: str | None = None
    rule_id: str = ""


class NodeFailureRef(_Frozen):
    """A typed failure recorded against the run.

    ``recoverable`` is what the coordinator routes on. An unrecoverable failure terminates
    the run; a recoverable one degrades it and the investigation continues with less.
    """

    node_id: NodeId
    node_version: str
    error_type: str
    message: str
    recoverable: bool
    occurred_at: str
    stage: str | None = None
    #: Phase 7's distinguishing vocabulary (master specification section 8), additive to
    #: ``error_type`` rather than a replacement for it: no failure recorded before this
    #: field existed changes meaning, and a category is only ever added, never inferred
    #: retroactively from ``error_type`` text.
    category: EvidenceFailureCategory | None = None


class PendingApproval(_Frozen):
    """A durable human-approval wait.

    Present in the state because the approval interrupt is part of the workflow contract
    (master specification section 12) and a state shape that cannot express it would have
    to be changed to add it. **Nothing in the read-only kernel populates it**: there is no
    action to approve until remediation exists, so it is always ``None`` here today.
    """

    action_id: str
    action_version_hash: str
    required_role: str
    requested_at: str
    expires_at: str


class BudgetSnapshot(_Frozen):
    """Budget consumption and headroom, as of the last node boundary."""

    consumed: dict[str, float]
    remaining: dict[str, float]
    exhausted_kind: str | None = None


class TraceContext(_Frozen):
    """Correlation identifiers carried on every span and every persisted row."""

    trace_id: str
    root_span_id: str
    correlation_id: str


class RunIdentity(_Frozen):
    """Immutable identity of one orchestration run.

    Separated from the mutable working state because these values must be identical
    before and after a resume. The checkpoint loader compares them, and a mismatch is a
    hard failure rather than a silent rebind onto another incident.
    """

    tenant_id: str
    incident_id: str
    workflow_run_id: str
    behaviour_version_id: str
    environment_id: str
    execution_trace_id: str


class InvestigationObjective(_Frozen):
    """What this investigation is trying to establish, and within what bounds.

    The time window and the service set are the *scope*: they are resolved from the
    incident by the coordinator and are never taken from model output, which is what stops
    a planner widening its own reach by asking about a different service.
    """

    statement: str
    service_names: tuple[str, ...]
    environment_name: str
    window_start: str
    window_end: str
    severity: str


class GraphState(TypedDict, total=False):
    """The state LangGraph threads between nodes.

    ``total=False`` because a node returns a *partial* update; the reducers below merge it.
    The kernel validates every update against the emitting node's contract, so a node
    cannot write a key it did not declare.
    """

    identity: RunIdentity
    trace: TraceContext
    objective: InvestigationObjective

    phase: InvestigationPhase
    iteration: int
    resumed_count: int

    # Accumulating collections. ``operator.add`` appends rather than replaces, so a node
    # that gathers two pieces of evidence does not silently discard the first.
    evidence: Annotated[list[EvidenceRef], operator.add]
    steps: Annotated[list[StepRef], operator.add]
    hypotheses: Annotated[list[HypothesisRef], operator.add]
    failures: Annotated[list[NodeFailureRef], operator.add]

    # Replaced wholesale each time, because each is a current view rather than a history.
    open_gaps: list[str]
    covered_domains: list[str]
    degraded_domains: list[str]
    capability_menu: list[str]
    last_decision: PlannerDecisionRef | None
    #: The validated outcome of the last bounded-reflection step, if one has run yet.
    #: ``None`` until the hypothesis engine has formed at least one hypothesis - reflection
    #: has nothing to reflect on before then.
    reflection_decision: ReflectionDecisionRef | None
    budget: BudgetSnapshot
    #: Set when a node was *refused* a step because taking it would exhaust a budget. The
    #: ledger alone cannot express this: the refusal happens before the cost is paid, so a
    #: run stopped by a budget looks under-budget afterwards. Without this the terminator
    #: could not tell "we ran out of allowance" from "we ran out of ideas".
    budget_refusal: str | None

    pending_approval: PendingApproval | None

    terminated: bool
    termination_reason: str | None
    termination_rule_id: str | None
    terminal_incident_status: str | None


#: Every key the graph state may contain. Node contracts declare a subset of this as their
#: permitted mutations, and the kernel rejects an update touching anything outside it.
STATE_KEYS: frozenset[str] = frozenset(GraphState.__annotations__)

#: Keys that are fixed for the lifetime of a run. A node returning one of these is a bug:
#: identity must survive a resume unchanged, and an objective that drifts mid-run makes
#: the gathered evidence unattributable.
IMMUTABLE_STATE_KEYS: frozenset[str] = frozenset({"identity", "trace", "objective"})


def state_summary(state: GraphState) -> dict[str, Any]:
    """A compact, JSON-safe view of the state for span attributes and log lines.

    Counts and identifiers only. Passing the whole state to a logger would put untrusted
    headlines and gap text into telemetry, which is exactly the leak the reference-only
    design exists to prevent.
    """
    return {
        "phase": state.get("phase", InvestigationPhase.INITIALISING).value,
        "iteration": state.get("iteration", 0),
        "resumed_count": state.get("resumed_count", 0),
        "evidence_count": len(state.get("evidence", [])),
        "step_count": len(state.get("steps", [])),
        "hypothesis_count": len(state.get("hypotheses", [])),
        "failure_count": len(state.get("failures", [])),
        "open_gap_count": len(state.get("open_gaps", [])),
        "covered_domains": sorted(state.get("covered_domains", [])),
        "degraded_domains": sorted(state.get("degraded_domains", [])),
        "terminated": state.get("terminated", False),
        "termination_reason": state.get("termination_reason"),
    }


__all__ = [
    "HEADLINE_MAX_CHARS",
    "IMMUTABLE_STATE_KEYS",
    "STATE_KEYS",
    "BudgetSnapshot",
    "CandidateTask",
    "EvidenceRef",
    "GraphState",
    "HypothesisRef",
    "InvestigationObjective",
    "NodeFailureRef",
    "PendingApproval",
    "PlannerDecisionRef",
    "ReflectionDecisionRef",
    "RunIdentity",
    "StepRef",
    "TraceContext",
    "state_summary",
]
