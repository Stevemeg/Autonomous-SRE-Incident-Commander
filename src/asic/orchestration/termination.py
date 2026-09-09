"""Deterministic termination.

Master specification section 5: *"Every run must terminate through success, uncertainty,
timeout, failure or human escalation."* This module is the only place that decides which,
and it is a pure function - no model, no clock read, no database.

The rule set has three properties that are asserted by the tests rather than assumed:

**It is ordered.** The first matching rule wins, and the order encodes precedence:
unrecoverable failure outranks a timeout, a timeout outranks exhaustion, exhaustion
outranks a weak conclusion. Getting the order wrong would report "insufficient evidence"
for a run that actually crashed.

**It is total.** The last rule matches unconditionally. There is no fall-through and no
implicit default: a run always leaves here with a verdict, and the verdict always names the
rule that produced it, so an operator asking "why did it stop?" gets a rule id rather than
an inference.

**Success is not reachable here, and that is correct.** The read-only kernel gathers
evidence and forms hypotheses; it cannot remediate and therefore cannot verify that
anything was fixed. An actionable cause is handed to a human - which is the ``escalated``
outcome, one of section 5's five. Reporting ``resolved`` would be claiming an outcome the
system did not produce.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from asic.contracts.state import HypothesisRef, NodeFailureRef
from asic.domain.budget import BudgetState, termination_reason_for
from asic.domain.enums import (
    BudgetKind,
    EvidenceDomain,
    HypothesisStatus,
    IncidentStatus,
    PlannerAction,
    TerminationReason,
)

#: A hypothesis below this confidence is not treated as an actionable conclusion. Set
#: conservatively: the cost of escalating a weak hypothesis to a human is an interruption,
#: while the cost of presenting one as an answer is a misdirected response.
MIN_ACTIONABLE_CONFIDENCE: Final[float] = 0.55

#: Below this many evidence records, no conclusion is actionable regardless of how
#: confident the model claimed to be. Guards the "confident answer from nothing" failure.
MIN_EVIDENCE_FOR_CONCLUSION: Final[int] = 2

#: Fraction of the domains the planner declared gaps in that must have been answered before
#: a conclusion is treated as adequately grounded.
MIN_DOMAIN_COVERAGE: Final[float] = 0.5


@dataclass(frozen=True, slots=True)
class TerminationInputs:
    """Everything the decision depends on. No other state may influence it."""

    budget: BudgetState
    hypotheses: Sequence[HypothesisRef]
    evidence_count: int
    failures: Sequence[NodeFailureRef]
    degraded_domains: Sequence[str]
    attempted_domains: Sequence[str]
    planner_action: PlannerAction | None
    open_gaps: Sequence[str]
    #: The budget dimension a node was refused on, if any. Distinct from an exhausted
    #: ledger because the refusal happens *before* the cost is paid, so the ledger still
    #: shows headroom afterwards.
    budget_refusal: BudgetKind | None = None

    @property
    def unrecoverable_failures(self) -> tuple[NodeFailureRef, ...]:
        return tuple(f for f in self.failures if not f.recoverable)

    @property
    def best_hypothesis(self) -> HypothesisRef | None:
        candidates = [
            h
            for h in self.hypotheses
            if h.status in (HypothesisStatus.PROPOSED, HypothesisStatus.ACCEPTED)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda h: (h.confidence, -h.rank))

    @property
    def domain_coverage(self) -> float:
        """Fraction of the domains attempted that actually produced evidence."""
        attempted = set(self.attempted_domains)
        if not attempted:
            return 0.0
        degraded = set(self.degraded_domains)
        return len(attempted - degraded) / len(attempted)


@dataclass(frozen=True, slots=True)
class TerminationVerdict:
    """The decision, with the rule that produced it."""

    should_terminate: bool
    rule_id: str
    reason: TerminationReason | None = None
    incident_status: IncidentStatus | None = None
    explanation: str = ""


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    matches: Callable[[TerminationInputs], bool]
    verdict: Callable[[TerminationInputs], TerminationVerdict]


def _unrecoverable(inputs: TerminationInputs) -> TerminationVerdict:
    first = inputs.unrecoverable_failures[0]
    return TerminationVerdict(
        should_terminate=True,
        rule_id="R1_unrecoverable_failure",
        reason=TerminationReason.UNRECOVERABLE_FAILURE,
        incident_status=IncidentStatus.FAILED,
        explanation=(
            f"{first.node_id.value} failed unrecoverably ({first.error_type}); the run "
            "cannot continue and is not retried"
        ),
    )


def _budget(inputs: TerminationInputs) -> TerminationVerdict:
    kind = inputs.budget.exhausted_kind() or inputs.budget_refusal
    assert kind is not None  # guarded by the rule's predicate
    reason = termination_reason_for(kind)
    return TerminationVerdict(
        should_terminate=True,
        rule_id=(
            "R2_wall_clock_timeout"
            if reason is TerminationReason.WALL_CLOCK_TIMEOUT
            else "R3_budget_exhausted"
        ),
        reason=reason,
        incident_status=IncidentStatus.UNCERTAIN,
        explanation=(
            f"the {kind.value} budget was exhausted; the investigation stops with the "
            f"{inputs.evidence_count} evidence record(s) it had gathered"
        ),
    )


def _actionable(inputs: TerminationInputs) -> TerminationVerdict:
    best = inputs.best_hypothesis
    assert best is not None  # guarded by the rule's predicate
    return TerminationVerdict(
        should_terminate=True,
        rule_id="R4_actionable_cause_escalated",
        reason=TerminationReason.HUMAN_ESCALATION,
        incident_status=IncidentStatus.ESCALATED,
        explanation=(
            f"a hypothesis ({best.root_cause_class}, confidence {best.confidence:.2f}) is "
            f"supported by {best.supporting_evidence_count} evidence record(s) and is "
            "handed to a human: this deployment cannot remediate or verify, so it does not "
            "claim resolution"
        ),
    )


def _planner_stopped(inputs: TerminationInputs) -> TerminationVerdict:
    best = inputs.best_hypothesis
    detail = (
        f"the strongest hypothesis reached confidence {best.confidence:.2f} with "
        f"{best.supporting_evidence_count} supporting and "
        f"{best.contradicting_evidence_count} contradicting record(s)"
        if best is not None
        else "no hypothesis could be formed from the evidence gathered"
    )
    return TerminationVerdict(
        should_terminate=True,
        rule_id="R5_planner_terminated_without_conclusion",
        reason=TerminationReason.INSUFFICIENT_EVIDENCE,
        incident_status=IncidentStatus.UNCERTAIN,
        explanation=f"the planner stopped and {detail}",
    )


def _continue(_: TerminationInputs) -> TerminationVerdict:
    return TerminationVerdict(should_terminate=False, rule_id="R6_continue")


def _is_actionable(inputs: TerminationInputs) -> bool:
    """Whether the evidence genuinely supports handing a cause to a human.

    Four conditions, all necessary. The model's stated confidence is only one of them, and
    on its own it is the weakest: a confident claim over one piece of evidence with a
    contradiction outstanding is the exact shape of failure F4.
    """
    best = inputs.best_hypothesis
    if best is None:
        return False
    return (
        best.confidence >= MIN_ACTIONABLE_CONFIDENCE
        and best.supporting_evidence_count >= MIN_EVIDENCE_FOR_CONCLUSION
        and best.contradicting_evidence_count == 0
        and inputs.domain_coverage >= MIN_DOMAIN_COVERAGE
    )


#: Ordered, total. Evaluated top to bottom; the last rule always matches.
RULES: Final[tuple[_Rule, ...]] = (
    _Rule("R1_unrecoverable_failure", lambda i: bool(i.unrecoverable_failures), _unrecoverable),
    _Rule(
        "R2_R3_budget",
        lambda i: i.budget.is_exhausted() or i.budget_refusal is not None,
        _budget,
    ),
    _Rule(
        "R4_actionable_cause_escalated",
        lambda i: i.planner_action is PlannerAction.TERMINATE and _is_actionable(i),
        _actionable,
    ),
    _Rule(
        "R5_planner_terminated_without_conclusion",
        lambda i: i.planner_action is PlannerAction.TERMINATE,
        _planner_stopped,
    ),
    _Rule("R6_continue", lambda _: True, _continue),
)


def decide(inputs: TerminationInputs) -> TerminationVerdict:
    """Apply the rule set. Always returns a verdict naming its rule."""
    for rule in RULES:
        if rule.matches(inputs):
            return rule.verdict(inputs)
    # Unreachable: R6 matches unconditionally. Raising rather than defaulting means a
    # future edit that removes the catch-all fails loudly instead of silently changing
    # what "the run did not stop" means.
    raise AssertionError(
        "the termination rule set failed to match; it is required to be total and the "
        "final rule must match unconditionally"
    )


def domains_of(values: Sequence[str]) -> tuple[EvidenceDomain, ...]:
    """Parse domain names, ignoring anything unrecognised rather than failing a run."""
    parsed: list[EvidenceDomain] = []
    for value in values:
        try:
            parsed.append(EvidenceDomain(value))
        except ValueError:
            continue
    return tuple(parsed)


__all__ = [
    "MIN_ACTIONABLE_CONFIDENCE",
    "MIN_DOMAIN_COVERAGE",
    "MIN_EVIDENCE_FOR_CONCLUSION",
    "RULES",
    "TerminationInputs",
    "TerminationVerdict",
    "decide",
    "domains_of",
]
