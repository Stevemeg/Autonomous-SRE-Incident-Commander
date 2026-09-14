"""Bounded reflection: the explicit control loop over what the hypothesis engine just formed.

Master specification section 3 requires a bounded reflection step that can continue, seek
counter-evidence, revise a hypothesis, or end the run - and requires that it be *bounded*:
not an unrestricted recursive loop, and not a sixth, ambiguous way for a run to stop. This
module is where a model's reflection proposal becomes a decision, on exactly the pattern
``asic.orchestration.nodes.planner`` already uses for the planner's own proposal:

    **The model's choice is a proposal. A deterministic guard can override it, and every
    override is recorded with a reason.**

Nothing here is a second termination authority. The three terminal members of
:class:`~asic.domain.enums.ReflectionAction` (``terminate_success``, ``terminate_uncertain``,
``escalate``) are validated *inputs* to ``asic.orchestration.termination.decide`` - the same
function the planner's own ``TERMINATE`` action feeds - so a run driven by reflection still
ends in exactly one of the five categories in
:class:`~asic.domain.enums.TerminationReason`, never in an outcome this module invents.

The four non-vacuous guards, in the order they are applied:

1. **An unknown target is not trusted.** ``revise_hypothesis`` and
   ``collect_counter_evidence`` name a hypothesis; the name is checked against this run's own
   persisted hypotheses before anything is done with it. A model that names a hypothesis
   from another run, an evidence id, or a fabricated id is refused exactly as an unsupported
   citation is refused in the hypothesis engine - not repaired, not partially trusted.
2. **A revision needs a replacement.** ``revise_hypothesis`` supersedes a hypothesis with a
   *better* one; without a hypothesis newly accepted this same step to supersede it with,
   there is nothing to revise onto, and the proposal is downgraded.
3. **A terminal claim of success must clear the same bar an escalation from the planner
   does.** ``terminate_success`` is downgraded to ``terminate_uncertain`` unless
   ``termination.is_actionable`` agrees - the model cannot manufacture certainty by choosing
   reflection's vocabulary instead of the planner's.
4. **Escalation needs something to escalate.** ``escalate`` with no hypothesis at all is
   downgraded to ``terminate_uncertain``: there is nothing to hand to a human.

Every path is total: :func:`decide_reflection` always returns a verdict naming the rule that
produced it, including when the model proposed nothing at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from asic.contracts.state import HypothesisRef
from asic.domain.enums import HypothesisStatus, ReflectionAction
from asic.orchestration.termination import best_hypothesis_of, domain_coverage_of, is_actionable

#: The two actions that name a hypothesis and therefore require one that actually exists.
_TARGETED_ACTIONS: tuple[ReflectionAction, ...] = (
    ReflectionAction.REVISE_HYPOTHESIS,
    ReflectionAction.COLLECT_COUNTER_EVIDENCE,
)


@dataclass(frozen=True, slots=True)
class ReflectionProposal:
    """What the model proposed, exactly as it proposed it - not yet believed."""

    action: ReflectionAction | None
    rationale: str
    target_hypothesis_id: str | None = None
    gap: str | None = None
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class ReflectionInputs:
    """Everything the decision depends on. No other state may influence it."""

    proposal: ReflectionProposal
    #: This run's hypotheses, current statuses, *after* this step's own persistence.
    hypotheses: Sequence[HypothesisRef]
    #: Ids accepted during this same step - the only hypotheses ``revise_hypothesis`` may
    #: supersede onto, because they are the only ones that could be "better" than a
    #: hypothesis this same evidence has already been weighed against.
    new_hypothesis_ids: frozenset[str]
    open_gaps: Sequence[str]
    degraded_domains: Sequence[str]
    attempted_domains: Sequence[str]

    @property
    def known_hypothesis_ids(self) -> frozenset[str]:
        return frozenset(h.hypothesis_id for h in self.hypotheses)

    @property
    def best_hypothesis(self) -> HypothesisRef | None:
        return best_hypothesis_of(self.hypotheses)

    @property
    def domain_coverage(self) -> float:
        return domain_coverage_of(self.attempted_domains, self.degraded_domains)

    def hypothesis(self, hypothesis_id: str) -> HypothesisRef | None:
        for h in self.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                return h
        return None


@dataclass(frozen=True, slots=True)
class ReflectionVerdict:
    """The validated decision, with the rule that produced it."""

    action: ReflectionAction
    rationale: str
    target_hypothesis_id: str | None
    gap: str | None
    confidence: float
    rule_id: str
    overridden_reason: str | None = None


def _fallback(inputs: ReflectionInputs, *, rule_id: str, reason: str) -> ReflectionVerdict:
    """Where a rejected proposal lands: continue on an open gap, escalate, or give up.

    The same three-way ladder every guard below falls back to, so "what happens when a
    proposal is refused" has one answer rather than one per guard.
    """
    if inputs.open_gaps:
        return ReflectionVerdict(
            action=ReflectionAction.CONTINUE_WITH_GAP,
            rationale=reason,
            target_hypothesis_id=None,
            gap=inputs.open_gaps[0],
            confidence=0.0,
            rule_id=rule_id,
            overridden_reason=reason,
        )
    if is_actionable(best=inputs.best_hypothesis, domain_coverage=inputs.domain_coverage):
        return ReflectionVerdict(
            action=ReflectionAction.ESCALATE,
            rationale=reason,
            target_hypothesis_id=None,
            gap=None,
            confidence=0.0,
            rule_id=rule_id,
            overridden_reason=reason,
        )
    return ReflectionVerdict(
        action=ReflectionAction.TERMINATE_UNCERTAIN,
        rationale=reason,
        target_hypothesis_id=None,
        gap=None,
        confidence=0.0,
        rule_id=rule_id,
        overridden_reason=reason,
    )


def decide_reflection(inputs: ReflectionInputs) -> ReflectionVerdict:
    """Turn a model's reflection proposal into a validated decision. Always returns one."""
    proposal = inputs.proposal

    # G0: no proposal at all - a missing or unparseable reflection block is not silently
    # treated as "continue"; it falls through the same ladder every other refusal does.
    if proposal.action is None:
        return _fallback(
            inputs,
            rule_id="G0_no_proposal",
            reason="no reflection decision was proposed for this step",
        )

    # G1: a targeted action naming a hypothesis this run never persisted is not trusted,
    # exactly as an unsupported evidence citation is not trusted in the hypothesis engine.
    if proposal.action in _TARGETED_ACTIONS:
        if not proposal.target_hypothesis_id:
            return _fallback(
                inputs,
                rule_id="G1_missing_target",
                reason=f"{proposal.action.value} was proposed with no target hypothesis id",
            )
        if proposal.target_hypothesis_id not in inputs.known_hypothesis_ids:
            return _fallback(
                inputs,
                rule_id="G1_unknown_target",
                reason=(
                    f"{proposal.action.value} named hypothesis "
                    f"{proposal.target_hypothesis_id!r}, which this run has not persisted; "
                    "the target is rejected rather than trusted"
                ),
            )

    # G2: a revision needs a hypothesis actually formed this step to supersede onto - not
    # itself, and not one already superseded.
    if proposal.action is ReflectionAction.REVISE_HYPOTHESIS:
        assert proposal.target_hypothesis_id is not None  # guarded by G1
        target = inputs.hypothesis(proposal.target_hypothesis_id)
        replacement_exists = bool(inputs.new_hypothesis_ids - {proposal.target_hypothesis_id})
        already_superseded = target is not None and target.status is HypothesisStatus.SUPERSEDED
        if not replacement_exists or already_superseded:
            return _fallback(
                inputs,
                rule_id="G2_no_replacement_hypothesis",
                reason=(
                    "revise_hypothesis was proposed but no newly formed hypothesis exists to "
                    "supersede the target with"
                    if not replacement_exists
                    else f"hypothesis {proposal.target_hypothesis_id!r} is already superseded"
                ),
            )
        return ReflectionVerdict(
            action=ReflectionAction.REVISE_HYPOTHESIS,
            rationale=proposal.rationale,
            target_hypothesis_id=proposal.target_hypothesis_id,
            gap=proposal.gap,
            confidence=proposal.confidence,
            rule_id="G6_accepted",
        )

    # G3: continuing needs something to continue on.
    if proposal.action is ReflectionAction.CONTINUE_WITH_GAP:
        gap = proposal.gap or (inputs.open_gaps[0] if inputs.open_gaps else None)
        if not gap:
            return _fallback(
                inputs,
                rule_id="G3_no_gap_to_continue_on",
                reason="continue_with_gap was proposed with no open gap and none remaining",
            )
        return ReflectionVerdict(
            action=ReflectionAction.CONTINUE_WITH_GAP,
            rationale=proposal.rationale,
            target_hypothesis_id=None,
            gap=gap,
            confidence=proposal.confidence,
            rule_id="G6_accepted",
        )

    # Counter-evidence collection always has a gap to hand the planner, synthesised when the
    # model did not supply one - this is a default, not a rejection, so it is not routed
    # through _fallback.
    if proposal.action is ReflectionAction.COLLECT_COUNTER_EVIDENCE:
        gap = proposal.gap or (
            f"evidence that would contradict hypothesis {proposal.target_hypothesis_id}"
        )
        return ReflectionVerdict(
            action=ReflectionAction.COLLECT_COUNTER_EVIDENCE,
            rationale=proposal.rationale,
            target_hypothesis_id=proposal.target_hypothesis_id,
            gap=gap,
            confidence=proposal.confidence,
            rule_id="G6_accepted",
        )

    # G4: a success claim must clear the same bar the planner's own TERMINATE does.
    if proposal.action is ReflectionAction.TERMINATE_SUCCESS:
        if not is_actionable(best=inputs.best_hypothesis, domain_coverage=inputs.domain_coverage):
            return _fallback(
                inputs,
                rule_id="G4_not_actionable",
                reason=(
                    "terminate_success was proposed but the evidence does not meet the "
                    "actionability bar (confidence, support, contradiction and coverage)"
                ),
            )
        return ReflectionVerdict(
            action=ReflectionAction.TERMINATE_SUCCESS,
            rationale=proposal.rationale,
            target_hypothesis_id=None,
            gap=None,
            confidence=proposal.confidence,
            rule_id="G6_accepted",
        )

    # G5: escalation needs a hypothesis to hand to a human.
    if proposal.action is ReflectionAction.ESCALATE:
        if inputs.best_hypothesis is None:
            return _fallback(
                inputs,
                rule_id="G5_nothing_to_escalate",
                reason="escalate was proposed but no hypothesis exists to escalate",
            )
        return ReflectionVerdict(
            action=ReflectionAction.ESCALATE,
            rationale=proposal.rationale,
            target_hypothesis_id=None,
            gap=None,
            confidence=proposal.confidence,
            rule_id="G6_accepted",
        )

    # TERMINATE_UNCERTAIN needs no guard: the model claiming uncertainty is never a claim
    # that must be checked, because it asserts nothing that could be wrong.
    assert proposal.action is ReflectionAction.TERMINATE_UNCERTAIN
    return ReflectionVerdict(
        action=ReflectionAction.TERMINATE_UNCERTAIN,
        rationale=proposal.rationale,
        target_hypothesis_id=None,
        gap=None,
        confidence=proposal.confidence,
        rule_id="G6_accepted",
    )


__all__ = [
    "ReflectionInputs",
    "ReflectionProposal",
    "ReflectionVerdict",
    "decide_reflection",
]
