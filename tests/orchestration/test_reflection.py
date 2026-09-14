"""Bounded reflection: the model's proposal is a proposal, never a decision.

Master specification section 3 requires reflection to be bounded rather than an unrestricted
recursive loop, and requires its terminal outcomes to land in exactly the five categories
:mod:`asic.orchestration.termination` already knows, never a sixth. These tests assert the
guard chain in :mod:`asic.orchestration.reflection` is total (every input yields a verdict),
and - the point that matters most - that each guard actually rejects the proposal it exists
to reject: a fabricated hypothesis id, a revision with nothing to supersede onto, a claimed
success the evidence does not support, an escalation with nothing to escalate.
"""

from __future__ import annotations

import itertools

from asic.contracts.state import HypothesisRef
from asic.domain.enums import HypothesisStatus, ReflectionAction
from asic.orchestration.reflection import (
    ReflectionInputs,
    ReflectionProposal,
    decide_reflection,
)


def _hyp(
    *,
    hypothesis_id: str = "h-1",
    rank: int = 1,
    confidence: float = 0.9,
    supporting: int = 3,
    contradicting: int = 0,
    status: HypothesisStatus = HypothesisStatus.PROPOSED,
) -> HypothesisRef:
    return HypothesisRef(
        hypothesis_id=hypothesis_id,
        rank=rank,
        root_cause_class="bad_deployment",
        confidence=confidence,
        status=status,
        supporting_evidence_count=supporting,
        contradicting_evidence_count=contradicting,
    )


def _inputs(**overrides: object) -> ReflectionInputs:
    defaults: dict[str, object] = {
        "proposal": ReflectionProposal(action=None, rationale=""),
        "hypotheses": [],
        "new_hypothesis_ids": frozenset(),
        "open_gaps": [],
        "degraded_domains": [],
        "attempted_domains": [],
    }
    defaults.update(overrides)
    return ReflectionInputs(**defaults)  # type: ignore[arg-type]


class TestTotality:
    def test_every_combination_yields_a_verdict(self) -> None:
        proposals = [
            ReflectionProposal(action=None, rationale=""),
            *(
                ReflectionProposal(
                    action=action,
                    rationale="because",
                    target_hypothesis_id="h-1",
                    gap="a gap",
                )
                for action in ReflectionAction
            ),
        ]
        hypothesis_sets: list[list[HypothesisRef]] = [
            [],
            [_hyp(confidence=0.9)],
            [_hyp(confidence=0.2, supporting=1)],
        ]
        gap_sets: list[list[str]] = [[], ["remaining gap"]]

        for proposal, hypotheses, gaps in itertools.product(proposals, hypothesis_sets, gap_sets):
            verdict = decide_reflection(
                _inputs(
                    proposal=proposal,
                    hypotheses=hypotheses,
                    new_hypothesis_ids=frozenset(h.hypothesis_id for h in hypotheses),
                    open_gaps=gaps,
                    attempted_domains=["metrics", "logs"],
                )
            )
            assert verdict.rule_id, "every verdict names the rule that produced it"
            assert isinstance(verdict.action, ReflectionAction)

    def test_a_verdict_never_proposes_an_action_outside_the_enum(self) -> None:
        verdict = decide_reflection(_inputs())
        assert verdict.action in set(ReflectionAction)


class TestUnknownTarget:
    def test_a_fabricated_hypothesis_id_is_rejected_for_revision(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id="00000000-0000-0000-0000-000000000099",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
                open_gaps=["a real gap"],
            )
        )
        assert verdict.rule_id == "G1_unknown_target"
        assert verdict.action is not ReflectionAction.REVISE_HYPOTHESIS
        assert verdict.overridden_reason is not None

    def test_a_fabricated_hypothesis_id_is_rejected_for_counter_evidence(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.COLLECT_COUNTER_EVIDENCE,
                    rationale="because",
                    target_hypothesis_id="not-a-real-id",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
            )
        )
        assert verdict.rule_id == "G1_unknown_target"

    def test_an_evidence_id_smuggled_in_as_a_hypothesis_id_is_rejected(self) -> None:
        # The exact shape of a forged-provenance attempt: an id that is real *somewhere*,
        # just not among this run's hypotheses.
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id="evidence-id-not-a-hypothesis",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
                new_hypothesis_ids=frozenset({"h-1"}),
            )
        )
        assert verdict.rule_id == "G1_unknown_target"

    def test_a_missing_target_is_rejected(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id=None,
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
            )
        )
        assert verdict.rule_id == "G1_missing_target"

    def test_a_valid_target_is_not_rejected_by_this_guard(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.COLLECT_COUNTER_EVIDENCE,
                    rationale="because",
                    target_hypothesis_id="h-1",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
            )
        )
        assert verdict.rule_id != "G1_unknown_target"
        assert verdict.rule_id != "G1_missing_target"


class TestRevisionNeedsAReplacement:
    def test_revising_with_no_newly_formed_hypothesis_is_rejected(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id="h-1",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
                new_hypothesis_ids=frozenset(),  # nothing new this step
            )
        )
        assert verdict.rule_id == "G2_no_replacement_hypothesis"
        assert verdict.action is not ReflectionAction.REVISE_HYPOTHESIS

    def test_a_hypothesis_cannot_supersede_itself(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id="h-1",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
                # "h-1" is the only new id, and it is also the target: no distinct
                # replacement exists.
                new_hypothesis_ids=frozenset({"h-1"}),
            )
        )
        assert verdict.rule_id == "G2_no_replacement_hypothesis"

    def test_an_already_superseded_hypothesis_cannot_be_superseded_again(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="because",
                    target_hypothesis_id="h-1",
                ),
                hypotheses=[
                    _hyp(hypothesis_id="h-1", status=HypothesisStatus.SUPERSEDED),
                    _hyp(hypothesis_id="h-2"),
                ],
                new_hypothesis_ids=frozenset({"h-2"}),
            )
        )
        assert verdict.rule_id == "G2_no_replacement_hypothesis"

    def test_a_genuine_replacement_is_accepted(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.REVISE_HYPOTHESIS,
                    rationale="the new evidence contradicts the old cause",
                    target_hypothesis_id="h-1",
                ),
                hypotheses=[_hyp(hypothesis_id="h-1"), _hyp(hypothesis_id="h-2", rank=2)],
                new_hypothesis_ids=frozenset({"h-2"}),
            )
        )
        assert verdict.action is ReflectionAction.REVISE_HYPOTHESIS
        assert verdict.target_hypothesis_id == "h-1"
        assert verdict.rule_id == "G6_accepted"
        assert verdict.overridden_reason is None


class TestTerminalClaimsAreBounded:
    def test_terminate_success_without_actionable_evidence_is_downgraded(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.TERMINATE_SUCCESS,
                    rationale="I am confident",
                ),
                hypotheses=[_hyp(confidence=0.99, supporting=1)],  # single-support, thin
                attempted_domains=["metrics"],
            )
        )
        assert verdict.action is not ReflectionAction.TERMINATE_SUCCESS
        assert verdict.rule_id == "G4_not_actionable"

    def test_terminate_success_with_actionable_evidence_is_accepted(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.TERMINATE_SUCCESS,
                    rationale="well supported",
                ),
                hypotheses=[_hyp(confidence=0.9, supporting=3, contradicting=0)],
                attempted_domains=["metrics", "logs", "deployments"],
            )
        )
        assert verdict.action is ReflectionAction.TERMINATE_SUCCESS
        assert verdict.rule_id == "G6_accepted"

    def test_a_contradicted_hypothesis_cannot_be_claimed_successful(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.TERMINATE_SUCCESS,
                    rationale="",
                ),
                hypotheses=[_hyp(confidence=0.95, supporting=4, contradicting=1)],
                attempted_domains=["metrics", "logs"],
            )
        )
        assert verdict.rule_id == "G4_not_actionable"

    def test_escalate_with_nothing_to_escalate_is_downgraded(self) -> None:
        verdict = decide_reflection(
            _inputs(proposal=ReflectionProposal(action=ReflectionAction.ESCALATE, rationale=""))
        )
        assert verdict.action is ReflectionAction.TERMINATE_UNCERTAIN
        assert verdict.rule_id == "G5_nothing_to_escalate"

    def test_escalate_with_a_hypothesis_is_accepted_regardless_of_actionability(self) -> None:
        # Escalation, unlike terminate_success, does not claim the cause is proven - it asks
        # a human to look, which is legitimate even over a weak hypothesis.
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(action=ReflectionAction.ESCALATE, rationale=""),
                hypotheses=[_hyp(confidence=0.2, supporting=1)],
            )
        )
        assert verdict.action is ReflectionAction.ESCALATE
        assert verdict.rule_id == "G6_accepted"


class TestContinuation:
    def test_continue_with_no_gap_anywhere_is_downgraded(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.CONTINUE_WITH_GAP, rationale="", gap=None
                ),
                open_gaps=[],
            )
        )
        assert verdict.action is not ReflectionAction.CONTINUE_WITH_GAP
        assert verdict.rule_id == "G3_no_gap_to_continue_on"

    def test_continue_falls_back_to_an_open_gap_when_none_is_proposed(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.CONTINUE_WITH_GAP, rationale="", gap=None
                ),
                open_gaps=["the remaining gap"],
            )
        )
        assert verdict.action is ReflectionAction.CONTINUE_WITH_GAP
        assert verdict.gap == "the remaining gap"

    def test_collect_counter_evidence_synthesises_a_gap_when_none_is_given(self) -> None:
        verdict = decide_reflection(
            _inputs(
                proposal=ReflectionProposal(
                    action=ReflectionAction.COLLECT_COUNTER_EVIDENCE,
                    rationale="",
                    target_hypothesis_id="h-1",
                    gap=None,
                ),
                hypotheses=[_hyp(hypothesis_id="h-1")],
            )
        )
        assert verdict.action is ReflectionAction.COLLECT_COUNTER_EVIDENCE
        assert verdict.gap
        assert "h-1" in verdict.gap


class TestNoProposal:
    def test_a_missing_proposal_does_not_silently_continue(self) -> None:
        verdict = decide_reflection(_inputs(open_gaps=["a gap"]))
        assert verdict.rule_id == "G0_no_proposal"
        # It still lands somewhere sensible (there is a gap), but the *reason* is recorded
        # as a guard rejection, not indistinguishable from a real continue decision.
        assert verdict.overridden_reason is not None

    def test_a_missing_proposal_with_nothing_open_terminates_uncertain(self) -> None:
        verdict = decide_reflection(_inputs())
        assert verdict.action is ReflectionAction.TERMINATE_UNCERTAIN
        assert verdict.rule_id == "G0_no_proposal"


def test_disabling_the_actionability_guard_would_let_an_unsupported_success_through() -> None:
    """Mutation check: the guard is not vacuous - removing it changes the outcome.

    If this test cannot demonstrate a difference, ``G4_not_actionable`` is not doing
    anything, and the earlier assertion that it downgrades an unsupported claim would be
    testing nothing.
    """
    import asic.orchestration.reflection as reflection_module

    weak = [_hyp(confidence=0.99, supporting=1)]
    proposal = ReflectionProposal(action=ReflectionAction.TERMINATE_SUCCESS, rationale="")
    guarded = decide_reflection(
        _inputs(proposal=proposal, hypotheses=weak, attempted_domains=["metrics"])
    )
    assert guarded.action is not ReflectionAction.TERMINATE_SUCCESS

    import unittest.mock as mock

    with mock.patch.object(reflection_module, "is_actionable", return_value=True):
        unguarded = decide_reflection(
            _inputs(proposal=proposal, hypotheses=weak, attempted_domains=["metrics"])
        )
    assert unguarded.action is ReflectionAction.TERMINATE_SUCCESS, (
        "with the guard disabled the same weak evidence is accepted, proving the guard - "
        "not something else - is what stopped it before"
    )
