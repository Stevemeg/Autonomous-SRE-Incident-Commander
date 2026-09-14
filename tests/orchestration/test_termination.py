"""The termination rule set is ordered, total, and does not claim success.

Master specification section 5 requires every run to end in one of five categories. These
tests assert that it always ends in exactly one, that precedence is right, and - the point
that matters most - that a confident hypothesis over thin or contradicted evidence is not
escalated as an answer.
"""

from __future__ import annotations

import itertools

import pytest

from asic.contracts.state import HypothesisRef, NodeFailureRef
from asic.domain.budget import BudgetLedger, BudgetPolicy, BudgetState
from asic.domain.enums import (
    HypothesisStatus,
    IncidentStatus,
    NodeId,
    PlannerAction,
    ReflectionAction,
    TerminationReason,
)
from asic.orchestration.termination import (
    MIN_ACTIONABLE_CONFIDENCE,
    RULES,
    TerminationInputs,
    best_hypothesis_of,
    decide,
)


def _hypothesis(
    *,
    confidence: float = 0.9,
    supporting: int = 3,
    contradicting: int = 0,
    rank: int = 1,
    status: HypothesisStatus = HypothesisStatus.PROPOSED,
) -> HypothesisRef:
    return HypothesisRef(
        hypothesis_id=f"h-{rank}",
        rank=rank,
        root_cause_class="bad_deployment",
        confidence=confidence,
        status=status,
        supporting_evidence_count=supporting,
        contradicting_evidence_count=contradicting,
    )


def _failure(*, recoverable: bool) -> NodeFailureRef:
    return NodeFailureRef(
        node_id=NodeId.G4_EVIDENCE_COLLECTOR,
        node_version="1.0.0",
        error_type="EvidenceUnavailable",
        message="the log backend refused the query",
        recoverable=recoverable,
        occurred_at="2026-09-07T10:00:00+00:00",
    )


def _inputs(**overrides: object) -> TerminationInputs:
    defaults: dict[str, object] = {
        "budget": BudgetState.initial(),
        "hypotheses": [],
        "evidence_count": 0,
        "failures": [],
        "degraded_domains": [],
        "attempted_domains": [],
        "planner_action": None,
        "open_gaps": [],
    }
    defaults.update(overrides)
    return TerminationInputs(**defaults)  # type: ignore[arg-type]


class TestTotality:
    def test_the_final_rule_matches_unconditionally(self) -> None:
        assert RULES[-1].matches(_inputs()) is True

    def test_every_combination_of_inputs_yields_a_verdict(self) -> None:
        # Exhaustive over the shape of the inputs, not over their values: the point is that
        # no combination falls through the rule set.
        budgets = [
            BudgetState.initial(),
            BudgetState(policy=BudgetPolicy(max_iterations=1), ledger=BudgetLedger(iterations=1)),
        ]
        hypothesis_sets: list[list[HypothesisRef]] = [
            [],
            [_hypothesis(confidence=0.9)],
            [_hypothesis(confidence=0.2, supporting=1)],
            [_hypothesis(confidence=0.9, contradicting=2)],
        ]
        failure_sets: list[list[NodeFailureRef]] = [
            [],
            [_failure(recoverable=True)],
            [_failure(recoverable=False)],
        ]
        actions: list[PlannerAction | None] = [None, *PlannerAction]

        for budget, hypotheses, failures, action in itertools.product(
            budgets, hypothesis_sets, failure_sets, actions
        ):
            verdict = decide(
                _inputs(
                    budget=budget,
                    hypotheses=hypotheses,
                    failures=failures,
                    planner_action=action,
                    evidence_count=len(hypotheses) * 2,
                    attempted_domains=["metrics", "logs"],
                )
            )
            assert verdict.rule_id, "every verdict names the rule that produced it"
            if verdict.should_terminate:
                assert verdict.reason is not None
                assert verdict.incident_status is not None

    def test_a_terminal_verdict_always_carries_a_reason_and_a_status(self) -> None:
        verdict = decide(_inputs(planner_action=PlannerAction.TERMINATE))
        assert verdict.should_terminate
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE
        assert verdict.incident_status is IncidentStatus.UNCERTAIN


class TestPrecedence:
    def test_an_unrecoverable_failure_outranks_everything(self) -> None:
        verdict = decide(
            _inputs(
                failures=[_failure(recoverable=False)],
                budget=BudgetState(
                    policy=BudgetPolicy(max_iterations=1), ledger=BudgetLedger(iterations=5)
                ),
                hypotheses=[_hypothesis()],
                planner_action=PlannerAction.TERMINATE,
            )
        )
        assert verdict.reason is TerminationReason.UNRECOVERABLE_FAILURE
        assert verdict.incident_status is IncidentStatus.FAILED

    def test_a_recoverable_failure_does_not_terminate_the_run(self) -> None:
        verdict = decide(_inputs(failures=[_failure(recoverable=True)]))
        assert verdict.should_terminate is False

    def test_budget_exhaustion_outranks_a_strong_hypothesis(self) -> None:
        verdict = decide(
            _inputs(
                budget=BudgetState(
                    policy=BudgetPolicy(max_tool_calls=2), ledger=BudgetLedger(tool_calls=2)
                ),
                hypotheses=[_hypothesis()],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "logs"],
                evidence_count=4,
            )
        )
        assert verdict.reason is TerminationReason.BUDGET_EXHAUSTED
        assert verdict.rule_id == "R3_budget_exhausted"

    def test_wall_clock_exhaustion_is_reported_as_a_timeout(self) -> None:
        verdict = decide(
            _inputs(
                budget=BudgetState(
                    policy=BudgetPolicy(max_wall_clock_seconds=60),
                    ledger=BudgetLedger(elapsed_seconds=61.0),
                )
            )
        )
        assert verdict.reason is TerminationReason.WALL_CLOCK_TIMEOUT
        assert verdict.rule_id == "R2_wall_clock_timeout"


class TestActionability:
    def test_a_well_supported_hypothesis_is_escalated_to_a_human(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.86, supporting=3)],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "logs", "deployments"],
                evidence_count=3,
            )
        )
        assert verdict.reason is TerminationReason.HUMAN_ESCALATION
        assert verdict.incident_status is IncidentStatus.ESCALATED

    def test_resolution_is_never_claimed(self) -> None:
        # The read-only kernel cannot remediate and therefore cannot verify a fix. Claiming
        # `resolved` would report an outcome the system did not produce.
        statuses = set()
        for confidence in (0.0, 0.3, 0.6, 0.99):
            for supporting in (0, 1, 3):
                for contradicting in (0, 2):
                    verdict = decide(
                        _inputs(
                            hypotheses=[
                                _hypothesis(
                                    confidence=confidence,
                                    supporting=supporting,
                                    contradicting=contradicting,
                                )
                            ],
                            planner_action=PlannerAction.TERMINATE,
                            attempted_domains=["metrics", "logs"],
                            evidence_count=supporting,
                        )
                    )
                    if verdict.incident_status:
                        statuses.add(verdict.incident_status)
        assert IncidentStatus.RESOLVED not in statuses

    def test_a_contradicted_hypothesis_is_not_actionable(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.95, supporting=4, contradicting=1)],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "deployments"],
                evidence_count=5,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE
        assert verdict.rule_id == "R5_planner_terminated_without_conclusion"

    def test_a_confident_hypothesis_on_one_record_is_not_actionable(self) -> None:
        # Failure mode F4: a confident, plausible, wrong answer that nothing crashes on.
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.99, supporting=1)],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics"],
                evidence_count=1,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_a_low_confidence_hypothesis_is_not_actionable(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=MIN_ACTIONABLE_CONFIDENCE - 0.01, supporting=4)],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "logs"],
                evidence_count=4,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_poor_domain_coverage_blocks_escalation_of_a_cause(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.9, supporting=3)],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "logs", "traces", "deployments"],
                degraded_domains=["logs", "traces", "deployments"],
                evidence_count=3,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_a_rejected_hypothesis_does_not_count(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[
                    _hypothesis(
                        confidence=0.99,
                        supporting=5,
                        status=HypothesisStatus.REJECTED_UNSUPPORTED,
                    )
                ],
                planner_action=PlannerAction.TERMINATE,
                attempted_domains=["metrics", "logs"],
                evidence_count=5,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE


class TestContinuation:
    def test_a_run_with_headroom_and_no_planner_verdict_continues(self) -> None:
        verdict = decide(_inputs(planner_action=PlannerAction.COLLECT_EVIDENCE))
        assert verdict.should_terminate is False
        assert verdict.rule_id == "R6_continue"
        assert verdict.reason is None

    def test_forming_a_hypothesis_does_not_end_the_run(self) -> None:
        verdict = decide(_inputs(planner_action=PlannerAction.FORM_HYPOTHESIS))
        assert verdict.should_terminate is False


class TestRuleSetShape:
    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.rule_id for rule in RULES]
        assert len(ids) == len(set(ids))

    def test_the_rule_set_is_not_empty_and_ends_with_the_catch_all(self) -> None:
        assert len(RULES) >= 2
        assert RULES[-1].rule_id == "R6_continue"

    def test_no_rule_before_the_last_matches_an_empty_input(self) -> None:
        empty = _inputs()
        for rule in RULES[:-1]:
            assert rule.matches(empty) is False, f"{rule.rule_id} matched a fresh run"


class TestReflectionDrivenTermination:
    """A terminal reflection decision is validated exactly like the planner's own.

    Master specification section 3: reflection's terminal members are *inputs* to this same
    rule set, never a second authority and never a sixth outcome.
    """

    def test_escalate_from_reflection_is_validated_by_the_same_actionability_gate(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.86, supporting=3)],
                reflection_action=ReflectionAction.ESCALATE,
                attempted_domains=["metrics", "logs", "deployments"],
                evidence_count=3,
            )
        )
        assert verdict.reason is TerminationReason.HUMAN_ESCALATION
        assert verdict.incident_status is IncidentStatus.ESCALATED
        assert verdict.rule_id == "R4_actionable_cause_escalated"

    def test_terminate_success_from_reflection_over_weak_evidence_is_not_escalated(self) -> None:
        verdict = decide(
            _inputs(
                hypotheses=[_hypothesis(confidence=0.99, supporting=1)],
                reflection_action=ReflectionAction.TERMINATE_SUCCESS,
                attempted_domains=["metrics"],
                evidence_count=1,
            )
        )
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE
        assert verdict.rule_id == "R5_planner_terminated_without_conclusion"

    def test_terminate_uncertain_from_reflection_ends_the_run_without_a_planner_verdict(
        self,
    ) -> None:
        verdict = decide(
            _inputs(
                reflection_action=ReflectionAction.TERMINATE_UNCERTAIN,
                planner_action=None,
            )
        )
        assert verdict.should_terminate
        assert verdict.reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_a_non_terminal_reflection_action_does_not_end_the_run(self) -> None:
        verdict = decide(
            _inputs(
                reflection_action=ReflectionAction.CONTINUE_WITH_GAP,
                planner_action=None,
            )
        )
        assert verdict.should_terminate is False
        assert verdict.rule_id == "R6_continue"

    def test_budget_exhaustion_still_outranks_a_reflection_escalation(self) -> None:
        verdict = decide(
            _inputs(
                budget=BudgetState(
                    policy=BudgetPolicy(max_tool_calls=2), ledger=BudgetLedger(tool_calls=2)
                ),
                hypotheses=[_hypothesis()],
                reflection_action=ReflectionAction.ESCALATE,
                attempted_domains=["metrics", "logs"],
                evidence_count=4,
            )
        )
        assert verdict.reason is TerminationReason.BUDGET_EXHAUSTED

    def test_disabling_wants_to_stop_would_leave_a_reflection_escalation_unterminated(
        self,
    ) -> None:
        """Mutation check: ``wants_to_stop`` is load-bearing, not a no-op wrapper."""
        inputs = _inputs(
            hypotheses=[_hypothesis(confidence=0.86, supporting=3)],
            reflection_action=ReflectionAction.ESCALATE,
            attempted_domains=["metrics", "logs", "deployments"],
            evidence_count=3,
        )
        assert decide(inputs).should_terminate is True

        stale = TerminationInputs(
            budget=inputs.budget,
            hypotheses=inputs.hypotheses,
            evidence_count=inputs.evidence_count,
            failures=inputs.failures,
            degraded_domains=inputs.degraded_domains,
            attempted_domains=inputs.attempted_domains,
            planner_action=None,
            open_gaps=inputs.open_gaps,
            reflection_action=None,  # the guard's input removed, not the guard itself
        )
        assert decide(stale).should_terminate is False, (
            "without a stop request from either the planner or reflection, the run must "
            "keep going - proving wants_to_stop is what made the earlier case terminate"
        )


class TestBestHypothesisOf:
    def test_a_later_status_for_the_same_id_overrides_an_earlier_one(self) -> None:
        # Graph state accumulates append-only; a revision re-emits the same id with a
        # corrected status rather than editing the earlier entry in place.
        stale = _hypothesis(rank=1, confidence=0.9)
        corrected = HypothesisRef(
            hypothesis_id=stale.hypothesis_id,
            rank=stale.rank,
            root_cause_class=stale.root_cause_class,
            confidence=stale.confidence,
            status=HypothesisStatus.SUPERSEDED,
            supporting_evidence_count=stale.supporting_evidence_count,
            contradicting_evidence_count=stale.contradicting_evidence_count,
        )
        replacement = _hypothesis(rank=2, confidence=0.5)
        assert best_hypothesis_of([stale, replacement, corrected]) == replacement

    def test_a_superseded_hypothesis_alone_has_no_best(self) -> None:
        superseded = _hypothesis(status=HypothesisStatus.SUPERSEDED)
        assert best_hypothesis_of([superseded]) is None


def test_decide_raises_if_the_rule_set_stops_being_total(monkeypatch: pytest.MonkeyPatch) -> None:
    """Removing the catch-all must fail loudly, not silently change what "continue" means."""
    monkeypatch.setattr("asic.orchestration.termination.RULES", RULES[:-1])
    with pytest.raises(AssertionError, match="required to be total"):
        decide(_inputs())
