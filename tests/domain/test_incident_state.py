"""Incident state machine.

These tests exercise the *rules*, not a happy path. The valuable assertions here are the
negative ones: that an unlisted transition is refused, that an actor without authority is
refused, and that no state can strand an incident forever.
"""

from __future__ import annotations

import pytest

from asic.domain.enums import ActorType, IncidentStatus, TerminationReason
from asic.domain.errors import IllegalStateTransition
from asic.domain.incident_state import (
    CLOSED_STATES,
    IRREVERSIBLE_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    TransitionRequest,
    allowed_targets,
    allowed_transitions_for,
    assert_transition_allowed,
    find_transition,
    is_terminal,
    reachable_from,
    states_without_path_to_closure,
)


def _request(
    source: IncidentStatus,
    target: IncidentStatus,
    actor: ActorType = ActorType.SYSTEM,
    **kwargs: object,
) -> TransitionRequest:
    return TransitionRequest(source=source, target=target, actor_type=actor, **kwargs)  # type: ignore[arg-type]


class TestTransitionTableIntegrity:
    def test_no_duplicate_edges(self) -> None:
        edges = [(t.source, t.target) for t in TRANSITIONS]
        assert len(edges) == len(set(edges))

    def test_no_self_transitions(self) -> None:
        assert [t for t in TRANSITIONS if t.source is t.target] == []

    def test_every_transition_has_at_least_one_permitted_actor(self) -> None:
        assert [t for t in TRANSITIONS if not t.allowed_actors] == []

    def test_every_status_is_reachable_or_is_the_entry_point(self) -> None:
        """No orphan states: a state nothing can reach is dead configuration."""
        targets = {t.target for t in TRANSITIONS}
        orphans = set(IncidentStatus) - targets - {IncidentStatus.DETECTED}
        assert orphans == set(), f"unreachable states: {sorted(s.value for s in orphans)}"

    def test_every_state_can_reach_closure(self) -> None:
        """Master specification section 5: every run must terminate."""
        assert states_without_path_to_closure() == frozenset()

    def test_failed_is_irreversible(self) -> None:
        assert allowed_targets(IncidentStatus.FAILED) == frozenset()
        assert IncidentStatus.FAILED in IRREVERSIBLE_STATES

    def test_terminal_states_cover_the_five_specification_outcomes(self) -> None:
        assert {
            IncidentStatus.RESOLVED,
            IncidentStatus.FAILED,
            IncidentStatus.ESCALATED,
            IncidentStatus.UNCERTAIN,
        } == TERMINAL_STATES
        assert CLOSED_STATES <= TERMINAL_STATES


class TestTransitionValidation:
    def test_permitted_transition_is_accepted(self) -> None:
        transition = assert_transition_allowed(
            _request(IncidentStatus.DETECTED, IncidentStatus.INVESTIGATING)
        )
        assert transition.source is IncidentStatus.DETECTED

    def test_unlisted_transition_is_refused(self) -> None:
        with pytest.raises(IllegalStateTransition, match="not a permitted transition"):
            assert_transition_allowed(_request(IncidentStatus.DETECTED, IncidentStatus.RESOLVED))

    def test_no_op_transition_is_refused(self) -> None:
        """Writing the same status twice is not a state change and must not emit an event."""
        with pytest.raises(IllegalStateTransition, match="no-op transition"):
            assert_transition_allowed(
                _request(IncidentStatus.INVESTIGATING, IncidentStatus.INVESTIGATING)
            )

    def test_nothing_escapes_failed(self) -> None:
        for target in IncidentStatus:
            if target is IncidentStatus.FAILED:
                continue
            with pytest.raises(IllegalStateTransition):
                assert_transition_allowed(_request(IncidentStatus.FAILED, target))


class TestActorAuthority:
    def test_only_a_human_may_approve_into_remediating(self) -> None:
        """An agent node must never be able to grant its own approval."""
        with pytest.raises(IllegalStateTransition, match="may not cause"):
            assert_transition_allowed(
                _request(
                    IncidentStatus.AWAITING_APPROVAL,
                    IncidentStatus.REMEDIATING,
                    ActorType.AGENT_NODE,
                )
            )

        assert_transition_allowed(
            _request(
                IncidentStatus.AWAITING_APPROVAL,
                IncidentStatus.REMEDIATING,
                ActorType.HUMAN,
            )
        )

    def test_agent_cannot_reopen_a_resolved_incident(self) -> None:
        with pytest.raises(IllegalStateTransition, match="may not cause"):
            assert_transition_allowed(
                _request(
                    IncidentStatus.RESOLVED,
                    IncidentStatus.INVESTIGATING,
                    ActorType.AGENT_NODE,
                    justification="symptoms recurred",
                )
            )

    def test_agent_cannot_mark_verifying_resolved_without_the_system_path(self) -> None:
        """A human may resolve, and the system may resolve after verification; an
        external system may do neither."""
        with pytest.raises(IllegalStateTransition, match="may not cause"):
            assert_transition_allowed(
                _request(
                    IncidentStatus.VERIFYING,
                    IncidentStatus.RESOLVED,
                    ActorType.EXTERNAL_SYSTEM,
                    termination_reason=TerminationReason.SUCCESS,
                )
            )

    def test_allowed_transitions_are_filtered_by_actor(self) -> None:
        human = allowed_transitions_for(IncidentStatus.AWAITING_APPROVAL, ActorType.HUMAN)
        agent = allowed_transitions_for(IncidentStatus.AWAITING_APPROVAL, ActorType.AGENT_NODE)
        assert IncidentStatus.REMEDIATING in human
        assert IncidentStatus.REMEDIATING not in agent


class TestTerminationEvidence:
    def test_terminal_transition_requires_a_reason(self) -> None:
        with pytest.raises(IllegalStateTransition, match="requires a termination reason"):
            assert_transition_allowed(
                _request(IncidentStatus.INVESTIGATING, IncidentStatus.UNCERTAIN)
            )

    def test_terminal_transition_with_a_reason_is_accepted(self) -> None:
        assert_transition_allowed(
            _request(
                IncidentStatus.INVESTIGATING,
                IncidentStatus.UNCERTAIN,
                termination_reason=TerminationReason.INSUFFICIENT_EVIDENCE,
            )
        )

    def test_every_transition_into_a_terminal_state_demands_a_reason(self) -> None:
        for transition in TRANSITIONS:
            if is_terminal(transition.target) and transition.target not in {
                IncidentStatus.RESOLVED,
                IncidentStatus.FAILED,
                IncidentStatus.ESCALATED,
                IncidentStatus.UNCERTAIN,
            }:
                continue
            if is_terminal(transition.target):
                assert transition.requires_termination_reason, (
                    f"{transition.source.value} -> {transition.target.value} enters a "
                    "terminal state without demanding a termination reason"
                )

    def test_human_reopen_requires_justification(self) -> None:
        with pytest.raises(IllegalStateTransition, match="requires a written justification"):
            assert_transition_allowed(
                _request(
                    IncidentStatus.RESOLVED,
                    IncidentStatus.INVESTIGATING,
                    ActorType.HUMAN,
                )
            )

        assert_transition_allowed(
            _request(
                IncidentStatus.RESOLVED,
                IncidentStatus.INVESTIGATING,
                ActorType.HUMAN,
                justification="error rate rose again 20 minutes after resolution",
            )
        )

    def test_blank_justification_does_not_satisfy_the_requirement(self) -> None:
        with pytest.raises(IllegalStateTransition, match="requires a written justification"):
            assert_transition_allowed(
                _request(
                    IncidentStatus.RESOLVED,
                    IncidentStatus.INVESTIGATING,
                    ActorType.HUMAN,
                    justification="   ",
                )
            )


class TestReachability:
    def test_investigating_can_reach_every_terminal_state(self) -> None:
        reachable = reachable_from(IncidentStatus.INVESTIGATING)
        assert reachable >= TERMINAL_STATES

    def test_uncertainty_is_a_legitimate_outcome_not_a_dead_end(self) -> None:
        """Terminating in uncertainty is a success case; a human must still be able to
        pick it up."""
        assert IncidentStatus.ESCALATED in allowed_targets(IncidentStatus.UNCERTAIN)
        assert IncidentStatus.INVESTIGATING in allowed_targets(IncidentStatus.UNCERTAIN)

    def test_awaiting_approval_cannot_reach_remediating_without_a_human(self) -> None:
        transition = find_transition(IncidentStatus.AWAITING_APPROVAL, IncidentStatus.REMEDIATING)
        assert transition is not None
        assert transition.allowed_actors == frozenset({ActorType.HUMAN})
