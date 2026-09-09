"""Budgets are enforced before a step, not after it.

The distinction is the whole value of the module: checking afterwards means the step that
broke the limit already cost its tokens, its latency and its tool call.
"""

from __future__ import annotations

import pytest

from asic.domain.budget import (
    BudgetLedger,
    BudgetPolicy,
    BudgetState,
    termination_reason_for,
)
from asic.domain.enums import BudgetKind, TerminationReason
from asic.domain.errors import BudgetExhausted


class TestPolicy:
    def test_a_zero_limit_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            BudgetPolicy(max_iterations=0)

    def test_a_negative_cost_ceiling_is_refused(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            BudgetPolicy(max_cost_usd=-1.0)

    def test_round_trips_through_a_dict(self) -> None:
        policy = BudgetPolicy(max_iterations=5, max_tool_calls=7, max_cost_usd=0.5)
        assert BudgetPolicy.from_dict(policy.to_dict()) == policy


class TestLedger:
    def test_charging_returns_a_new_ledger(self) -> None:
        original = BudgetLedger()
        charged = original.charge(iterations=1, tokens=100)
        assert original.iterations == 0, "the ledger is immutable"
        assert charged.iterations == 1
        assert charged.tokens == 100

    def test_a_negative_charge_is_refused(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            BudgetLedger().charge(tokens=-1)


class TestExhaustion:
    def test_a_fresh_state_is_not_exhausted(self) -> None:
        assert BudgetState.initial().exhausted_kind() is None

    def test_iterations_are_reported_before_other_dimensions(self) -> None:
        # A non-converging loop consumes iterations and tool calls first, so naming them
        # first makes the common termination reason the informative one.
        state = BudgetState(
            policy=BudgetPolicy(max_iterations=1, max_tool_calls=1),
            ledger=BudgetLedger(iterations=5, tool_calls=5),
        )
        assert state.exhausted_kind() is BudgetKind.ITERATIONS

    def test_reaching_the_limit_exactly_counts_as_exhausted(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_iterations=3), ledger=BudgetLedger(iterations=3)
        )
        assert state.is_exhausted()

    def test_wall_clock_maps_to_a_timeout_not_to_exhaustion(self) -> None:
        assert termination_reason_for(BudgetKind.WALL_CLOCK) is TerminationReason.WALL_CLOCK_TIMEOUT
        for kind in (BudgetKind.ITERATIONS, BudgetKind.TOOL_CALLS, BudgetKind.TOKENS):
            assert termination_reason_for(kind) is TerminationReason.BUDGET_EXHAUSTED

    def test_every_budget_kind_has_a_termination_reason(self) -> None:
        for kind in BudgetKind:
            assert termination_reason_for(kind) is not None


class TestPreStepEnforcement:
    def test_headroom_is_granted_when_the_step_fits(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_iterations=3), ledger=BudgetLedger(iterations=1)
        )
        state.require_headroom(iterations=1)  # does not raise

    def test_a_step_that_would_exhaust_is_refused_before_it_runs(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_iterations=3), ledger=BudgetLedger(iterations=2)
        )
        with pytest.raises(BudgetExhausted, match="would exhaust") as caught:
            state.require_headroom(iterations=1)
        assert caught.value.kind is BudgetKind.ITERATIONS

    def test_an_already_exhausted_budget_refuses_even_a_free_check(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_tool_calls=1), ledger=BudgetLedger(tool_calls=1)
        )
        with pytest.raises(BudgetExhausted, match="already exhausted"):
            state.require_headroom()

    def test_the_exception_names_the_dimension_so_termination_is_accurate(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_wall_clock_seconds=10),
            ledger=BudgetLedger(elapsed_seconds=11.0),
        )
        with pytest.raises(BudgetExhausted) as caught:
            state.require_headroom(iterations=1)
        assert termination_reason_for(caught.value.kind) is TerminationReason.WALL_CLOCK_TIMEOUT

    def test_remaining_never_goes_negative(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_iterations=2), ledger=BudgetLedger(iterations=9)
        )
        assert state.remaining()["iterations"] == 0.0

    def test_remaining_covers_every_dimension(self) -> None:
        remaining = BudgetState.initial().remaining()
        assert set(remaining) == {kind.value for kind in BudgetKind}


class TestSerialisation:
    def test_state_round_trips(self) -> None:
        state = BudgetState.initial(BudgetPolicy(max_iterations=4)).charge(
            iterations=2, tool_calls=3, tokens=500, cost_usd=0.02
        )
        restored = BudgetState.from_dict(state.to_dict())
        assert restored == state

    def test_a_partial_dict_restores_to_defaults(self) -> None:
        restored = BudgetState.from_dict({})
        assert restored.ledger == BudgetLedger()
        assert restored.policy == BudgetPolicy()
