"""Bounded autonomy: budget policy, ledger, and the enforcement that ends a run.

Master specification section 5 makes hard limits mandatory - iterations, tool calls,
wall-clock time, token budget and cost - and forbids infinite loops. This module is where
those limits live, and the single most important property of it is stated once here:

**Budgets are checked before a step is taken, never after.**

Checking afterwards means the step that broke the limit already cost its tokens, its
latency and its tool call. Checking beforehand means exhaustion produces a clean partial
result with everything gathered so far intact, which is a legitimate outcome rather than a
crash (``docs/architecture/failure-and-recovery.md`` section 4).

Nothing here consults a model. "The model should stop" is not a termination mechanism: a
model asked to respect a budget can misreport its own consumption, and a model that has
lost the plot is exactly the case the budget exists for.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Final

from asic.domain.enums import BudgetKind, TerminationReason
from asic.domain.errors import BudgetExhausted

#: Defaults from ``docs/architecture/failure-and-recovery.md`` section 4. These are
#: *configured* limits, not measured ones: no load test has been run, and nothing here
#: claims these are the right numbers for production traffic.
DEFAULT_MAX_ITERATIONS: Final[int] = 12
DEFAULT_MAX_TOOL_CALLS: Final[int] = 40
DEFAULT_MAX_WALL_CLOCK_SECONDS: Final[int] = 21_600  # 6 hours
DEFAULT_MAX_TOKENS: Final[int] = 200_000
DEFAULT_MAX_COST_USD: Final[float] = 5.0

_POSITIVE_INT_FIELDS: Final[tuple[str, ...]] = (
    "max_iterations",
    "max_tool_calls",
    "max_wall_clock_seconds",
    "max_tokens",
)


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    """The ceiling for one workflow run.

    Tenant-configurable in a later phase. For now the defaults above apply and are
    recorded on the run, so a historical run stays interpretable after the defaults change.
    """

    max_iterations: int = DEFAULT_MAX_ITERATIONS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_wall_clock_seconds: int = DEFAULT_MAX_WALL_CLOCK_SECONDS
    max_tokens: int = DEFAULT_MAX_TOKENS
    max_cost_usd: float = DEFAULT_MAX_COST_USD

    def __post_init__(self) -> None:
        for field_name in _POSITIVE_INT_FIELDS:
            value = int(getattr(self, field_name))
            if value < 1:
                raise ValueError(f"{field_name} must be at least 1, got {value}")
        if self.max_cost_usd <= 0:
            raise ValueError("max_cost_usd must be positive")

    def limit_for(self, kind: BudgetKind) -> float:
        return {
            BudgetKind.ITERATIONS: float(self.max_iterations),
            BudgetKind.TOOL_CALLS: float(self.max_tool_calls),
            BudgetKind.WALL_CLOCK: float(self.max_wall_clock_seconds),
            BudgetKind.TOKENS: float(self.max_tokens),
            BudgetKind.COST: float(self.max_cost_usd),
        }[kind]

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_iterations": self.max_iterations,
            "max_tool_calls": self.max_tool_calls,
            "max_wall_clock_seconds": self.max_wall_clock_seconds,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BudgetPolicy:
        fields = (*_POSITIVE_INT_FIELDS, "max_cost_usd")
        return cls(**{name: raw[name] for name in fields if name in raw})


@dataclass(frozen=True, slots=True)
class BudgetLedger:
    """What one run has consumed so far. Immutable; charging returns a new ledger."""

    iterations: int = 0
    tool_calls: int = 0
    elapsed_seconds: float = 0.0
    tokens: int = 0
    cost_usd: float = 0.0

    def consumed_for(self, kind: BudgetKind) -> float:
        return {
            BudgetKind.ITERATIONS: float(self.iterations),
            BudgetKind.TOOL_CALLS: float(self.tool_calls),
            BudgetKind.WALL_CLOCK: float(self.elapsed_seconds),
            BudgetKind.TOKENS: float(self.tokens),
            BudgetKind.COST: float(self.cost_usd),
        }[kind]

    def charge(
        self,
        *,
        iterations: int = 0,
        tool_calls: int = 0,
        elapsed_seconds: float = 0.0,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> BudgetLedger:
        if min(iterations, tool_calls, tokens) < 0 or min(elapsed_seconds, cost_usd) < 0:
            raise ValueError("budget charges must be non-negative; a refund is not a thing")
        return replace(
            self,
            iterations=self.iterations + iterations,
            tool_calls=self.tool_calls + tool_calls,
            elapsed_seconds=self.elapsed_seconds + elapsed_seconds,
            tokens=self.tokens + tokens,
            cost_usd=self.cost_usd + cost_usd,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "elapsed_seconds": self.elapsed_seconds,
            "tokens": self.tokens,
            "cost_usd": self.cost_usd,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BudgetLedger:
        return cls(
            iterations=int(raw.get("iterations", 0)),
            tool_calls=int(raw.get("tool_calls", 0)),
            elapsed_seconds=float(raw.get("elapsed_seconds", 0.0)),
            tokens=int(raw.get("tokens", 0)),
            cost_usd=float(raw.get("cost_usd", 0.0)),
        )


#: Which termination reason each budget dimension produces when it runs out. Wall clock is
#: a timeout; the rest are exhaustion. Master specification section 5 lists these as
#: distinct outcomes, and conflating them would hide the difference between "we ran out of
#: time" and "we ran out of allowance", which have different operational responses.
_REASON_FOR_KIND: Final[dict[BudgetKind, TerminationReason]] = {
    BudgetKind.ITERATIONS: TerminationReason.BUDGET_EXHAUSTED,
    BudgetKind.TOOL_CALLS: TerminationReason.BUDGET_EXHAUSTED,
    BudgetKind.TOKENS: TerminationReason.BUDGET_EXHAUSTED,
    BudgetKind.COST: TerminationReason.BUDGET_EXHAUSTED,
    BudgetKind.WALL_CLOCK: TerminationReason.WALL_CLOCK_TIMEOUT,
}

#: Order in which exhaustion is reported. Iterations and tool calls are what a
#: non-converging loop consumes first, so naming them first makes the common termination
#: reason the informative one.
_EXHAUSTION_ORDER: Final[tuple[BudgetKind, ...]] = (
    BudgetKind.ITERATIONS,
    BudgetKind.TOOL_CALLS,
    BudgetKind.WALL_CLOCK,
    BudgetKind.TOKENS,
    BudgetKind.COST,
)


def termination_reason_for(kind: BudgetKind) -> TerminationReason:
    return _REASON_FOR_KIND[kind]


@dataclass(frozen=True, slots=True)
class BudgetState:
    """Policy plus ledger: everything needed to answer "may we take another step?"."""

    policy: BudgetPolicy
    ledger: BudgetLedger

    @classmethod
    def initial(cls, policy: BudgetPolicy | None = None) -> BudgetState:
        return cls(policy=policy or BudgetPolicy(), ledger=BudgetLedger())

    def exhausted_kind(self) -> BudgetKind | None:
        """The first dimension that has reached or passed its limit, if any."""
        for kind in _EXHAUSTION_ORDER:
            if self.ledger.consumed_for(kind) >= self.policy.limit_for(kind):
                return kind
        return None

    def is_exhausted(self) -> bool:
        return self.exhausted_kind() is not None

    def remaining(self) -> dict[str, float]:
        """Headroom per dimension, floored at zero. Recorded on every span."""
        return {
            kind.value: max(0.0, self.policy.limit_for(kind) - self.ledger.consumed_for(kind))
            for kind in _EXHAUSTION_ORDER
        }

    def charge(
        self,
        *,
        iterations: int = 0,
        tool_calls: int = 0,
        elapsed_seconds: float = 0.0,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> BudgetState:
        return replace(
            self,
            ledger=self.ledger.charge(
                iterations=iterations,
                tool_calls=tool_calls,
                elapsed_seconds=elapsed_seconds,
                tokens=tokens,
                cost_usd=cost_usd,
            ),
        )

    def require_headroom(self, *, iterations: int = 0, tool_calls: int = 0) -> None:
        """Fail before a step that would exceed a limit.

        Raises:
            BudgetExhausted: naming the dimension and the reason it maps to, so the caller
                terminates with an accurate reason rather than a generic one.
        """
        already = self.exhausted_kind()
        if already is not None:
            raise BudgetExhausted(
                f"{already.value} budget already exhausted "
                f"({self.ledger.consumed_for(already):g}/{self.policy.limit_for(already):g})",
                kind=already,
            )
        if not (iterations or tool_calls):
            return
        projected = self.charge(iterations=iterations, tool_calls=tool_calls)
        would_exceed = projected.exhausted_kind()
        if would_exceed is not None:
            raise BudgetExhausted(
                f"taking this step would exhaust the {would_exceed.value} budget "
                f"({projected.ledger.consumed_for(would_exceed):g}/"
                f"{self.policy.limit_for(would_exceed):g}); refusing before the cost is paid",
                kind=would_exceed,
            )

    def to_dict(self) -> dict[str, Any]:
        return {"policy": self.policy.to_dict(), "ledger": self.ledger.to_dict()}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BudgetState:
        return cls(
            policy=BudgetPolicy.from_dict(dict(raw.get("policy", {}))),
            ledger=BudgetLedger.from_dict(dict(raw.get("ledger", {}))),
        )


__all__ = [
    "DEFAULT_MAX_COST_USD",
    "DEFAULT_MAX_ITERATIONS",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MAX_TOOL_CALLS",
    "DEFAULT_MAX_WALL_CLOCK_SECONDS",
    "BudgetLedger",
    "BudgetPolicy",
    "BudgetState",
    "termination_reason_for",
]
