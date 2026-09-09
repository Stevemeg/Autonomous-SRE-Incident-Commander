"""Time as an injected dependency.

Replay is the reason. Master specification section 11 requires that important behaviour be
reproducible from fixtures and traces, and a component that reads the wall clock directly
cannot be replayed: the second run sees different timestamps, so evidence windows move,
correlation windows shift and the run is a re-execution rather than a reproduction.

Every component that needs the time takes a :class:`Clock`. Production passes
:class:`SystemClock`; replay and the deterministic simulators pass :class:`FrozenClock`,
whose start instant is recorded on ``execution_trace.clock_start``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """The only sanctioned source of the current time."""

    def now(self) -> datetime:
        """Timezone-aware current instant. Never naive."""


class SystemClock:
    """Wall-clock time in UTC."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(slots=True)
class FrozenClock:
    """A clock that only moves when told to.

    Deliberately mutable while :class:`SystemClock` is not: a test or a replay advances it
    explicitly, which makes elapsed time an input to the scenario rather than an accident
    of how fast the machine ran.
    """

    start: datetime
    _elapsed: timedelta = field(default_factory=timedelta)

    def __post_init__(self) -> None:
        if self.start.tzinfo is None:
            raise ValueError("FrozenClock needs a timezone-aware start instant")

    def now(self) -> datetime:
        return self.start + self._elapsed

    def advance(self, seconds: float) -> datetime:
        if seconds < 0:
            raise ValueError("a clock does not run backwards")
        self._elapsed += timedelta(seconds=seconds)
        return self.now()


__all__ = ["Clock", "FrozenClock", "SystemClock"]
