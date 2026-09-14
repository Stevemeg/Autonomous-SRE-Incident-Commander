"""Bounded per-principal request limiter for the Phase 9 single-process edge."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        limit: int,
        *,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("rate limit and window must be positive")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def admit(self, key: str) -> bool:
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True


__all__ = ["RateLimiter"]
