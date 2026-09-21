"""Bounded per-key request limiter for the single-process API edge.

Limits: this is an in-process sliding window. It bounds abuse *per process*; a horizontally
scaled deployment multiplies the effective limit by the replica count, and a shared limiter
(gateway, ingress or a distributed store) is a Phase 14/15 deployment concern (ADR-0006
records why no Redis is introduced for it here).

The key space is bounded. Keys are only ever derived from verified identity or from the
peer address, never from an attacker-chosen header, and the table itself has a hard ceiling:
once full, expired keys are pruned and, if it is still full, *new* keys are refused. A
limiter that grew without bound would itself be a memory-exhaustion vector.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

DEFAULT_MAX_KEYS = 10_000


class RateLimiter:
    def __init__(
        self,
        limit: int,
        *,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("rate limit, window and key ceiling must be positive")
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def admit(self, key: str) -> bool:
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._prune(cutoff)
                    if len(self._hits) >= self._max_keys:
                        return False  # fail closed for a new key when the table is full
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True

    def _prune(self, cutoff: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[key]

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._hits)


__all__ = ["DEFAULT_MAX_KEYS", "RateLimiter"]
