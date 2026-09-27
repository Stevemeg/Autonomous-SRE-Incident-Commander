"""Phase 15.8/15.9: retries never amplify an outage, and one failing dependency is isolated.

Design being validated (ADR-0026, safety policy section 5): the broker retries only reads (and
only transient failures), at most ``max_attempts`` times (3 for the investigation catalogue),
with linear backoff that now carries "equal jitter" (delay in [base/2, base]); a vendor
``Retry-After`` is honoured but capped at 5 s; effectful calls and unknown outcomes are never
retried; per-run tool-call budgets bound the total. There is deliberately no circuit breaker:
calls are synchronous with hard deadlines, each run's broker owns a two-thread executor, and
runs do not share adapter threads - so the bulkhead is per run, and it is tested here.
"""

from __future__ import annotations

import statistics
import threading
import time
import uuid
from typing import Any

import pytest
from sqlalchemy.orm import Session

from asic.contracts.nodes import G4_EVIDENCE_COLLECTOR
from asic.domain.clock import FrozenClock
from asic.domain.enums import IntegrationFailureClass
from asic.domain.errors import IntegrationError
from asic.tools.broker import MAX_RETRY_AFTER_SECONDS
from asic.tools.provider import InvocationContext
from asic.tools.registry import ToolRegistry
from tests.kernel_fixtures import build_fixture
from tests.tools.test_broker import WINDOW_END, WINDOW_START, _broker
from tests.tools.test_broker import _request as _broker_request

pytestmark = pytest.mark.postgres

METRICS = "read.metrics"


def _request(fixture: Any, capability: str) -> Any:
    return _broker_request(
        fixture,
        capability,
        arguments={
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "metric": "http_request_duration_p95_seconds",
        },
    )


class FailingProvider:
    """Every call is a transient outage (or a rate limit with a long Retry-After)."""

    def __init__(self, delegate: Any, *, retry_after: float | None = None) -> None:
        self.delegate, self.retry_after, self.calls = delegate, retry_after, 0
        self._lock = threading.Lock()

    @property
    def kind(self) -> Any:
        return self.delegate.kind

    def list_tools(self) -> tuple[str, ...]:
        return tuple(self.delegate.list_tools())

    def supports(self, descriptor: Any) -> bool:
        return bool(self.delegate.supports(descriptor))

    def invoke(self, descriptor: Any, bound: Any, context: InvocationContext) -> Any:
        with self._lock:
            self.calls += 1
        if self.retry_after is not None:
            raise IntegrationError(
                "rate limited",
                failure_class=IntegrationFailureClass.RATE_LIMITED,
                transient=True,
                effect_not_applied=True,
                retry_after_seconds=self.retry_after,
            )
        raise IntegrationError(
            "dependency down",
            failure_class=IntegrationFailureClass.TRANSIENT_UNAVAILABLE,
            transient=True,
            effect_not_applied=True,
        )


def _failing_broker(
    session: Session, clock: FrozenClock, sleeps: list[float], **provider_options: Any
) -> tuple[Any, Any, FailingProvider]:
    fixture = build_fixture(session, slug=f"retry-{uuid.uuid4().hex[:8]}")
    broker, simulator, _ = _broker(fixture, session, clock)
    failing = FailingProvider(simulator, **provider_options)
    broker._providers = (failing,)
    broker._sleep = sleeps.append
    return fixture, broker, failing


def test_a_sustained_outage_costs_at_most_max_attempts_with_bounded_jittered_backoff(
    kernel_session: Session, clock: FrozenClock
) -> None:
    sleeps: list[float] = []
    fixture, broker, failing = _failing_broker(kernel_session, clock, sleeps)
    descriptor = ToolRegistry.read_only().by_name("metrics.query")
    result = broker.invoke(
        kernel_session, request=_request(fixture, METRICS), contract=G4_EVIDENCE_COLLECTOR
    )
    assert result.failure is not None and result.attempts == 3
    assert failing.calls == descriptor.max_attempts == 3
    assert len(sleeps) == descriptor.max_attempts - 1
    for attempt, delay in enumerate(sleeps, start=1):
        base = descriptor.retry_backoff_seconds * attempt
        assert base / 2 <= delay <= base  # never above the documented linear bound
    assert sum(sleeps) <= descriptor.retry_backoff_seconds * 3  # 1 s + 2 s at most


def test_retry_after_is_honoured_but_capped(kernel_session: Session, clock: FrozenClock) -> None:
    sleeps: list[float] = []
    fixture, broker, failing = _failing_broker(kernel_session, clock, sleeps, retry_after=600.0)
    broker.invoke(
        kernel_session, request=_request(fixture, METRICS), contract=G4_EVIDENCE_COLLECTOR
    )
    assert sleeps and all(delay == MAX_RETRY_AFTER_SECONDS for delay in sleeps)
    assert failing.calls == 3


def test_concurrent_runs_failing_together_do_not_retry_in_lockstep(
    kernel_session: Session, clock: FrozenClock
) -> None:
    """Forty runs hit the same outage at once. Without jitter every one of them would retry
    at exactly +1 s and +3 s; with it the first retries spread across [0.5 s, 1 s]."""
    first_delays: list[float] = []
    for _ in range(40):
        sleeps: list[float] = []
        fixture, broker, _ = _failing_broker(kernel_session, clock, sleeps)
        broker.invoke(
            kernel_session, request=_request(fixture, METRICS), contract=G4_EVIDENCE_COLLECTOR
        )
        first_delays.append(sleeps[0])
        broker.close()
    assert all(0.5 <= d <= 1.0 for d in first_delays)
    assert len({round(d, 3) for d in first_delays}) > 30
    assert statistics.pstdev(first_delays) > 0.05


class BlockingProvider:
    """An adapter that hangs far beyond its deadline (a wedged dependency)."""

    def __init__(self, delegate: Any) -> None:
        self.delegate, self.release = delegate, threading.Event()

    @property
    def kind(self) -> Any:
        return self.delegate.kind

    def list_tools(self) -> tuple[str, ...]:
        return tuple(self.delegate.list_tools())

    def supports(self, descriptor: Any) -> bool:
        return bool(self.delegate.supports(descriptor))

    def invoke(self, descriptor: Any, bound: Any, context: InvocationContext) -> Any:
        self.release.wait(30)
        raise IntegrationError(
            "released", failure_class=IntegrationFailureClass.TIMEOUT, transient=False
        )


def test_a_wedged_dependency_in_one_run_does_not_starve_another(
    kernel_session: Session, clock: FrozenClock
) -> None:
    wedged_fixture = build_fixture(kernel_session, slug=f"bulk-a-{uuid.uuid4().hex[:8]}")
    wedged, simulator_a, _ = _broker(wedged_fixture, kernel_session, clock)
    healthy_fixture = build_fixture(kernel_session, slug=f"bulk-b-{uuid.uuid4().hex[:8]}")
    healthy, _, _ = _broker(healthy_fixture, kernel_session, clock)
    blocking = BlockingProvider(simulator_a)
    impatient = (
        ToolRegistry.read_only().by_name("metrics.query").model_copy(update={"timeout_seconds": 1})
    )
    threads_before = sum(1 for t in threading.enumerate() if t.name.startswith("asic-tool"))
    try:
        # Saturate the wedged run's executor: every call is abandoned at its 1 s deadline.
        errors = 0
        for _ in range(4):
            try:
                wedged._invoke_with_deadline(
                    blocking,
                    impatient,
                    {"service": wedged_fixture.service.name},
                    InvocationContext(
                        tenant_id=wedged_fixture.tenant_id,
                        correlation_id=uuid.uuid4(),
                        idempotency_key="b" * 64,
                        credential_ref=None,
                        timeout_seconds=1,
                        attempt=1,
                    ),
                )
            except Exception:
                errors += 1
        assert errors == 4
        # Meanwhile the other run's broker answers at full speed: it owns its own threads.
        started = time.perf_counter()
        result = healthy.invoke(
            kernel_session,
            request=_request(healthy_fixture, METRICS),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        assert result.failure is None
        assert time.perf_counter() - started < 2.0
        # The wedged run holds at most its own two executor threads, never more.
        wedged_threads = (
            sum(1 for t in threading.enumerate() if t.name.startswith("asic-tool")) - threads_before
        )
        assert wedged_threads <= 2 + 2  # two per broker; the healthy broker may hold two
    finally:
        blocking.release.set()
        wedged.close()
        healthy.close()
