"""What each timeout actually does, and what it does not.

Phase 4 originally described five timeout layers and enforced two of them. These tests fix
the claims to the behaviour: every layer here is either demonstrated to bound a genuinely
hanging operation, or demonstrated to be declarative with the limitation stated in the test
itself. A timeout value present in a contract is not enforcement, and none is treated as
such here.

The distinction that matters when reading this file:

* **Enforced** - something cancels or abandons the operation. Proved with an operation that
  really does not return.
* **Declarative** - the number is recorded, honoured by convention at a boundary, and
  nothing interrupts work in flight. Proved by showing the number exists and by naming what
  would be required to enforce it.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from asic.contracts.nodes import G4_EVIDENCE_COLLECTOR, NODE_CONTRACTS
from asic.db.session import (
    DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS,
    DEFAULT_STATEMENT_TIMEOUT_MS,
    apply_statement_timeouts,
)
from asic.domain.budget import BudgetLedger, BudgetPolicy, BudgetState
from asic.domain.clock import Clock, FrozenClock
from asic.domain.enums import BudgetKind, NodeId, TerminationReason
from asic.domain.errors import BudgetExhausted, ToolTimeout
from asic.llm.deterministic import DeterministicModelProvider
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_trace_id
from asic.orchestration.kernel import InvestigationKernel
from asic.simulators.provider import SimulatorProvider
from asic.tools.broker import BrokerStage, CapabilityRequest, ToolBroker
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ProviderHealth
from asic.tools.registry import ToolRegistry
from tests.conftest import requires_postgres
from tests.kernel_fixtures import CLOCK_START, Fixture, build_fixture


class HangingProvider:
    """An adapter that genuinely does not return.

    The existing timeout scenario *raises* ``ToolTimeout``, which proves the error path but
    not the deadline. This one blocks on an event that is never set, so only the broker's
    own deadline can end the call. That is the difference between testing a message and
    testing an execution boundary.
    """

    def __init__(self) -> None:
        self.released = threading.Event()
        self.entered = threading.Event()
        self.calls = 0

    @property
    def kind(self) -> Any:
        from asic.domain.enums import ToolProviderKind

        return ToolProviderKind.SIMULATOR

    def list_tools(self) -> tuple[str, ...]:
        return ("metrics.query",)

    def supports(self, descriptor: ToolDescriptor) -> bool:
        return descriptor.name == "metrics.query"

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=True, detail="hangs on purpose")

    def invoke(
        self,
        descriptor: ToolDescriptor,
        arguments: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        self.calls += 1
        self.entered.set()
        # Bounded so a failing test cannot wedge the suite; far longer than any deadline
        # the test sets, so the deadline is what ends the call.
        self.released.wait(timeout=30.0)
        return {"samples": [], "unit": "s", "source": "never", "schema_version": 1}


class TickingClock:
    """A clock that advances a fixed amount every time it is read.

    Lets a wall-clock deadline be reached deterministically, without the test sleeping.
    """

    def __init__(self, *, step_seconds: float) -> None:
        self._now = CLOCK_START
        self._step = timedelta(seconds=step_seconds)

    def now(self) -> Any:
        current = self._now
        self._now = self._now + self._step
        return current


# ------------------------------------------------------------------ tool invocation


@requires_postgres
class TestToolInvocationTimeoutIsEnforced:
    """The broker's adapter deadline is a real execution boundary."""

    def _broker(
        self, fixture: Fixture, session: Session, clock: Clock, provider: Any
    ) -> tuple[ToolBroker, TraceRecorder]:
        scope = load_incident_scope(
            session,
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            environment_id=fixture.environment.id,
            service_ids=fixture.service_ids,
        )
        tracer = TraceRecorder(
            tenant_id=fixture.tenant_id,
            execution_trace_id=uuid.uuid4(),
            trace_id=derive_trace_id(uuid.uuid4()),
            clock=clock,
        )
        broker = ToolBroker(
            resolver=CapabilityResolver(ToolRegistry.read_only()),
            providers=[provider],
            scope=scope,
            audit=AuditWriter(tenant_id=fixture.tenant_id, clock=clock),
            tracer=tracer,
            clock=clock,
            sleep=lambda _s: None,
        )
        return broker, tracer

    def test_a_hanging_adapter_is_abandoned_at_the_deadline(
        self, kernel_session: Session, clock: FrozenClock
    ) -> None:
        """The deadline ends a call the adapter would never have ended.

        Exercised against ``_invoke_with_deadline`` directly, with a one-second descriptor,
        because that is the method that *is* the boundary. Driving it through the registry
        would need a registered tool with a one-second timeout, and inventing one purely to
        make a test fast would put a fiction in the catalogue.
        """
        fixture = build_fixture(kernel_session, slug="timeout-hang")
        provider = HangingProvider()
        broker, _ = self._broker(fixture, kernel_session, clock, provider)

        impatient = (
            ToolRegistry.read_only()
            .by_name("metrics.query")
            .model_copy(update={"timeout_seconds": 1})
        )
        started = time.perf_counter()
        try:
            with pytest.raises(ToolTimeout, match="did not answer within 1s"):
                broker._invoke_with_deadline(
                    provider,
                    impatient,
                    {"service": fixture.service.name},
                    InvocationContext(
                        tenant_id=fixture.tenant_id,
                        correlation_id=uuid.uuid4(),
                        idempotency_key="a" * 64,
                        credential_ref=None,
                        timeout_seconds=1,
                        attempt=1,
                    ),
                )
        finally:
            elapsed = time.perf_counter() - started
            provider.released.set()
            broker.close()

        assert provider.entered.is_set(), "the adapter really was entered and really blocked"
        assert elapsed < 10.0, (
            f"the caller waited {elapsed:.1f}s on a one-second deadline; the adapter blocks "
            "for 30s, so anything near that means the deadline is not a boundary"
        )

    def test_a_timed_out_call_is_a_typed_failure_with_no_payload(
        self, kernel_session: Session, clock: FrozenClock
    ) -> None:
        """A call that never answered must not surface as a success or a guess."""
        from asic.simulators.scenarios import scenario

        fixture = build_fixture(kernel_session, slug="timeout-typed")
        provider = SimulatorProvider(scenario("SC-0005-metrics-source-timeout"), clock=clock)
        broker, _ = self._broker(fixture, kernel_session, clock, provider)
        result = broker.invoke(
            kernel_session,
            request=CapabilityRequest(
                node_id=NodeId.G4_EVIDENCE_COLLECTOR,
                capability="read.metrics",
                service_name=fixture.service.name,
                arguments={
                    "window_start": CLOCK_START.replace(hour=9),
                    "window_end": CLOCK_START,
                    "metric": "http_request_duration_p95_seconds",
                },
                incident_id=fixture.incident.id,
                correlation_id=uuid.uuid4(),
                purpose="timeout probe",
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert not result.succeeded
        assert result.failure is not None
        assert result.failure.error_type == "ToolTimeout"
        assert result.failure.stage is BrokerStage.ADAPTER_INVOCATION
        assert result.payload == {}, "a timed-out call carries no fabricated payload"

    def test_the_deadline_is_taken_from_the_registered_descriptor(self) -> None:
        # Enforcement uses the descriptor's declared value, not a constant buried in the
        # broker, so a tool's timeout is reviewable in the registry.
        registry = ToolRegistry.read_only()
        for descriptor in registry.descriptors():
            assert descriptor.timeout_seconds >= 1
            assert descriptor.timeout_seconds <= 60, (
                f"{descriptor.name} declares a {descriptor.timeout_seconds}s deadline; a "
                "read that slow is a stuck read"
            )


# ---------------------------------------------------------------- database statements


@requires_postgres
class TestDatabaseTimeoutsAreEnforcedByTheServer:
    """PostgreSQL cancels the statement itself, so nothing in this process need be watching."""

    def test_an_over_running_statement_is_cancelled(self, app_session: Session) -> None:
        apply_statement_timeouts(app_session, statement_timeout_ms=250)
        with pytest.raises(OperationalError) as caught:
            app_session.execute(sa.text("SELECT pg_sleep(5)"))
        assert "statement timeout" in str(caught.value).lower()
        app_session.rollback()

    def test_the_setting_is_transaction_local(self, app_session: Session) -> None:
        # Transaction-local for the same reason the tenant binding is: a session-level SET
        # would persist on a pooled connection and silently apply to the next request.
        apply_statement_timeouts(app_session, statement_timeout_ms=250)
        assert app_session.execute(sa.text("SHOW statement_timeout")).scalar_one() == "250ms"
        app_session.rollback()
        after = app_session.execute(sa.text("SHOW statement_timeout")).scalar_one()
        assert after != "250ms", "the timeout survived the transaction that set it"

    def test_the_idle_in_transaction_bound_exceeds_the_longest_node_timeout(self) -> None:
        # A node legitimately holds its transaction open across a model call, during which
        # the database sees nothing happening. A bound below the node timeout would kill
        # healthy work.
        longest_node = max(c.timeout_seconds for c in NODE_CONTRACTS.values())
        assert longest_node * 1000 < DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS

    def test_the_statement_bound_is_the_innermost(self) -> None:
        shortest_node = min(c.timeout_seconds for c in NODE_CONTRACTS.values())
        assert shortest_node * 1000 >= DEFAULT_STATEMENT_TIMEOUT_MS, (
            "a statement must be able to fail before the node containing it, so the error "
            "names the query rather than the node"
        )

    def test_every_unit_of_work_applies_the_bound(
        self, session_factory: Callable[[], Session], kernel_session: Session
    ) -> None:
        from asic.orchestration.context import UnitOfWork

        fixture = build_fixture(kernel_session, slug="timeout-uow")
        uow = UnitOfWork(session_factory, tenant_id=fixture.tenant_id)
        session = uow.begin()
        try:
            value = session.execute(sa.text("SHOW statement_timeout")).scalar_one()
            assert value == f"{DEFAULT_STATEMENT_TIMEOUT_MS // 1000}s"
        finally:
            uow.rollback()


# ------------------------------------------------------------------------ wall clock


class TestWallClockBudgetIsEnforced:
    """The wall-clock limit was declarative until the kernel began observing it."""

    def test_the_ledger_records_elapsed_time_as_a_total_not_a_sum(self) -> None:
        ledger = BudgetLedger(elapsed_seconds=10.0)
        assert ledger.with_elapsed(4.0).elapsed_seconds == 4.0, (
            "wall clock is measured against the run's start, so it is written rather than "
            "accumulated"
        )

    def test_negative_elapsed_time_is_refused(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            BudgetLedger().with_elapsed(-1.0)

    def test_observing_elapsed_time_can_exhaust_the_budget(self) -> None:
        state = BudgetState(policy=BudgetPolicy(max_wall_clock_seconds=60), ledger=BudgetLedger())
        assert state.exhausted_kind() is None
        exceeded = state.observe_elapsed(61.0)
        assert exceeded.exhausted_kind() is BudgetKind.WALL_CLOCK

    def test_an_exhausted_wall_clock_refuses_the_next_step(self) -> None:
        state = BudgetState(
            policy=BudgetPolicy(max_wall_clock_seconds=60), ledger=BudgetLedger()
        ).observe_elapsed(61.0)
        with pytest.raises(BudgetExhausted) as caught:
            state.require_headroom(iterations=1)
        assert caught.value.kind is BudgetKind.WALL_CLOCK


@requires_postgres
class TestWallClockTerminatesARun:
    def test_a_run_past_its_wall_clock_deadline_terminates_as_a_timeout(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
    ) -> None:
        """The end-to-end proof that the wall-clock limit now ends a run.

        A ticking clock advances a minute per read, so the deadline is reached in a handful
        of node boundaries without the test sleeping. Before the kernel observed elapsed
        time, this run would have continued until it ran out of iterations instead - and
        would have reported ``budget_exhausted`` for what was really a timeout.
        """
        from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, scenario

        scenario_obj = scenario(PRIMARY_SCENARIO_ID)
        fixture = build_fixture(kernel_session, slug="timeout-wallclock")
        kernel_session.commit()

        clock = TickingClock(step_seconds=10.0)
        kernel = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(scenario_obj, clock=clock)],
            model=DeterministicModelProvider(scenario_obj),
            clock=clock,
            # Generous on every other dimension, so only the clock can stop it.
            budget_policy=BudgetPolicy(
                max_iterations=50,
                max_tool_calls=200,
                max_wall_clock_seconds=60,
            ),
        )
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        kernel_session.expire_all()

        assert outcome.terminated is True
        assert outcome.termination_reason is TerminationReason.WALL_CLOCK_TIMEOUT, (
            f"expected a timeout, got {outcome.termination_reason} "
            f"(rule {outcome.termination_rule_id})"
        )
        assert outcome.termination_rule_id == "R2_wall_clock_timeout"
        assert outcome.summary["iteration"] < 50, "it stopped on time, not on iterations"
        assert len(outcome.nodes_executed) >= 2, "the run got going before the clock ended it"

    def test_a_resumed_run_does_not_get_a_fresh_wall_clock_allowance(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        primary_scenario: Any,
    ) -> None:
        """An interruption must not reset the deadline.

        The elapsed total is measured from ``execution_trace.started_at``, which survives a
        resume, rather than from the moment this attempt began.
        """
        from asic.db.models import ExecutionTrace
        from asic.orchestration.kernel import KernelInterrupted

        fixture = build_fixture(kernel_session, slug="timeout-resume")
        kernel_session.commit()

        clock = FrozenClock(start=CLOCK_START)

        def interrupt(name: str, _ordinal: int) -> None:
            if name == "evidence_collector":
                raise KernelInterrupted(name)

        crashing = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(primary_scenario, clock=clock)],
            model=DeterministicModelProvider(primary_scenario),
            clock=clock,
            interrupt_probe=interrupt,
        )
        first = crashing.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        kernel_session.expire_all()
        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.workflow_run_id == first.workflow_run_id)
        ).scalar_one()
        original_start = trace.started_at

        # Time passes while the run is suspended. A resumed run must count it.
        clock.advance(3600)
        resuming = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(primary_scenario, clock=clock)],
            model=DeterministicModelProvider(primary_scenario),
            clock=clock,
            budget_policy=BudgetPolicy(max_wall_clock_seconds=600),
        )
        second = resuming.resume(tenant_id=fixture.tenant_id, workflow_run_id=first.workflow_run_id)
        kernel_session.expire_all()

        assert second.terminated is True
        assert second.termination_reason is TerminationReason.WALL_CLOCK_TIMEOUT, (
            "an hour elapsed while suspended and the limit is ten minutes; a resumed run "
            "that reset its clock would have continued"
        )
        assert trace.started_at == original_start


# ------------------------------------------------------- declared but not enforced


class TestDeclarativeTimeoutsAreHonestlyLabelled:
    """Node-level timeouts are declared and *not* preemptively enforced.

    Recorded as a test rather than only as prose, so the claim and the code cannot drift
    apart: if node preemption is ever implemented, this test should be replaced by one that
    proves a hanging node is interrupted.
    """

    def test_every_node_declares_a_timeout(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            assert contract.timeout_seconds >= 1, name

    def test_node_timeouts_are_layered_beneath_the_wall_clock_budget(self) -> None:
        longest_node = max(c.timeout_seconds for c in NODE_CONTRACTS.values())
        assert longest_node < BudgetPolicy().max_wall_clock_seconds

    def test_the_kernel_does_not_preempt_a_node(self) -> None:
        """The limitation, asserted so it stays visible.

        Preempting a node would mean abandoning a thread that holds an open transaction on
        a psycopg2 connection, and a connection being used concurrently from two threads is
        undefined behaviour - so the abandoned work could corrupt the very checkpoint meant
        to make the run recoverable. Enforcing this properly needs async execution or a
        per-node connection that can be closed out of band, which is a Phase 15 obligation
        recorded in docs/architecture/orchestration-kernel.md.

        What bounds a slow node today: the tool deadline and the database statement timeout
        inside it, both enforced, plus the wall-clock budget at the next boundary.
        """
        import inspect

        from asic.orchestration import kernel as kernel_module

        source = inspect.getsource(kernel_module)
        assert "ThreadPoolExecutor" not in source, (
            "the kernel now runs nodes on a worker pool; if node preemption has been "
            "implemented, replace this test with one that proves a hanging node is "
            "interrupted, and update the timeout table in the architecture document"
        )

    def test_the_broker_by_contrast_does_preempt(self) -> None:
        import inspect

        from asic.tools import broker as broker_module

        source = inspect.getsource(broker_module)
        assert "ThreadPoolExecutor" in source
        assert "future.result(timeout=" in source, (
            "the adapter deadline must remain a real execution boundary"
        )
