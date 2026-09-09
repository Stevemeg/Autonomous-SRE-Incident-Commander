"""The trace is the system of record for what happened, and it holds no secrets.

``docs/architecture/observability.md`` commits to one trace serving operations, replay and
evaluation. These tests assert the properties that commitment depends on: the span tree is
well-formed, the required fields are present, correlation identifiers join everything, and
nothing sensitive is written.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ExecutionTrace, ToolExecution, TraceSpan
from asic.domain.clock import FrozenClock
from asic.domain.enums import NodeId, SpanStatus, TraceSpanKind
from asic.llm.deterministic import DeterministicModelProvider
from asic.observability.redaction import (
    REDACTED,
    looks_like_secret,
    redact_mapping,
    redact_value,
)
from asic.observability.tracing import TraceRecorder, derive_span_id, derive_trace_id
from asic.orchestration.kernel import InvestigationKernel, RunOutcome
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import Scenario
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import CLOCK_START, Fixture, build_fixture


class TestIdentifiers:
    def test_a_trace_id_is_derived_deterministically(self) -> None:
        correlation = uuid.uuid4()
        assert derive_trace_id(correlation) == derive_trace_id(correlation)
        assert len(derive_trace_id(correlation)) == 32

    def test_span_ids_are_stable_for_a_trace_and_ordinal(self) -> None:
        trace_id = derive_trace_id(uuid.uuid4())
        assert derive_span_id(trace_id, 3) == derive_span_id(trace_id, 3)
        assert derive_span_id(trace_id, 3) != derive_span_id(trace_id, 4)
        assert len(derive_span_id(trace_id, 3)) == 16

    def test_a_negative_ordinal_is_refused(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            derive_span_id("abcdef01", -1)


class TestRecorder:
    def _recorder(self) -> TraceRecorder:
        return TraceRecorder(
            tenant_id=uuid.uuid4(),
            execution_trace_id=uuid.uuid4(),
            trace_id=derive_trace_id(uuid.uuid4()),
            clock=FrozenClock(start=CLOCK_START),
        )

    def test_nested_spans_record_their_parent(self) -> None:
        recorder = self._recorder()
        with (
            recorder.span(kind=TraceSpanKind.NODE_EXECUTE, name="outer") as outer,
            recorder.span(kind=TraceSpanKind.TOOL_INVOKE, name="inner") as inner,
        ):
            assert inner.parent_span_id == outer.span_id
        spans = {s.name: s for s in recorder.pending}
        assert spans["outer"].parent_span_id is None
        assert spans["inner"].parent_span_id == spans["outer"].span_id

    def test_an_exception_marks_the_span_as_an_error_and_propagates(self) -> None:
        recorder = self._recorder()
        with pytest.raises(RuntimeError, match="boom"):  # noqa: SIM117 - clarity
            with recorder.span(kind=TraceSpanKind.NODE_EXECUTE, name="failing"):
                raise RuntimeError("boom")
        span = recorder.pending[-1]
        assert span.status is SpanStatus.ERROR
        assert span.failure_reason is not None
        assert "boom" in span.failure_reason

    def test_a_model_call_is_recorded_by_reference_not_by_content(self) -> None:
        recorder = self._recorder()
        with recorder.span(kind=TraceSpanKind.LLM_CALL, name="llm") as span:
            span.set_model_call(
                provider="p",
                model_id="m",
                prompt_version="1.0.0",
                prompt_hash="deadbeef",
                input_tokens=10,
                output_tokens=5,
                cost_usd=0.001,
                finish_reason="stop",
            )
        span = recorder.pending[-1]
        assert span.prompt_version == "1.0.0"
        assert span.model_metadata["prompt_hash"] == "deadbeef"
        assert "prompt_text" not in span.model_metadata
        assert "prompt" not in str(span.model_metadata).lower().replace("prompt_hash", "")

    def test_the_ordinal_can_be_continued_for_a_resumed_run(self) -> None:
        trace_id = derive_trace_id(uuid.uuid4())
        recorder = TraceRecorder(
            tenant_id=uuid.uuid4(),
            execution_trace_id=uuid.uuid4(),
            trace_id=trace_id,
            clock=FrozenClock(start=CLOCK_START),
            start_ordinal=7,
        )
        with recorder.span(kind=TraceSpanKind.NODE_EXECUTE, name="resumed"):
            pass
        assert recorder.pending[0].span_id == derive_span_id(trace_id, 7)


class TestRedaction:
    # These are synthetic credentials, present so the redactor is tested against the shapes
    # it exists to catch. Each line carries the hygiene pragma so the repository secret
    # scanner skips it explicitly rather than through a path exemption.
    @pytest.mark.parametrize(
        "value",
        [
            "Bearer abcdefghijklmnopqrstuvwxyz012345",  # hygiene: synthetic-secret-fixture
            "-----BEGIN RSA PRIVATE KEY-----",  # hygiene: synthetic-secret-fixture
            "postgresql://user:hunter2@db.internal:5432/asic",  # hygiene: synthetic-secret-fixture
            "AKIAIOSFODNN7EXAMPLE",  # hygiene: synthetic-secret-fixture
            "ghp_abcdefghijklmnopqrstuvwxyz0123",  # hygiene: synthetic-secret-fixture
        ],
    )
    def test_secret_shaped_values_are_replaced(self, value: str) -> None:
        assert looks_like_secret(value)
        assert redact_value(value) == REDACTED

    def test_a_secret_named_key_is_replaced_not_truncated(self) -> None:
        # A truncated secret is a leaked prefix.
        redacted = redact_mapping({"password": "hunter2", "api_key": "abc"})
        assert redacted == {"password": REDACTED, "api_key": REDACTED}

    def test_a_secret_reference_is_kept_because_that_is_its_purpose(self) -> None:
        redacted = redact_mapping({"credential_ref": "asic/read/prometheus"})
        assert redacted["credential_ref"] == "asic/read/prometheus"

    def test_long_values_are_bounded(self) -> None:
        rendered = redact_value("x" * 5000)
        assert isinstance(rendered, str)
        assert len(rendered) < 5000
        assert rendered.endswith("[truncated]")

    def test_nested_structures_are_redacted(self) -> None:
        redacted = redact_mapping({"outer": {"token": "abc", "safe": "value"}})
        assert redacted["outer"]["token"] == REDACTED
        assert redacted["outer"]["safe"] == "value"

    def test_deep_recursion_is_bounded(self) -> None:
        payload: dict[str, object] = {"k": "v"}
        for _ in range(20):
            payload = {"k": payload}
        rendered = redact_value(payload)
        assert "depth>" in str(rendered)


@requires_postgres
class TestPersistedTrace:
    @pytest.fixture
    def executed(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> tuple[Fixture, RunOutcome]:
        fixture = build_fixture(kernel_session, slug="trace-tenant")
        kernel_session.commit()
        kernel = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(primary_scenario, clock=clock)],
            model=DeterministicModelProvider(primary_scenario),
            clock=clock,
        )
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
            fixture_refs=primary_scenario.fixture_ref(),
            random_seed=7,
        )
        kernel_session.expire_all()
        return fixture, outcome

    def _spans(self, session: Session, outcome: RunOutcome) -> list[TraceSpan]:
        return list(
            session.execute(
                sa.select(TraceSpan)
                .where(TraceSpan.execution_trace_id == outcome.execution_trace_id)
                .order_by(TraceSpan.started_at, TraceSpan.span_id)
            ).scalars()
        )

    def test_the_span_tree_is_well_formed(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        spans = self._spans(kernel_session, outcome)
        assert spans
        ids = {span.span_id for span in spans}
        for span in spans:
            if span.parent_span_id is not None:
                assert span.parent_span_id in ids, f"{span.name} has a dangling parent"
            assert span.parent_span_id != span.span_id

    def test_every_node_span_names_its_node_and_version(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        node_spans = [
            span
            for span in self._spans(kernel_session, outcome)
            if span.kind in (TraceSpanKind.NODE_EXECUTE, TraceSpanKind.PLANNER_STEP)
        ]
        assert node_spans
        for span in node_spans:
            assert span.node_id is not None
            assert span.node_version, f"{span.name} has no node version"

    def test_a_tool_span_names_the_tool_and_joins_to_its_execution(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, outcome = executed
        tool_spans = [
            span
            for span in self._spans(kernel_session, outcome)
            if span.kind is TraceSpanKind.TOOL_INVOKE
        ]
        assert tool_spans
        execution_ids = set(
            kernel_session.execute(
                sa.select(ToolExecution.id).where(ToolExecution.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        for span in tool_spans:
            assert span.attributes["tool_name"]
            assert span.attributes["tool_version"]
            assert span.tool_execution_id in execution_ids

    def test_planner_spans_record_the_alternatives_considered(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        # Without the alternatives, tool-call efficiency can be measured but not diagnosed.
        _, outcome = executed
        planner_spans = [
            span
            for span in self._spans(kernel_session, outcome)
            if span.kind is TraceSpanKind.PLANNER_STEP
        ]
        assert planner_spans
        assert any(span.decision.get("candidates") for span in planner_spans)
        for span in planner_spans:
            assert "action" in span.decision or "overridden_reason" in span.decision

    def test_every_span_records_budget_headroom_at_entry(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        node_spans = [
            span
            for span in self._spans(kernel_session, outcome)
            if span.node_id is not None and span.kind is not TraceSpanKind.TOOL_INVOKE
        ]
        assert node_spans
        for span in node_spans:
            assert span.budget_snapshot, f"{span.name} recorded no budget state"

    def test_the_terminal_span_records_the_termination_reason(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        terminal = [
            span
            for span in self._spans(kernel_session, outcome)
            if span.termination_reason is not None
        ]
        assert terminal, "a run's ending must be attributable to a span"

    def test_model_spans_carry_provider_model_and_prompt_reference(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        model_spans = [span for span in self._spans(kernel_session, outcome) if span.model_metadata]
        assert model_spans
        for span in model_spans:
            assert span.model_metadata["provider"]
            assert span.model_metadata["model_id"]
            assert span.model_metadata["prompt_hash"]
            assert span.prompt_version
            assert span.input_tokens is not None
            assert span.output_tokens is not None
            assert span.cost_usd is not None

    def test_no_span_contains_prompt_text_or_a_secret(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        for span in self._spans(kernel_session, outcome):
            blob = " ".join(
                str(part)
                for part in (
                    span.decision,
                    span.attributes,
                    span.input_refs,
                    span.model_metadata,
                )
            )
            assert "You are the investigation planner" not in blob, (
                "prompt text reached the trace; it must be referenced by version and hash"
            )
            assert not looks_like_secret(blob)

    def test_correlation_identifiers_join_the_whole_run(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, outcome = executed
        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.id == outcome.execution_trace_id)
        ).scalar_one()
        assert trace.workflow_run_id == outcome.workflow_run_id
        assert trace.incident_id == outcome.incident_id
        assert trace.trace_id == derive_trace_id(trace.correlation_id)

        executions = list(
            kernel_session.execute(
                sa.select(ToolExecution).where(ToolExecution.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert executions
        assert all(e.correlation_id == trace.correlation_id for e in executions)

    def test_the_trace_rolls_up_cost_and_effort(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.id == outcome.execution_trace_id)
        ).scalar_one()
        assert trace.total_tokens is not None and trace.total_tokens > 0
        assert trace.total_cost_usd is not None and trace.total_cost_usd > 0
        assert trace.total_tool_calls is not None and trace.total_tool_calls > 0

    def test_the_trace_is_replayable(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.id == outcome.execution_trace_id)
        ).scalar_one()
        assert trace.clock_start is not None
        assert trace.random_seed == 7
        assert trace.fixture_refs.get("scenario_id")

    def test_node_ids_span_the_nodes_that_actually_ran(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        _, outcome = executed
        node_ids = {span.node_id for span in self._spans(kernel_session, outcome) if span.node_id}
        assert NodeId.G2_INCIDENT_COORDINATOR in node_ids
        assert NodeId.G3_INVESTIGATION_PLANNER in node_ids
        assert NodeId.G4_EVIDENCE_COLLECTOR in node_ids
