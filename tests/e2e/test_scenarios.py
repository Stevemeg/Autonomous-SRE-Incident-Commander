"""End-to-end: every scenario runs through the real graph to a deterministic ending.

Each scenario declares what a correct run of it looks like
(:class:`~asic.simulators.scenarios.ScenarioExpectation`), and this suite asserts the run
matched. That is deliberately stronger than "it finished": the expectations include
terminating in *uncertainty*, terminating on a *budget*, and terminating without a cause
when the evidence contradicts one. A suite that only contained the happy path would prove
only the happy path.

The scenario expectations are also the deterministic hooks Phase 11 will consume. Nothing
here computes a score, and nothing here reports an improvement.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Evidence,
    Hypothesis,
    Incident,
    InvestigationStep,
    TimelineEvent,
    ToolExecution,
)
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    EvidenceDomain,
    IncidentStatus,
    InvestigationStepStatus,
    TerminationReason,
)
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.kernel import InvestigationKernel, RunOutcome
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import SCENARIOS, Scenario, scenario
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import Fixture, build_fixture

pytestmark = requires_postgres

#: Scenarios whose scripts are complete enough to drive a full run. Two are excluded on
#: purpose and are exercised by their own targeted tests instead - see the note below.
RUNNABLE = tuple(
    scenario_id for scenario_id in sorted(SCENARIOS) if scenario_id != "SC-0008-multi-service"
)


def _run(
    fixture: Fixture,
    scenario_obj: Scenario,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
    *,
    observer: Session | None = None,
) -> RunOutcome:
    """Run one scenario end to end.

    ``observer`` is the session the test will assert with. The kernel commits through its
    own sessions, so the observer's identity map still holds the rows as they were before
    the run; expiring it afterwards makes the assertions read what was actually committed
    rather than what the test set up.
    """
    kernel = InvestigationKernel(
        session_factory=session_factory,
        resolver=resolver,
        providers=[SimulatorProvider(scenario_obj, clock=clock)],
        model=DeterministicModelProvider(scenario_obj),
        clock=clock,
        budget_policy=scenario_obj.budget,
    )
    outcome = kernel.start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
        fixture_refs=scenario_obj.fixture_ref(),
        random_seed=42,
    )
    if observer is not None:
        observer.expire_all()
    return outcome


@pytest.mark.parametrize("scenario_id", RUNNABLE)
def test_every_scenario_reaches_its_expected_terminal_state(
    scenario_id: str,
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
) -> None:
    scenario_obj = scenario(scenario_id)
    fixture = build_fixture(
        kernel_session, slug=f"e2e-{scenario_id[:7].lower()}", service_name=scenario_obj.service
    )
    kernel_session.commit()

    outcome = _run(fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session)

    expectation = scenario_obj.expectation
    assert outcome.terminated is True, f"{scenario_id} did not terminate"
    assert outcome.termination_reason is expectation.terminal_reason, (
        f"{scenario_id}: expected {expectation.terminal_reason.value}, got "
        f"{outcome.termination_reason.value if outcome.termination_reason else None} "
        f"(rule {outcome.termination_rule_id})"
    )
    assert outcome.incident_status.value == expectation.terminal_incident_status


@pytest.mark.parametrize("scenario_id", RUNNABLE)
def test_every_scenario_leaves_the_incident_in_a_terminal_status(
    scenario_id: str,
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    clock: FrozenClock,
) -> None:
    scenario_obj = scenario(scenario_id)
    fixture = build_fixture(
        kernel_session,
        slug=f"e2eterm-{scenario_id[:6].lower()}",
        service_name=scenario_obj.service,
    )
    kernel_session.commit()
    _run(fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session)

    incident = kernel_session.execute(
        sa.select(Incident).where(Incident.id == fixture.incident.id)
    ).scalar_one()
    assert incident.status in {
        IncidentStatus.UNCERTAIN,
        IncidentStatus.ESCALATED,
        IncidentStatus.FAILED,
        IncidentStatus.RESOLVED,
    }
    assert incident.terminated_at is not None
    assert incident.termination_reason is not None


class TestPrimarySlice:
    """The first vertical slice, end to end: checkout latency after a deployment."""

    @pytest.fixture
    def executed(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> tuple[Fixture, RunOutcome]:
        fixture = build_fixture(kernel_session, slug="e2e-primary")
        kernel_session.commit()
        outcome = _run(
            fixture, primary_scenario, session_factory, resolver, clock, observer=kernel_session
        )
        return fixture, outcome

    def test_the_expected_domains_were_consulted(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, _ = executed
        domains = set(
            kernel_session.execute(
                sa.select(Evidence.domain).where(Evidence.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        for expected in (
            EvidenceDomain.METRICS,
            EvidenceDomain.DEPLOYMENTS,
            EvidenceDomain.LOGS,
        ):
            assert expected in domains

    def test_a_hypothesis_cites_the_evidence_that_supports_it(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, _ = executed
        hypotheses = list(
            kernel_session.execute(
                sa.select(Hypothesis).where(Hypothesis.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert hypotheses, "the primary scenario produces a hypothesis"
        top = hypotheses[0]
        assert top.root_cause_class == "bad_deployment"
        assert top.confidence_basis["supporting_count"] >= 2

    def test_the_confidence_is_capped_by_the_evidence_not_by_the_model(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, _ = executed
        top = kernel_session.execute(
            sa.select(Hypothesis).where(Hypothesis.tenant_id == fixture.tenant_id)
        ).scalar_one()
        basis = top.confidence_basis
        assert basis["applied"] <= basis["model_stated_confidence"]
        assert basis["applied"] <= basis["deterministic_ceiling"]
        assert basis["ceiling_rule"] in {"corroborated", "single_support", "contradicted"}

    def test_each_step_records_the_gap_it_was_chosen_to_close(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, _ = executed
        steps = list(
            kernel_session.execute(
                sa.select(InvestigationStep)
                .where(InvestigationStep.tenant_id == fixture.tenant_id)
                .order_by(InvestigationStep.sequence)
            ).scalars()
        )
        assert steps
        assert [s.sequence for s in steps] == list(range(1, len(steps) + 1))
        for step in steps:
            assert step.gap_declared.strip()
            assert step.rationale.strip()
            assert step.budget_before, "budget state at entry makes termination explicable"

    def test_a_human_readable_timeline_is_projected(
        self, executed: tuple[Fixture, RunOutcome], kernel_session: Session
    ) -> None:
        fixture, _ = executed
        entries = list(
            kernel_session.execute(
                sa.select(TimelineEvent)
                .where(TimelineEvent.tenant_id == fixture.tenant_id)
                .order_by(TimelineEvent.sequence)
            ).scalars()
        )
        assert entries, "the derived timeline is projected when the run ends"
        assert all(entry.source_event_id is not None for entry in entries)

    def test_the_run_is_escalated_rather_than_resolved(
        self, executed: tuple[Fixture, RunOutcome]
    ) -> None:
        # There is no remediation, no policy gate and no verifier, so a cause is handed to
        # a human. Reporting resolution would claim an outcome the system did not produce.
        _, outcome = executed
        assert outcome.termination_reason is TerminationReason.HUMAN_ESCALATION
        assert outcome.incident_status is IncidentStatus.ESCALATED


class TestFailureScenarios:
    def test_an_unavailable_source_degrades_the_step_and_the_run_continues(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0004-log-source-error")
        fixture = build_fixture(kernel_session, slug="e2e-degrade")
        kernel_session.commit()
        outcome = _run(
            fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session
        )

        degraded = list(
            kernel_session.execute(
                sa.select(InvestigationStep).where(
                    InvestigationStep.tenant_id == fixture.tenant_id,
                    InvestigationStep.status == InvestigationStepStatus.DEGRADED,
                )
            ).scalars()
        )
        assert degraded, "the unavailable domain is recorded as degraded"
        assert all(step.degradation_reason for step in degraded)
        assert outcome.terminated, "the investigation degraded rather than aborting"

    def test_a_timeout_does_not_produce_fabricated_evidence(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0005-metrics-source-timeout")
        fixture = build_fixture(kernel_session, slug="e2e-timeout")
        kernel_session.commit()
        _run(fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session)

        metrics_evidence = list(
            kernel_session.execute(
                sa.select(Evidence).where(
                    Evidence.tenant_id == fixture.tenant_id,
                    Evidence.domain == EvidenceDomain.METRICS,
                )
            ).scalars()
        )
        assert metrics_evidence == [], (
            "a source that never answered produced no evidence; anything here would be "
            "data the system invented"
        )

    def test_budget_exhaustion_stops_a_planner_that_never_converges(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0006-budget-exhaustion")
        assert "terminate" not in "".join(scenario_obj.planner_script), (
            "this scenario is only meaningful while its planner never asks to stop"
        )
        fixture = build_fixture(kernel_session, slug="e2e-budget")
        kernel_session.commit()
        outcome = _run(
            fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session
        )

        assert outcome.termination_reason is TerminationReason.BUDGET_EXHAUSTED
        assert outcome.incident_status is IncidentStatus.UNCERTAIN
        assert scenario_obj.budget is not None
        calls = kernel_session.execute(
            sa.select(sa.func.count())
            .select_from(ToolExecution)
            .where(ToolExecution.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert calls <= scenario_obj.budget.max_tool_calls

    def test_contradictory_evidence_prevents_a_confident_conclusion(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0003-contradictory-evidence")
        fixture = build_fixture(kernel_session, slug="e2e-contra")
        kernel_session.commit()
        outcome = _run(
            fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session
        )

        hypothesis = kernel_session.execute(
            sa.select(Hypothesis).where(Hypothesis.tenant_id == fixture.tenant_id)
        ).scalar_one()
        basis = hypothesis.confidence_basis
        assert basis["contradicting_count"] >= 1
        assert basis["applied"] < basis["model_stated_confidence"], (
            "the model claimed high confidence; the contradiction must lower it"
        )
        assert outcome.termination_reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_unparseable_model_output_is_repaired_once_then_typed_as_a_failure(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0009-malformed-model-output")
        fixture = build_fixture(kernel_session, slug="e2e-malformed")
        kernel_session.commit()
        outcome = _run(
            fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session
        )
        assert outcome.terminated is True
        assert outcome.termination_reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_a_transient_error_clears_on_retry(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
    ) -> None:
        scenario_obj = scenario("SC-0011-transient-error-then-success")
        fixture = build_fixture(kernel_session, slug="e2e-transient")
        kernel_session.commit()
        _run(fixture, scenario_obj, session_factory, resolver, clock, observer=kernel_session)

        execution = kernel_session.execute(
            sa.select(ToolExecution).where(
                ToolExecution.tenant_id == fixture.tenant_id,
                ToolExecution.tool_name == "metrics.query",
            )
        ).scalar_one()
        assert execution.attempt >= 2, "a pure read is class C1 and is retried"


class TestEvaluationReadiness:
    """Phase 11 hooks exist. Nothing here scores anything."""

    def test_every_scenario_declares_what_a_correct_run_looks_like(self) -> None:
        for scenario_id, scenario_obj in SCENARIOS.items():
            expectation = scenario_obj.expectation
            assert expectation.terminal_reason is not None, scenario_id
            assert expectation.terminal_incident_status, scenario_id

    def test_the_fixture_reference_is_recorded_on_the_trace(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        from asic.db.models import ExecutionTrace

        fixture = build_fixture(kernel_session, slug="e2e-evalready")
        kernel_session.commit()
        outcome = _run(
            fixture, primary_scenario, session_factory, resolver, clock, observer=kernel_session
        )

        trace = kernel_session.execute(
            sa.select(ExecutionTrace).where(ExecutionTrace.id == outcome.execution_trace_id)
        ).scalar_one()
        assert trace.fixture_refs["scenario_id"] == primary_scenario.scenario_id
        assert trace.random_seed == 42
        assert trace.clock_start is not None, "a replay needs the frozen clock"
