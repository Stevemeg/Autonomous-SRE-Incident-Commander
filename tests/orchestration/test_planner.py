"""The planner's bounds hold against the model, not with its cooperation.

Every test here is written against a model output that a well-behaved planner would not
produce. The point is that the system's behaviour does not depend on the model behaving.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import InvestigationStep, ToolExecution
from asic.domain.budget import BudgetPolicy
from asic.domain.clock import FrozenClock
from asic.domain.enums import EvidenceDomain, PlannerAction, TerminationReason
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.kernel import InvestigationKernel, RunOutcome
from asic.orchestration.nodes.planner import PlannerDecision
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import Scenario
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import Fixture, build_fixture


class TestDecisionSchema:
    def test_a_valid_decision_parses(self) -> None:
        decision = PlannerDecision.model_validate(
            {
                "action": "collect_evidence",
                "domain": "metrics",
                "gap": "onset unknown",
                "rationale": "establish onset",
                "expected_gain": 0.8,
                "candidates": [],
            }
        )
        assert decision.action is PlannerAction.COLLECT_EVIDENCE
        assert decision.domain is EvidenceDomain.METRICS

    def test_an_unknown_action_is_rejected(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            PlannerDecision.model_validate(
                {"action": "execute_remediation", "gap": "g", "rationale": "r"}
            )

    def test_an_extra_field_is_rejected(self) -> None:
        # A planner that could smuggle an extra field could smuggle an instruction.
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            PlannerDecision.model_validate(
                {
                    "action": "terminate",
                    "gap": "g",
                    "rationale": "r",
                    "tool_name": "k8s.deployment.rollback",
                }
            )

    def test_an_unknown_domain_is_rejected(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            PlannerDecision.model_validate(
                {
                    "action": "collect_evidence",
                    "domain": "billing_database",
                    "gap": "g",
                    "rationale": "r",
                }
            )

    def test_expected_gain_is_bounded(self) -> None:
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            PlannerDecision.model_validate(
                {"action": "terminate", "gap": "g", "rationale": "r", "expected_gain": 5.0}
            )


@requires_postgres
class TestPlannerBounds:
    def _run(
        self,
        fixture: Fixture,
        scenario_obj: Scenario,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        observer: Session,
        *,
        budget: BudgetPolicy | None = None,
    ) -> RunOutcome:
        kernel = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(scenario_obj, clock=clock)],
            model=DeterministicModelProvider(scenario_obj),
            clock=clock,
            budget_policy=budget or scenario_obj.budget,
        )
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        observer.expire_all()
        return outcome

    def test_a_domain_outside_the_menu_is_rejected_never_repaired(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        # The tenant is granted metrics only. The planner asks for logs, which is a real
        # domain but an ungranted capability: the selection is rejected and converted into
        # hypothesis formation, not repaired into a different request.
        scenario_obj = replace(
            primary_scenario,
            planner_script=(
                '{"action": "collect_evidence", "domain": "logs", "gap": "errors unknown",'
                ' "rationale": "look for errors", "expected_gain": 0.7, "candidates": []}',
                '{"action": "terminate", "gap": "nothing more", "rationale": "done",'
                ' "expected_gain": 0.0, "candidates": []}',
            ),
        )
        fixture = build_fixture(
            kernel_session, slug="plan-ungranted", grant_capabilities=("read.metrics",)
        )
        kernel_session.commit()
        self._run(fixture, scenario_obj, session_factory, resolver, clock, kernel_session)

        steps = list(
            kernel_session.execute(
                sa.select(InvestigationStep).where(InvestigationStep.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert steps == [], "an ungranted domain must not become a planned step"
        calls = list(
            kernel_session.execute(
                sa.select(ToolExecution).where(ToolExecution.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert calls == [], "nothing reached an adapter"

    def test_a_redundant_collection_is_converted_rather_than_repeated(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        gap = "the shape and onset of the latency regression are unknown"
        step = (
            '{"action": "collect_evidence", "domain": "metrics", "gap": "' + gap + '",'
            ' "rationale": "establish onset", "expected_gain": 0.8, "candidates": []}'
        )
        scenario_obj = replace(
            primary_scenario,
            planner_script=(
                step,
                step,  # the identical request again: same domain, same gap
                '{"action": "terminate", "gap": "nothing more", "rationale": "done",'
                ' "expected_gain": 0.0, "candidates": []}',
            ),
        )
        fixture = build_fixture(kernel_session, slug="plan-redundant")
        kernel_session.commit()
        self._run(fixture, scenario_obj, session_factory, resolver, clock, kernel_session)

        steps = list(
            kernel_session.execute(
                sa.select(InvestigationStep).where(InvestigationStep.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert len(steps) == 1, "the repeat must not become a second step"

    def test_the_iteration_budget_stops_a_planner_that_never_stops(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        endless = (
            '{"action": "collect_evidence", "domain": "metrics", "gap": "gap %d",'
            ' "rationale": "keep going", "expected_gain": 0.5, "candidates": []}'
        )
        scenario_obj = replace(
            primary_scenario,
            planner_script=tuple(endless % n for n in range(50)),
        )
        fixture = build_fixture(kernel_session, slug="plan-endless")
        kernel_session.commit()
        outcome = self._run(
            fixture,
            scenario_obj,
            session_factory,
            resolver,
            clock,
            kernel_session,
            budget=BudgetPolicy(max_iterations=4, max_tool_calls=20),
        )
        assert outcome.terminated is True
        assert outcome.termination_reason is TerminationReason.BUDGET_EXHAUSTED
        assert outcome.summary["iteration"] <= 4

    def test_the_tool_call_budget_bounds_collection_independently(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        endless = (
            '{"action": "collect_evidence", "domain": "%s", "gap": "gap %d",'
            ' "rationale": "keep going", "expected_gain": 0.5, "candidates": []}'
        )
        domains = ("metrics", "logs", "traces", "deployments", "kubernetes_state", "knowledge")
        scenario_obj = replace(
            primary_scenario,
            planner_script=tuple(endless % (domains[n % len(domains)], n) for n in range(50)),
        )
        fixture = build_fixture(kernel_session, slug="plan-toolcap")
        kernel_session.commit()
        outcome = self._run(
            fixture,
            scenario_obj,
            session_factory,
            resolver,
            clock,
            kernel_session,
            budget=BudgetPolicy(max_iterations=40, max_tool_calls=3),
        )
        assert outcome.terminated is True
        calls = kernel_session.execute(
            sa.select(sa.func.count())
            .select_from(ToolExecution)
            .where(ToolExecution.tenant_id == fixture.tenant_id)
        ).scalar_one()
        assert calls <= 3

    def test_a_planner_that_only_ever_emits_rubbish_still_terminates(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        scenario_obj = replace(
            primary_scenario,
            planner_script=("nonsense", "still nonsense", "more nonsense"),
        )
        fixture = build_fixture(kernel_session, slug="plan-rubbish")
        kernel_session.commit()
        outcome = self._run(fixture, scenario_obj, session_factory, resolver, clock, kernel_session)
        assert outcome.terminated is True
        assert outcome.termination_reason is not None

    def test_a_provider_outage_terminates_rather_than_hanging(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        fixture = build_fixture(kernel_session, slug="plan-outage")
        kernel_session.commit()
        kernel = InvestigationKernel(
            session_factory=session_factory,
            resolver=resolver,
            providers=[SimulatorProvider(primary_scenario, clock=clock)],
            model=DeterministicModelProvider(primary_scenario, fail_after=0),
            clock=clock,
        )
        outcome = kernel.start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=fixture.service_ids,
        )
        assert outcome.terminated is True
        assert outcome.termination_reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_a_planned_step_records_the_budget_it_started_with(
        self,
        kernel_session: Session,
        session_factory: Callable[[], Session],
        resolver: CapabilityResolver,
        clock: FrozenClock,
        primary_scenario: Scenario,
    ) -> None:
        fixture = build_fixture(kernel_session, slug="plan-budgetrec")
        kernel_session.commit()
        self._run(fixture, primary_scenario, session_factory, resolver, clock, kernel_session)
        steps = list(
            kernel_session.execute(
                sa.select(InvestigationStep).where(InvestigationStep.tenant_id == fixture.tenant_id)
            ).scalars()
        )
        assert steps
        for step in steps:
            assert step.budget_before.get("ledger") is not None
            assert step.budget_after.get("ledger") is not None
