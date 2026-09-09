"""G2 Incident Coordinator, and the terminator that shares its identity.

Deterministic by design (ADR-0001). The coordinator owns incident state and routing, and
routing is a function of state: making it a model would put incident control flow inside a
probabilistic component, where a wrong route is a durability bug rather than a reasoning
error and is far harder to reproduce.

It calls no tools. Its contract declares no capabilities, so the broker would refuse it
even if a future edit tried.
"""

from __future__ import annotations

from typing import Any

from asic.contracts.nodes import (
    G2_INCIDENT_COORDINATOR,
    G2_TERMINATOR,
    G4_EVIDENCE_COLLECTOR,
)
from asic.contracts.state import BudgetSnapshot, GraphState
from asic.domain.budget import BudgetLedger, BudgetState
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    BudgetKind,
    IncidentEventType,
    InvestigationPhase,
    NodeId,
    TerminationReason,
    TraceSpanKind,
)
from asic.observability import metrics
from asic.orchestration.context import NodeDependencies
from asic.orchestration.termination import TerminationInputs, decide


def coordinator_node(deps: NodeDependencies) -> Any:
    """Build the entry node: validate context, publish the menu, route into the loop."""

    contract = G2_INCIDENT_COORDINATOR

    def run(state: GraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.coordinator",
            node_id=NodeId.G2_INCIDENT_COORDINATOR,
            node_version=contract.node_version,
            input_refs={"incident_id": deps.context.identity.incident_id},
        ) as span:
            # The *collector's* menu, not the coordinator's: the collector is the only
            # node that calls tools, so publishing the coordinator's own (empty) menu
            # would tell the planner there is nothing available to ask for.
            menu = deps.broker.menu_for(deps.session, G4_EVIDENCE_COLLECTOR)
            budget = _budget_state(state, deps)

            span.set_decision(
                capability_menu=list(menu.names()),
                services_in_scope=list(deps.context.scope.service_names),
                environment=deps.context.scope.environment_name,
            )
            span.budget_snapshot = dict(budget.remaining())

            deps.audit.record(
                deps.session,
                event_type=AuditEventType.AUTHORIZATION_GRANTED,
                outcome="allowed",
                actor_type=ActorType.SYSTEM,
                actor_id=NodeId.G2_INCIDENT_COORDINATOR.value,
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                target_type="capability_menu",
                target_id=deps.context.identity.workflow_run_id,
                payload={
                    "capabilities": list(menu.names()),
                    "services": list(deps.context.scope.service_names),
                    "environment": deps.context.scope.environment_name,
                    "risk_ceiling": "ro",
                },
            )

            update: dict[str, Any] = {
                "phase": InvestigationPhase.PLANNING,
                "capability_menu": list(menu.names()),
                "budget": _snapshot(budget),
            }
            if not state.get("open_gaps"):
                update["open_gaps"] = [_initial_gap(deps)]
            contract.validate_update(update)
            return update

    return run


def terminator_node(deps: NodeDependencies) -> Any:
    """Build the terminal decision node.

    Separated from the coordinator's entry role because the two write different parts of
    the state and one of them must be permitted to end the run. Sharing a contract would
    mean the entry node could terminate, which is not a power it needs.
    """

    contract = G2_TERMINATOR

    def run(state: GraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.WORKFLOW_PHASE,
            name="phase.terminate",
            node_id=NodeId.G2_INCIDENT_COORDINATOR,
            node_version=contract.node_version,
        ) as span:
            budget = _budget_state(state, deps)
            decision = state.get("last_decision")
            inputs = TerminationInputs(
                budget=budget,
                hypotheses=state.get("hypotheses", []),
                evidence_count=len(state.get("evidence", [])),
                failures=state.get("failures", []),
                degraded_domains=state.get("degraded_domains", []),
                attempted_domains=state.get("covered_domains", [])
                + state.get("degraded_domains", []),
                planner_action=decision.action if decision else None,
                open_gaps=state.get("open_gaps", []),
                budget_refusal=_refusal(state),
            )
            verdict = decide(inputs)

            span.set_decision(
                rule_id=verdict.rule_id,
                should_terminate=verdict.should_terminate,
                explanation=verdict.explanation,
                evidence_count=inputs.evidence_count,
                domain_coverage=round(inputs.domain_coverage, 3),
                hypothesis_count=len(inputs.hypotheses),
            )
            span.budget_snapshot = dict(budget.remaining())
            span.termination_reason = verdict.reason

            update: dict[str, Any] = {
                "terminated": verdict.should_terminate,
                "termination_rule_id": verdict.rule_id,
                "budget": _snapshot(budget),
            }
            if verdict.should_terminate:
                update["phase"] = InvestigationPhase.TERMINATED
                update["termination_reason"] = verdict.reason.value if verdict.reason else None
                update["terminal_incident_status"] = (
                    verdict.incident_status.value if verdict.incident_status else None
                )
                metrics.runs_terminated_total.add(
                    1, {"reason": verdict.reason.value if verdict.reason else "unknown"}
                )
                if verdict.reason in (
                    TerminationReason.BUDGET_EXHAUSTED,
                    TerminationReason.WALL_CLOCK_TIMEOUT,
                ):
                    kind = budget.exhausted_kind()
                    metrics.budget_exhaustions_total.add(
                        1, {"budget_kind": kind.value if kind else "unknown"}
                    )
                metrics.investigation_iterations.record(float(state.get("iteration", 0)))
            else:
                update["phase"] = InvestigationPhase.PLANNING

            contract.validate_update(update)
            return update

    return run


#: Event types the coordinator emits, exposed so the kernel can append them once the
#: node's update has been accepted rather than the node writing events itself.
COORDINATOR_EVENTS = (
    IncidentEventType.INCIDENT_STATE_CHANGED,
    IncidentEventType.INCIDENT_TERMINATED,
)


def _refusal(state: GraphState) -> BudgetKind | None:
    raw = state.get("budget_refusal")
    return BudgetKind(raw) if raw else None


def _initial_gap(deps: NodeDependencies) -> str:
    services = ", ".join(deps.context.scope.service_names) or "the affected service"
    return f"the cause of the reported symptoms in {services} is unknown"


def _budget_state(state: GraphState, deps: NodeDependencies) -> BudgetState:
    snapshot = state.get("budget")
    if snapshot is None:
        return BudgetState.initial(deps.budget_policy)
    return BudgetState(policy=deps.budget_policy, ledger=BudgetLedger.from_dict(snapshot.consumed))


def _snapshot(budget: BudgetState) -> BudgetSnapshot:
    kind = budget.exhausted_kind()
    return BudgetSnapshot(
        consumed=budget.ledger.to_dict(),
        remaining=budget.remaining(),
        exhausted_kind=kind.value if kind else None,
    )


__all__ = ["COORDINATOR_EVENTS", "coordinator_node", "terminator_node"]
