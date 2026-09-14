"""The remediation graph topology (Phase 8, ADR-0023).

.. code-block:: text

    START -> G6 --nothing/rejected--> END
              |
              +--proposed--> G7 --deny-------------> END
                              |
                              +--allow-----> G9 --> G10 --> END
                              |
                              +--approval--> G8 --pending--------> END (suspend)
                                              |
                                              +--approved--> G9 --> G10 --> END
                                              +--rejected/expired/invalidated--> END

Every edge is explicit, exactly as investigation's graph requires of itself - a router
returning an unmapped value is a ``KeyError`` at graph construction, never a silent
fall-through. The one property distinguishing this graph from investigation's: **a run that
reaches ``END`` without ``terminated`` set to ``True`` is not finished - it is suspended,**
because G8 and G10 are the two nodes that can legitimately stop the graph without ending the
run (an outstanding approval, an unsettled effect). The kernel is what turns that
distinction into a suspend rather than a crash.
"""

from __future__ import annotations

from typing import Final

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from asic.contracts.remediation_state import RemediationGraphState
from asic.domain.enums import PolicyVerdict
from asic.orchestration.remediation.context import RemediationDependencies
from asic.orchestration.remediation.nodes.approval import approval_service_node
from asic.orchestration.remediation.nodes.executor import remediation_executor_node
from asic.orchestration.remediation.nodes.planner import remediation_planner_node
from asic.orchestration.remediation.nodes.policy_gate import policy_gate_node
from asic.orchestration.remediation.nodes.verifier import verifier_node

PLANNER: Final[str] = "remediation_planner"
POLICY_GATE: Final[str] = "policy_gate"
APPROVAL_SERVICE: Final[str] = "approval_service"
EXECUTOR: Final[str] = "remediation_executor"
VERIFIER: Final[str] = "verifier"

GRAPH_NODES: Final[tuple[str, ...]] = (PLANNER, POLICY_GATE, APPROVAL_SERVICE, EXECUTOR, VERIFIER)

#: Absolute ceiling. Remediation is linear (one action, at most one approval wait, at most
#: one execution, at most one verification attempt beyond the first) so this is generous
#: headroom, not a bound anything should approach - unlike investigation's, which is sized
#: against a real iteration budget.
RECURSION_LIMIT: Final[int] = 25

GRAPH_VERSION: Final[str] = "1.0.0"


def _route_after_planner(state: RemediationGraphState) -> str:
    return END if state.get("terminated") else POLICY_GATE


def _route_after_policy_gate(state: RemediationGraphState) -> str:
    if state.get("terminated"):
        return END
    decision = state.get("policy_decision")
    if decision is None:  # pragma: no cover - defensive; the node always sets it when continuing
        return END
    if decision.verdict is PolicyVerdict.ALLOW:
        return EXECUTOR
    if decision.verdict is PolicyVerdict.REQUIRE_APPROVAL:
        return APPROVAL_SERVICE
    return END  # pragma: no cover - DENY already sets terminated=True above


def _route_after_approval(state: RemediationGraphState) -> str:
    if state.get("phase") == "executing":
        return EXECUTOR
    return END  # either pending (suspend) or a terminal rejection/expiry/invalidation


def _route_after_executor(state: RemediationGraphState) -> str:
    return END if state.get("terminated") else VERIFIER


def build_graph(
    deps: RemediationDependencies,
) -> CompiledStateGraph[RemediationGraphState, None, RemediationGraphState, RemediationGraphState]:
    """Compile the remediation graph against one run's dependencies.

    Built per run, exactly as investigation's is and for the same reason: every node closes
    over the broker, tracer and unit of work belonging to *this* run.
    """
    graph: StateGraph[RemediationGraphState, None, RemediationGraphState, RemediationGraphState] = (
        StateGraph(RemediationGraphState)
    )

    graph.add_node(PLANNER, remediation_planner_node(deps))
    graph.add_node(POLICY_GATE, policy_gate_node(deps))
    graph.add_node(APPROVAL_SERVICE, approval_service_node(deps))
    graph.add_node(EXECUTOR, remediation_executor_node(deps))
    graph.add_node(VERIFIER, verifier_node(deps))

    graph.add_edge(START, PLANNER)
    graph.add_conditional_edges(PLANNER, _route_after_planner, {POLICY_GATE: POLICY_GATE, END: END})
    graph.add_conditional_edges(
        POLICY_GATE,
        _route_after_policy_gate,
        {EXECUTOR: EXECUTOR, APPROVAL_SERVICE: APPROVAL_SERVICE, END: END},
    )
    graph.add_conditional_edges(
        APPROVAL_SERVICE, _route_after_approval, {EXECUTOR: EXECUTOR, END: END}
    )
    graph.add_conditional_edges(EXECUTOR, _route_after_executor, {VERIFIER: VERIFIER, END: END})
    graph.add_edge(VERIFIER, END)

    return graph.compile(name=f"asic-remediation-{GRAPH_VERSION}")


__all__ = [
    "APPROVAL_SERVICE",
    "EXECUTOR",
    "GRAPH_NODES",
    "GRAPH_VERSION",
    "PLANNER",
    "POLICY_GATE",
    "RECURSION_LIMIT",
    "VERIFIER",
    "build_graph",
]
