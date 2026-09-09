"""The LangGraph topology.

ADR-0002 chose LangGraph, so the graph shape, the routing and the recursion bound are its
concern. ADR-0015 keeps durability ours: the kernel owns the transaction boundary, the
checkpoint and the lease, and this module owns only the shape.

.. code-block:: text

    START -> coordinator -> planner --collect--> evidence_collector --+
                              ^  |                                     |
                              |  +--hypothesise--> hypothesis_engine --+
                              |                                        |
                              +----------------------------------------+
                                 |
                                 +--terminate--> terminator -> END
                                                     |
                                                     +--continue--> planner

Two properties are asserted by the tests rather than left to inspection.

**Every edge is explicit.** ``add_conditional_edges`` is always given a ``path_map``, so a
router returning an unmapped value fails loudly instead of falling through to an
unpredictable node. There is no default branch anywhere in the graph.

**Every path terminates.** The only cycle is the planner loop, and it passes through the
planner on every pass - where the budget is checked before anything is spent. LangGraph's
own ``recursion_limit`` is set as a second, independent bound, so even a defect in the
budget accounting cannot produce an unbounded run.
"""

from __future__ import annotations

from typing import Final

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from asic.contracts.state import GraphState
from asic.domain.enums import PlannerAction
from asic.orchestration.context import NodeDependencies
from asic.orchestration.nodes.coordinator import coordinator_node, terminator_node
from asic.orchestration.nodes.evidence import evidence_node
from asic.orchestration.nodes.hypothesis import hypothesis_node
from asic.orchestration.nodes.planner import planner_node

#: Graph node names. They key :data:`asic.contracts.nodes.NODE_CONTRACTS`, so a node added
#: here without a contract cannot be scheduled.
COORDINATOR: Final[str] = "coordinator"
PLANNER: Final[str] = "planner"
EVIDENCE_COLLECTOR: Final[str] = "evidence_collector"
HYPOTHESIS_ENGINE: Final[str] = "hypothesis_engine"
TERMINATOR: Final[str] = "terminator"

GRAPH_NODES: Final[tuple[str, ...]] = (
    COORDINATOR,
    PLANNER,
    EVIDENCE_COLLECTOR,
    HYPOTHESIS_ENGINE,
    TERMINATOR,
)

#: Graph steps consumed by one full pass of the investigation loop: plan, act, decide.
NODES_PER_ITERATION: Final[int] = 3

#: Steps outside the loop: the coordinator, and the final terminator pass.
LOOP_ENTRY_STEPS: Final[int] = 2

#: Absolute ceiling regardless of configuration. A budget generous enough to exceed this
#: is a configuration error, and this is what stops it becoming an unbounded run.
MAX_RECURSION_LIMIT: Final[int] = 600

#: Default when no budget is supplied.
RECURSION_LIMIT: Final[int] = 120


def recursion_limit_for(max_iterations: int) -> int:
    """The framework's step ceiling, derived from the iteration budget.

    LangGraph's ``recursion_limit`` is a *backstop*, not the bound that should ever fire:
    termination is supposed to come from the budget, checked before each step, which
    produces a clean partial result. A backstop that fired first would turn an orderly
    stop into an exception, so it is set above the worst case the budget permits - and
    capped, because an unbounded backstop is not a backstop.
    """
    projected = max_iterations * NODES_PER_ITERATION + LOOP_ENTRY_STEPS
    # A margin for the passes that do not consume an iteration: a degraded collection, a
    # terminator pass that decides to continue.
    return min(MAX_RECURSION_LIMIT, max(RECURSION_LIMIT, projected + NODES_PER_ITERATION * 2))


#: Version of the topology itself. A change to the shape - a new node, a new edge - is a
#: behaviour change, and a run records which shape produced it.
GRAPH_VERSION: Final[str] = "1.0.0"


def _route_after_planner(state: GraphState) -> str:
    """Where the planner's decision sends the run.

    Reads only the planner's structured decision, never its prose. A decision that is
    absent routes to the terminator, which is the safe direction: stopping with what we
    have beats continuing without knowing why.
    """
    decision = state.get("last_decision")
    if decision is None:
        return TERMINATOR
    if decision.action is PlannerAction.COLLECT_EVIDENCE and decision.domain is not None:
        return EVIDENCE_COLLECTOR
    if decision.action is PlannerAction.FORM_HYPOTHESIS:
        return HYPOTHESIS_ENGINE
    return TERMINATOR


def _route_after_terminator(state: GraphState) -> str:
    """Either the run is over, or it goes back to the planner. There is no third option."""
    return END if state.get("terminated", False) else PLANNER


def build_graph(
    deps: NodeDependencies,
) -> CompiledStateGraph[GraphState, None, GraphState, GraphState]:
    """Compile the investigation graph against one run's dependencies.

    Built per run rather than compiled once and shared, because every node closes over the
    broker, tracer and unit of work belonging to *this* run. A shared graph would need those
    to arrive through mutable ambient state, which is how a tenant's tool broker ends up
    serving another tenant's run.

    No LangGraph checkpointer is attached. Durability is the kernel's, per ADR-0015: it
    commits at each node boundary and writes a ``workflow_checkpoint`` in the same
    transaction, so a checkpoint can never describe work that was rolled back.
    """
    graph: StateGraph[GraphState, None, GraphState, GraphState] = StateGraph(GraphState)

    graph.add_node(COORDINATOR, coordinator_node(deps))
    graph.add_node(PLANNER, planner_node(deps))
    graph.add_node(EVIDENCE_COLLECTOR, evidence_node(deps))
    graph.add_node(HYPOTHESIS_ENGINE, hypothesis_node(deps))
    graph.add_node(TERMINATOR, terminator_node(deps))

    graph.add_edge(START, COORDINATOR)
    graph.add_edge(COORDINATOR, PLANNER)

    # Exhaustive path maps. A router returning anything else is a KeyError at graph
    # construction time rather than a silent fall-through at run time.
    graph.add_conditional_edges(
        PLANNER,
        _route_after_planner,
        {
            EVIDENCE_COLLECTOR: EVIDENCE_COLLECTOR,
            HYPOTHESIS_ENGINE: HYPOTHESIS_ENGINE,
            TERMINATOR: TERMINATOR,
        },
    )
    graph.add_edge(EVIDENCE_COLLECTOR, TERMINATOR)
    graph.add_edge(HYPOTHESIS_ENGINE, TERMINATOR)
    graph.add_conditional_edges(
        TERMINATOR,
        _route_after_terminator,
        {PLANNER: PLANNER, END: END},
    )

    return graph.compile(name=f"asic-investigation-{GRAPH_VERSION}")


__all__ = [
    "COORDINATOR",
    "EVIDENCE_COLLECTOR",
    "GRAPH_NODES",
    "GRAPH_VERSION",
    "HYPOTHESIS_ENGINE",
    "MAX_RECURSION_LIMIT",
    "PLANNER",
    "RECURSION_LIMIT",
    "TERMINATOR",
    "build_graph",
    "recursion_limit_for",
]
