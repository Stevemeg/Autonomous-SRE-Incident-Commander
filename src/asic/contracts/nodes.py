"""Node contracts: what each node may consume, produce, mutate and invoke.

Master specification section 4 requires every node to declare explicit input/output
schemas, tool permissions, confidence, timeout, retry policy, audit events and a
deterministic failure/exit path. This module is that declaration, in a form the kernel
enforces rather than merely publishes:

* ``permitted_state_keys`` is checked against every update a node returns, so "allowed
  state mutations" is a constraint and not a comment;
* ``capabilities`` is checked by the tool broker against the calling node, so a node with
  an empty capability set is structurally incapable of reaching an adapter - the
  Investigation Planner is exactly that, deliberately;
* ``audit_events`` and ``span_kind`` are asserted by the contract tests, so a node that
  quietly stops emitting its audit trail fails the build.

Contracts are versioned independently of the code that satisfies them. ``contract_version``
is written onto every span, so a behaviour change is attributable to a contract revision
rather than inferred from a deployment timestamp.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from asic.contracts.state import IMMUTABLE_STATE_KEYS, STATE_KEYS
from asic.domain.enums import (
    AuditEventType,
    IncidentEventType,
    NodeId,
    OperationClass,
    TraceSpanKind,
)
from asic.domain.errors import ContractViolation


class RetryContract(BaseModel):
    """How a node's own failures are retried - not how its tool calls are retried.

    Tool retry is the broker's business and is classified per operation
    (``docs/architecture/failure-and-recovery.md`` section 1). This is the node-level
    policy: how many times the orchestrator re-enters the node itself.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_attempts: int = Field(default=1, ge=1, le=5)
    #: A single repair attempt when structured output failed validation. Distinct from a
    #: generic retry because it is a different request, not the same one repeated.
    schema_repair_attempts: int = Field(default=0, ge=0, le=1)
    operation_class: OperationClass = OperationClass.C1_PURE_READ
    backoff_seconds: float = Field(default=0.0, ge=0.0)


class NodeContract(BaseModel):
    """The full declared contract for one graph node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: NodeId
    node_version: str
    contract_version: str
    purpose: str

    #: Human-readable description of what the node consumes. The concrete input is always
    #: :class:`~asic.contracts.state.GraphState`; this records which parts are meaningful,
    #: which is what makes an unused-input regression visible in review.
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]

    #: Graph-state keys this node may write. Enforced by the kernel on every update.
    permitted_state_keys: frozenset[str]

    #: Capability names this node may request from the broker. Empty means the node has no
    #: path to any external system, which for a reasoning node is a security property.
    capabilities: frozenset[str]

    #: Whether this node may invoke a language model at all. The deterministic nodes are
    #: deterministic by design (ADR-0001); a model call from one of them is a defect.
    model_backed: bool

    timeout_seconds: int = Field(ge=1, le=3600)
    retry: RetryContract

    #: What makes two executions of this node the same logical operation. ``None`` means
    #: the node is naturally repeatable because it writes nothing durable.
    idempotency: str | None

    failure_modes: tuple[str, ...]
    #: What the node does when it cannot continue. Every node has exactly one such path.
    termination_behaviour: str

    audit_events: tuple[AuditEventType, ...] = ()
    incident_events: tuple[IncidentEventType, ...] = ()
    span_kind: TraceSpanKind = TraceSpanKind.NODE_EXECUTE

    def validate_update(self, update: Mapping[str, object]) -> None:
        """Reject a state update that exceeds this contract.

        Raises:
            ContractViolation: on an unknown key, an immutable key, or a key the contract
                does not list.
        """
        offending = [key for key in update if key not in STATE_KEYS]
        if offending:
            raise ContractViolation(
                f"{self.node_id.value} returned unknown state key(s) {sorted(offending)}; "
                f"the graph state has no such field"
            )
        immutable = [key for key in update if key in IMMUTABLE_STATE_KEYS]
        if immutable:
            raise ContractViolation(
                f"{self.node_id.value} attempted to rewrite immutable run state "
                f"{sorted(immutable)}; identity, trace context and objective are fixed for "
                "the lifetime of a run so that a resume cannot rebind onto another incident"
            )
        beyond = [key for key in update if key not in self.permitted_state_keys]
        if beyond:
            raise ContractViolation(
                f"{self.node_id.value} wrote state key(s) {sorted(beyond)} that its "
                f"contract {self.contract_version} does not permit; permitted keys are "
                f"{sorted(self.permitted_state_keys)}"
            )

    def permits_capability(self, capability: str) -> bool:
        return capability in self.capabilities


# --------------------------------------------------------------------------- registry

#: Capability names the read-only kernel uses. They match ``capability`` values in the
#: tool registry; the mapping from a name to a concrete tool is the registry's business,
#: not a node's.
_READ_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "read.metrics",
        "read.logs",
        "read.traces",
        "read.deploy",
        "read.k8s_workload",
        "read.knowledge",
    }
)

G2_INCIDENT_COORDINATOR: Final = NodeContract(
    node_id=NodeId.G2_INCIDENT_COORDINATOR,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Validate run context, establish execution identity, resolve the investigation "
        "objective and scope from the incident, and route into the bounded loop."
    ),
    inputs=("identity", "incident row", "environment", "services", "budget policy"),
    outputs=("objective", "capability_menu", "phase", "budget"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "capability_menu",
            "open_gaps",
            "budget",
            "iteration",
            "resumed_count",
            "failures",
            "terminated",
            "termination_reason",
            "termination_rule_id",
            "terminal_incident_status",
        }
    ),
    capabilities=frozenset(),
    model_backed=False,
    timeout_seconds=30,
    retry=RetryContract(max_attempts=1, operation_class=OperationClass.C1_PURE_READ),
    idempotency=(
        "Re-entering the coordinator for the same run is safe: it resolves scope from "
        "durable rows and applies the incident transition only when the status differs."
    ),
    failure_modes=(
        "incident not found or belongs to another tenant",
        "incident already terminal",
        "environment or service scope unresolvable",
        "illegal state transition into investigating",
    ),
    termination_behaviour=(
        "Refuses to start and terminates the run as unrecoverable_failure. It never "
        "invents a scope in order to proceed."
    ),
    audit_events=(AuditEventType.AUTHORIZATION_GRANTED,),
    incident_events=(IncidentEventType.INCIDENT_STATE_CHANGED,),
    span_kind=TraceSpanKind.NODE_EXECUTE,
)

G3_INVESTIGATION_PLANNER: Final = NodeContract(
    node_id=NodeId.G3_INVESTIGATION_PLANNER,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Identify the largest open information gap and select the next evidence task to "
        "close it, or declare that the investigation should stop."
    ),
    inputs=("evidence", "hypotheses", "open_gaps", "covered_domains", "capability_menu", "budget"),
    outputs=("last_decision", "open_gaps", "steps", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "iteration",
            "last_decision",
            "open_gaps",
            "steps",
            "budget",
            "budget_refusal",
            "failures",
            "terminated",
            "termination_reason",
            "termination_rule_id",
        }
    ),
    # Deliberately empty. The planner reasons about what to ask and is structurally
    # incapable of asking: the broker refuses any request whose calling node does not
    # declare the capability, and this node declares none.
    capabilities=frozenset(),
    model_backed=True,
    timeout_seconds=60,
    retry=RetryContract(
        max_attempts=1,
        schema_repair_attempts=1,
        operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
    ),
    idempotency=(
        "Keyed by (workflow_run_id, iteration). A resumed run recomputes the same step "
        "sequence number and collides with its own earlier write rather than adding a "
        "duplicate step."
    ),
    failure_modes=(
        "schema-invalid model output",
        "model provider outage",
        "selection of a domain outside the capability menu",
        "redundant selection of an already-covered domain with no new gap",
        "non-convergence",
    ),
    termination_behaviour=(
        "Terminates deterministically on budget exhaustion, iteration cap, or a model "
        "output that cannot be repaired. The budget check runs before the model call, so "
        "exhaustion costs nothing."
    ),
    incident_events=(
        IncidentEventType.PLAN_GAP_DECLARED,
        IncidentEventType.PLAN_STEP_SELECTED,
        IncidentEventType.PLAN_TERMINATED,
    ),
    span_kind=TraceSpanKind.PLANNER_STEP,
)

G4_EVIDENCE_COLLECTOR: Final = NodeContract(
    node_id=NodeId.G4_EVIDENCE_COLLECTOR,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Execute one planned evidence task against one domain through the tool broker and "
        "return normalised, cited evidence with its provenance."
    ),
    inputs=("last_decision", "objective", "capability_menu"),
    outputs=("evidence", "steps", "covered_domains", "degraded_domains", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "evidence",
            "steps",
            "covered_domains",
            "degraded_domains",
            "budget",
            "budget_refusal",
            "failures",
        }
    ),
    capabilities=_READ_CAPABILITIES,
    # Narrowed for this phase: collection and normalisation are deterministic, so the
    # first vertical slice has no model in the evidence path at all. Model-assisted
    # interpretation per strategy is Phase 7 work; see docs/architecture/
    # orchestration-kernel.md section 9.
    model_backed=False,
    timeout_seconds=120,
    retry=RetryContract(max_attempts=1, operation_class=OperationClass.C1_PURE_READ),
    idempotency=(
        "The broker keys a tool execution on the effect - tenant, tool, major version and "
        "resolved scope - so a repeated collection returns the recorded result instead of "
        "querying again."
    ),
    failure_modes=(
        "adapter timeout",
        "adapter error",
        "empty result (a finding, not a failure)",
        "oversized result",
        "malformed adapter payload",
        "injected content in retrieved text",
        "capability not granted",
    ),
    termination_behaviour=(
        "Never terminates the run on its own. A failed domain is recorded as degraded and "
        "the investigation continues with reduced coverage; the terminator decides whether "
        "the remaining coverage is enough."
    ),
    audit_events=(AuditEventType.TOOL_EXECUTED,),
    incident_events=(
        IncidentEventType.EVIDENCE_RECORDED,
        IncidentEventType.CONTENT_INJECTION_FLAGGED,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
)

G5_HYPOTHESIS_ENGINE: Final = NodeContract(
    node_id=NodeId.G5_HYPOTHESIS_ENGINE,
    node_version="1.1.0",
    contract_version="1.1.0",
    purpose=(
        "Form and rank root-cause hypotheses strictly against the persisted evidence set, "
        "recording supporting and contradicting evidence and a confidence with its basis; "
        "then validate a bounded-reflection decision over the result - continue on a gap, "
        "seek counter-evidence, revise a hypothesis, or propose a terminal outcome - "
        "(Phase 7, contract 1.1.0)."
    ),
    inputs=("evidence", "objective", "open_gaps"),
    outputs=("hypotheses", "open_gaps", "reflection_decision", "phase"),
    permitted_state_keys=frozenset(
        {"phase", "hypotheses", "open_gaps", "reflection_decision", "budget", "failures"}
    ),
    # No capabilities: it reasons over evidence already gathered and calls nothing.
    capabilities=frozenset(),
    model_backed=True,
    timeout_seconds=90,
    retry=RetryContract(
        max_attempts=1,
        schema_repair_attempts=1,
        operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
    ),
    idempotency=(
        "Keyed by (workflow_run_id, iteration). Hypotheses from an earlier iteration are "
        "superseded rather than duplicated. A revision is a supersede update on the target "
        "row plus a new row; re-entering the node re-derives the same decision from the "
        "same persisted evidence and does not double-supersede an already-superseded row."
    ),
    failure_modes=(
        "citation of a non-existent evidence id",
        "over-confidence relative to the evidence",
        "unsupported claim",
        "schema-invalid model output",
        "no hypothesis expressible from the evidence",
        "a reflection decision naming a hypothesis this run never persisted",
        "a reflection decision claiming success or escalation the evidence does not support",
        "a revision proposed with no newly formed hypothesis to supersede onto",
    ),
    termination_behaviour=(
        "Emits ranked hypotheses or an explicit insufficient-evidence verdict. A "
        "hypothesis citing evidence that does not exist is dropped in code before ranking, "
        "so a hallucinated citation is an impossible state rather than a low score. Its "
        "reflection decision is always one validated by "
        "asic.orchestration.reflection.decide_reflection, never the model's raw proposal, "
        "and a terminal reflection outcome only ever feeds the same five-category "
        "termination rule set the planner's own TERMINATE proposal feeds - it never ends a "
        "run by itself."
    ),
    incident_events=(
        IncidentEventType.HYPOTHESIS_FORMED,
        IncidentEventType.HYPOTHESIS_REJECTED_UNSUPPORTED,
        IncidentEventType.HYPOTHESIS_CRITIQUED,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
)

G2_TERMINATOR: Final = NodeContract(
    node_id=NodeId.G2_INCIDENT_COORDINATOR,
    node_version="1.1.0",
    contract_version="1.1.0-terminator",
    purpose=(
        "Decide deterministically whether the run continues, and if not, which of the five "
        "termination categories it ends in. A terminal bounded-reflection decision "
        "(``terminate_success``, ``terminate_uncertain``, ``escalate``) is accepted as an "
        "input alongside the planner's own ``TERMINATE`` action - both are validated "
        "against the same rule set, and neither is a sixth outcome of its own (Phase 7)."
    ),
    inputs=(
        "budget",
        "hypotheses",
        "evidence",
        "failures",
        "degraded_domains",
        "reflection_decision",
    ),
    outputs=("terminated", "termination_reason", "termination_rule_id", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "terminated",
            "termination_reason",
            "termination_rule_id",
            "terminal_incident_status",
            "budget",
            "budget_refusal",
            "failures",
        }
    ),
    capabilities=frozenset(),
    model_backed=False,
    timeout_seconds=10,
    retry=RetryContract(max_attempts=1, operation_class=OperationClass.C1_PURE_READ),
    idempotency="Pure function of the state; re-running it yields the same verdict.",
    failure_modes=("none - the rule set is total and every rule is deterministic",),
    termination_behaviour=(
        "Always returns exactly one verdict from an ordered, total rule set. There is no "
        "fall-through: the final rule matches unconditionally and is named in the trace."
    ),
    incident_events=(IncidentEventType.INCIDENT_TERMINATED, IncidentEventType.BUDGET_EXHAUSTED),
    span_kind=TraceSpanKind.WORKFLOW_PHASE,
)


#: Graph-node key -> contract. Keyed by the graph node name rather than by
#: :class:`~asic.domain.enums.NodeId` because the coordinator contributes two nodes to the
#: graph - entry routing and termination - with different permitted mutations.
NODE_CONTRACTS: Final[Mapping[str, NodeContract]] = {
    "coordinator": G2_INCIDENT_COORDINATOR,
    "planner": G3_INVESTIGATION_PLANNER,
    "evidence_collector": G4_EVIDENCE_COLLECTOR,
    "hypothesis_engine": G5_HYPOTHESIS_ENGINE,
    "terminator": G2_TERMINATOR,
}


def contract_for(graph_node: str) -> NodeContract:
    try:
        return NODE_CONTRACTS[graph_node]
    except KeyError as exc:
        raise ContractViolation(
            f"no contract registered for graph node {graph_node!r}; a node without a "
            "contract cannot be scheduled, because nothing would constrain what it writes"
        ) from exc


__all__ = [
    "NODE_CONTRACTS",
    "NodeContract",
    "RetryContract",
    "contract_for",
]
