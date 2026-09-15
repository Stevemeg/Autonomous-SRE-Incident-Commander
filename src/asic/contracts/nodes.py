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

from asic.contracts.remediation_state import (
    REMEDIATION_IMMUTABLE_STATE_KEYS,
    REMEDIATION_STATE_KEYS,
)
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

    #: The state-key universe this contract is validated against. Defaults to the
    #: investigation graph's own (:mod:`asic.contracts.state`); the remediation graph's
    #: contracts pass :data:`asic.contracts.remediation_state.REMEDIATION_STATE_KEYS`
    #: instead (ADR-0023) - a separate universe, so a remediation node's contract cannot
    #: accidentally be satisfied by an investigation-only key or vice versa.
    state_keys: frozenset[str] = STATE_KEYS
    immutable_state_keys: frozenset[str] = IMMUTABLE_STATE_KEYS

    def validate_update(self, update: Mapping[str, object]) -> None:
        """Reject a state update that exceeds this contract.

        Raises:
            ContractViolation: on an unknown key, an immutable key, or a key the contract
                does not list.
        """
        offending = [key for key in update if key not in self.state_keys]
        if offending:
            raise ContractViolation(
                f"{self.node_id.value} returned unknown state key(s) {sorted(offending)}; "
                f"the graph state has no such field"
            )
        immutable = [key for key in update if key in self.immutable_state_keys]
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


# ------------------------------------------------------------- remediation (Phase 8)

#: Write capability names the remediation executor may request. Mirrors
#: ``_READ_CAPABILITIES`` above: the set the registry's write catalogue actually
#: registers, not a guess at what it might one day contain.
_WRITE_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"mutate.k8s_deployment", "mutate.k8s_scale", "mutate.k8s_node"}
)

_REMEDIATION_RETRY = RetryContract(max_attempts=1, operation_class=OperationClass.C1_PURE_READ)

G6_REMEDIATION_PLANNER: Final = NodeContract(
    node_id=NodeId.G6_REMEDIATION_PLANNER,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Propose exactly one remediation action against the incident's accepted "
        "hypothesis, selected from a pre-resolved menu of registered write capabilities. "
        "Authors only reason, evidence references, expected effect and verification "
        "criteria (master specification section 6 fields 2, 3, 4, 11); risk tier, "
        "permission scope, preconditions, rollback, approval requirement and timeout are "
        "resolved from the registry and the incident, never from the model."
    ),
    inputs=("objective", "hypothesis", "write_capability_menu"),
    outputs=("remediation_action", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "remediation_action",
            "budget",
            "failures",
            "terminated",
            "termination_reason",
            "target_incident_status",
        }
    ),
    # Deliberately empty, on the same principle as the investigation planner: this node
    # reasons about what to propose and is structurally incapable of proposing anything
    # that reaches an adapter. The broker refuses any request whose calling node does not
    # declare the capability, and this node declares none.
    capabilities=frozenset(),
    model_backed=True,
    timeout_seconds=90,
    retry=RetryContract(
        max_attempts=1,
        schema_repair_attempts=1,
        operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
    ),
    idempotency=(
        "Keyed by (workflow_run_id, hypothesis_id, tool_name, scope) via "
        "remediation_request_key; a re-proposal of the same effect against the same "
        "hypothesis collides with the earlier row rather than duplicating it."
    ),
    failure_modes=(
        "schema-invalid model output",
        "model provider outage",
        "selection of a capability outside the resolved write menu",
        "a proposal naming a hypothesis this run's incident does not hold",
        "no safe action expressible for this root cause class",
    ),
    termination_behaviour=(
        "Terminates the run with no target incident status change if it proposes "
        "nothing; the incident remains investigating and a human reviews it, exactly as "
        "an escalation from the investigation kernel already would."
    ),
    incident_events=(
        IncidentEventType.REMEDIATION_PROPOSED,
        IncidentEventType.REMEDIATION_REJECTED_UNREGISTERED,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
    state_keys=REMEDIATION_STATE_KEYS,
    immutable_state_keys=REMEDIATION_IMMUTABLE_STATE_KEYS,
)

G7_POLICY_GATE: Final = NodeContract(
    node_id=NodeId.G7_POLICY_GATE,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Decide, deterministically, whether a proposed action is allowed, denied, or "
        "requires human approval, applying the risk-tier autonomy matrix and the five "
        "ambiguity signals of the safety policy - never a model's stated confidence."
    ),
    inputs=("remediation_action",),
    outputs=("policy_decision", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "policy_decision",
            "remediation_action",
            "budget",
            "failures",
            "terminated",
            "termination_reason",
            "target_incident_status",
        }
    ),
    capabilities=frozenset(),
    model_backed=False,
    timeout_seconds=10,
    retry=_REMEDIATION_RETRY,
    idempotency="Pure function of durable rows; re-running it against the same action yields the same verdict.",
    failure_modes=("none - the rule set is total and every rule is deterministic",),
    termination_behaviour=(
        "Never terminates the run on its own; it routes to the approval service, the "
        "executor, or a denial that ends the run in escalation, and always writes exactly "
        "one policy_decision row (INV-6), including on allow."
    ),
    audit_events=(AuditEventType.POLICY_DECIDED,),
    incident_events=(IncidentEventType.POLICY_EVALUATED,),
    span_kind=TraceSpanKind.NODE_EXECUTE,
    state_keys=REMEDIATION_STATE_KEYS,
    immutable_state_keys=REMEDIATION_IMMUTABLE_STATE_KEYS,
)

G8_APPROVAL_SERVICE: Final = NodeContract(
    node_id=NodeId.G8_APPROVAL_SERVICE,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Create a durable, time-bounded approval request bound to one action version, and "
        "suspend the run until a human decides, the request expires, or the action's "
        "version changes underneath it."
    ),
    inputs=("remediation_action", "policy_decision"),
    outputs=("approval", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "approval",
            "remediation_action",
            "budget",
            "failures",
            "terminated",
            "termination_reason",
            "target_incident_status",
        }
    ),
    capabilities=frozenset(),
    model_backed=False,
    timeout_seconds=10,
    retry=_REMEDIATION_RETRY,
    idempotency=(
        "Keyed by (action_id, action_version_hash) via approval_callback_key; a "
        "re-proposed action with changed parameters requires a new decision rather than "
        "being satisfied by an earlier reply (SI-6)."
    ),
    failure_modes=(
        "approval expired before a human decided",
        "approval decided by the same actor who proposed the action (INV-10)",
        "action parameters changed after the approval was requested (SI-6)",
    ),
    termination_behaviour=(
        "Suspends the run (a durable interrupt, not a crash) while a decision is "
        "outstanding; the resumed run re-reads the approval row rather than trusting "
        "in-memory state, so a decision made while the process was down is not missed."
    ),
    audit_events=(AuditEventType.APPROVAL_REQUESTED, AuditEventType.APPROVAL_DECIDED),
    incident_events=(
        IncidentEventType.APPROVAL_REQUESTED,
        IncidentEventType.APPROVAL_GRANTED,
        IncidentEventType.APPROVAL_REJECTED,
        IncidentEventType.APPROVAL_EXPIRED,
        IncidentEventType.APPROVAL_INVALIDATED_STALE,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
    state_keys=REMEDIATION_STATE_KEYS,
    immutable_state_keys=REMEDIATION_IMMUTABLE_STATE_KEYS,
)

G9_REMEDIATION_EXECUTOR: Final = NodeContract(
    node_id=NodeId.G9_REMEDIATION_EXECUTOR,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Re-validate the action's version hash and preconditions immediately before "
        "dispatch, then execute it through the tool broker - the only node besides the "
        "evidence collector with any capability at all, and the only one that may write."
    ),
    inputs=("remediation_action", "policy_decision", "approval"),
    outputs=("remediation_action", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "remediation_action",
            "budget",
            "failures",
            "terminated",
            "termination_reason",
            "target_incident_status",
        }
    ),
    # Both write (to execute) and read (to re-validate preconditions against live state
    # immediately before dispatch - SI-7) - the only node in either graph with both.
    capabilities=_WRITE_CAPABILITIES | _READ_CAPABILITIES,
    model_backed=False,
    # Below the idle-in-transaction bound (docs/architecture/orchestration-kernel.md
    # §11): the node's own DB transaction stays open for the duration of a tool call, so
    # its declared timeout must leave headroom under the server-enforced bound, not just
    # under the tool's own ceiling.
    timeout_seconds=150,
    retry=RetryContract(max_attempts=1, operation_class=OperationClass.C2_IDEMPOTENT_WRITE),
    idempotency=(
        "The broker keys the effect on business identifiers (tool, scope), not the "
        "action id, so a repeated execution of the same effect returns the recorded "
        "result rather than applying twice (SI-8)."
    ),
    failure_modes=(
        "action_version_hash mismatch (approval no longer matches the action)",
        "precondition drift since approval",
        "adapter timeout (unknown outcome; reconciled by query, never blindly retried)",
        "adapter error",
        "malformed adapter result",
    ),
    termination_behaviour=(
        "Never claims success on its own; it records what happened and hands the "
        "observed outcome to the verifier, which is independent of it (SI-9)."
    ),
    audit_events=(AuditEventType.REMEDIATION_EXECUTED, AuditEventType.TOOL_EXECUTED),
    incident_events=(
        IncidentEventType.EXECUTION_STARTED,
        IncidentEventType.EXECUTION_COMPLETED,
        IncidentEventType.EXECUTION_FAILED,
        IncidentEventType.COMPENSATION_STARTED,
        IncidentEventType.COMPENSATION_COMPLETED,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
    state_keys=REMEDIATION_STATE_KEYS,
    immutable_state_keys=REMEDIATION_IMMUTABLE_STATE_KEYS,
)

G10_VERIFIER: Final = NodeContract(
    node_id=NodeId.G10_VERIFIER,
    node_version="1.0.0",
    contract_version="1.0.0",
    purpose=(
        "Independently observe the target system's actual state through the read-only "
        "broker path and compare it against the criteria frozen at proposal time. Never "
        "receives, and never trusts, the executor's own claim of success (SI-9)."
    ),
    inputs=("remediation_action", "verification_criteria"),
    outputs=("verification", "phase"),
    permitted_state_keys=frozenset(
        {
            "phase",
            "verification",
            "remediation_action",
            "baseline_captured",
            "budget",
            "failures",
            "terminated",
            "termination_reason",
            "target_incident_status",
        }
    ),
    capabilities=_READ_CAPABILITIES,
    model_backed=False,
    timeout_seconds=90,
    retry=_REMEDIATION_RETRY,
    idempotency=(
        "Keyed by (action_id, attempt) via verification_callback_key; a duplicated "
        "callback for the same attempt returns the recorded verdict."
    ),
    failure_modes=(
        "observation window has not yet settled (verification refuses to start early)",
        "the read path itself fails (inconclusive, never assumed success)",
        "criteria hash mismatch against the frozen proposal (redefinition after the fact)",
    ),
    termination_behaviour=(
        "Always produces exactly one of verified, not_verified or inconclusive - never "
        "silently omits a verdict. not_verified routes to compensation; inconclusive "
        "escalates without compensating, because acting on an unknown state can itself "
        "cause harm."
    ),
    audit_events=(AuditEventType.VERIFICATION_RECORDED,),
    incident_events=(
        IncidentEventType.VERIFICATION_STARTED,
        IncidentEventType.VERIFICATION_RESULT,
    ),
    span_kind=TraceSpanKind.NODE_EXECUTE,
    state_keys=REMEDIATION_STATE_KEYS,
    immutable_state_keys=REMEDIATION_IMMUTABLE_STATE_KEYS,
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
    "remediation_planner": G6_REMEDIATION_PLANNER,
    "policy_gate": G7_POLICY_GATE,
    "approval_service": G8_APPROVAL_SERVICE,
    "remediation_executor": G9_REMEDIATION_EXECUTOR,
    "verifier": G10_VERIFIER,
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
