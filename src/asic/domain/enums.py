"""Closed domain vocabularies.

Every enum here is rendered as a native PostgreSQL ``ENUM`` type. That is deliberate:
the architecture package requires closed vocabularies for event types and status values
(``docs/architecture/data-model-and-api.md`` section 5), and a native type makes the
database refuse an unknown value rather than trusting every writer to validate first.

Adding a value is therefore a migration, which is exactly the change-control property the
specification asks for.

One section is explicitly exempt. The orchestration vocabularies at the end of this module
describe *in-flight* execution - which phase the graph is in, which pipeline stage refused
a request - and are persisted only inside JSONB checkpoints and span attributes, never as
a column type. They live here so that there is one place to look for a closed vocabulary,
and they are marked as non-persisted where they are defined.
"""

from __future__ import annotations

from enum import StrEnum, unique

# --------------------------------------------------------------------------- tenancy


@unique
class TenantStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    #: Retained for audit while operational data is purged.
    DEPROVISIONING = "deprovisioning"


@unique
class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


@unique
class ActorType(StrEnum):
    """Who or what caused something to happen.

    ``AGENT_NODE`` is not a credential holder. Nodes act only through the tool broker
    under the incident's resolved scope; this value records attribution, not authority.
    """

    HUMAN = "human"
    AGENT_NODE = "agent_node"
    SYSTEM = "system"
    EXTERNAL_SYSTEM = "external_system"


# ------------------------------------------------------------------------ provenance


@unique
class ProvenanceLabel(StrEnum):
    """Trust label attached to every piece of content in the system.

    The governing invariant (SEC-I4, ``docs/security/THREAT_MODEL.md``): **authority flows
    only from SYSTEM and HUMAN**. ``RETRIEVED`` and ``MODEL_CLAIM`` content can never
    influence an authorization decision.
    """

    SYSTEM = "system"
    HUMAN = "human"
    VERIFIED_FACT = "verified_fact"
    RETRIEVED = "retrieved"
    MODEL_CLAIM = "model_claim"

    @property
    def confers_authority(self) -> bool:
        return self in _AUTHORITY_BEARING

    @property
    def is_untrusted(self) -> bool:
        return self in {ProvenanceLabel.RETRIEVED, ProvenanceLabel.MODEL_CLAIM}


_AUTHORITY_BEARING = frozenset({ProvenanceLabel.SYSTEM, ProvenanceLabel.HUMAN})


@unique
class SensitivityLevel(StrEnum):
    """Data classification driving redaction, retention and access decisions."""

    PUBLIC = "public"
    INTERNAL = "internal"
    #: Customer operational content: log excerpts, runbook text, ticket bodies.
    CUSTOMER_CONTENT = "customer_content"
    #: May contain personal data; subject to retention and erasure controls.
    RESTRICTED = "restricted"


# ------------------------------------------------------------------------- catalogue


@unique
class ServiceCriticality(StrEnum):
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


@unique
class DependencyKind(StrEnum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    DATASTORE = "datastore"
    INFRASTRUCTURE = "infrastructure"


# ----------------------------------------------------------------------------- alert


@unique
class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@unique
class AlertStatus(StrEnum):
    RECEIVED = "received"
    NORMALISED = "normalised"
    CORRELATED = "correlated"
    #: Recognised as a duplicate of an alert already attached to an open incident.
    SUPPRESSED = "suppressed"
    #: Unparseable or unauthorised. Never silently dropped (FR-ING-05).
    DEAD_LETTERED = "dead_lettered"


# -------------------------------------------------------------------------- incident


@unique
class IncidentStatus(StrEnum):
    """Coarse incident lifecycle state.

    Fine-grained execution state lives on :class:`RemediationActionStatus`. The incident
    status answers "what is happening to this incident"; the action status answers "what
    happened to this specific action". Keeping them separate stops the incident state
    machine from acquiring a state per execution edge case.
    """

    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


@unique
class IncidentSeverity(StrEnum):
    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"


@unique
class TerminationReason(StrEnum):
    """Why a run stopped.

    Master specification section 5 requires every run to terminate through success,
    uncertainty, timeout, failure or human escalation. These are those five, plus the
    budget dimension that produced a timeout.
    """

    SUCCESS = "success"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    WALL_CLOCK_TIMEOUT = "wall_clock_timeout"
    POLICY_DENIED = "policy_denied"
    APPROVAL_NOT_GRANTED = "approval_not_granted"
    VERIFICATION_FAILED = "verification_failed"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"
    HUMAN_ESCALATION = "human_escalation"
    CANCELLED = "cancelled"


@unique
class BudgetKind(StrEnum):
    ITERATIONS = "iterations"
    TOOL_CALLS = "tool_calls"
    WALL_CLOCK = "wall_clock"
    TOKENS = "tokens"
    COST = "cost"


# ----------------------------------------------------------------------------- event


@unique
class EventCategory(StrEnum):
    """How an event entered the system.

    This is the distinction the Phase 3 brief asks for between external events, internal
    workflow events and derived data.
    """

    #: Originated outside our boundary (an alert, a webhook, a chat approval reply).
    EXTERNAL = "external"
    #: Emitted by our own orchestration or nodes.
    INTERNAL = "internal"
    #: Computed from other events; never a source of truth.
    DERIVED = "derived"


@unique
class IncidentEventType(StrEnum):
    """Closed event vocabulary.

    Mirrors ``docs/architecture/data-model-and-api.md`` section 5. Adding a member is a
    migration and requires the timeline projection to be updated.
    """

    # lifecycle
    INCIDENT_OPENED = "incident.opened"
    INCIDENT_JOINED = "incident.joined"
    INCIDENT_ACKNOWLEDGED = "incident.acknowledged"
    INCIDENT_SEVERITY_CHANGED = "incident.severity_changed"
    INCIDENT_STATE_CHANGED = "incident.state_changed"
    INCIDENT_TERMINATED = "incident.terminated"

    # correlation
    ALERT_RECEIVED = "alert.received"
    ALERT_NORMALISED = "alert.normalised"
    ALERT_DEAD_LETTERED = "alert.dead_lettered"
    ALERT_SUPPRESSED = "alert.suppressed"
    CORRELATION_DECIDED = "correlation.decided"

    # investigation
    PLAN_GAP_DECLARED = "plan.gap_declared"
    PLAN_STEP_SELECTED = "plan.step_selected"
    EVIDENCE_RECORDED = "evidence.recorded"
    PLAN_TERMINATED = "plan.terminated"

    # reasoning
    HYPOTHESIS_FORMED = "hypothesis.formed"
    HYPOTHESIS_CRITIQUED = "hypothesis.critiqued"
    HYPOTHESIS_REJECTED_UNSUPPORTED = "hypothesis.rejected_unsupported"

    # safety
    REMEDIATION_PROPOSED = "remediation.proposed"
    REMEDIATION_REJECTED_UNREGISTERED = "remediation.rejected_unregistered"
    POLICY_EVALUATED = "policy.evaluated"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXPIRED = "approval.expired"
    APPROVAL_INVALIDATED_STALE = "approval.invalidated_stale"

    # execution
    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    COMPENSATION_STARTED = "compensation.started"
    COMPENSATION_COMPLETED = "compensation.completed"

    # verification
    VERIFICATION_STARTED = "verification.started"
    VERIFICATION_RESULT = "verification.result"

    # post-incident
    POSTMORTEM_DRAFTED = "postmortem.drafted"
    MEMORY_PROMOTION_PROPOSED = "memory.promotion_proposed"
    MEMORY_PROMOTION_APPROVED = "memory.promotion_approved"

    # operations
    WORKFLOW_CHECKPOINTED = "workflow.checkpointed"
    WORKFLOW_RESUMED = "workflow.resumed"
    BUDGET_EXHAUSTED = "budget.exhausted"
    CONTENT_INJECTION_FLAGGED = "content.injection_flagged"


@unique
class TimelineCategory(StrEnum):
    """Presentation grouping for the derived timeline projection."""

    DETECTION = "detection"
    INVESTIGATION = "investigation"
    REASONING = "reasoning"
    DECISION = "decision"
    ACTION = "action"
    VERIFICATION = "verification"
    COMMUNICATION = "communication"
    RESOLUTION = "resolution"


# --------------------------------------------------------------------- investigation


@unique
class EvidenceDomain(StrEnum):
    """The six evidence domains the Evidence Collector's strategies cover."""

    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"
    DEPLOYMENTS = "deployments"
    KUBERNETES_STATE = "kubernetes_state"
    KNOWLEDGE = "knowledge"


@unique
class InvestigationStepStatus(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    #: Produced partial evidence because an adapter degraded (NFR-REL-07).
    DEGRADED = "degraded"
    FAILED = "failed"
    ABANDONED = "abandoned"


@unique
class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    #: Dropped because it cited evidence that does not exist (FR-RCA-02).
    REJECTED_UNSUPPORTED = "rejected_unsupported"
    SUPERSEDED = "superseded"


@unique
class EvidenceRelation(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


# ----------------------------------------------------------------- tools and safety


@unique
class RiskTier(StrEnum):
    """Action risk classification (master specification section 6).

    ``R3`` exists as a vocabulary member so that policy can *name and refuse* it. It must
    never be assigned to a registered, agent-invocable tool: a capability the system
    cannot express is safer than one it is told not to use.
    """

    RO = "ro"
    R1 = "r1"
    R2 = "r2"
    R3 = "r3"

    @property
    def is_read_only(self) -> bool:
        return self is RiskTier.RO

    @property
    def is_agent_invocable(self) -> bool:
        return self is not RiskTier.R3


@unique
class ToolProviderKind(StrEnum):
    """Where a tool implementation comes from (ADR-0003).

    ``MCP`` is present in the vocabulary because the boundary is designed for it; no MCP
    provider is implemented, and a descriptor imported from one is untrusted until a human
    assigns its capability, scope and risk tier.
    """

    NATIVE = "native"
    SIMULATOR = "simulator"
    MCP = "mcp"


@unique
class ToolExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    #: Failed with certainty that no effect was applied.
    FAILED_CLEAN = "failed_clean"
    #: Effect partially applied; compensation required.
    FAILED_PARTIAL = "failed_partial"
    #: Timed out; whether the effect applied is unknown until reconciled. Never retried
    #: blindly (see docs/architecture/failure-and-recovery.md section 1).
    UNKNOWN = "unknown"
    #: Preconditions no longer held at execution time; nothing was attempted.
    PRECONDITION_FAILED = "precondition_failed"


@unique
class PolicyVerdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@unique
class RemediationActionStatus(StrEnum):
    """Fine-grained action lifecycle.

    Mirrors the state machine in ``docs/architecture/remediation-safety-policy.md``
    section 4.
    """

    PROPOSED = "proposed"
    SCHEMA_REJECTED = "schema_rejected"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    AUTHORIZED = "authorized"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED_CLEAN = "failed_clean"
    FAILED_PARTIAL = "failed_partial"
    UNKNOWN_OUTCOME = "unknown_outcome"
    RECONCILING = "reconciling"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    COMPENSATION_FAILED = "compensation_failed"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    INCONCLUSIVE = "inconclusive"


@unique
class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    #: The action changed after approval was granted; the approval no longer binds (SI-6).
    INVALIDATED = "invalidated"


@unique
class VerificationVerdict(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    INCONCLUSIVE = "inconclusive"


# ---------------------------------------------------------------- knowledge and memory


@unique
class KnowledgeDocumentType(StrEnum):
    RUNBOOK = "runbook"
    SERVICE_DOC = "service_doc"
    KNOWN_ERROR = "known_error"
    POSTMORTEM = "postmortem"


@unique
class TrustClass(StrEnum):
    """Relative authority of a knowledge source.

    Never confers authorization: all knowledge is ``RETRIEVED`` provenance. This only
    influences retrieval ranking.
    """

    OFFICIAL_RUNBOOK = "official_runbook"
    SERVICE_DOCUMENTATION = "service_documentation"
    HISTORICAL_POSTMORTEM = "historical_postmortem"
    COMMUNITY = "community"


@unique
class ChunkStrategy(StrEnum):
    STRUCTURE_AWARE = "structure_aware"
    WINDOW_OVERLAP = "window_overlap"


@unique
class MemoryKind(StrEnum):
    """Durable memory tiers T4/T5 (docs/architecture/memory-and-rag.md)."""

    #: T5 - an action whose effect was observed and independently verified.
    VERIFIED_OUTCOME = "verified_outcome"
    #: T4 - an operational fact promoted from incident experience.
    OPERATIONAL_FACT = "operational_fact"


@unique
class MemoryPromotionStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"


@unique
class PostmortemStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    PUBLISHED = "published"


# ------------------------------------------------------------ evaluation and tracing


@unique
class EvaluationScenarioClass(StrEnum):
    GOLDEN = "golden"
    REPLAY = "replay"
    ADVERSARIAL = "adversarial"


@unique
class EvaluationRunVerdict(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    #: Judges disagreed beyond tolerance; requires human adjudication rather than an
    #: averaged score (docs/evaluation/EVALUATION_ARCHITECTURE.md section 5.3).
    CONTESTED = "contested"
    ERRORED = "errored"


@unique
class TraceSpanKind(StrEnum):
    """Span taxonomy from ``docs/architecture/observability.md`` section 3."""

    INCIDENT = "incident"
    CORRELATION = "correlation"
    WORKFLOW_PHASE = "workflow.phase"
    NODE_EXECUTE = "node.execute"
    PLANNER_STEP = "planner.step"
    LLM_CALL = "llm.call"
    TOOL_INVOKE = "tool.invoke"
    RETRIEVAL_QUERY = "retrieval.query"
    DB_OPERATION = "db.operation"
    POLICY_EVALUATE = "policy.evaluate"
    APPROVAL_WAIT = "approval.wait"
    REMEDIATION_EXECUTE = "remediation.execute"
    VERIFICATION_CHECK = "verification.check"
    INTEGRATION_CALL = "integration.call"
    EVALUATION_SCORE = "evaluation.score"


@unique
class SpanStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


@unique
class WorkflowRunStatus(StrEnum):
    RUNNING = "running"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    FAILED = "failed"
    #: Could not checkpoint or reached an inconsistent state; needs manual inspection.
    DEAD_LETTERED = "dead_lettered"


@unique
class NodeId(StrEnum):
    """The approved topology: 12 graph nodes plus 2 derived services (ADR-0001)."""

    G1_ALERT_CORRELATOR = "g1_alert_correlator"
    G2_INCIDENT_COORDINATOR = "g2_incident_coordinator"
    G3_INVESTIGATION_PLANNER = "g3_investigation_planner"
    G4_EVIDENCE_COLLECTOR = "g4_evidence_collector"
    G5_HYPOTHESIS_ENGINE = "g5_hypothesis_engine"
    G6_REMEDIATION_PLANNER = "g6_remediation_planner"
    G7_POLICY_GATE = "g7_policy_gate"
    G8_APPROVAL_SERVICE = "g8_approval_service"
    G9_REMEDIATION_EXECUTOR = "g9_remediation_executor"
    G10_VERIFIER = "g10_verifier"
    G11_POSTMORTEM_AUTHOR = "g11_postmortem_author"
    G12_MEMORY_CURATOR = "g12_memory_curator"
    S1_TIMELINE_PROJECTION = "s1_timeline_projection"
    S2_NOTIFICATION_SERVICE = "s2_notification_service"

    @property
    def uses_model(self) -> bool:
        """Whether this node may invoke a language model.

        The deterministic nodes are deterministic *by design*: putting authorization,
        human authority or command dispatch inside a model would violate master
        specification sections 6 and 15 (ADR-0001).
        """
        return self in _MODEL_BACKED_NODES


_MODEL_BACKED_NODES = frozenset(
    {
        NodeId.G1_ALERT_CORRELATOR,  # hybrid: deterministic core, model-assisted ranking
        NodeId.G3_INVESTIGATION_PLANNER,
        NodeId.G4_EVIDENCE_COLLECTOR,
        NodeId.G5_HYPOTHESIS_ENGINE,
        NodeId.G6_REMEDIATION_PLANNER,
        NodeId.G10_VERIFIER,
        NodeId.G11_POSTMORTEM_AUTHOR,
        NodeId.G12_MEMORY_CURATOR,
    }
)


# ----------------------------------------------------------------------------- audit


@unique
class AuditEventType(StrEnum):
    """Actions that must produce an immutable audit record.

    Derived from the Phase 3 brief section E and master specification section 15.
    """

    AUTHENTICATION_SUCCEEDED = "authentication.succeeded"
    AUTHENTICATION_FAILED = "authentication.failed"
    AUTHORIZATION_GRANTED = "authorization.granted"
    AUTHORIZATION_DENIED = "authorization.denied"
    TOOL_AUTHORIZATION_EVALUATED = "tool_authorization.evaluated"
    TOOL_EXECUTED = "tool.executed"
    REMEDIATION_PLANNED = "remediation.planned"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_DECIDED = "approval.decided"
    REMEDIATION_EXECUTED = "remediation.executed"
    VERIFICATION_RECORDED = "verification.recorded"
    POLICY_DECIDED = "policy.decided"
    CONFIGURATION_CHANGED = "configuration.changed"
    SECURITY_SETTING_CHANGED = "security_setting.changed"
    TENANT_LIFECYCLE_CHANGED = "tenant_lifecycle.changed"
    DATA_EXPORTED = "data.exported"
    DATA_DELETED = "data.deleted"


# --------------------------------------------------- orchestration (not persisted as
# --------------------------------------------------- native PostgreSQL enum types)
#
# The vocabularies below describe execution in flight. They are written into JSONB
# checkpoints, span attributes and event payloads, never into a typed column, so adding a
# member here is not a migration. They are closed vocabularies all the same: a phase or a
# broker stage invented at a call site would make routing and failure attribution
# unanalysable.


@unique
class InvestigationPhase(StrEnum):
    """Where the bounded investigation loop currently is.

    Mirrors the ``Investigating`` composite state in
    ``docs/architecture/failure-and-recovery.md`` section 2. Distinct from
    :class:`IncidentStatus`, which is coarser and durable: an incident is ``INVESTIGATING``
    throughout all of these.
    """

    INITIALISING = "initialising"
    PLANNING = "planning"
    COLLECTING = "collecting"
    ANALYSING = "analysing"
    TERMINATING = "terminating"
    TERMINATED = "terminated"


@unique
class PlannerAction(StrEnum):
    """The only three things a planning step may decide to do.

    A closed set is the point. A planner that could emit a free-form next action would be
    a planner that could emit an instruction, and the whole design rests on it emitting a
    *selection* from a bounded menu instead.
    """

    COLLECT_EVIDENCE = "collect_evidence"
    FORM_HYPOTHESIS = "form_hypothesis"
    TERMINATE = "terminate"


@unique
class OperationClass(StrEnum):
    """Retry classification from ``docs/architecture/failure-and-recovery.md`` section 1.

    Every failure is classified before any retry decision is made, because the most common
    durability defect in agent systems is retrying something that must not be retried.
    """

    #: No side effect; safely repeatable.
    C1_PURE_READ = "c1_pure_read"
    #: Repeatable under the same key; same end state.
    C2_IDEMPOTENT_WRITE = "c2_idempotent_write"
    #: Repetition changes the result. Reconcile, never retry.
    C3_NON_IDEMPOTENT_WRITE = "c3_non_idempotent_write"
    #: Timed out; may or may not have applied. Query actual state first.
    C4_UNKNOWN_OUTCOME = "c4_unknown_outcome"
    #: The operation worked and the answer is simply unwelcome. Never retried.
    C5_SEMANTIC_FAILURE = "c5_semantic_failure"
    #: The input is invalid. Repair once at most, or reject.
    C6_DETERMINISTIC_REJECTION = "c6_deterministic_rejection"

    @property
    def is_retryable(self) -> bool:
        return self in _RETRYABLE_CLASSES


_RETRYABLE_CLASSES = frozenset({OperationClass.C1_PURE_READ, OperationClass.C2_IDEMPOTENT_WRITE})


@unique
class BrokerStage(StrEnum):
    """The ordered pipeline every capability request passes through.

    Recorded on every refusal so that "denied" always says *where* it was denied. A broker
    that reports only a boolean cannot be audited, and cannot be debugged when a legitimate
    request stops working.
    """

    REQUEST_VALIDATION = "request_validation"
    TENANT_CONTEXT = "tenant_context"
    CAPABILITY_RESOLUTION = "capability_resolution"
    RISK_BOUNDARY = "risk_boundary"
    ARGUMENT_VALIDATION = "argument_validation"
    IDEMPOTENCY = "idempotency"
    ADAPTER_INVOCATION = "adapter_invocation"
    RESULT_VALIDATION = "result_validation"


@unique
class NodeOutcome(StrEnum):
    """How one node execution ended. Every node ends in exactly one of these."""

    COMPLETED = "completed"
    #: Completed with reduced coverage because a source degraded (NFR-REL-07).
    DEGRADED = "degraded"
    #: A typed failure the coordinator can route around.
    FAILED = "failed"
    #: The run must stop; the termination reason says why.
    TERMINAL = "terminal"
