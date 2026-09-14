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

    @property
    def rank(self) -> int:
        """Total order over the agent-invocable tiers, RO lowest.

        Phase 8 (ADR-0023): a resolver's ``max_risk_tier`` is a *ceiling* - a run
        authorised for R1 may still read - so callers compare rank rather than identity.
        R3 has no meaningful rank: it is never resolved against because it is never
        registered (SI-5), and comparing against it would imply a ceiling could admit it.
        """
        return {RiskTier.RO: 0, RiskTier.R1: 1, RiskTier.R2: 2}[self]


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


@unique
class KnowledgeSourceStatus(StrEnum):
    """Whether a knowledge source may be served at all.

    ``revoked`` and ``deleted`` both withdraw content from every read path, including
    replay of past retrievals; ``deleted`` additionally records that the source is gone
    rather than merely withdrawn. Physical purge is retention automation (C8), not this.
    """

    ACTIVE = "active"
    REVOKED = "revoked"
    DELETED = "deleted"


@unique
class KnowledgeVersionState(StrEnum):
    """Lifecycle of one immutable document version (INV-14)."""

    CURRENT = "current"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@unique
class KnowledgeContentFormat(StrEnum):
    MARKDOWN = "markdown"
    TEXT = "text"
    HTML = "html"


@unique
class KnowledgeIngestionOutcome(StrEnum):
    #: A new immutable version with chunks and embeddings was committed.
    CREATED = "created"
    #: The content equals the current version; nothing new was written or embedded.
    UNCHANGED = "unchanged"
    #: Deterministic refusal - malformed, oversized, unsupported or out of policy.
    REJECTED = "rejected"
    #: A dependency failed (embedding timeout, provider error). Retrying may succeed.
    FAILED = "failed"


@unique
class RetrievalPrincipalKind(StrEnum):
    """Who a retrieval was performed for. Established by trusted wiring, never by text."""

    INVESTIGATION = "investigation"
    USER = "user"
    SERVICE = "service"


@unique
class MemoryCategory(StrEnum):
    """The five categories a durable-memory write request is classified into.

    Only two can ever become durable memory, and both only through a human-approved
    promotion. The others are named so a request for them is refused *by category* rather
    than by accident: working state already lives in the workflow, incident history is
    derived from the append-only event log, and model inferences are not retained.
    """

    WORKING_STATE = "working_state"
    OPERATIONAL_KNOWLEDGE = "operational_knowledge"
    INCIDENT_HISTORY = "incident_history"
    VERIFIED_OUTCOME = "verified_outcome"
    MODEL_INFERENCE = "model_inference"


@unique
class MemoryVerificationStatus(StrEnum):
    #: Backed by a verification record whose verdict was ``verified``.
    VERIFIED = "verified"
    #: Anything else, however it was approved. Approval is not verification.
    UNVERIFIED = "unverified"


@unique
class MemoryDecisionOutcome(StrEnum):
    #: A write request passed policy and became a proposal awaiting a human.
    PROPOSED = "proposed"
    #: A write request failed policy and produced nothing.
    REJECTED = "rejected"
    #: A human approved a proposal and a memory entry was written.
    APPROVED = "approved"
    #: A human declined a proposal.
    DECLINED = "declined"


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
class ReflectionAction(StrEnum):
    """The only six things a bounded-reflection step may decide, once evidence exists.

    Phase 7 (master specification section 3). A closed set for the same reason
    :class:`PlannerAction` is one: the model proposes a member of this vocabulary, never a
    free-form instruction, and :mod:`asic.orchestration.reflection` is the only place a
    proposal is turned into a decision. Terminal members do not end a run by themselves -
    they are inputs the deterministic termination rule set (``termination.py``) accepts
    alongside the planner's own ``TERMINATE`` action, so a run still ends in exactly one of
    the five categories in :class:`TerminationReason` and never in a sixth, reflection-only
    outcome.
    """

    #: Keep investigating; the gap named on the decision is the one to close next.
    CONTINUE_WITH_GAP = "continue_with_gap"
    #: Deliberately seek evidence that would contradict the leading hypothesis, rather than
    #: more evidence that would merely agree with it.
    COLLECT_COUNTER_EVIDENCE = "collect_counter_evidence"
    #: Supersede a named hypothesis with a better-supported one formed this same step.
    REVISE_HYPOTHESIS = "revise_hypothesis"
    #: Propose that the leading hypothesis is sufficiently supported to stop on. Accepted
    #: only if the same actionability guard the planner's own proposal must pass also
    #: passes here; the read-only kernel still cannot verify a fix, so this is realised as
    #: :attr:`TerminationReason.HUMAN_ESCALATION`, never as ``SUCCESS``.
    TERMINATE_SUCCESS = "terminate_success"
    #: Propose stopping because the evidence does not, and is not expected to, distinguish a
    #: cause. Realised as :attr:`TerminationReason.INSUFFICIENT_EVIDENCE`.
    TERMINATE_UNCERTAIN = "terminate_uncertain"
    #: Propose handing the investigation to a human now, independent of confidence -
    #: contradictory evidence, a stalled loop, or a finding a human should see regardless of
    #: whether it clears the actionability bar.
    ESCALATE = "escalate"


@unique
class EvidenceFailureCategory(StrEnum):
    """Why one node's step could not produce what was asked of it.

    Distinct from :class:`TerminationReason`, which is why the *run* stopped: several of
    these can occur inside a run that continues afterwards with reduced coverage. Recorded
    on :class:`~asic.contracts.state.NodeFailureRef` as an additional, optional
    classification alongside the existing free-form ``error_type`` - additive, so it never
    changes the meaning of a value already being asserted on elsewhere.
    """

    #: A source answered successfully with nothing in it. Not a failure; recorded here only
    #: when reflection or the terminator must explain why no hypothesis could be formed at
    #: all, so "we found nothing" is never confused with "something broke".
    NO_EVIDENCE_FOUND = "no_evidence_found"
    #: An adapter could not complete a requested collection (error, timeout, malformed
    #: result). Corresponds to the tool broker's own failure outcomes.
    EVIDENCE_COLLECTION_FAILED = "evidence_collection_failed"
    #: A capability, scope or manifest check refused the request. Distinct from a source
    #: failure: nothing was attempted because it was not permitted.
    EVIDENCE_UNAUTHORIZED = "evidence_unauthorized"
    #: The run's wall-clock deadline was reached. Mirrors
    #: :attr:`TerminationReason.WALL_CLOCK_TIMEOUT`.
    INVESTIGATION_TIMEOUT = "investigation_timeout"
    #: The model provider failed, or its output could not be schema-validated after the
    #: permitted repair attempt.
    MODEL_FAILURE = "model_failure"
    #: A tool call reached its adapter and the adapter failed or timed out.
    TOOL_FAILURE = "tool_failure"
    #: The evidence gathered exists but does not, and is not expected to, distinguish a
    #: cause. Mirrors :attr:`TerminationReason.INSUFFICIENT_EVIDENCE`.
    UNCERTAIN = "uncertain"


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
