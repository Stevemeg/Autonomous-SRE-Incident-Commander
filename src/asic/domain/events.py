"""Incident event contract and the timeline projection rules.

The event log is the system of record (DM-2). Everything else about an incident's history
- including its status and its timeline - is derivable from it.

This module owns three things:

* the **envelope contract**: what every event must carry, independent of payload;
* the **classification** of each event type as external, internal or derived;
* the **projection rules** that turn events into timeline entries deterministically.

No model output participates in any of it. A timeline built by a language model would add
hallucination risk to something the event log already knows exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from asic.domain.enums import (
    ActorType,
    EventCategory,
    IncidentEventType,
    ProvenanceLabel,
    TimelineCategory,
)

#: Payload schema version. Bumped when an event type's payload shape changes
#: incompatibly; readers must tolerate older versions rather than assume the newest.
CURRENT_PAYLOAD_SCHEMA_VERSION: Final[int] = 1


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Everything an incident event carries besides its payload.

    Field-by-field this is the contract the Phase 3 brief section C asks for. It is a
    frozen dataclass because an event, once constructed, is immutable: the persistence
    layer refuses updates and deletes on the event table.
    """

    #: Globally unique event identity.
    event_id: UUID
    tenant_id: UUID
    incident_id: UUID
    #: Monotonic, gapless per incident. A gap is detectable, which is the point.
    sequence: int
    event_type: IncidentEventType
    #: Where the event came from, in the external/internal/derived sense.
    category: EventCategory
    #: The concrete system or component that emitted it ("alertmanager", "g3_planner").
    source: str
    #: When the thing actually happened (may predate ingestion for external events).
    occurred_at: datetime
    #: When we durably recorded it. Never before ``occurred_at`` for internal events.
    recorded_at: datetime
    #: Links every artefact of one incident run together (FR-OBS-04).
    correlation_id: UUID
    #: The event that caused this one, where a causal parent exists.
    causation_id: UUID | None
    actor_type: ActorType
    #: Human user id, or the node identifier for an agent actor.
    actor_id: str | None
    #: Trust label of the event's content. External payloads are never authority-bearing.
    provenance: ProvenanceLabel
    payload_schema_version: int
    payload: dict[str, Any] = field(default_factory=dict)
    #: Deduplication key; ``None`` only for events that are legitimately repeatable and
    #: carry no external delivery risk.
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise ValueError("incident event sequence starts at 1")
        if self.occurred_at.tzinfo is None or self.recorded_at.tzinfo is None:
            raise ValueError("event timestamps must be timezone-aware")
        expected = classify(self.event_type)
        if self.category is not expected:
            raise ValueError(
                f"{self.event_type.value} is a {expected.value} event, not {self.category.value}"
            )
        if self.category is EventCategory.EXTERNAL and self.provenance.confers_authority:
            raise ValueError(
                f"external event {self.event_type.value} may not carry authority-bearing "
                f"provenance {self.provenance.value}: content arriving from outside our "
                "boundary is untrusted (SEC-I4)"
            )


# --------------------------------------------------------------------- classification

#: Events that originate outside our trust boundary. Their payloads are untrusted.
_EXTERNAL: Final[frozenset[IncidentEventType]] = frozenset(
    {
        IncidentEventType.ALERT_RECEIVED,
    }
)

#: Events computed from other events rather than observed. They are never a source of
#: truth and must be reproducible by recomputation.
_DERIVED: Final[frozenset[IncidentEventType]] = frozenset(
    {
        IncidentEventType.CORRELATION_DECIDED,
    }
)


def classify(event_type: IncidentEventType) -> EventCategory:
    """Classify an event type as external, internal or derived."""
    if event_type in _EXTERNAL:
        return EventCategory.EXTERNAL
    if event_type in _DERIVED:
        return EventCategory.DERIVED
    return EventCategory.INTERNAL


# ------------------------------------------------------------------ immutability

#: Event types that must be preserved for the audit retention period even when
#: incident data is otherwise purged. These are the safety-critical decision points.
AUDIT_CRITICAL_EVENTS: Final[frozenset[IncidentEventType]] = frozenset(
    {
        IncidentEventType.POLICY_EVALUATED,
        IncidentEventType.APPROVAL_REQUESTED,
        IncidentEventType.APPROVAL_GRANTED,
        IncidentEventType.APPROVAL_REJECTED,
        IncidentEventType.APPROVAL_EXPIRED,
        IncidentEventType.APPROVAL_INVALIDATED_STALE,
        IncidentEventType.EXECUTION_STARTED,
        IncidentEventType.EXECUTION_COMPLETED,
        IncidentEventType.EXECUTION_FAILED,
        IncidentEventType.COMPENSATION_STARTED,
        IncidentEventType.COMPENSATION_COMPLETED,
        IncidentEventType.VERIFICATION_RESULT,
        IncidentEventType.MEMORY_PROMOTION_APPROVED,
    }
)


# -------------------------------------------------------------- timeline projection


@dataclass(frozen=True, slots=True)
class TimelineRule:
    """How one event type renders into the derived timeline."""

    category: TimelineCategory
    #: Whether this event appears in the operator-facing timeline at all. Internal
    #: bookkeeping (checkpoints) is recorded as an event but is noise on a timeline.
    visible: bool = True


#: Projection rules. Every :class:`IncidentEventType` must appear here; the test suite
#: asserts exhaustiveness so that adding an event type forces a projection decision.
TIMELINE_RULES: Final[dict[IncidentEventType, TimelineRule]] = {
    # detection
    IncidentEventType.ALERT_RECEIVED: TimelineRule(TimelineCategory.DETECTION),
    IncidentEventType.ALERT_NORMALISED: TimelineRule(TimelineCategory.DETECTION, visible=False),
    IncidentEventType.ALERT_DEAD_LETTERED: TimelineRule(TimelineCategory.DETECTION),
    IncidentEventType.ALERT_SUPPRESSED: TimelineRule(TimelineCategory.DETECTION, visible=False),
    IncidentEventType.CORRELATION_DECIDED: TimelineRule(TimelineCategory.DETECTION),
    IncidentEventType.INCIDENT_OPENED: TimelineRule(TimelineCategory.DETECTION),
    IncidentEventType.INCIDENT_JOINED: TimelineRule(TimelineCategory.DETECTION),
    # investigation
    IncidentEventType.PLAN_GAP_DECLARED: TimelineRule(TimelineCategory.INVESTIGATION),
    IncidentEventType.PLAN_STEP_SELECTED: TimelineRule(TimelineCategory.INVESTIGATION),
    IncidentEventType.EVIDENCE_RECORDED: TimelineRule(TimelineCategory.INVESTIGATION),
    IncidentEventType.PLAN_TERMINATED: TimelineRule(TimelineCategory.INVESTIGATION),
    # reasoning
    IncidentEventType.HYPOTHESIS_FORMED: TimelineRule(TimelineCategory.REASONING),
    IncidentEventType.HYPOTHESIS_CRITIQUED: TimelineRule(TimelineCategory.REASONING),
    IncidentEventType.HYPOTHESIS_REJECTED_UNSUPPORTED: TimelineRule(TimelineCategory.REASONING),
    # decision
    IncidentEventType.REMEDIATION_PROPOSED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.REMEDIATION_REJECTED_UNREGISTERED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.POLICY_EVALUATED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.APPROVAL_REQUESTED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.APPROVAL_GRANTED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.APPROVAL_REJECTED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.APPROVAL_EXPIRED: TimelineRule(TimelineCategory.DECISION),
    IncidentEventType.APPROVAL_INVALIDATED_STALE: TimelineRule(TimelineCategory.DECISION),
    # action
    IncidentEventType.EXECUTION_STARTED: TimelineRule(TimelineCategory.ACTION),
    IncidentEventType.EXECUTION_COMPLETED: TimelineRule(TimelineCategory.ACTION),
    IncidentEventType.EXECUTION_FAILED: TimelineRule(TimelineCategory.ACTION),
    IncidentEventType.COMPENSATION_STARTED: TimelineRule(TimelineCategory.ACTION),
    IncidentEventType.COMPENSATION_COMPLETED: TimelineRule(TimelineCategory.ACTION),
    # verification
    IncidentEventType.VERIFICATION_STARTED: TimelineRule(TimelineCategory.VERIFICATION),
    IncidentEventType.VERIFICATION_RESULT: TimelineRule(TimelineCategory.VERIFICATION),
    # resolution and post-incident
    IncidentEventType.INCIDENT_ACKNOWLEDGED: TimelineRule(TimelineCategory.COMMUNICATION),
    IncidentEventType.INCIDENT_SEVERITY_CHANGED: TimelineRule(TimelineCategory.COMMUNICATION),
    IncidentEventType.INCIDENT_STATE_CHANGED: TimelineRule(TimelineCategory.RESOLUTION),
    IncidentEventType.INCIDENT_TERMINATED: TimelineRule(TimelineCategory.RESOLUTION),
    IncidentEventType.POSTMORTEM_DRAFTED: TimelineRule(TimelineCategory.RESOLUTION),
    IncidentEventType.MEMORY_PROMOTION_PROPOSED: TimelineRule(
        TimelineCategory.RESOLUTION, visible=False
    ),
    IncidentEventType.MEMORY_PROMOTION_APPROVED: TimelineRule(TimelineCategory.RESOLUTION),
    # operations - recorded, not shown on the operator timeline
    IncidentEventType.WORKFLOW_CHECKPOINTED: TimelineRule(
        TimelineCategory.INVESTIGATION, visible=False
    ),
    IncidentEventType.WORKFLOW_RESUMED: TimelineRule(TimelineCategory.INVESTIGATION),
    IncidentEventType.BUDGET_EXHAUSTED: TimelineRule(TimelineCategory.INVESTIGATION),
    IncidentEventType.CONTENT_INJECTION_FLAGGED: TimelineRule(TimelineCategory.INVESTIGATION),
}


def timeline_rule(event_type: IncidentEventType) -> TimelineRule:
    try:
        return TIMELINE_RULES[event_type]
    except KeyError as exc:  # pragma: no cover - prevented by the exhaustiveness test
        raise KeyError(
            f"no timeline projection rule for {event_type.value}; adding an event type "
            "requires deciding how it projects"
        ) from exc


def is_visible_on_timeline(event_type: IncidentEventType) -> bool:
    return timeline_rule(event_type).visible


def unmapped_event_types() -> frozenset[IncidentEventType]:
    """Event types with no projection rule. Asserted empty by the test suite."""
    return frozenset(set(IncidentEventType) - set(TIMELINE_RULES))
