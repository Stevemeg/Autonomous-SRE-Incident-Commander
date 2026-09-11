"""Event append and the projections derived from the event log.

The event log is the system of record (DM-2). This module is the only place that writes to
it, and the only place that derives ``incident.status`` and ``timeline_event`` from it.

Three properties are enforced here rather than left to callers:

**Gapless sequencing.** The incident row is locked before the counter is read and
incremented, so two concurrent appends serialise rather than racing to the same sequence
number. A gap in the sequence therefore means an event was lost, which is exactly the
signal a gapless counter exists to give.

**Idempotent append.** An event carrying an idempotency key that has already been recorded
returns the existing row instead of inserting a second one. External deliveries repeat;
that is normal, not exceptional.

**Derived status.** ``incident.status`` is materialised for query performance, but it is
*derived*. :func:`recompute_incident_status` re-derives it from the log so the two can be
compared, and the test suite asserts they never disagree.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.incident import Incident, IncidentEvent, TimelineEvent
from asic.domain.enums import (
    ActorType,
    IncidentEventType,
    IncidentStatus,
    ProvenanceLabel,
    TerminationReason,
)
from asic.domain.errors import IllegalStateTransition
from asic.domain.events import classify, is_visible_on_timeline, timeline_rule
from asic.domain.incident_state import (
    TransitionRequest,
    assert_transition_allowed,
    is_terminal,
)

#: Bumped when the timeline projection logic changes, so rows produced by an older
#: version are identifiable and the projection can be rebuilt.
TIMELINE_PROJECTION_VERSION = 1


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Outcome of an append, distinguishing a new event from a de-duplicated one."""

    event: IncidentEvent
    #: ``False`` when the event already existed under the same idempotency key.
    created: bool


def append_incident_event(
    session: Session,
    *,
    incident: Incident,
    event_type: IncidentEventType,
    source: str,
    actor_type: ActorType,
    correlation_id: uuid.UUID,
    provenance: ProvenanceLabel = ProvenanceLabel.SYSTEM,
    actor_id: str | None = None,
    causation_id: uuid.UUID | None = None,
    occurred_at: datetime | None = None,
    payload: dict[str, Any] | None = None,
    payload_schema_version: int = 1,
    idempotency_key: str | None = None,
) -> AppendResult:
    """Append one event, gaplessly and idempotently.

    Must be called inside a transaction with a tenant already bound. The incident row is
    locked for the duration, which serialises concurrent appends to the same incident.
    """
    if idempotency_key is not None:
        existing = session.execute(
            sa.select(IncidentEvent).where(
                IncidentEvent.tenant_id == incident.tenant_id,
                IncidentEvent.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return AppendResult(event=existing, created=False)

    # Lock the incident row, then read the counter. Reading before locking would let two
    # transactions observe the same high-water mark and collide on the sequence.
    locked_high_water = session.execute(
        sa.select(Incident.event_sequence_high_water)
        .where(Incident.id == incident.id, Incident.tenant_id == incident.tenant_id)
        # Only the high-water mark and other non-key columns change. FOR NO KEY UPDATE
        # preserves serialization while remaining compatible with FK KEY SHARE locks held
        # by Phase 4 child-row inserts.
        .with_for_update(key_share=True)
    ).scalar_one()

    next_sequence = locked_high_water + 1

    event = IncidentEvent(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        sequence=next_sequence,
        event_type=event_type,
        category=classify(event_type),
        source=source,
        occurred_at=occurred_at or datetime.now(UTC),
        correlation_id=correlation_id,
        causation_id=causation_id,
        actor_type=actor_type,
        actor_id=actor_id,
        provenance=provenance,
        payload_schema_version=payload_schema_version,
        payload=payload or {},
        idempotency_key=idempotency_key,
    )
    session.add(event)

    session.execute(
        sa.update(Incident)
        .where(Incident.id == incident.id, Incident.tenant_id == incident.tenant_id)
        .values(event_sequence_high_water=next_sequence)
    )
    session.flush()
    return AppendResult(event=event, created=True)


def apply_transition(
    session: Session,
    *,
    incident: Incident,
    target: IncidentStatus,
    actor_type: ActorType,
    source: str,
    correlation_id: uuid.UUID,
    actor_id: str | None = None,
    termination_reason: TerminationReason | None = None,
    justification: str | None = None,
) -> IncidentEvent:
    """Move an incident to a new state, recording the change as an event.

    The state machine validates first; nothing is written if the transition is not
    permitted. The status column and the event are written in the same transaction, which
    is what keeps the materialised status and the log in agreement.

    Raises:
        IllegalStateTransition: if the machine refuses the transition.
    """
    request = TransitionRequest(
        source=incident.status,
        target=target,
        actor_type=actor_type,
        termination_reason=termination_reason,
        justification=justification,
    )
    assert_transition_allowed(request)

    previous = incident.status
    now = datetime.now(UTC)

    incident.status = target
    if target is IncidentStatus.ACKNOWLEDGED and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    if is_terminal(target):
        incident.terminated_at = now
        incident.termination_reason = termination_reason
    else:
        # Reopening clears the terminal markers; the event log retains the history.
        incident.terminated_at = None
        incident.termination_reason = None

    session.flush()

    result = append_incident_event(
        session,
        incident=incident,
        event_type=IncidentEventType.INCIDENT_STATE_CHANGED,
        source=source,
        actor_type=actor_type,
        actor_id=actor_id,
        correlation_id=correlation_id,
        payload={
            "from": previous.value,
            "to": target.value,
            "termination_reason": termination_reason.value if termination_reason else None,
            "justification": justification,
        },
    )
    return result.event


def recompute_incident_status(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> IncidentStatus | None:
    """Re-derive incident status from the event log.

    Returns ``None`` when the incident has no state-change event yet, which is the correct
    answer for a freshly opened incident that has not moved.

    This exists so the materialised ``incident.status`` can be *checked* rather than
    trusted. A divergence means something wrote the column without writing an event, which
    is a defect in the caller, not a data-repair job.
    """
    latest = session.execute(
        sa.select(IncidentEvent.payload)
        .where(
            IncidentEvent.tenant_id == tenant_id,
            IncidentEvent.incident_id == incident_id,
            IncidentEvent.event_type == IncidentEventType.INCIDENT_STATE_CHANGED,
        )
        .order_by(IncidentEvent.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()

    if latest is None:
        return None
    return IncidentStatus(latest["to"])


def assert_status_matches_log(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> None:
    """Raise if the materialised status disagrees with the event log."""
    incident = session.execute(
        sa.select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    ).scalar_one()
    derived = recompute_incident_status(session, tenant_id=tenant_id, incident_id=incident_id)
    if derived is None:
        return
    if derived is not incident.status:
        raise IllegalStateTransition(
            f"incident {incident_id} has status {incident.status.value!r} but its event "
            f"log derives {derived.value!r}: the status column was written without a "
            "corresponding state-change event"
        )


def event_sequence_gaps(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[int]:
    """Sequence numbers missing from an incident's event stream.

    A gapless counter is only useful if something checks it. A non-empty result means an
    event was lost, which is a durability defect worth failing a test over.
    """
    sequences = list(
        session.execute(
            sa.select(IncidentEvent.sequence)
            .where(
                IncidentEvent.tenant_id == tenant_id,
                IncidentEvent.incident_id == incident_id,
            )
            .order_by(IncidentEvent.sequence)
        ).scalars()
    )
    if not sequences:
        return []
    return [n for n in range(1, sequences[-1] + 1) if n not in set(sequences)]


def _summarise(event: IncidentEvent) -> str:
    """Deterministic one-line rendering of an event.

    Deliberately mechanical. A model-authored summary would introduce hallucination risk
    into a compliance artifact that the event log already describes exactly.
    """
    payload = event.payload or {}
    if event.event_type is IncidentEventType.INCIDENT_STATE_CHANGED:
        reason = payload.get("termination_reason")
        suffix = f" ({reason})" if reason else ""
        return f"Status changed from {payload.get('from')} to {payload.get('to')}{suffix}"
    if event.event_type is IncidentEventType.EVIDENCE_RECORDED:
        return f"Evidence recorded from {payload.get('domain', 'unknown')} source"
    if event.event_type is IncidentEventType.POLICY_EVALUATED:
        return f"Policy gate returned {payload.get('verdict')} (rule {payload.get('rule_id')})"
    return event.event_type.value.replace(".", ": ").replace("_", " ")


def project_timeline(session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> int:
    """Build or extend the derived timeline for an incident.

    Idempotent: a unique constraint on ``(tenant_id, source_event_id)`` means re-running
    the projection over already-projected events inserts nothing. Returns the number of
    new timeline rows.
    """
    already_projected = set(
        session.execute(
            sa.select(TimelineEvent.source_event_id).where(
                TimelineEvent.tenant_id == tenant_id,
                TimelineEvent.incident_id == incident_id,
            )
        ).scalars()
    )

    events = list(
        session.execute(
            sa.select(IncidentEvent)
            .where(
                IncidentEvent.tenant_id == tenant_id,
                IncidentEvent.incident_id == incident_id,
            )
            .order_by(IncidentEvent.sequence)
        ).scalars()
    )

    created = 0
    for event in events:
        if event.id in already_projected:
            continue
        if not is_visible_on_timeline(event.event_type):
            continue
        session.add(
            TimelineEvent(
                tenant_id=tenant_id,
                incident_id=incident_id,
                sequence=event.sequence,
                occurred_at=event.occurred_at,
                category=timeline_rule(event.event_type).category,
                summary=_summarise(event),
                source_event_id=event.id,
                projection_version=TIMELINE_PROJECTION_VERSION,
            )
        )
        created += 1

    session.flush()
    return created
