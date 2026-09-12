"""Incident history (tier T3): a read model over closed incidents, never a write path.

The append-only event log is the durable history already; copying it into a memory store
would create a second history that could disagree with the first. This module derives a
bounded, structured summary of terminated incidents for a scope, and renders it as
``RETRIEVED`` untrusted data - true of *those* incidents, not a statement about this one.
Titles are omitted: they are source-controlled text and add nothing a structured summary
does not already say.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Alert, Evidence, Hypothesis, Incident
from asic.domain.enums import IncidentSeverity, IncidentStatus, ProvenanceLabel, TerminationReason
from asic.domain.untrusted import UntrustedBlock


@dataclass(frozen=True, slots=True)
class IncidentHistoryRecord:
    incident_id: uuid.UUID
    reference: str
    status: IncidentStatus
    termination_reason: TerminationReason | None
    severity: IncidentSeverity
    opened_at: datetime
    terminated_at: datetime
    service_ids: tuple[uuid.UUID, ...]
    evidence_count: int
    #: Hypotheses are MODEL_CLAIMs; this is a count, never their content.
    hypothesis_count: int

    def untrusted_block(self) -> UntrustedBlock:
        return UntrustedBlock(
            source=f"history:{self.incident_id}",
            provenance=ProvenanceLabel.RETRIEVED,
            content=(
                f"Past incident {self.reference}: status={self.status.value}, "
                f"termination={self.termination_reason.value if self.termination_reason else 'none'}, "
                f"severity={self.severity.value}, opened={self.opened_at.isoformat()}, "
                f"terminated={self.terminated_at.isoformat()}, evidence={self.evidence_count}, "
                f"hypotheses={self.hypothesis_count} (model claims)"
            ),
        )


def incident_history(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    service_ids: tuple[uuid.UUID, ...],
    before: datetime | None = None,
    limit: int = 10,
) -> tuple[IncidentHistoryRecord, ...]:
    """Terminated incidents in scope, most recent first. Bounded to 50."""
    alerted = (
        sa.select(Alert.incident_id)
        .where(
            Alert.tenant_id == tenant_id,
            Alert.incident_id.is_not(None),
            Alert.service_id.in_(service_ids),
        )
        .distinct()
    )
    query = sa.select(Incident).where(
        Incident.tenant_id == tenant_id,
        Incident.environment_id == environment_id,
        Incident.terminated_at.is_not(None),
        Incident.id.in_(alerted),
    )
    if before is not None:
        query = query.where(Incident.terminated_at < before)
    incidents = session.scalars(
        query.order_by(Incident.terminated_at.desc(), Incident.id).limit(max(1, min(limit, 50)))
    ).all()
    records = []
    for incident in incidents:
        services = tuple(
            sorted(
                {
                    s
                    for s in session.scalars(
                        sa.select(Alert.service_id).where(
                            Alert.tenant_id == tenant_id, Alert.incident_id == incident.id
                        )
                    )
                    if s is not None
                },
                key=str,
            )
        )
        evidence_count = session.scalar(
            sa.select(sa.func.count())
            .select_from(Evidence)
            .where(Evidence.tenant_id == tenant_id, Evidence.incident_id == incident.id)
        )
        hypothesis_count = session.scalar(
            sa.select(sa.func.count())
            .select_from(Hypothesis)
            .where(Hypothesis.tenant_id == tenant_id, Hypothesis.incident_id == incident.id)
        )
        assert incident.terminated_at is not None
        records.append(
            IncidentHistoryRecord(
                incident_id=incident.id,
                reference=incident.reference,
                status=incident.status,
                termination_reason=incident.termination_reason,
                severity=incident.severity,
                opened_at=incident.opened_at,
                terminated_at=incident.terminated_at,
                service_ids=services,
                evidence_count=int(evidence_count or 0),
                hypothesis_count=int(hypothesis_count or 0),
            )
        )
    return tuple(records)


__all__ = ["IncidentHistoryRecord", "incident_history"]
