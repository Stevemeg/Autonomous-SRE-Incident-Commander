"""The authoritative record set a postmortem is built from, and its citation handles.

Everything here is read from persisted rows under the caller's tenant binding: the incident,
its alerts, its append-only event log, the derived timeline, evidence, hypotheses and the
remediation safety path (action, policy decision, approval, execution, verification). Nothing
is read from a model, and nothing retrieved confers authority.

Each record gets a short, **deterministic** handle (``INC``, ``A1``, ``E7``, ``EV2``, ``H1``,
``RA1``, ``PD1``, ``AP1``, ``TX1``, ``VF1``). A model is shown handles, never raw UUIDs, and
cites handles back; the grounding validator resolves them. Handles are stable for a given
record set (ordered by sequence, timestamp and id), which is what lets a replayed or scripted
generator cite the same records twice.

The **source fingerprint** is a SHA-256 over the identity and state of every record. It is the
idempotency key for drafts: the same records produce the same fingerprint and therefore the same
draft, however often the worker retries; a changed record (a new event, a reopened incident)
produces a new fingerprint and a new draft version. The author's own ``postmortem.drafted``
event is excluded, or writing a draft would invalidate it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Alert,
    Approval,
    Environment,
    Evidence,
    Hypothesis,
    HypothesisEvidence,
    Incident,
    IncidentEvent,
    PolicyDecision,
    RemediationAction,
    RemediationTarget,
    Service,
    TimelineEvent,
    ToolExecution,
    Verification,
)
from asic.domain.enums import (
    ActorType,
    EvidenceRelation,
    HypothesisStatus,
    IncidentEventType,
    IncidentStatus,
    VerificationVerdict,
)

#: Event types the postmortem author itself produces; excluded from its own sources.
SELF_EVENTS: Final[frozenset[IncidentEventType]] = frozenset({IncidentEventType.POSTMORTEM_DRAFTED})

#: Hypotheses that are still a candidate explanation.
LIVE_HYPOTHESES: Final[tuple[HypothesisStatus, ...]] = (
    HypothesisStatus.ACCEPTED,
    HypothesisStatus.PROPOSED,
)


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """One citable record: its handle, table, id and a trusted, mechanical description.

    ``description`` is built by this module from typed columns (never from free text a tool
    or model supplied) and is what a reviewer and the grounding validator compare a claim
    against. ``untrusted_text`` carries content that did arrive from outside - an evidence
    headline, a human note - which a model may read inside a fence and never as instruction.
    """

    handle: str
    kind: str
    record_id: uuid.UUID
    description: str
    untrusted_text: str | None = None
    injection_flagged: bool = False
    #: A typed label from the record (an evidence domain), for mechanical grouping.
    label: str | None = None

    def citation(self) -> dict[str, str]:
        return {"handle": self.handle, "kind": self.kind, "id": str(self.record_id)}


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    occurred_at: datetime
    summary: str
    event_handle: str
    evidence_handle: str | None


@dataclass(frozen=True, slots=True)
class RemediationPath:
    """One action and the decisions and outcome recorded for it."""

    action: SourceRecord
    tool_name: str
    risk_tier: str
    status: str
    hypothesis_id: uuid.UUID
    policy: SourceRecord | None
    policy_verdict: str | None
    approval: SourceRecord | None
    approval_decision: str | None
    execution: SourceRecord | None
    verification: SourceRecord | None
    verification_verdict: str | None


@dataclass(frozen=True, slots=True)
class PostmortemSources:
    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    reference: str
    title: str
    severity: str
    status: IncidentStatus
    environment: str
    services: tuple[str, ...]
    opened_at: datetime
    terminated_at: datetime | None
    incident: SourceRecord
    alerts: tuple[SourceRecord, ...]
    events: tuple[SourceRecord, ...]
    timeline: tuple[TimelineEntry, ...]
    evidence: tuple[SourceRecord, ...]
    hypotheses: tuple[SourceRecord, ...]
    root_cause: SourceRecord | None
    root_cause_class: str | None
    root_cause_statement: str | None
    root_cause_confidence: float | None
    supporting: tuple[str, ...]
    contradicting: tuple[str, ...]
    alternatives: tuple[tuple[SourceRecord, str, str], ...]
    remediation: tuple[RemediationPath, ...]
    resolution_event: SourceRecord | None
    resolution_actor: ActorType | None
    human_notes: tuple[SourceRecord, ...]
    fingerprint: str
    records: Mapping[str, SourceRecord] = field(default_factory=dict)

    @property
    def resolution_basis(self) -> str:
        """``independently_verified`` only when G10 verified an executed action and the system,
        not a person, moved the incident to resolved. Anything else is a human declaration."""
        verified = any(
            path.verification_verdict == VerificationVerdict.VERIFIED.value
            for path in self.remediation
        )
        if verified and self.resolution_actor in (ActorType.SYSTEM, ActorType.AGENT_NODE):
            return "independently_verified"
        return "human_declared"


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "unknown"


def load_sources(
    session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> PostmortemSources | None:
    """Read the record set for one incident, or ``None`` if the incident is not visible."""
    incident = session.scalar(
        sa.select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    )
    if incident is None:
        return None
    environment = session.scalar(
        sa.select(Environment.name).where(
            Environment.tenant_id == tenant_id, Environment.id == incident.environment_id
        )
    )
    records: dict[str, SourceRecord] = {}

    def add(record: SourceRecord) -> SourceRecord:
        records[record.handle] = record
        return record

    incident_record = add(
        SourceRecord(
            "INC",
            "incident",
            incident.id,
            f"incident {incident.reference} '{incident.title}', severity "
            f"{incident.severity.value}, status {incident.status.value}, opened "
            f"{_iso(incident.opened_at)}, terminated {_iso(incident.terminated_at)}",
        )
    )

    alert_rows = list(
        session.scalars(
            sa.select(Alert)
            .where(Alert.tenant_id == tenant_id, Alert.incident_id == incident_id)
            .order_by(Alert.received_at, Alert.id)
        )
    )
    service_names: dict[uuid.UUID, str] = dict(
        session.execute(
            sa.select(Service.id, Service.name).where(
                Service.tenant_id == tenant_id,
                Service.id.in_([a.service_id for a in alert_rows if a.service_id is not None]),
            )
        )
        .tuples()
        .all()
    )
    alerts = tuple(
        add(
            SourceRecord(
                f"A{index}",
                "alert",
                row.id,
                f"alert from {row.source}, severity {row.severity.value}, service "
                f"{service_names.get(row.service_id, 'unknown') if row.service_id else 'unknown'}"
                f", started {_iso(row.started_at)}, received {_iso(row.received_at)}",
                untrusted_text=row.title,
            )
        )
        for index, row in enumerate(alert_rows, start=1)
    )

    event_rows = [
        row
        for row in session.scalars(
            sa.select(IncidentEvent)
            .where(IncidentEvent.tenant_id == tenant_id, IncidentEvent.incident_id == incident_id)
            .order_by(IncidentEvent.sequence)
        )
        if row.event_type not in SELF_EVENTS
    ]
    events_by_id: dict[uuid.UUID, SourceRecord] = {}
    resolution_event: SourceRecord | None = None
    resolution_actor: ActorType | None = None
    human_notes: list[SourceRecord] = []
    for row in event_rows:
        payload = row.payload or {}
        detail = ""
        if row.event_type is IncidentEventType.INCIDENT_STATE_CHANGED:
            detail = f" from {payload.get('from')} to {payload.get('to')}"
            reason = payload.get("termination_reason")
            if reason:
                detail += f" ({reason})"
        note = None
        if row.event_type is IncidentEventType.INCIDENT_ANNOTATED:
            text = payload.get("annotation")
            note = str(text) if text else None
        elif payload.get("justification"):
            note = str(payload["justification"])
        record = add(
            SourceRecord(
                f"E{row.sequence}",
                "incident_event",
                row.id,
                f"event {row.event_type.value}{detail} by {row.actor_type.value} "
                f"({row.source}) at {_iso(row.occurred_at)}",
                untrusted_text=note,
            )
        )
        events_by_id[row.id] = record
        if row.actor_type is ActorType.HUMAN and note:
            human_notes.append(record)
        if (
            row.event_type is IncidentEventType.INCIDENT_STATE_CHANGED
            and payload.get("to") == IncidentStatus.RESOLVED.value
        ):
            resolution_event, resolution_actor = record, row.actor_type

    evidence_rows = list(
        session.scalars(
            sa.select(Evidence)
            .where(Evidence.tenant_id == tenant_id, Evidence.incident_id == incident_id)
            .order_by(Evidence.gathered_at, Evidence.id)
        )
    )
    evidence_by_id: dict[uuid.UUID, SourceRecord] = {}
    for index, evidence_row in enumerate(evidence_rows, start=1):
        headline = (evidence_row.content or {}).get("headline")
        evidence_by_id[evidence_row.id] = add(
            SourceRecord(
                f"EV{index}",
                "evidence",
                evidence_row.id,
                f"evidence from the {evidence_row.domain.value} source, provenance "
                f"{evidence_row.provenance.value}, gathered {_iso(evidence_row.gathered_at)}"
                + (
                    ", flagged as possible prompt injection"
                    if evidence_row.injection_flagged
                    else ""
                ),
                untrusted_text=str(headline) if headline else None,
                injection_flagged=evidence_row.injection_flagged,
                label=evidence_row.domain.value,
            )
        )

    timeline = tuple(
        TimelineEntry(
            occurred_at=row.occurred_at,
            summary=row.summary,
            event_handle=events_by_id[row.source_event_id].handle,
            evidence_handle=(
                evidence_by_id[row.source_evidence_id].handle
                if row.source_evidence_id in evidence_by_id
                else None
            ),
        )
        for row in session.scalars(
            sa.select(TimelineEvent)
            .where(TimelineEvent.tenant_id == tenant_id, TimelineEvent.incident_id == incident_id)
            .order_by(TimelineEvent.sequence)
        )
        if row.source_event_id in events_by_id
    )

    action_rows = list(
        session.scalars(
            sa.select(RemediationAction)
            .where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.incident_id == incident_id,
            )
            .order_by(RemediationAction.proposed_at, RemediationAction.id)
        )
    )
    hypothesis_rows = list(
        session.scalars(
            sa.select(Hypothesis)
            .where(Hypothesis.tenant_id == tenant_id, Hypothesis.incident_id == incident_id)
            .order_by(Hypothesis.created_at, Hypothesis.id)
        )
    )
    verified_targets = _verified_hypotheses(session, tenant_id, action_rows)
    root = _root_cause(hypothesis_rows, verified_targets, session, tenant_id, incident_id)
    ordered = ([root] if root is not None else []) + [h for h in hypothesis_rows if h is not root]
    hypotheses_by_id: dict[uuid.UUID, SourceRecord] = {}
    for index, hypothesis in enumerate(ordered, start=1):
        hypotheses_by_id[hypothesis.id] = add(
            SourceRecord(
                f"H{index}",
                "hypothesis",
                hypothesis.id,
                f"hypothesis ({hypothesis.root_cause_class}), status {hypothesis.status.value}, "
                f"confidence {float(hypothesis.confidence):.2f}, rank {hypothesis.rank}",
                untrusted_text=hypothesis.statement,
            )
        )

    supporting: list[str] = []
    contradicting: list[str] = []
    if root is not None:
        for link in session.scalars(
            sa.select(HypothesisEvidence)
            .where(
                HypothesisEvidence.tenant_id == tenant_id,
                HypothesisEvidence.hypothesis_id == root.id,
            )
            .order_by(HypothesisEvidence.created_at, HypothesisEvidence.id)
        ):
            evidence_record = evidence_by_id.get(link.evidence_id)
            if evidence_record is None:
                continue
            target = supporting if link.relation is EvidenceRelation.SUPPORTS else contradicting
            target.append(evidence_record.handle)

    remediation = tuple(
        _remediation_path(session, tenant_id, index, row, add)
        for index, row in enumerate(action_rows, start=1)
    )

    alternatives = tuple(
        (hypotheses_by_id[row.id], row.root_cause_class, row.status.value)
        for row in ordered
        if row is not root
    )

    fingerprint = _fingerprint(
        incident,
        alert_rows,
        event_rows,
        evidence_rows,
        hypothesis_rows,
        remediation,
    )
    return PostmortemSources(
        tenant_id=tenant_id,
        incident_id=incident.id,
        reference=incident.reference,
        title=incident.title,
        severity=incident.severity.value,
        status=incident.status,
        environment=environment or "unknown",
        services=tuple(sorted(set(service_names.values()))),
        opened_at=incident.opened_at,
        terminated_at=incident.terminated_at,
        incident=incident_record,
        alerts=alerts,
        events=tuple(events_by_id.values()),
        timeline=timeline,
        evidence=tuple(evidence_by_id.values()),
        hypotheses=tuple(hypotheses_by_id.values()),
        root_cause=hypotheses_by_id[root.id] if root is not None else None,
        root_cause_class=root.root_cause_class if root is not None else None,
        root_cause_statement=root.statement if root is not None else None,
        root_cause_confidence=float(root.confidence) if root is not None else None,
        supporting=tuple(supporting),
        contradicting=tuple(contradicting),
        alternatives=alternatives,
        remediation=remediation,
        resolution_event=resolution_event,
        resolution_actor=resolution_actor,
        human_notes=tuple(human_notes),
        fingerprint=fingerprint,
        records=records,
    )


def _verified_hypotheses(
    session: Session, tenant_id: uuid.UUID, actions: Sequence[RemediationAction]
) -> list[uuid.UUID]:
    """Hypotheses whose remediation was independently verified, most recent last."""
    if not actions:
        return []
    verified = set(
        session.scalars(
            sa.select(Verification.remediation_action_id).where(
                Verification.tenant_id == tenant_id,
                Verification.remediation_action_id.in_([a.id for a in actions]),
                Verification.verdict == VerificationVerdict.VERIFIED,
            )
        )
    )
    return [a.hypothesis_id for a in actions if a.id in verified]


def _root_cause(
    hypotheses: Sequence[Hypothesis],
    verified_targets: Sequence[uuid.UUID],
    session: Session,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> Hypothesis | None:
    """The hypothesis a postmortem reports as the leading cause.

    Preference: the hypothesis whose remediation was independently verified; otherwise the
    hypothesis a remediation run was started against; otherwise the best-ranked live one.
    Rejected, unsupported and superseded hypotheses are never promoted to the root cause.
    """
    by_id = {h.id: h for h in hypotheses}
    for hypothesis_id in reversed(verified_targets):
        if hypothesis_id in by_id:
            return by_id[hypothesis_id]
    targeted = session.scalars(
        sa.select(RemediationTarget.hypothesis_id)
        .where(
            RemediationTarget.tenant_id == tenant_id,
            RemediationTarget.incident_id == incident_id,
        )
        .order_by(RemediationTarget.created_at.desc())
    ).first()
    if targeted is not None and targeted in by_id:
        return by_id[targeted]
    live = [h for h in hypotheses if h.status in LIVE_HYPOTHESES]
    if not live:
        return None
    return sorted(
        live,
        key=lambda h: (h.status is not HypothesisStatus.ACCEPTED, h.rank, -float(h.confidence)),
    )[0]


def _remediation_path(
    session: Session,
    tenant_id: uuid.UUID,
    index: int,
    action: RemediationAction,
    add: Any,
) -> RemediationPath:
    action_record = add(
        SourceRecord(
            f"RA{index}",
            "remediation_action",
            action.id,
            f"remediation action {action.tool_name}@{action.tool_version}, risk tier "
            f"{action.risk_tier.value}, approval required {action.approval_required}, status "
            f"{action.status.value}, proposed {_iso(action.proposed_at)}, executed "
            f"{_iso(action.executed_at)}",
        )
    )
    policy = session.scalar(
        sa.select(PolicyDecision).where(
            PolicyDecision.tenant_id == tenant_id,
            PolicyDecision.remediation_action_id == action.id,
        )
    )
    policy_record = (
        add(
            SourceRecord(
                f"PD{index}",
                "policy_decision",
                policy.id,
                f"policy decision {policy.verdict.value} by rule {policy.rule_id} (policy "
                f"{policy.policy_version}) at {_iso(policy.evaluated_at)}",
            )
        )
        if policy is not None
        else None
    )
    approval = session.scalar(
        sa.select(Approval)
        .where(Approval.tenant_id == tenant_id, Approval.remediation_action_id == action.id)
        .order_by(Approval.created_at.desc(), Approval.id)
        .limit(1)
    )
    approval_record = (
        add(
            SourceRecord(
                f"AP{index}",
                "approval",
                approval.id,
                f"approval decision {approval.decision.value} by "
                f"{'a human approver' if approval.approver_user_id else 'the system'} "
                f"(required role {approval.required_role_key}), bound to action version "
                f"{approval.action_version_hash[:12]}, decided {_iso(approval.decided_at)}",
                untrusted_text=approval.justification,
            )
        )
        if approval is not None
        else None
    )
    execution = session.scalar(
        sa.select(ToolExecution)
        .where(
            ToolExecution.tenant_id == tenant_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.tool_name == action.tool_name,
        )
        .order_by(ToolExecution.started_at.desc(), ToolExecution.id)
        .limit(1)
    )
    execution_record = (
        add(
            SourceRecord(
                f"TX{index}",
                "tool_execution",
                execution.id,
                f"tool execution {execution.tool_name}@{execution.tool_version}, outcome "
                f"{execution.outcome.value if execution.outcome else 'pending'}, attempt "
                f"{execution.attempt}, started {_iso(execution.started_at)}",
            )
        )
        if execution is not None
        else None
    )
    verification = session.scalar(
        sa.select(Verification)
        .where(
            Verification.tenant_id == tenant_id,
            Verification.remediation_action_id == action.id,
        )
        .order_by(Verification.verified_at.desc(), Verification.id)
        .limit(1)
    )
    verification_record = (
        add(
            SourceRecord(
                f"VF{index}",
                "verification",
                verification.id,
                f"verification verdict {verification.verdict.value}, metric "
                f"{verification.observed_metric or 'unknown'} observed "
                f"{_number(verification.observed_value)} at {_iso(verification.observed_at)}, "
                f"attempt {verification.attempt}",
            )
        )
        if verification is not None
        else None
    )
    return RemediationPath(
        action=action_record,
        tool_name=action.tool_name,
        risk_tier=action.risk_tier.value,
        status=action.status.value,
        hypothesis_id=action.hypothesis_id,
        policy=policy_record,
        policy_verdict=policy.verdict.value if policy is not None else None,
        approval=approval_record,
        approval_decision=approval.decision.value if approval is not None else None,
        execution=execution_record,
        verification=verification_record,
        verification_verdict=verification.verdict.value if verification is not None else None,
    )


def _number(value: object) -> str:
    if value is None:
        return "unknown"
    number = float(value)  # type: ignore[arg-type]
    return f"{number:g}"


def _fingerprint(
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[IncidentEvent],
    evidence: Sequence[Evidence],
    hypotheses: Sequence[Hypothesis],
    remediation: Sequence[RemediationPath],
) -> str:
    material: dict[str, Any] = {
        "incident": [str(incident.id), incident.status.value],
        "alerts": sorted(str(a.id) for a in alerts),
        "events": sorted(str(e.id) for e in events),
        "evidence": sorted(str(e.id) for e in evidence),
        "hypotheses": sorted(f"{h.id}:{h.status.value}" for h in hypotheses),
        "remediation": sorted(
            ":".join(
                str(part)
                for part in (
                    path.action.record_id,
                    path.status,
                    path.policy.record_id if path.policy else "",
                    path.approval.record_id if path.approval else "",
                    path.execution.record_id if path.execution else "",
                    path.verification.record_id if path.verification else "",
                )
            )
            for path in remediation
        ),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "LIVE_HYPOTHESES",
    "SELF_EVENTS",
    "PostmortemSources",
    "RemediationPath",
    "SourceRecord",
    "TimelineEntry",
    "load_sources",
]
