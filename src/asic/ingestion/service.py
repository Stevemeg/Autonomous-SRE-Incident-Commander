"""Atomic receive/normalize/correlate service. Caller retries failed transactions."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Alert,
    Environment,
    Incident,
    IncidentEvent,
    InvestigationDispatch,
    Service,
    SignalReceipt,
)
from asic.db.projections import append_incident_event
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    AlertStatus,
    IncidentEventType,
    IncidentSeverity,
    IncidentStatus,
    ProvenanceLabel,
)
from asic.ingestion.contracts import (
    ConnectorContext,
    IngestionRejected,
    NormalizedEnvelope,
    Normalizer,
    Signal,
    SimulatorNormalizer,
    SourceState,
    digest,
    occurrence_key,
    parse_payload,
)
from asic.ingestion.correlation import (
    MAX_CANDIDATES,
    POLICY_VERSION,
    WINDOW_SECONDS,
    Candidate,
    decide,
)
from asic.ingestion.normalizers import AlertmanagerFixtureNormalizer
from asic.ingestion.telemetry import stage


@dataclass(frozen=True)
class IngestionResult:
    receipt_id: UUID
    incident_id: UUID | None
    alert_id: UUID | None
    outcome: str
    reason: str
    duplicate: bool
    correlation_id: UUID


class IngestionService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        normalizers: Sequence[Normalizer] | None = None,
        clock: Clock | None = None,
    ) -> None:
        if os.environ.get("ASIC_DEPLOYMENT_ENVIRONMENT", "").lower() in {"prod", "production"}:
            raise RuntimeError("Phase 5 fixture ingestion is unavailable in production deployments")
        self.factory = session_factory
        adapters: list[Normalizer] = (
            list(normalizers)
            if normalizers is not None
            else [SimulatorNormalizer(), AlertmanagerFixtureNormalizer()]
        )
        self.normalizers = {adapter.source: adapter for adapter in adapters}
        if len(self.normalizers) != len(adapters):
            raise ValueError("duplicate normalizer source")
        self.clock = clock or SystemClock()

    def ingest(self, context: ConnectorContext, raw: bytes) -> IngestionResult:
        correlation_id = uuid4()
        raw_hash = hashlib.sha256(raw).hexdigest()
        with stage(
            "receipt", tenant_id=str(context.tenant_id), correlation_id=str(correlation_id)
        ) as receipt_span:
            signal: Signal | None = None
            error: str | None = None
            adapter = self.normalizers.get(context.source)
            try:
                with stage("normalization"):
                    if adapter is None:
                        raise IngestionRejected("unknown_source")
                    signal = adapter.normalize(parse_payload(raw), context)
            except IngestionRejected as exc:
                error = exc.code
            canonical = signal.canonical() if signal else {}
            semantic = {k: v for k, v in canonical.items() if k != "source_event_id"}
            content_hash = (
                digest([context.model_dump(mode="json"), semantic]) if signal else raw_hash
            )
            normalized = (
                NormalizedEnvelope(
                    context=context,
                    signal=signal,
                    ingested_at=self.clock.now(),
                    correlation_id=correlation_id,
                    normalizer_version=adapter.version,
                ).model_dump(mode="json")
                if signal is not None and adapter is not None
                else {}
            )
            key = digest(
                [
                    str(context.tenant_id),
                    context.connector_id,
                    context.source,
                    signal.source_event_id if signal and signal.source_event_id else content_hash,
                ]
            )
            receipt_span.set_attribute("source_event_key", key)
            with self.factory() as session, session.begin():
                bind_tenant(session, context.tenant_id)
                apply_statement_timeouts(session)
                # READ COMMITTED required: readers following a wait see the prior commit.
                if session.scalar(sa.text("SHOW transaction_isolation")) != "read committed":
                    raise RuntimeError("ingestion_requires_read_committed")
                lock = int.from_bytes(
                    hashlib.sha256(context.tenant_id.bytes).digest()[:8], "big", signed=True
                )
                session.execute(sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock})
                with stage("deduplication"):
                    existing = session.scalar(
                        sa.select(SignalReceipt).where(
                            SignalReceipt.tenant_id == context.tenant_id,
                            SignalReceipt.delivery_key == key,
                        )
                    )
                    if existing is not None:
                        if existing.content_digest == content_hash:
                            receipt_span.set_attribute("outcome", "duplicate")
                            receipt_span.set_attribute("receipt_id", str(existing.id))
                            receipt_span.set_attribute(
                                "correlation_id", str(existing.correlation_id)
                            )
                            if existing.incident_id:
                                receipt_span.set_attribute("incident_id", str(existing.incident_id))
                            return self._result(existing, duplicate=True)
                        # Reused event id with changed content is a rejection, not a retry.
                        error = "source_event_conflict"
                        key = digest([key, content_hash, "conflict"])
                        conflict = session.scalar(
                            sa.select(SignalReceipt).where(
                                SignalReceipt.tenant_id == context.tenant_id,
                                SignalReceipt.delivery_key == key,
                            )
                        )
                        if conflict is not None:
                            return self._result(conflict, duplicate=True)
                with stage("validation"):
                    if error is None:
                        service = session.scalar(
                            sa.select(Service).where(
                                Service.tenant_id == context.tenant_id,
                                Service.id == context.service_id,
                                Service.is_active.is_(True),
                            )
                        )
                        environment = session.scalar(
                            sa.select(Environment).where(
                                Environment.tenant_id == context.tenant_id,
                                Environment.id == context.environment_id,
                            )
                        )
                        if service is None:
                            error = "unknown_service"
                        elif environment is None:
                            error = "invalid_environment"
                receipt = SignalReceipt(
                    id=uuid4(),
                    tenant_id=context.tenant_id,
                    connector_id=context.connector_id,
                    source=context.source,
                    delivery_key=key,
                    content_digest=content_hash,
                    raw_digest=raw_hash,
                    correlation_id=correlation_id,
                    kind=signal.kind if signal else "invalid",
                    outcome="rejected" if error else "accepted",
                    reason=error or "normalized",
                    envelope=normalized,
                    decision={"policy_version": POLICY_VERSION},
                )
                if error is None and signal is not None and adapter is not None:
                    receipt.service_id = context.service_id
                    receipt.environment_id = context.environment_id
                    receipt.observed_at = signal.observed_at
                    if signal.kind == "alert":
                        with stage("correlation"):
                            self._alert(session, context, signal, receipt)
                    else:
                        receipt.reason = "change_recorded_not_causation"
                with stage("persistence"):
                    session.add(receipt)
                    session.flush()
                receipt_span.set_attribute("receipt_id", str(receipt.id))
                receipt_span.set_attribute("outcome", receipt.outcome)
                if receipt.incident_id:
                    receipt_span.set_attribute("incident_id", str(receipt.incident_id))
                return self._result(receipt)

    @staticmethod
    def _result(receipt: SignalReceipt, *, duplicate: bool = False) -> IngestionResult:
        return IngestionResult(
            receipt.id,
            receipt.incident_id,
            receipt.alert_id,
            receipt.outcome,
            receipt.reason,
            duplicate,
            receipt.correlation_id,
        )

    def _alert(
        self, session: Session, context: ConnectorContext, signal: Signal, receipt: SignalReceipt
    ) -> None:
        key = occurrence_key(context, signal)
        alert = session.scalar(
            sa.select(Alert).where(
                Alert.tenant_id == context.tenant_id,
                sa.or_(
                    Alert.idempotency_key == key,
                    sa.and_(
                        Alert.source == context.source,
                        Alert.source_fingerprint == signal.fingerprint,
                        Alert.started_at == signal.started_at,
                    ),
                ),
            )
        )
        if alert is not None:
            if (
                alert.service_id != context.service_id
                or alert.environment_id != context.environment_id
                or alert.correlation_category not in (None, signal.category)
            ):
                receipt.outcome, receipt.reason = "rejected", "occurrence_identity_conflict"
                return
            if alert.source_observed_at is not None:
                old = (
                    alert.source_observed_at,
                    alert.source_state == "resolved",
                    alert.source_digest or "",
                )
                new = (
                    signal.observed_at,
                    signal.state is SourceState.RESOLVED,
                    receipt.content_digest,
                )
                if new <= old:
                    receipt.outcome = "unchanged" if new == old else "stale"
                    receipt.reason = "equal_observation" if new == old else "out_of_order"
                    receipt.alert_id, receipt.incident_id = alert.id, alert.incident_id
                    receipt.decision.update(
                        {"ordering": "observed_at,state_rank,digest", "winner": list(map(str, old))}
                    )
                    if alert.incident_id:
                        existing_incident = self._incident(
                            session, context.tenant_id, alert.incident_id
                        )
                        self._event(
                            session,
                            existing_incident,
                            receipt,
                            IncidentEventType.ALERT_SUPPRESSED,
                            {"reason": receipt.reason, "decision": receipt.decision},
                        )
                    return
        else:
            alert = Alert(
                id=uuid4(),
                tenant_id=context.tenant_id,
                source=context.source,
                source_fingerprint=signal.fingerprint,
                idempotency_key=key,
                service_id=context.service_id,
                environment_id=context.environment_id,
                title=signal.title,
                severity=signal.severity,
                status=AlertStatus.NORMALISED,
                started_at=signal.started_at,
                received_at=self.clock.now(),
            )
            session.add(alert)
        alert.source_state = signal.state.value
        alert.source_observed_at = signal.observed_at
        alert.source_digest = receipt.content_digest
        alert.correlation_category = signal.category
        alert.title, alert.severity = signal.title, signal.severity
        alert.labels, alert.annotations = signal.labels, signal.annotations
        alert.resolved_at = signal.resolved_at
        session.flush()
        receipt.alert_id = alert.id
        incident = (
            self._incident(session, context.tenant_id, alert.incident_id)
            if alert.incident_id
            else None
        )
        created = False
        attached = False
        if incident is None and signal.state is SourceState.FIRING:
            # Opening events pin the anchor; subsequent arrivals never slide the window.
            anchor_time = sa.cast(
                IncidentEvent.payload["correlation_anchor"]["started_at"].astext,
                sa.DateTime(timezone=True),
            )
            rows = session.execute(
                sa.select(Incident, IncidentEvent.payload)
                .join(
                    IncidentEvent,
                    sa.and_(
                        IncidentEvent.incident_id == Incident.id,
                        IncidentEvent.tenant_id == Incident.tenant_id,
                    ),
                )
                .where(
                    Incident.tenant_id == context.tenant_id,
                    IncidentEvent.event_type == IncidentEventType.INCIDENT_OPENED,
                    anchor_time >= signal.started_at - timedelta(seconds=WINDOW_SECONDS),
                    anchor_time <= signal.started_at + timedelta(seconds=WINDOW_SECONDS),
                )
                .order_by(Incident.id)
                .limit(MAX_CANDIDATES + 1)
            ).all()
            if len(rows) > MAX_CANDIDATES:
                raise IngestionRejected("candidate_limit_retry_after_review")
            candidates: list[Candidate] = []
            for row, payload in rows:
                anchor = payload.get("correlation_anchor")
                if anchor:
                    from datetime import datetime

                    candidates.append(
                        Candidate(
                            row.id,
                            row.environment_id,
                            UUID(anchor["service_id"]),
                            anchor["category"],
                            datetime.fromisoformat(anchor["started_at"]),
                            row.terminated_at is None,
                        )
                    )
            decision = decide(
                candidates,
                environment_id=context.environment_id,
                service_id=context.service_id,
                category=signal.category,
                started_at=signal.started_at,
            )
            receipt.decision = decision
            if decision["selected"]:
                incident = self._incident(session, context.tenant_id, UUID(decision["selected"]))
                # Row lock refreshed status. A concurrent lifecycle termination cannot join.
                if incident.terminated_at is not None:
                    decision.update(selected=None, result="new", reason="candidate_terminated")
                    incident = None
            if incident is None:
                with stage("incident_create"):
                    incident = Incident(
                        id=uuid4(),
                        tenant_id=context.tenant_id,
                        reference=f"INC-{uuid4().hex[:28]}",
                        title=signal.title,
                        environment_id=context.environment_id,
                        severity=_severity(signal),
                        status=IncidentStatus.DETECTED,
                        opened_at=self.clock.now(),
                    )
                    session.add(incident)
                    session.flush()
                    created = True
            alert.incident_id = incident.id
            alert.status = AlertStatus.CORRELATED
            attached = True
        if incident is None:
            receipt.reason = "resolution_without_incident"
            return
        receipt.incident_id = incident.id
        with stage(
            "incident_update",
            incident_id=str(incident.id),
            correlation_id=str(receipt.correlation_id),
        ):
            changes = list(
                session.scalars(
                    sa.select(SignalReceipt.id)
                    .where(
                        SignalReceipt.tenant_id == context.tenant_id,
                        SignalReceipt.kind == "change",
                        SignalReceipt.outcome == "accepted",
                        SignalReceipt.service_id == context.service_id,
                        SignalReceipt.environment_id == context.environment_id,
                        SignalReceipt.observed_at <= signal.started_at,
                        SignalReceipt.observed_at
                        >= signal.started_at - timedelta(seconds=WINDOW_SECONDS),
                    )
                    .order_by(SignalReceipt.observed_at.desc(), SignalReceipt.id)
                    .limit(64)
                )
            )
            receipt.decision.update(
                {
                    "preceding_change_receipts": list(map(str, changes)),
                    "change_interpretation": "temporal association; causation not established",
                }
            )
            if created:
                event = self._event(
                    session,
                    incident,
                    receipt,
                    IncidentEventType.INCIDENT_OPENED,
                    {
                        "title": incident.title,
                        "severity": incident.severity.value,
                        "status": "detected",
                        "environment_id": str(context.environment_id),
                        "investigation_requested": True,
                        "correlation_anchor": {
                            "service_id": str(context.service_id),
                            "category": signal.category,
                            "started_at": signal.canonical()["started_at"],
                        },
                    },
                )
                session.add(
                    InvestigationDispatch(
                        id=uuid4(),
                        tenant_id=context.tenant_id,
                        incident_id=incident.id,
                        event_id=event.id,
                        correlation_id=receipt.correlation_id,
                    )
                )
            self._event(
                session,
                incident,
                receipt,
                IncidentEventType.ALERT_RECEIVED,
                {"envelope": receipt.envelope},
                external=True,
            )
            self._event(
                session,
                incident,
                receipt,
                IncidentEventType.ALERT_NORMALISED,
                {"source_state": signal.state.value, "envelope": receipt.envelope},
            )
            if attached:
                self._event(
                    session,
                    incident,
                    receipt,
                    IncidentEventType.CORRELATION_DECIDED,
                    receipt.decision,
                )
                self._event(
                    session,
                    incident,
                    receipt,
                    IncidentEventType.INCIDENT_JOINED,
                    {"alert_id": str(alert.id), "service_id": str(context.service_id)},
                )
            if (
                signal.state is SourceState.FIRING
                and _severity(signal).value < incident.severity.value
            ):
                previous = incident.severity
                incident.severity = _severity(signal)
                session.flush()
                self._event(
                    session,
                    incident,
                    receipt,
                    IncidentEventType.INCIDENT_SEVERITY_CHANGED,
                    {
                        "from": previous.value,
                        "to": incident.severity.value,
                        "reason": "firing_alert",
                    },
                )
            receipt.reason = (
                "source_resolved_incident_unchanged"
                if signal.state is SourceState.RESOLVED
                else "incident_created"
                if created
                else "incident_updated"
            )

    @staticmethod
    def _incident(session: Session, tenant_id: UUID, incident_id: UUID) -> Incident:
        return session.scalars(
            sa.select(Incident)
            .where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).one()

    @staticmethod
    def _event(
        session: Session,
        incident: Incident,
        receipt: SignalReceipt,
        event_type: IncidentEventType,
        payload: dict[str, Any],
        *,
        external: bool = False,
    ) -> IncidentEvent:
        return append_incident_event(
            session,
            incident=incident,
            event_type=event_type,
            source="telemetry_ingestion",
            actor_type=ActorType.EXTERNAL_SYSTEM if external else ActorType.SYSTEM,
            provenance=ProvenanceLabel.RETRIEVED
            if external or event_type is IncidentEventType.ALERT_NORMALISED
            else ProvenanceLabel.SYSTEM,
            correlation_id=receipt.correlation_id,
            occurred_at=receipt.observed_at,
            payload={"receipt_id": str(receipt.id), **payload},
        ).event


def _severity(signal: Signal) -> IncidentSeverity:
    return {
        "critical": IncidentSeverity.SEV1,
        "high": IncidentSeverity.SEV2,
        "medium": IncidentSeverity.SEV3,
        "low": IncidentSeverity.SEV4,
        "info": IncidentSeverity.SEV4,
    }[signal.severity.value]
