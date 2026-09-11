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
    IncidentReopenCandidate,
    InvestigationDispatch,
    Service,
    SignalReceipt,
)
from asic.db.projections import append_incident_event
from asic.db.session import (
    DEFAULT_INGESTION_LOCK_TIMEOUT_MS,
    apply_lock_timeout,
    apply_statement_timeouts,
    bind_tenant,
)
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
    IngestionPolicy,
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
from asic.ingestion.locks import INGESTION_TENANT_LOCK_NAMESPACE, advisory_lock_key
from asic.ingestion.normalizers import AlertmanagerFixtureNormalizer
from asic.ingestion.telemetry import lock_wait, stage


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
        policy: IngestionPolicy | None = None,
        lock_timeout_ms: int = DEFAULT_INGESTION_LOCK_TIMEOUT_MS,
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
        self.policy = policy or IngestionPolicy()
        self.lock_timeout_ms = lock_timeout_ms

    def ingest(self, context: ConnectorContext, raw: bytes) -> IngestionResult:
        correlation_id = uuid4()
        raw_hash = hashlib.sha256(raw).hexdigest()
        with stage(
            "receipt", tenant_id=str(context.tenant_id), correlation_id=str(correlation_id)
        ) as receipt_span:
            signal: Signal | None = None
            error: str | None = None
            canonical: dict[str, Any] = {}
            adapter = self.normalizers.get(context.source)
            ingested_at = self.clock.now()
            try:
                with stage("normalization"):
                    if adapter is None:
                        raise IngestionRejected("unknown_source")
                    signal = adapter.normalize(parse_payload(raw), context)
                    canonical = signal.canonical()
                    self.policy.validate_observation_time(signal, ingested_at)
            except IngestionRejected as exc:
                error = exc.code
            semantic = {k: v for k, v in canonical.items() if k != "source_event_id"}
            content_hash = (
                digest([context.model_dump(mode="json"), semantic]) if signal else raw_hash
            )
            normalized = (
                NormalizedEnvelope(
                    context=context,
                    signal=signal,
                    ingested_at=ingested_at,
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
                apply_lock_timeout(session, lock_timeout_ms=self.lock_timeout_ms)
                # READ COMMITTED required: readers following a wait see the prior commit.
                if session.scalar(sa.text("SHOW transaction_isolation")) != "read committed":
                    raise RuntimeError("ingestion_requires_read_committed")
                lock_domain, lock_tenant = advisory_lock_key(
                    INGESTION_TENANT_LOCK_NAMESPACE, context.tenant_id
                )
                with lock_wait(
                    INGESTION_TENANT_LOCK_NAMESPACE,
                    tenant_id=str(context.tenant_id),
                    correlation_id=str(correlation_id),
                ):
                    session.execute(
                        sa.text("SELECT pg_advisory_xact_lock(:domain, :tenant)"),
                        {"domain": lock_domain, "tenant": lock_tenant},
                    )
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
                retryable = error in {"unknown_service", "invalid_environment"}
                if retryable:
                    key = _retryable_delivery_key(key, content_hash, error or "catalogue")
                    existing_retry = self._receipt(session, context.tenant_id, key)
                    if existing_retry is not None:
                        return self._result(existing_retry, duplicate=True)
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
                    outcome="retryable" if retryable else "rejected" if error else "accepted",
                    reason=error or "normalized",
                    envelope=normalized,
                    decision={
                        "policy_version": POLICY_VERSION,
                        "validation_policy_version": self.policy.version,
                        "retry": "same delivery may be retried"
                        if retryable
                        else "committed outcome is idempotent",
                    },
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
                if receipt.outcome == "retryable" and not retryable:
                    receipt.delivery_key = _retryable_delivery_key(
                        key, content_hash, receipt.reason
                    )
                    existing_retry = self._receipt(session, context.tenant_id, receipt.delivery_key)
                    if existing_retry is not None:
                        return self._result(existing_retry, duplicate=True)
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

    @staticmethod
    def _receipt(session: Session, tenant_id: UUID, delivery_key: str) -> SignalReceipt | None:
        return session.scalar(
            sa.select(SignalReceipt).where(
                SignalReceipt.tenant_id == tenant_id,
                SignalReceipt.delivery_key == delivery_key,
            )
        )

    def _alert(
        self, session: Session, context: ConnectorContext, signal: Signal, receipt: SignalReceipt
    ) -> None:
        key = occurrence_key(context, signal)
        alerts = list(
            session.scalars(
                sa.select(Alert)
                .where(
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
                .limit(2)
            )
        )
        if len(alerts) > 1:
            receipt.outcome, receipt.reason = "rejected", "occurrence_invariant_violation"
            receipt.decision.update({"occurrence_matches": "multiple", "action": "fail_closed"})
            return
        alert = alerts[0] if alerts else None
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
                    _alert_severity_rank(alert.severity.value),
                    alert.source_digest or "",
                )
                new = (
                    signal.observed_at,
                    signal.state is SourceState.RESOLVED,
                    _alert_severity_rank(signal.severity.value),
                    receipt.content_digest,
                )
                retrying_unattached_firing = (
                    alert.incident_id is None
                    and signal.state is SourceState.FIRING
                    and session.scalar(
                        sa.select(
                            sa.exists().where(
                                SignalReceipt.tenant_id == context.tenant_id,
                                SignalReceipt.alert_id == alert.id,
                                SignalReceipt.outcome == "retryable",
                                SignalReceipt.reason == "correlation_candidate_overflow",
                            )
                        )
                    )
                    is True
                )
                if new <= old and not retrying_unattached_firing:
                    receipt.outcome = "unchanged" if new == old else "stale"
                    receipt.reason = "equal_observation" if new == old else "out_of_order"
                    receipt.alert_id, receipt.incident_id = alert.id, alert.incident_id
                    receipt.decision.update(
                        {
                            "ordering": "observed_at,state_rank,severity_rank,digest",
                            "winner": list(map(str, old)),
                        }
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
        if incident is not None and incident.terminated_at is not None:
            receipt.incident_id = incident.id
            receipt.decision.update(
                {
                    "result": "terminal_reopen_candidate"
                    if signal.state is SourceState.FIRING
                    else "terminal_source_resolution",
                    "selected": str(incident.id),
                    "terminal_status": incident.status.value,
                    "policy_version": POLICY_VERSION,
                    "reason": "automatic_reopen_forbidden",
                }
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
                IncidentEventType.CORRELATION_DECIDED,
                receipt.decision,
            )
            if signal.state is SourceState.FIRING:
                receipt.reason = "terminal_reopen_candidate"
                # The append-only candidate references this immutable decision. Flush the
                # receipt first so PostgreSQL can enforce the composite FK immediately.
                session.add(receipt)
                session.flush()
                session.add(
                    IncidentReopenCandidate(
                        id=uuid4(),
                        tenant_id=context.tenant_id,
                        incident_id=incident.id,
                        alert_id=alert.id,
                        receipt_id=receipt.id,
                        requested_severity=_severity(signal),
                        reason="new_firing_signal_after_terminal",
                    )
                )
            else:
                receipt.reason = "terminal_source_resolution_recorded"
            return
        created = False
        attached = False
        if incident is None and signal.state is SourceState.FIRING:
            # Opening events pin the anchor; subsequent arrivals never slide the window.
            anchor_time = sa.cast(
                IncidentEvent.payload["correlation_anchor"]["started_at"].astext,
                sa.DateTime(timezone=True),
            )
            anchor_service = IncidentEvent.payload["correlation_anchor"]["service_id"].astext
            anchor_category = IncidentEvent.payload["correlation_anchor"]["category"].astext
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
                    Incident.environment_id == context.environment_id,
                    Incident.terminated_at.is_(None),
                    IncidentEvent.event_type == IncidentEventType.INCIDENT_OPENED,
                    anchor_service == str(context.service_id),
                    anchor_category == signal.category,
                    anchor_time >= signal.started_at - timedelta(seconds=WINDOW_SECONDS),
                    anchor_time <= signal.started_at + timedelta(seconds=WINDOW_SECONDS),
                )
                .order_by(anchor_time, Incident.id)
                .limit(MAX_CANDIDATES + 1)
            ).all()
            if len(rows) > MAX_CANDIDATES:
                receipt.outcome = "retryable"
                receipt.reason = "correlation_candidate_overflow"
                receipt.decision = {
                    "policy_version": POLICY_VERSION,
                    "result": "overflow",
                    "candidate_count_lower_bound": MAX_CANDIDATES + 1,
                    "candidate_limit": MAX_CANDIDATES,
                    "retry": "retry after relevant active candidate set is reduced",
                    "action": "no correlation selected",
                }
                return
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
            .with_for_update(key_share=True)
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


def _alert_severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[value]


def _retryable_delivery_key(delivery_key: str, content_digest: str, reason: str) -> str:
    return digest([delivery_key, content_digest, "retryable", reason])
