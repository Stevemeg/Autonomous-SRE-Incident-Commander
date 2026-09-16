"""S2 notification service: incident records -> external records, through the broker.

Deterministic by design (ADR-0001): no model writes a message sent under the organisation's
name. Every field is rendered from durable rows - the incident's reference, severity and
status, and its title bounded as untrusted display text - and every delivery is a broker
capability request, so connector scope, credentials, idempotency, audit and trace are the
same as for any other tool call.

Three rules are enforced here rather than left to callers:

* **Destinations come from grants, not arguments.** A delivery is attempted only for
  capabilities on the tenant's resolved S2 menu; which channel or project it reaches is the
  connector's business.
* **Delivery never fails the incident.** Every failure becomes a typed receipt; this
  service commits its own records and returns.
* **At most once per transition per destination.** The event id is a digest of the tenant,
  incident, event type and the record that caused the event; the broker's durable effect
  claim refuses a repeat, including a concurrent or resumed one.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import S2_NOTIFICATION_SERVICE
from asic.db.models import Alert, ExecutionTrace, Incident, TraceSpan
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.clock import Clock
from asic.domain.enums import IntegrationFailureClass, RiskTier, ToolExecutionOutcome
from asic.integrations.base import display_text
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder
from asic.tools.broker import CapabilityRequest, ToolBroker
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.integration_catalogue import NOTIFICATION_EVENT_TYPES
from asic.tools.provider import ToolProvider
from asic.tools.registry import ToolRegistry

#: Delivery order. Ticket creation precedes comments so a comment has an issue to land on.
_CAPABILITY_ORDER: Final[tuple[str, ...]] = (
    "write.jira_issue",
    "write.jira_comment",
    "write.pagerduty_event",
    "notify.slack_channel",
    "notify.teams_channel",
    "write.grafana_annotation",
)

#: Which events open a ticket and which append to it. Every other capability receives all.
_TICKET_OPENING_EVENTS: Final[frozenset[str]] = frozenset({"incident_opened", "incident_escalated"})


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    event_type: str
    #: The durable record that caused the event (workflow run, approval, verification).
    source_record_id: uuid.UUID
    #: The execution trace the delivery spans are appended to.
    execution_trace_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    capability: str
    outcome: ToolExecutionOutcome
    external_reference: str | None
    failure_class: IntegrationFailureClass | None
    deduplicated: bool
    tool_execution_id: uuid.UUID | None


def event_id(event: NotificationEvent) -> str:
    return hashlib.sha256(
        f"{event.tenant_id}|{event.incident_id}|{event.event_type}|{event.source_record_id}".encode()
    ).hexdigest()


class NotificationService:
    """Announces incident transitions to every destination the tenant has granted."""

    __slots__ = ("_clock", "_providers", "_session_factory")

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        providers: Sequence[ToolProvider],
        clock: Clock,
    ) -> None:
        self._session_factory = session_factory
        self._providers = tuple(providers)
        self._clock = clock

    def announce(self, event: NotificationEvent) -> tuple[DeliveryReceipt, ...]:
        if event.event_type not in NOTIFICATION_EVENT_TYPES:
            raise ValueError(f"event type {event.event_type!r} is not a registered notification")
        session = self._session_factory()
        try:
            bind_tenant(session, event.tenant_id)
            apply_statement_timeouts(session)
            incident = session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == event.tenant_id, Incident.id == event.incident_id
                )
            ).scalar_one()
            trace = session.execute(
                sa.select(ExecutionTrace).where(
                    ExecutionTrace.tenant_id == event.tenant_id,
                    ExecutionTrace.id == event.execution_trace_id,
                    ExecutionTrace.incident_id == event.incident_id,
                )
            ).scalar_one()
            service_ids = list(
                session.scalars(
                    sa.select(Alert.service_id)
                    .where(
                        Alert.tenant_id == event.tenant_id,
                        Alert.incident_id == event.incident_id,
                        Alert.service_id.is_not(None),
                    )
                    .distinct()
                )
            )
            if not service_ids:
                return ()
            scope = load_incident_scope(
                session,
                tenant_id=event.tenant_id,
                incident_id=event.incident_id,
                environment_id=incident.environment_id,
                service_ids=[sid for sid in service_ids if sid is not None],
            )
            ordinal = int(
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(TraceSpan)
                    .where(
                        TraceSpan.tenant_id == event.tenant_id,
                        TraceSpan.execution_trace_id == trace.id,
                    )
                )
                or 0
            )
            tracer = TraceRecorder(
                tenant_id=event.tenant_id,
                execution_trace_id=trace.id,
                trace_id=trace.trace_id,
                clock=self._clock,
                start_ordinal=ordinal,
            )
            broker = ToolBroker(
                resolver=CapabilityResolver(ToolRegistry.integrations(), max_risk_tier=RiskTier.R1),
                providers=self._providers,
                scope=scope,
                audit=AuditWriter(tenant_id=event.tenant_id, clock=self._clock),
                tracer=tracer,
                clock=self._clock,
                claim_session_factory=self._session_factory,
            )
            try:
                menu = broker.menu_for(session, S2_NOTIFICATION_SERVICE)
                service_name = scope.services[0].name
                arguments = {
                    "event_id": event_id(event),
                    "event_type": event.event_type,
                    "incident_reference": incident.reference,
                    "severity": incident.severity.value,
                    "status": incident.status.value,
                    "summary": display_text(incident.title, limit=300),
                }
                receipts: list[DeliveryReceipt] = []
                for capability in _CAPABILITY_ORDER:
                    if capability not in menu:
                        continue
                    opening = event.event_type in _TICKET_OPENING_EVENTS
                    if capability == "write.jira_issue" and not opening:
                        continue
                    if capability == "write.jira_comment" and opening:
                        continue
                    result = broker.invoke(
                        session,
                        request=CapabilityRequest(
                            node_id=S2_NOTIFICATION_SERVICE.node_id,
                            capability=capability,
                            service_name=service_name,
                            arguments=arguments,
                            incident_id=event.incident_id,
                            correlation_id=trace.correlation_id,
                            purpose=f"announce {event.event_type}",
                        ),
                        contract=S2_NOTIFICATION_SERVICE,
                    )
                    tracer.flush(session)
                    session.commit()
                    bind_tenant(session, event.tenant_id)
                    receipts.append(
                        DeliveryReceipt(
                            capability=capability,
                            outcome=result.outcome,
                            external_reference=(
                                str(result.payload.get("external_reference"))
                                if result.succeeded and result.payload.get("external_reference")
                                else None
                            ),
                            failure_class=(
                                result.failure.failure_class if result.failure is not None else None
                            ),
                            deduplicated=result.deduplicated,
                            tool_execution_id=result.tool_execution_id,
                        )
                    )
                return tuple(receipts)
            finally:
                broker.close()
        finally:
            session.close()


__all__ = ["DeliveryReceipt", "NotificationEvent", "NotificationService", "event_id"]
