"""The Phase 10 external-record catalogue: collaboration, paging, ticketing, annotation.

Registered alongside - never merged into - the read catalogue and the remediation write
catalogue (ADR-0026), and loaded only by :meth:`ToolRegistry.integrations`, whose sole
consumer is the deterministic S2 notification service.

Three properties are structural, not conventional:

**No free text is an instruction or a destination.** A caller supplies an event type
from a closed enumeration, an incident reference, a severity and a bounded summary. The
channel, project, routing key, dashboard and every URL come from the tenant's
server-side connector configuration; no argument can name them.

**Every record is an external record, never an infrastructure change.** The effect class
is ``external_record`` (tier ``r1``): no rollback is invented for a message that cannot be
un-sent, nothing here passes through the remediation policy gate because nothing here
changes a workload, and no descriptor retries - a repeated send after an unknown outcome
is a duplicate user-visible message.

**Every effect is keyed on a deterministic event id.** The broker's durable effect claim
refuses a second dispatch of the same event, so an incident transition produces at most
one message per channel even under concurrent or resumed delivery.

The rows are seeded by migration ``0016_external_integrations`` from frozen literals, not
derived from this module (ADR-0018).
"""

from __future__ import annotations

from typing import Final

from asic.domain.enums import RiskTier, ToolEffectClass, ToolProviderKind
from asic.tools.catalogue import scope_arguments
from asic.tools.descriptor import ArgumentKind, ArgumentSpec, ResultField, ToolDescriptor

INTEGRATION_CATALOGUE_VERSION: Final[str] = "2026.09.16-integrations-1"

#: Lifecycle events S2 may announce. Closed: an event type invented at a call site would
#: be a message template nobody reviewed.
NOTIFICATION_EVENT_TYPES: Final[tuple[str, ...]] = (
    "incident_opened",
    "incident_escalated",
    "incident_resolved",
    "approval_requested",
    "remediation_executed",
    "verification_completed",
)

INCIDENT_REFERENCE_PATTERN: Final[str] = r"[A-Za-z][A-Za-z0-9-]{0,39}"
EVENT_ID_PATTERN: Final[str] = r"[0-9a-f]{64}"


def _event_arguments() -> tuple[ArgumentSpec, ...]:
    return (
        *scope_arguments(),
        ArgumentSpec(
            name="event_id",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Deterministic digest of the incident transition being announced.",
            pattern=EVENT_ID_PATTERN,
            max_length=64,
        ),
        ArgumentSpec(
            name="event_type",
            kind=ArgumentKind.ENUM,
            description="Which lifecycle transition this record announces.",
            allowed_values=NOTIFICATION_EVENT_TYPES,
        ),
        ArgumentSpec(
            name="incident_reference",
            kind=ArgumentKind.BOUNDED_STRING,
            description="The incident's human reference, e.g. INC-0042.",
            pattern=INCIDENT_REFERENCE_PATTERN,
            max_length=40,
        ),
        ArgumentSpec(
            name="severity",
            kind=ArgumentKind.ENUM,
            description="Incident severity.",
            allowed_values=("sev1", "sev2", "sev3", "sev4"),
        ),
        ArgumentSpec(
            name="status",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Incident lifecycle status at the time of the event.",
            pattern=r"[a-z][a-z_]{0,31}",
            max_length=32,
        ),
        ArgumentSpec(
            name="summary",
            kind=ArgumentKind.BOUNDED_STRING,
            description=(
                "Bounded summary rendered by S2 from records. Treated as untrusted display "
                "text by every adapter: escaped, never interpreted."
            ),
            max_length=300,
        ),
    )


def _record_result() -> tuple[ResultField, ...]:
    return (
        ResultField(name="external_reference", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="created", kind=ArgumentKind.BOOLEAN),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    )


def _record(name: str, capability: str, description: str, timeout: int) -> ToolDescriptor:
    return ToolDescriptor(
        name=name,
        version="1.0.0",
        capability=capability,
        description=description,
        risk_tier=RiskTier.R1,
        effect_class=ToolEffectClass.EXTERNAL_RECORD,
        provider_kind=ToolProviderKind.NATIVE,
        arguments=_event_arguments(),
        result_fields=_record_result(),
        timeout_seconds=timeout,
        is_idempotent=True,
        idempotency_key_fields=("tenant_id", "environment", "service", "event_id"),
        max_attempts=1,
        audit_events=("tool.executed",),
    )


SLACK_POST: Final = _record(
    "slack.post",
    "notify.slack_channel",
    "Post a templated incident update to the tenant's configured Slack channel.",
    20,
)
TEAMS_POST: Final = _record(
    "teams.post",
    "notify.teams_channel",
    "Post a templated incident card to the tenant's configured Microsoft Teams workflow.",
    20,
)
PAGERDUTY_EVENT: Final = _record(
    "pagerduty.event",
    "write.pagerduty_event",
    (
        "Send a PagerDuty Events API v2 trigger/acknowledge/resolve derived from the internal "
        "incident status. PagerDuty state never drives internal incident state."
    ),
    20,
)
JIRA_ISSUE: Final = _record(
    "jira.issue.create",
    "write.jira_issue",
    "Create, or find the already-created, Jira issue for one incident (label-deduplicated).",
    30,
)
JIRA_COMMENT: Final = _record(
    "jira.issue.comment",
    "write.jira_comment",
    "Append a structured status comment to the incident's own Jira issue.",
    30,
)
GRAFANA_ANNOTATION: Final = _record(
    "grafana.annotation.create",
    "write.grafana_annotation",
    "Annotate the tenant's configured service dashboard with an incident lifecycle event.",
    20,
)

INTEGRATION_CATALOGUE: Final[tuple[ToolDescriptor, ...]] = (
    GRAFANA_ANNOTATION,
    JIRA_COMMENT,
    JIRA_ISSUE,
    PAGERDUTY_EVENT,
    SLACK_POST,
    TEAMS_POST,
)

for _descriptor in INTEGRATION_CATALOGUE:
    if _descriptor.effect_class is not ToolEffectClass.EXTERNAL_RECORD:  # pragma: no cover
        raise ValueError(f"{_descriptor.name} is not an external record")

__all__ = [
    "EVENT_ID_PATTERN",
    "GRAFANA_ANNOTATION",
    "INCIDENT_REFERENCE_PATTERN",
    "INTEGRATION_CATALOGUE",
    "INTEGRATION_CATALOGUE_VERSION",
    "JIRA_COMMENT",
    "JIRA_ISSUE",
    "NOTIFICATION_EVENT_TYPES",
    "PAGERDUTY_EVENT",
    "SLACK_POST",
    "TEAMS_POST",
]
