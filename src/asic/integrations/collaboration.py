"""Slack, Microsoft Teams, PagerDuty, Jira and Grafana: external records from S2 events.

Every adapter here receives the same typed event (event id, event type, incident reference,
severity, status, bounded summary) and nothing else. Destinations - channel, workflow URL,
routing key, project, dashboard - come from the tenant's connector and credential store.

Inbound text is not part of this module at all. Chat replies, ticket comments and PagerDuty
state changes are not read back into the incident: a Slack message is not an approval, and
a PagerDuty "resolved" does not resolve an incident. Approval authority lives only in the
authenticated approval API (FR-CLB-03); interactive chat approval is deferred rather than
built on a weaker identity.

Summaries are untrusted display text. Each adapter neutralises the destination's own markup
(Slack mentions and links, Markdown links) so text drawn from an alert cannot ping a
channel, forge a link or impersonate a system message.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlsplit

from asic.domain.enums import IntegrationFailureClass, IntegrationKind
from asic.domain.errors import IntegrationError
from asic.integrations.base import (
    AdapterRuntime,
    authorization,
    base_headers,
    configuration_error,
    display_text,
    endpoint_for,
    json_body,
    mapping,
    require_connector,
    resolve_secret,
    send_json,
    sequence,
    setting,
)
from asic.integrations.transport import HttpRequest, malformed, path, validate_endpoint
from asic.tools.provider import ConnectorGrant, InvocationContext

_TITLES: Final[dict[str, str]] = {
    "incident_opened": "Incident opened",
    "incident_escalated": "Incident escalated to humans",
    "incident_resolved": "Incident resolved",
    "approval_requested": "Remediation approval requested",
    "remediation_executed": "Remediation executed",
    "verification_completed": "Remediation verification completed",
}

TEAMS_HOST_SUFFIXES: Final[tuple[str, ...]] = (
    ".logic.azure.com",
    ".webhook.office.com",
    ".environment.api.powerplatform.com",
)
PAGERDUTY_HOSTS: Final[tuple[str, ...]] = ("events.pagerduty.com", "events.eu.pagerduty.com")
_PAGERDUTY_SEVERITY: Final[dict[str, str]] = {
    "sev1": "critical",
    "sev2": "error",
    "sev3": "warning",
    "sev4": "info",
}


def incident_key(
    connector: ConnectorGrant, incident_reference: str, *, prefix: str, length: int
) -> str:
    """A stable external identity for one incident, derived from server-side values only."""
    digest = hashlib.sha256(
        f"{connector.connector_id}|{connector.environment_name}|{incident_reference}".encode()
    ).hexdigest()
    return f"{prefix}{digest[:length]}"


def _headline(arguments: Mapping[str, Any]) -> str:
    return (
        f"{_TITLES[str(arguments['event_type'])]}: {arguments['incident_reference']} "
        f"({str(arguments['severity']).upper()}, status {arguments['status']})"
    )


def _scope_line(arguments: Mapping[str, Any]) -> str:
    return f"service {arguments['service']} in {arguments['environment']}"


def slack_escape(text: str) -> str:
    """Slack mrkdwn control characters. ``<!channel>`` and ``<https://..|..>`` become inert."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def markdown_escape(text: str) -> str:
    """Neutralise Markdown link and emphasis syntax used by Teams Adaptive Cards."""
    return re.sub(r"([\\`*_\[\]()#>!|~])", r"\\\1", text)


class SlackAdapter:
    kind = IntegrationKind.SLACK
    _ERRORS: Final[dict[str, IntegrationFailureClass]] = {
        "invalid_auth": IntegrationFailureClass.UNAUTHORIZED,
        "not_authed": IntegrationFailureClass.UNAUTHORIZED,
        "account_inactive": IntegrationFailureClass.UNAUTHORIZED,
        "token_revoked": IntegrationFailureClass.UNAUTHORIZED,
        "token_expired": IntegrationFailureClass.UNAUTHORIZED,
        "missing_scope": IntegrationFailureClass.FORBIDDEN,
        "channel_not_found": IntegrationFailureClass.NOT_FOUND,
        "not_in_channel": IntegrationFailureClass.FORBIDDEN,
        "is_archived": IntegrationFailureClass.FORBIDDEN,
        "ratelimited": IntegrationFailureClass.RATE_LIMITED,
    }

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def post(self, arguments: Mapping[str, Any], context: InvocationContext) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        channel = setting(connector, "channel_id", pattern=r"[CG][A-Z0-9]{8,12}")
        secret = resolve_secret(self._runtime, connector.credential_ref, purpose="bot")
        headline = slack_escape(display_text(_headline(arguments), limit=200))
        summary = slack_escape(display_text(arguments["summary"], limit=300))
        scope = slack_escape(_scope_line(arguments))
        body = {
            "channel": channel,
            "text": headline,
            "unfurl_links": False,
            "unfurl_media": False,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": headline[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"{summary}\n_{scope}_"}},
            ],
        }
        headers = base_headers(context)
        headers.append(authorization(secret, "bearer"))
        headers.append(("Content-Type", "application/json; charset=utf-8"))
        request = HttpRequest(
            method="POST",
            endpoint=endpoint_for(
                self._runtime,
                connector,
                default="https://slack.com",
                allowed_host_suffixes=(".slack.com",),
            ),
            path=path("api", "chat.postMessage"),
            headers=tuple(headers),
            body=json_body(body),
            effectful=True,
        )
        response = mapping(
            send_json(self._runtime, request, context), "slack response", effectful=True
        )
        if response.get("ok") is not True:
            code = str(response.get("error", "unknown"))[:64]
            # Slack answered ok=false: the message was not posted.
            raise IntegrationError(
                f"slack rejected the message ({re.sub(r'[^a-z_]', '', code)})",
                failure_class=self._ERRORS.get(code, IntegrationFailureClass.INVALID_REQUEST),
                transient=False,
                effect_not_applied=True,
            )
        ts = response.get("ts")
        if not isinstance(ts, str) or not re.fullmatch(r"\d{1,12}\.\d{1,8}", ts):
            raise malformed("slack response has no message timestamp", effectful=True)
        return {
            "external_reference": f"slack:{channel}:{ts}",
            "created": True,
            "source": "slack",
            "schema_version": 1,
        }


class TeamsAdapter:
    """Teams via a Workflows (Power Automate) webhook whose URL is itself the secret."""

    kind = IntegrationKind.TEAMS

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def post(self, arguments: Mapping[str, Any], context: InvocationContext) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        webhook = resolve_secret(
            self._runtime, connector.credential_ref, purpose="webhook"
        ).reveal()
        parts = urlsplit(webhook)
        if parts.username or parts.password or parts.fragment:
            raise configuration_error("teams webhook reference is malformed")
        endpoint = validate_endpoint(
            f"{parts.scheme}://{parts.netloc}",
            allow_loopback_http=self._runtime.allow_loopback_http,
            allowed_host_suffixes=TEAMS_HOST_SUFFIXES,
        )
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "weight": "Bolder",
                                "wrap": True,
                                "text": markdown_escape(
                                    display_text(_headline(arguments), limit=200)
                                ),
                            },
                            {
                                "type": "TextBlock",
                                "wrap": True,
                                "text": markdown_escape(
                                    display_text(arguments["summary"], limit=300)
                                ),
                            },
                            {
                                "type": "TextBlock",
                                "isSubtle": True,
                                "wrap": True,
                                "text": markdown_escape(_scope_line(arguments)),
                            },
                        ],
                    },
                }
            ],
        }
        headers = base_headers(context)
        headers.append(("Content-Type", "application/json"))
        request = _OpaqueTargetRequest(
            method="POST",
            endpoint=endpoint,
            path=target,
            headers=tuple(headers),
            body=json_body(card),
            effectful=True,
        )
        send_json(self._runtime, request, context, allow_empty=True)
        # Workflows webhooks acknowledge without returning a message identifier. The
        # reference is ours, derived from the event, and says so.
        return {
            "external_reference": f"teams:accepted:{str(arguments['event_id'])[:16]}",
            "created": True,
            "source": "teams",
            "schema_version": 1,
        }


class _OpaqueTargetRequest(HttpRequest):
    """A request whose path carries a secret (a signed webhook). Never rendered."""

    __slots__ = ()

    def describe(self) -> str:
        return f"{self.method} {self.endpoint.origin_label()}/[redacted webhook path]"


class PagerDutyAdapter:
    """Events API v2. Internal incident status drives PagerDuty; never the reverse.

    ``dedup_key`` is derived from the connector and incident, so every event for one
    incident lands on one PagerDuty alert: a repeated trigger updates rather than re-pages,
    and an internal resolution resolves it. Acknowledgement is a responder's action in
    PagerDuty and is never sent by this system.
    """

    kind = IntegrationKind.PAGERDUTY

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def event(self, arguments: Mapping[str, Any], context: InvocationContext) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        routing_key = resolve_secret(self._runtime, connector.credential_ref, purpose="routing")
        dedup_key = incident_key(
            connector, str(arguments["incident_reference"]), prefix="asic-", length=32
        )
        status = str(arguments["status"])
        action = "resolve" if status in {"resolved", "closed"} else "trigger"
        body: dict[str, Any] = {
            "routing_key": routing_key.reveal(),
            "event_action": action,
            "dedup_key": dedup_key,
        }
        if action == "trigger":
            body["payload"] = {
                "summary": display_text(
                    _headline(arguments) + " - " + str(arguments["summary"]), limit=1000
                ),
                "source": f"asic:{arguments['service']}",
                "severity": _PAGERDUTY_SEVERITY[str(arguments["severity"])],
                "component": str(arguments["service"]),
                "group": str(arguments["environment"]),
                "custom_details": {
                    "incident_reference": str(arguments["incident_reference"]),
                    "status": status,
                    "event_type": str(arguments["event_type"]),
                },
            }
        headers = base_headers(context)
        headers.append(("Content-Type", "application/json"))
        request = HttpRequest(
            method="POST",
            endpoint=endpoint_for(
                self._runtime,
                connector,
                default="https://events.pagerduty.com",
                allowed_host_suffixes=PAGERDUTY_HOSTS,
            ),
            path=path("v2", "enqueue"),
            headers=tuple(headers),
            body=json_body(body),
            effectful=True,
        )
        response = mapping(
            send_json(self._runtime, request, context), "pagerduty response", effectful=True
        )
        if response.get("status") != "success" or response.get("dedup_key") != dedup_key:
            raise malformed("pagerduty did not confirm the event", effectful=True)
        return {
            "external_reference": f"pagerduty:{dedup_key}:{action}",
            "created": action == "trigger",
            "source": "pagerduty",
            "schema_version": 1,
        }


class JiraAdapter:
    """Jira Cloud REST v3. One issue per incident, found by a derived label before creating.

    The only JQL this system ever sends is composed here from the configured project key
    and a derived label, both pattern-validated. Comments are appended only to the issue
    that label identifies; no caller can name an issue key.
    """

    kind = IntegrationKind.JIRA

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def _headers(
        self, connector: ConnectorGrant, context: InvocationContext
    ) -> list[tuple[str, str]]:
        secret = resolve_secret(self._runtime, connector.credential_ref, purpose="api")
        scheme = setting(connector, "auth_scheme", pattern="basic|bearer", default="basic")
        headers = base_headers(context)
        headers.append(authorization(secret, scheme))
        headers.append(("Content-Type", "application/json"))
        headers.append(("X-Atlassian-Token", "no-check"))
        return headers

    def _find(
        self, connector: ConnectorGrant, context: InvocationContext, label: str
    ) -> str | None:
        project = setting(connector, "project_key", pattern=r"[A-Z][A-Z0-9_]{1,9}")
        jql = f'project = "{project}" AND labels = "{label}" ORDER BY created ASC'
        request = HttpRequest(
            method="GET",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("rest", "api", "3", "search", "jql"),
            query=(("jql", jql), ("maxResults", "2"), ("fields", "key")),
            headers=tuple(self._headers(connector, context)),
        )
        response = mapping(send_json(self._runtime, request, context), "jira search")
        issues = sequence(response.get("issues"), "jira issues")
        if len(issues) > 1:
            raise IntegrationError(
                "more than one Jira issue carries this incident's label",
                failure_class=IntegrationFailureClass.CONFLICT,
                effect_not_applied=True,
            )
        if not issues:
            return None
        key = mapping(issues[0], "jira issue").get("key")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,9}-\d{1,9}", key):
            raise malformed("jira returned an invalid issue key")
        return key

    @staticmethod
    def _document(*paragraphs: str) -> dict[str, Any]:
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": text}]}
                for text in paragraphs
            ],
        }

    def create(self, arguments: Mapping[str, Any], context: InvocationContext) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        label = incident_key(
            connector, str(arguments["incident_reference"]), prefix="asic-", length=24
        )
        existing = self._find(connector, context, label)
        if existing is not None:
            return {
                "external_reference": f"jira:{existing}",
                "created": False,
                "source": "jira",
                "schema_version": 1,
            }
        project = setting(connector, "project_key", pattern=r"[A-Z][A-Z0-9_]{1,9}")
        issue_type = setting(
            connector, "issue_type", pattern=r"[A-Za-z][A-Za-z0-9 _-]{0,31}", default="Task"
        )
        fields = {
            "project": {"key": project},
            "issuetype": {"name": issue_type},
            "summary": display_text(
                f"[{arguments['incident_reference']}] {arguments['summary']}", limit=250
            ),
            "labels": [label, "asic-incident"],
            "description": self._document(
                display_text(_headline(arguments), limit=300),
                display_text(arguments["summary"], limit=300),
                _scope_line(arguments),
            ),
        }
        request = HttpRequest(
            method="POST",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("rest", "api", "3", "issue"),
            headers=tuple(self._headers(connector, context)),
            body=json_body({"fields": fields}),
            effectful=True,
        )
        response = mapping(
            send_json(self._runtime, request, context), "jira create", effectful=True
        )
        key = response.get("key")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,9}-\d{1,9}", key):
            raise malformed("jira create returned no issue key", effectful=True)
        return {
            "external_reference": f"jira:{key}",
            "created": True,
            "source": "jira",
            "schema_version": 1,
        }

    def comment(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        label = incident_key(
            connector, str(arguments["incident_reference"]), prefix="asic-", length=24
        )
        key = self._find(connector, context, label)
        if key is None:
            raise IntegrationError(
                "the incident has no Jira issue to comment on",
                failure_class=IntegrationFailureClass.NOT_FOUND,
                effect_not_applied=True,
            )
        request = HttpRequest(
            method="POST",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("rest", "api", "3", "issue", key, "comment"),
            headers=tuple(self._headers(connector, context)),
            body=json_body(
                {
                    "body": self._document(
                        display_text(_headline(arguments), limit=300),
                        display_text(arguments["summary"], limit=300),
                    )
                }
            ),
            effectful=True,
        )
        response = mapping(
            send_json(self._runtime, request, context), "jira comment", effectful=True
        )
        comment_id = response.get("id")
        if not isinstance(comment_id, str) or not comment_id.isdigit():
            raise malformed("jira comment returned no id", effectful=True)
        return {
            "external_reference": f"jira:{key}#comment-{comment_id}",
            "created": True,
            "source": "jira",
            "schema_version": 1,
        }


class GrafanaAdapter:
    """Dashboard annotations and deterministic deep links. Grafana is not a query engine here."""

    kind = IntegrationKind.GRAFANA

    def __init__(self, runtime: AdapterRuntime) -> None:
        self._runtime = runtime

    def annotate(
        self, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        connector = require_connector(context, self.kind)
        dashboard = setting(connector, "dashboard_uid", pattern=r"[A-Za-z0-9_-]{1,40}")
        secret = resolve_secret(self._runtime, connector.credential_ref, purpose="service account")
        headers = base_headers(context)
        headers.append(authorization(secret, "bearer"))
        headers.append(("Content-Type", "application/json"))
        body = {
            "dashboardUID": dashboard,
            "time": int(self._runtime.clock.now().timestamp() * 1000),
            "tags": [
                "asic",
                str(arguments["event_type"]),
                f"incident:{arguments['incident_reference']}",
                f"service:{arguments['service']}",
            ],
            "text": display_text(f"{_headline(arguments)} - {arguments['summary']}", limit=500),
        }
        request = HttpRequest(
            method="POST",
            endpoint=endpoint_for(self._runtime, connector),
            path=path("api", "annotations"),
            headers=tuple(headers),
            body=json_body(body),
            effectful=True,
        )
        response = mapping(
            send_json(self._runtime, request, context), "grafana response", effectful=True
        )
        annotation_id = response.get("id")
        if isinstance(annotation_id, bool) or not isinstance(annotation_id, int):
            raise malformed("grafana did not return an annotation id", effectful=True)
        return {
            "external_reference": f"grafana:annotation:{annotation_id}",
            "created": True,
            "source": "grafana",
            "schema_version": 1,
        }


def grafana_dashboard_link(
    *,
    endpoint_url: str,
    dashboard_uid: str,
    service: str,
    environment: str,
    start_ms: int,
    end_ms: int,
) -> str:
    """A deterministic deep link. Pure: builds a URL from validated values, calls nothing."""
    endpoint = validate_endpoint(endpoint_url, allow_loopback_http=False)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", dashboard_uid):
        raise configuration_error("dashboard uid is invalid")
    if not (0 <= start_ms < end_ms):
        raise configuration_error("dashboard link window is invalid")
    from urllib.parse import urlencode

    query = urlencode(
        {
            "from": str(start_ms),
            "to": str(end_ms),
            "var-service": service,
            "var-environment": environment,
        }
    )
    return (
        f"{endpoint.scheme}://{endpoint.host}"
        f"{'' if endpoint.port in (80, 443) else ':' + str(endpoint.port)}"
        f"{endpoint.base_path}{path('d', dashboard_uid)}?{query}"
    )


__all__ = [
    "GrafanaAdapter",
    "JiraAdapter",
    "PagerDutyAdapter",
    "SlackAdapter",
    "TeamsAdapter",
    "grafana_dashboard_link",
    "incident_key",
    "markdown_escape",
    "slack_escape",
]
