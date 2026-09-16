"""The native integration provider: registered tools mapped to typed adapter methods.

Each supported tool is bound to exactly one adapter method and one connector kind, and to
the capability it is registered under. ``supports`` requires the name *and* the capability
to match, so a descriptor that reuses a name under a different capability is not served.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Final

from asic.domain.enums import IntegrationFailureClass, IntegrationKind, ToolProviderKind
from asic.domain.errors import IntegrationError
from asic.integrations.base import AdapterRuntime
from asic.integrations.collaboration import (
    GrafanaAdapter,
    JiraAdapter,
    PagerDutyAdapter,
    SlackAdapter,
    TeamsAdapter,
)
from asic.integrations.kubernetes import KubernetesAdapter
from asic.integrations.loki import LokiAdapter
from asic.integrations.prometheus import PrometheusAdapter
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ProviderHealth

Operation = Callable[[Mapping[str, Any], InvocationContext], Mapping[str, Any]]

#: tool name -> (capability, connector kind). The authoritative map of what is real.
NATIVE_TOOLS: Final[dict[str, tuple[str, IntegrationKind]]] = {
    "metrics.query": ("read.metrics", IntegrationKind.PROMETHEUS),
    "logs.query": ("read.logs", IntegrationKind.LOKI),
    "k8s.workload.read": ("read.k8s_workload", IntegrationKind.KUBERNETES),
    "deploy.list": ("read.deploy", IntegrationKind.KUBERNETES),
    "k8s.deployment.rollback": ("mutate.k8s_deployment", IntegrationKind.KUBERNETES),
    "k8s.hpa.adjust": ("mutate.k8s_scale", IntegrationKind.KUBERNETES),
    "k8s.node.cordon": ("mutate.k8s_node", IntegrationKind.KUBERNETES),
    "k8s.node.uncordon": ("mutate.k8s_node", IntegrationKind.KUBERNETES),
    "slack.post": ("notify.slack_channel", IntegrationKind.SLACK),
    "teams.post": ("notify.teams_channel", IntegrationKind.TEAMS),
    "pagerduty.event": ("write.pagerduty_event", IntegrationKind.PAGERDUTY),
    "jira.issue.create": ("write.jira_issue", IntegrationKind.JIRA),
    "jira.issue.comment": ("write.jira_comment", IntegrationKind.JIRA),
    "grafana.annotation.create": ("write.grafana_annotation", IntegrationKind.GRAFANA),
}

#: Registered read capabilities with no native adapter, and why. Reported, not hidden.
UNIMPLEMENTED_NATIVE_TOOLS: Final[dict[str, str]] = {
    "traces.query": (
        "no trace backend is selected by an accepted ADR; OpenTelemetry export is Phase 12 "
        "and querying a trace store would need its own decision"
    ),
    "knowledge.search": "served by the governed PostgreSQL KnowledgeStoreProvider (Phase 6)",
}


class NativeIntegrationProvider:
    """Live adapters for the tools in :data:`NATIVE_TOOLS`."""

    __slots__ = ("_operations",)

    def __init__(self, runtime: AdapterRuntime) -> None:
        kubernetes = KubernetesAdapter(runtime)
        jira = JiraAdapter(runtime)
        self._operations: dict[str, Operation] = {
            "metrics.query": PrometheusAdapter(runtime).query_range,
            "logs.query": LokiAdapter(runtime).query_range,
            "k8s.workload.read": kubernetes.workload_read,
            "deploy.list": kubernetes.deploy_list,
            "k8s.deployment.rollback": kubernetes.deployment_rollback,
            "k8s.hpa.adjust": kubernetes.hpa_adjust,
            "k8s.node.cordon": lambda a, c: kubernetes.node_schedulability(a, c, schedulable=False),
            "k8s.node.uncordon": lambda a, c: kubernetes.node_schedulability(
                a, c, schedulable=True
            ),
            "slack.post": SlackAdapter(runtime).post,
            "teams.post": TeamsAdapter(runtime).post,
            "pagerduty.event": PagerDutyAdapter(runtime).event,
            "jira.issue.create": jira.create,
            "jira.issue.comment": jira.comment,
            "grafana.annotation.create": GrafanaAdapter(runtime).annotate,
        }
        if set(self._operations) != set(NATIVE_TOOLS):  # pragma: no cover - construction guard
            raise ValueError("native operation map and NATIVE_TOOLS disagree")

    @property
    def kind(self) -> ToolProviderKind:
        return ToolProviderKind.NATIVE

    def list_tools(self) -> tuple[str, ...]:
        return tuple(sorted(NATIVE_TOOLS))

    def supports(self, descriptor: ToolDescriptor) -> bool:
        registered = NATIVE_TOOLS.get(descriptor.name)
        return registered is not None and registered[0] == descriptor.capability

    def connector_kind_for(self, descriptor: ToolDescriptor) -> IntegrationKind:
        registered = NATIVE_TOOLS.get(descriptor.name)
        if registered is None or registered[0] != descriptor.capability:
            raise IntegrationError(
                f"{descriptor.name} has no native adapter",
                failure_class=IntegrationFailureClass.CONFIGURATION_ERROR,
                effect_not_applied=True,
            )
        return registered[1]

    def health(self) -> ProviderHealth:
        # No network probe: health of each external system is observed per call and
        # recorded with a failure class, not assumed from a background check.
        return ProviderHealth(available=True, detail="native integrations; per-call health")

    def invoke(
        self,
        descriptor: ToolDescriptor,
        arguments: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        expected = self.connector_kind_for(descriptor)
        if context.connector is None or context.connector.kind is not expected:
            raise IntegrationError(
                f"{descriptor.name} reached the native provider without an authorised connector",
                failure_class=IntegrationFailureClass.SCOPE_DENIED,
                effect_not_applied=True,
            )
        return self._operations[descriptor.name](arguments, context)


__all__ = ["NATIVE_TOOLS", "UNIMPLEMENTED_NATIVE_TOOLS", "NativeIntegrationProvider"]
