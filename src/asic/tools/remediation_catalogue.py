"""The v1 write capability catalogue (Phase 8).

Everything not declared here is, by definition, not something this system can mutate.
Registered alongside - never merged into - :data:`asic.tools.catalogue.READ_ONLY_CATALOGUE`
(ADR-0023): the investigation kernel's ``ToolRegistry.read_only()`` never sees a row from
here, so its read-only guarantee is unaffected by this module existing at all.

A narrower subset of ``docs/architecture/tool-registry.md`` section 8's table than the full
thirteen tools, and deliberately so. Two categories from that table are not registered here:

* ``notify.collaboration`` and ``write.ticketing`` (Slack/Teams/Jira/PagerDuty). Real
  adapters for these are Phase 10 work, and a *simulated* write to an outbound channel has
  no genuine rollback - you cannot un-send a message - which is exactly the property
  :class:`~asic.tools.descriptor.ToolDescriptor` requires every non-``RO`` tool to declare.
  Registering one with an invented rollback would be dishonest about what "reversible"
  means for this class of action, so it waits for Phase 10's real design of that question.
* ``mutate.k8s_pod`` (``k8s.pod.delete``). Its real-world rollback is "the controller
  recreates it", which is not a tool call this broker invokes and so has no honest value
  for ``rollback_tool_name`` either.

What remains covers both tiers the autonomy matrix distinguishes: ``mutate.k8s_deployment``
and ``mutate.k8s_scale`` (R1, reversible - production requires approval, non-production
does not) and ``mutate.k8s_node`` (R2, high-risk - always requires approval), with a genuine
tool-to-tool rollback pair in both cases.

Every tool here is :attr:`~asic.domain.enums.ToolProviderKind.SIMULATOR`-backed, exactly
like the read catalogue - explicit test infrastructure (master specification section 20),
never presented as a real Kubernetes integration.
"""

from __future__ import annotations

from typing import Final

from asic.domain.enums import RiskTier, ToolProviderKind
from asic.tools.catalogue import NAMESPACE_PATTERN, scope_arguments
from asic.tools.descriptor import ArgumentKind, ArgumentSpec, ResultField, ToolDescriptor

#: The catalogue's own version, recorded alongside ``CATALOGUE_VERSION`` on
#: ``behaviour_version.tool_registry_version`` so a run can be attributed to the exact set
#: of write capabilities that existed when it ran.
REMEDIATION_CATALOGUE_VERSION: Final[str] = "2026.09.14-write-1"

_DEPLOYMENT_NAME_PATTERN: Final[str] = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_NODE_NAME_PATTERN: Final[str] = r"[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?"


def _k8s_scope_arguments() -> tuple[ArgumentSpec, ...]:
    return (
        *scope_arguments(),
        ArgumentSpec(
            name="namespace",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Namespace, resolved from the service's registered ownership.",
            scope_resolved=True,
            pattern=NAMESPACE_PATTERN,
        ),
    )


K8S_DEPLOYMENT_ROLLBACK: Final = ToolDescriptor(
    name="k8s.deployment.rollback",
    version="1.0.0",
    capability="mutate.k8s_deployment",
    description=(
        "Roll a Deployment back to a specific prior revision. The same tool, with the "
        "target revision as its own parameter, is this action's declared rollback: "
        "rolling forward again is rolling back to a different revision, not a different "
        "operation."
    ),
    risk_tier=RiskTier.R1,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_k8s_scope_arguments(),
        ArgumentSpec(
            name="deployment",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Deployment name.",
            pattern=_DEPLOYMENT_NAME_PATTERN,
        ),
        ArgumentSpec(
            name="to_revision",
            kind=ArgumentKind.INTEGER,
            description="Target revision to roll back to.",
            min_value=1,
            max_value=1_000_000,
        ),
    ),
    result_fields=(
        ResultField(name="previous_revision", kind=ArgumentKind.INTEGER),
        ResultField(name="new_revision", kind=ArgumentKind.INTEGER),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    # Below the idle-in-transaction bound (see G9's node contract) - not the 300s
    # tool-registry.md's illustrative example uses, deliberately: this deployment's node
    # holds a DB transaction open for the call, and that transaction must survive it.
    timeout_seconds=150,
    settling_seconds=60,
    is_idempotent=True,
    idempotency_key_fields=("tenant_id", "environment", "namespace", "deployment", "to_revision"),
    max_attempts=1,
    preconditions=(
        "deployment_exists",
        "target_revision_available",
        "no_other_rollout_in_progress",
    ),
    rollback_tool_name="k8s.deployment.rollback",
    audit_events=("tool.executed",),
)

K8S_HPA_ADJUST: Final = ToolDescriptor(
    name="k8s.hpa.adjust",
    version="1.0.0",
    capability="mutate.k8s_scale",
    description=(
        "Adjust a HorizontalPodAutoscaler's min/max replica bounds within the range the "
        "registry has pre-registered for this workload. The same tool restores the prior "
        "bounds and is its own rollback."
    ),
    risk_tier=RiskTier.R1,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_k8s_scope_arguments(),
        ArgumentSpec(
            name="hpa_name",
            kind=ArgumentKind.BOUNDED_STRING,
            description="HorizontalPodAutoscaler name.",
            pattern=_DEPLOYMENT_NAME_PATTERN,
        ),
        ArgumentSpec(
            name="min_replicas",
            kind=ArgumentKind.INTEGER,
            description="New minimum replica count.",
            min_value=1,
            max_value=100,
        ),
        ArgumentSpec(
            name="max_replicas",
            kind=ArgumentKind.INTEGER,
            description="New maximum replica count.",
            min_value=1,
            max_value=100,
        ),
    ),
    result_fields=(
        ResultField(name="previous_min", kind=ArgumentKind.INTEGER),
        ResultField(name="previous_max", kind=ArgumentKind.INTEGER),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=120,
    settling_seconds=120,
    is_idempotent=True,
    idempotency_key_fields=(
        "tenant_id",
        "environment",
        "namespace",
        "hpa_name",
        "min_replicas",
        "max_replicas",
    ),
    max_attempts=1,
    preconditions=("hpa_exists", "bounds_within_registered_maxima"),
    rollback_tool_name="k8s.hpa.adjust",
    audit_events=("tool.executed",),
)

K8S_NODE_CORDON: Final = ToolDescriptor(
    name="k8s.node.cordon",
    version="1.0.0",
    capability="mutate.k8s_node",
    description=(
        "Mark a node unschedulable. Never autonomous (R2): draining or losing a node "
        "affects every workload on it, not only the one under investigation."
    ),
    risk_tier=RiskTier.R2,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        ArgumentSpec(
            name="tenant_id",
            kind=ArgumentKind.UUID,
            description="Owning tenant. Resolved from the bound session, never supplied.",
            scope_resolved=True,
        ),
        ArgumentSpec(
            name="environment",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Environment name resolved from the incident.",
            scope_resolved=True,
            pattern=r"[a-z][a-z0-9_-]{0,31}",
            max_length=32,
        ),
        ArgumentSpec(
            name="node",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Node name.",
            pattern=_NODE_NAME_PATTERN,
        ),
    ),
    result_fields=(
        ResultField(name="was_schedulable", kind=ArgumentKind.BOOLEAN),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=60,
    settling_seconds=10,
    is_idempotent=True,
    idempotency_key_fields=("tenant_id", "environment", "node"),
    max_attempts=1,
    preconditions=("node_exists", "node_not_already_cordoned"),
    rollback_tool_name="k8s.node.uncordon",
    audit_events=("tool.executed",),
)

K8S_NODE_UNCORDON: Final = ToolDescriptor(
    name="k8s.node.uncordon",
    version="1.0.0",
    capability="mutate.k8s_node",
    description="Mark a node schedulable again. The declared rollback of k8s.node.cordon.",
    risk_tier=RiskTier.R2,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=K8S_NODE_CORDON.arguments,
    result_fields=(
        ResultField(name="was_schedulable", kind=ArgumentKind.BOOLEAN),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=60,
    settling_seconds=10,
    is_idempotent=True,
    idempotency_key_fields=("tenant_id", "environment", "node"),
    max_attempts=1,
    preconditions=("node_exists", "node_currently_cordoned"),
    rollback_tool_name="k8s.node.cordon",
    audit_events=("tool.executed",),
)


#: Capabilities whose target is a cluster *node*, not a service's workload (F-08).
#:
#: A node is shared infrastructure: cordoning it affects every workload scheduled there, so it
#: has no service label to check and the service-ownership rule that scopes deployment and HPA
#: mutations is deliberately not applied to it. Its authority model is different and explicit:
#:
#: * environment and tenant come from the immutable remediation target, never from the model;
#: * the node's identity is the ``node`` argument, frozen into the action and covered by the
#:   action-version hash the human approval is bound to - a different node is a different
#:   action that needs a new approval;
#: * risk tier is R2 and policy can never admit it autonomously: dispatch demands a current,
#:   scoped human approval every time (``asic.remediation.authorization``).
NODE_SCOPED_CAPABILITIES: Final[frozenset[str]] = frozenset({"mutate.k8s_node"})

#: The complete write catalogue. Ordered so the seeding migration is deterministic.
WRITE_CATALOGUE: Final[tuple[ToolDescriptor, ...]] = (
    K8S_DEPLOYMENT_ROLLBACK,
    K8S_HPA_ADJUST,
    K8S_NODE_CORDON,
    K8S_NODE_UNCORDON,
)

for _descriptor in WRITE_CATALOGUE:
    if _descriptor.risk_tier is RiskTier.RO:  # pragma: no cover - defensive, see module docstring
        raise ValueError(f"{_descriptor.name} is registered as RO in the write catalogue")

#: Precondition name -> the read capability whose result answers it. The executor resolves
#: each precondition through the broker's own read path (the same credential, the same
#: audit trail), never by trusting the proposal that named it.
PRECONDITION_CAPABILITY: Final[dict[str, str]] = {
    "deployment_exists": "read.k8s_workload",
    "target_revision_available": "read.deploy",
    "no_other_rollout_in_progress": "read.k8s_workload",
    "hpa_exists": "read.k8s_workload",
    "bounds_within_registered_maxima": "read.k8s_workload",
    "node_exists": "read.k8s_workload",
    "node_not_already_cordoned": "read.k8s_workload",
    "node_currently_cordoned": "read.k8s_workload",
}

__all__ = [
    "K8S_DEPLOYMENT_ROLLBACK",
    "K8S_HPA_ADJUST",
    "K8S_NODE_CORDON",
    "K8S_NODE_UNCORDON",
    "NODE_SCOPED_CAPABILITIES",
    "PRECONDITION_CAPABILITY",
    "REMEDIATION_CATALOGUE_VERSION",
    "WRITE_CATALOGUE",
]
