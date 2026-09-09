"""The v1 read-only capability catalogue.

Everything not declared here is, by definition, not something this system can do. The
catalogue lives in code so that it is reviewed like code and versioned in Git
(``docs/architecture/tool-registry.md`` section 3.2), and is seeded into the global
``tool_definition`` table by a migration so that a tenant cannot edit it.

Two properties are worth noticing while reading:

**Every query is built from typed parameters.** There is no PromQL argument, no LogQL
argument and no label-selector argument. ``metrics.query`` takes a metric from an
enumeration, an aggregation from an enumeration, and a window; the adapter composes the
query. That is more work than accepting a query string, and it is the reason a caller
cannot ask for a series belonging to a service it has no business reading.

**Scope arguments carry no default.** ``tenant_id``, ``environment`` and ``service`` are
marked ``scope_resolved``, so they are filled by the broker from the incident and a caller
supplying one is rejected. This is the mechanism behind "the model cannot widen its own
reach".

The write tiers named in ``docs/architecture/tool-registry.md`` section 8 - deployment
rollback, HPA adjustment, pod deletion, node cordon, notification and ticketing - are
deliberately **absent**. They belong to remediation, which this phase does not implement,
and a capability that is absent cannot be misused.
"""

from __future__ import annotations

from typing import Final

from asic.domain.enums import EvidenceDomain, RiskTier, ToolProviderKind
from asic.tools.descriptor import (
    ArgumentKind,
    ArgumentSpec,
    ResultField,
    ToolDescriptor,
    assert_no_write_capability,
)

#: The catalogue's own version, recorded on ``behaviour_version.tool_registry_version`` so
#: a run can be attributed to the exact set of capabilities that existed when it ran.
CATALOGUE_VERSION: Final[str] = "2026.09.07-ro-1"

_SERVICE_NAME_PATTERN: Final[str] = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_NAMESPACE_PATTERN: Final[str] = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"


def _scope_arguments() -> tuple[ArgumentSpec, ...]:
    """The scope every read tool receives from the broker and never from a caller."""
    return (
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
            name="service",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Service resolved from the incident's affected services.",
            scope_resolved=True,
            pattern=_SERVICE_NAME_PATTERN,
        ),
    )


def _window_arguments() -> tuple[ArgumentSpec, ...]:
    return (
        ArgumentSpec(
            name="window_start",
            kind=ArgumentKind.TIMESTAMP,
            description="Inclusive start of the observation window (timezone-aware).",
        ),
        ArgumentSpec(
            name="window_end",
            kind=ArgumentKind.TIMESTAMP,
            description="Exclusive end of the observation window (timezone-aware).",
        ),
    )


METRICS_QUERY: Final = ToolDescriptor(
    name="metrics.query",
    version="1.0.0",
    capability="read.metrics",
    description=(
        "Read one registered metric series for one service over a window. The query is "
        "composed by the adapter from these typed parameters; no query language is "
        "accepted as input."
    ),
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_scope_arguments(),
        *_window_arguments(),
        ArgumentSpec(
            name="metric",
            kind=ArgumentKind.ENUM,
            description="Registered metric name.",
            allowed_values=(
                "http_request_duration_p95_seconds",
                "http_request_duration_p50_seconds",
                "http_requests_total",
                "http_request_errors_total",
                "container_memory_working_set_bytes",
                "container_cpu_usage_seconds_total",
            ),
        ),
        ArgumentSpec(
            name="step_seconds",
            kind=ArgumentKind.DURATION_SECONDS,
            description="Resolution of the returned series.",
            required=False,
            min_value=15,
            max_value=3600,
        ),
    ),
    result_fields=(
        ResultField(name="samples", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="unit", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=30,
    idempotency_key_fields=("tenant_id", "environment", "service", "metric", "window_start"),
    max_attempts=3,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
    max_result_items=500,
)

LOGS_QUERY: Final = ToolDescriptor(
    name="logs.query",
    version="1.0.0",
    capability="read.logs",
    description=(
        "Read log lines for one service over a window, filtered by level and an optional "
        "bounded substring. Returns untrusted content: the caller labels it accordingly."
    ),
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_scope_arguments(),
        *_window_arguments(),
        ArgumentSpec(
            name="min_level",
            kind=ArgumentKind.ENUM,
            description="Lowest severity to return.",
            allowed_values=("debug", "info", "warn", "error", "fatal"),
            required=False,
        ),
        ArgumentSpec(
            name="contains",
            kind=ArgumentKind.BOUNDED_STRING,
            description=(
                "Literal substring filter. Bounded and treated as a literal by the "
                "adapter, never as a query expression."
            ),
            required=False,
            max_length=120,
        ),
        ArgumentSpec(
            name="limit",
            kind=ArgumentKind.INTEGER,
            description="Maximum lines returned.",
            required=False,
            min_value=1,
            max_value=200,
        ),
    ),
    result_fields=(
        ResultField(name="lines", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="truncated", kind=ArgumentKind.BOOLEAN),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=30,
    idempotency_key_fields=("tenant_id", "environment", "service", "window_start", "min_level"),
    max_attempts=3,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
)

TRACES_QUERY: Final = ToolDescriptor(
    name="traces.query",
    version="1.0.0",
    capability="read.traces",
    description="Read aggregated span statistics for one service's operations over a window.",
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_scope_arguments(),
        *_window_arguments(),
        ArgumentSpec(
            name="min_duration_ms",
            kind=ArgumentKind.INTEGER,
            description="Only spans at least this slow.",
            required=False,
            min_value=0,
            max_value=600_000,
        ),
    ),
    result_fields=(
        ResultField(name="operations", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=30,
    idempotency_key_fields=("tenant_id", "environment", "service", "window_start"),
    max_attempts=3,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
)

DEPLOY_LIST: Final = ToolDescriptor(
    name="deploy.list",
    version="1.0.0",
    capability="read.deploy",
    description="List deployments and configuration changes for one service over a window.",
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(*_scope_arguments(), *_window_arguments()),
    result_fields=(
        ResultField(name="deployments", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=20,
    idempotency_key_fields=("tenant_id", "environment", "service", "window_start"),
    max_attempts=3,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
)

K8S_WORKLOAD_READ: Final = ToolDescriptor(
    name="k8s.workload.read",
    version="1.0.0",
    capability="read.k8s_workload",
    description=(
        "Read workload state and recent events for one service. Read-only: the credential "
        "the broker resolves for this tool is physically incapable of mutation (SI-4)."
    ),
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_scope_arguments(),
        ArgumentSpec(
            name="namespace",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Namespace, resolved from the service's registered ownership.",
            scope_resolved=True,
            pattern=_NAMESPACE_PATTERN,
        ),
        ArgumentSpec(
            name="include_events",
            kind=ArgumentKind.BOOLEAN,
            description="Include recent namespace events alongside workload status.",
            required=False,
        ),
    ),
    result_fields=(
        ResultField(name="workloads", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="events", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=30,
    idempotency_key_fields=("tenant_id", "environment", "service", "namespace"),
    max_attempts=3,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
)

KNOWLEDGE_SEARCH: Final = ToolDescriptor(
    name="knowledge.search",
    version="1.0.0",
    capability="read.knowledge",
    description=(
        "Search operational knowledge - runbooks, service docs, known errors - scoped to "
        "the tenant. Results are RETRIEVED provenance and never confer authority."
    ),
    risk_tier=RiskTier.RO,
    provider_kind=ToolProviderKind.SIMULATOR,
    arguments=(
        *_scope_arguments(),
        ArgumentSpec(
            name="topic",
            kind=ArgumentKind.BOUNDED_STRING,
            description="Bounded topic phrase used for retrieval.",
            max_length=200,
        ),
        ArgumentSpec(
            name="limit",
            kind=ArgumentKind.INTEGER,
            description="Maximum documents returned.",
            required=False,
            min_value=1,
            max_value=20,
        ),
    ),
    result_fields=(
        ResultField(name="documents", kind=ArgumentKind.STRING_LIST, required=False),
        ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),
        ResultField(name="schema_version", kind=ArgumentKind.INTEGER),
    ),
    timeout_seconds=20,
    idempotency_key_fields=("tenant_id", "environment", "service", "topic"),
    max_attempts=2,
    retry_backoff_seconds=1.0,
    audit_events=("tool.executed",),
)


#: The complete read-only catalogue. Ordered so the seeding migration is deterministic.
READ_ONLY_CATALOGUE: Final[tuple[ToolDescriptor, ...]] = (
    DEPLOY_LIST,
    K8S_WORKLOAD_READ,
    KNOWLEDGE_SEARCH,
    LOGS_QUERY,
    METRICS_QUERY,
    TRACES_QUERY,
)

assert_no_write_capability(READ_ONLY_CATALOGUE)


#: Which capability answers questions in which evidence domain. The planner selects a
#: *domain*; this mapping turns that into a capability, and the registry turns the
#: capability into a tool. The planner therefore never names a tool, which is what keeps
#: the catalogue's shape out of the model's reach.
DOMAIN_CAPABILITY: Final[dict[EvidenceDomain, str]] = {
    EvidenceDomain.METRICS: "read.metrics",
    EvidenceDomain.LOGS: "read.logs",
    EvidenceDomain.TRACES: "read.traces",
    EvidenceDomain.DEPLOYMENTS: "read.deploy",
    EvidenceDomain.KUBERNETES_STATE: "read.k8s_workload",
    EvidenceDomain.KNOWLEDGE: "read.knowledge",
}

#: Domains whose content originates in a document store rather than a telemetry system,
#: and which are therefore RETRIEVED rather than VERIFIED_FACT.
RETRIEVED_DOMAINS: Final[frozenset[EvidenceDomain]] = frozenset({EvidenceDomain.KNOWLEDGE})


def capability_for_domain(domain: EvidenceDomain) -> str:
    return DOMAIN_CAPABILITY[domain]


__all__ = [
    "CATALOGUE_VERSION",
    "DOMAIN_CAPABILITY",
    "READ_ONLY_CATALOGUE",
    "RETRIEVED_DOMAINS",
    "capability_for_domain",
]
