"""All mapped classes.

Importing this module populates :data:`asic.db.base.metadata_obj` with every table, which
is what Alembic autogenerate and the schema tests rely on. A model file that is not
imported here is invisible to migrations - so every new module must be added.
"""

from __future__ import annotations

from asic.db.base import Base, metadata_obj
from asic.db.models.api import ApiIdempotencyRecord
from asic.db.models.audit import AuditRecord
from asic.db.models.catalog import ConnectorScopeBinding, Environment, Service, ServiceDependency
from asic.db.models.evaluation import (
    BehaviourVersion,
    EvaluationRun,
    EvaluationScenario,
    ExecutionTrace,
    TraceSpan,
)
from asic.db.models.incident import (
    Alert,
    Incident,
    IncidentEvent,
    ModelCallReservation,
    TimelineEvent,
    WorkflowRun,
)
from asic.db.models.ingestion import (
    IncidentReopenCandidate,
    InvestigationDispatch,
    SignalReceipt,
)
from asic.db.models.investigation import (
    Evidence,
    Hypothesis,
    HypothesisEvidence,
    InvestigationStep,
)
from asic.db.models.knowledge import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIngestion,
    KnowledgeRetrieval,
    KnowledgeRetrievalResult,
    KnowledgeSource,
    MemoryEntry,
    MemoryPromotion,
    MemoryWriteDecision,
    Postmortem,
)
from asic.db.models.orchestration import WorkflowCheckpoint
from asic.db.models.remediation import (
    Approval,
    PolicyDecision,
    RemediationAction,
    RemediationBaseline,
    RemediationTarget,
    Verification,
)
from asic.db.models.tenancy import (
    Permission,
    Role,
    RolePermission,
    Tenant,
    User,
    UserRoleAssignment,
)
from asic.db.models.tools import TenantToolGrant, ToolDefinition, ToolExecution

#: Tables that are deliberately global: no tenant column, no row-level security.
#: ``tenant`` defines the boundary and cannot sit inside it; the rest are platform-owned
#: catalogues that a tenant must not be able to edit, because doing so would let a tenant
#: widen its own authority.
GLOBAL_TABLES: frozenset[str] = frozenset(
    {
        "tenant",
        "role",
        "permission",
        "role_permission",
        "tool_definition",
        "behaviour_version",
        "alembic_version",
    }
)


def tenant_scoped_tables() -> frozenset[str]:
    """Every table carrying a tenant boundary, derived from the mappings themselves.

    The RLS migration and the RLS coverage test both read this, so a new tenant-scoped
    table cannot be added without also being protected.
    """
    return frozenset(
        mapper.class_.__tablename__
        for mapper in Base.registry.mappers
        if getattr(mapper.class_, "__tenant_scoped__", False)
    )


def append_only_tables() -> frozenset[str]:
    """Tables whose rows must never be updated or deleted once written."""
    return frozenset(
        mapper.class_.__tablename__
        for mapper in Base.registry.mappers
        if getattr(mapper.class_, "__append_only__", False)
    )


__all__ = [
    "GLOBAL_TABLES",
    "Alert",
    "ApiIdempotencyRecord",
    "Approval",
    "AuditRecord",
    "Base",
    "BehaviourVersion",
    "ConnectorScopeBinding",
    "Environment",
    "EvaluationRun",
    "EvaluationScenario",
    "Evidence",
    "ExecutionTrace",
    "Hypothesis",
    "HypothesisEvidence",
    "Incident",
    "IncidentEvent",
    "IncidentReopenCandidate",
    "InvestigationDispatch",
    "InvestigationStep",
    "KnowledgeChunk",
    "KnowledgeDocument",
    "KnowledgeIngestion",
    "KnowledgeRetrieval",
    "KnowledgeRetrievalResult",
    "KnowledgeSource",
    "MemoryEntry",
    "MemoryPromotion",
    "MemoryWriteDecision",
    "ModelCallReservation",
    "Permission",
    "PolicyDecision",
    "Postmortem",
    "RemediationAction",
    "RemediationBaseline",
    "RemediationTarget",
    "Role",
    "RolePermission",
    "Service",
    "ServiceDependency",
    "SignalReceipt",
    "Tenant",
    "TenantToolGrant",
    "TimelineEvent",
    "ToolDefinition",
    "ToolExecution",
    "TraceSpan",
    "User",
    "UserRoleAssignment",
    "Verification",
    "WorkflowCheckpoint",
    "WorkflowRun",
    "append_only_tables",
    "metadata_obj",
    "tenant_scoped_tables",
]
