"""The one permission vocabulary and the system-role matrix (Phase 13, ADR-0030).

Before Phase 13 the same permission strings were spelled independently in the API module,
the approval service, the memory service and the knowledge service. This module is the
single definition: every enforcement site imports its constant from here, and
``tests/security/test_rbac_matrix.py`` asserts the migrated database catalogue and the
seeded system roles equal what is written below, so the vocabulary cannot drift silently.

Three kinds of authority exist and must never be conflated:

* **Human RBAC** - a :class:`PermissionKey` held through a role assignment, reloaded from
  the database on every request. This module.
* **Human approval** - a recorded, action-hash-bound decision by a principal who *currently*
  holds ``remediation.approve``. Approval is not RBAC; it is a separate artefact that
  itself requires RBAC at decision time and again at dispatch.
* **Connector authority** - a ``ConnectorScopeBinding`` naming a connector, source, service
  and environment. It authorises a *machine* to ingest or to be called; it is never held by
  a human and never satisfies a human permission.

Model output is none of these. It can propose; it cannot hold, grant or widen any of them.
"""

from __future__ import annotations

from enum import StrEnum, unique
from types import MappingProxyType
from typing import Final


@unique
class PermissionKey(StrEnum):
    INCIDENT_READ = "incident.read"
    INCIDENT_CONTROL = "incident.control"
    INGESTION_WRITE = "ingestion.write"
    REMEDIATION_APPROVE = "remediation.approve"
    EVALUATION_READ = "evaluation.read"
    ADMINISTRATION_READ = "administration.read"
    AUDIT_READ = "audit.read"
    MEMORY_PROMOTION_DECIDE = "memory.promotion.decide"
    KNOWLEDGE_ACCESS_MANAGE = "knowledge.source.access.manage"
    KNOWLEDGE_LIFECYCLE_MANAGE = "knowledge.source.lifecycle.manage"


@unique
class ScopeRule(StrEnum):
    """Where a grant of the permission is honoured."""

    #: A grant scoped to one environment authorises that environment only; a tenant-wide
    #: grant (no environment) authorises all of them.
    ENVIRONMENT = "environment"
    #: The resource is not environment-owned (tenant configuration, audit stream,
    #: evaluation history). Only a tenant-wide grant satisfies it: an environment-scoped
    #: role must not become a window onto tenant-wide data.
    TENANT_WIDE = "tenant_wide"


#: Permission -> scope rule. Complete: a test asserts every key appears.
SCOPE_RULES: Final = MappingProxyType(
    {
        PermissionKey.INCIDENT_READ: ScopeRule.ENVIRONMENT,
        PermissionKey.INCIDENT_CONTROL: ScopeRule.ENVIRONMENT,
        PermissionKey.INGESTION_WRITE: ScopeRule.ENVIRONMENT,
        PermissionKey.REMEDIATION_APPROVE: ScopeRule.ENVIRONMENT,
        PermissionKey.EVALUATION_READ: ScopeRule.TENANT_WIDE,
        PermissionKey.ADMINISTRATION_READ: ScopeRule.TENANT_WIDE,
        PermissionKey.AUDIT_READ: ScopeRule.TENANT_WIDE,
        PermissionKey.MEMORY_PROMOTION_DECIDE: ScopeRule.TENANT_WIDE,
        PermissionKey.KNOWLEDGE_ACCESS_MANAGE: ScopeRule.TENANT_WIDE,
        PermissionKey.KNOWLEDGE_LIFECYCLE_MANAGE: ScopeRule.TENANT_WIDE,
    }
)

_P = PermissionKey

#: The seven platform-owned system roles and exactly what each grants, as migrated by
#: 0012 (API surface), 0011 (approval) and 0013 (knowledge lifecycle).
#:
#: Two permissions are deliberately held by **no** system role today:
#: ``memory.promotion.decide`` and ``knowledge.source.access.manage``. Authority to govern
#: memory and to change knowledge-source access is not granted by default; a deployment
#: provisions a dedicated role. That is least privilege, and it is recorded here so it is a
#: decision rather than an accident.
SYSTEM_ROLE_GRANTS: Final = MappingProxyType(
    {
        "viewer": frozenset({_P.INCIDENT_READ}),
        "responder": frozenset({_P.INCIDENT_READ, _P.INCIDENT_CONTROL}),
        "sre_approver": frozenset({_P.INCIDENT_READ, _P.INCIDENT_CONTROL, _P.REMEDIATION_APPROVE}),
        "senior_approver": frozenset(
            {_P.INCIDENT_READ, _P.INCIDENT_CONTROL, _P.REMEDIATION_APPROVE}
        ),
        "platform_admin": frozenset(
            {
                _P.INCIDENT_READ,
                _P.INCIDENT_CONTROL,
                _P.REMEDIATION_APPROVE,
                _P.ADMINISTRATION_READ,
                _P.AUDIT_READ,
                _P.KNOWLEDGE_LIFECYCLE_MANAGE,
            }
        ),
        "security_auditor": frozenset({_P.INCIDENT_READ, _P.AUDIT_READ}),
        "system_operator": frozenset({_P.INCIDENT_READ, _P.INGESTION_WRITE, _P.EVALUATION_READ}),
    }
)

#: Permissions no system role holds (see above).
UNASSIGNED_BY_DEFAULT: Final = frozenset({_P.MEMORY_PROMOTION_DECIDE, _P.KNOWLEDGE_ACCESS_MANAGE})

__all__ = [
    "SCOPE_RULES",
    "SYSTEM_ROLE_GRANTS",
    "UNASSIGNED_BY_DEFAULT",
    "PermissionKey",
    "ScopeRule",
]
