"""The one place that decides whether a principal may see a piece of knowledge content.

**Persistence does not establish authority. Embedding does not establish authority.
Similarity does not establish authority. Provider output does not establish authority.**
Only this module's checks do, and they run against the *current* state of
:class:`~asic.db.models.knowledge.KnowledgeSource` and
:class:`~asic.db.models.knowledge.KnowledgeDocument` - never against what a manifest, a
citation token or a replay request claims.

:func:`current_access` is deliberately the single implementation shared by three call
sites that must agree or the trust boundary has a seam: manifest verification (P6-02,
:mod:`asic.orchestration.knowledge_context`), citation resolution and content replay
(P6-03, :mod:`asic.knowledge.citations` and :mod:`asic.knowledge.retrieval`). Each call
site re-derives the principal and scope from *its own* trusted context at the moment of
the check - a principal or scope computed once and threaded through stale is exactly the
"historical authorization overrides current authorization" defect P6-03 exists to close.

:func:`investigation_principal` is the only place an automated investigation's clearances
come from: the tenant's grant for ``knowledge.search``, read at the moment of the check -
never from a query, a document, or anything a provider asserts.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import KnowledgeDocument, KnowledgeSource, TenantToolGrant, ToolDefinition
from asic.domain.enums import KnowledgeSourceStatus, KnowledgeVersionState, RetrievalPrincipalKind
from asic.knowledge.contracts import LABEL_PATTERN, RetrievalPrincipal, RetrievalScope
from asic.knowledge.errors import RetrievalRefused

TOOL_NAME: Final[str] = "knowledge.search"
CAPABILITY: Final[str] = "read.knowledge"
#: Key in a tenant grant's ``scope_overrides`` naming the investigation's clearances.
CLEARANCE_OVERRIDE_KEY: Final[str] = "knowledge_acl_clearances"

_LABEL = re.compile(LABEL_PATTERN)


def investigation_principal(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    principal_id: str,
) -> RetrievalPrincipal:
    """The principal an investigation retrieves as, from the tenant's grant.

    The environment-specific grant wins over a tenant-wide one. Malformed clearance
    configuration fails closed rather than being interpreted.
    """
    rows = session.execute(
        sa.select(TenantToolGrant.environment_id, TenantToolGrant.scope_overrides)
        .join(ToolDefinition, ToolDefinition.id == TenantToolGrant.tool_definition_id)
        .where(
            TenantToolGrant.tenant_id == tenant_id,
            TenantToolGrant.is_enabled.is_(True),
            ToolDefinition.name == TOOL_NAME,
            ToolDefinition.capability == CAPABILITY,
            ToolDefinition.is_enabled.is_(True),
            sa.or_(
                TenantToolGrant.environment_id == environment_id,
                TenantToolGrant.environment_id.is_(None),
            ),
        )
    ).all()
    chosen = sorted(rows, key=lambda row: row[0] is None)
    overrides: Mapping[str, Any] = dict(chosen[0][1] or {}) if chosen else {}
    raw = overrides.get(CLEARANCE_OVERRIDE_KEY, [])
    if not isinstance(raw, list) or len(raw) > 32:
        raise RetrievalRefused("invalid_clearance_configuration")
    if not all(isinstance(label, str) and _LABEL.match(label) for label in raw):
        raise RetrievalRefused("invalid_clearance_configuration")
    return RetrievalPrincipal(
        tenant_id=tenant_id,
        kind=RetrievalPrincipalKind.INVESTIGATION,
        principal_id=principal_id,
        clearances=frozenset(raw),
    )


def current_access(
    *,
    source: KnowledgeSource,
    document: KnowledgeDocument | None,
    principal: RetrievalPrincipal,
    scope: RetrievalScope,
) -> str | None:
    """``None`` if ``principal`` may currently see content from ``source``/``document``.

    Otherwise, a safe reason code - never derived from document text. Checked against the
    row as it stands *right now*, regardless of what any historical retrieval, citation or
    manifest recorded. Mirrors the ``authorized`` predicate in
    :data:`asic.knowledge.retrieval._RETRIEVAL_SQL`, plus the lifecycle gates
    :func:`asic.knowledge.citations.resolve_citation` has always applied - one
    implementation instead of three that could quietly drift apart.
    """
    if source.status is not KnowledgeSourceStatus.ACTIVE:
        return f"source_{source.status.value}"
    if document is not None and document.lifecycle is KnowledgeVersionState.REVOKED:
        return "version_revoked"
    if source.acl_labels and not (set(source.acl_labels) & set(principal.clearances)):
        return "acl_denied"
    if source.service_ids and not (set(source.service_ids) & set(scope.service_ids)):
        return "service_out_of_scope"
    if source.environment_ids and scope.environment_id not in set(source.environment_ids):
        return "environment_out_of_scope"
    if scope.document_types and source.document_type not in scope.document_types:
        return "document_type_out_of_scope"
    return None


__all__ = [
    "CAPABILITY",
    "CLEARANCE_OVERRIDE_KEY",
    "TOOL_NAME",
    "current_access",
    "investigation_principal",
]
