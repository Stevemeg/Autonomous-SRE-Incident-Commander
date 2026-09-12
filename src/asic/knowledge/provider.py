"""``knowledge.search`` served from the governed store, behind the Tool Broker.

ADR-0003 and ADR-0017 put every capability behind one broker, and ``read.knowledge`` is a
registered read-only capability. Knowledge retrieval therefore reaches the investigation
through this provider and through nothing else: there is no second egress path, and a node
still names only a domain, never a tool or a query language.

The broker resolves tenant, environment and service from the incident and runs this
provider on a worker thread under a deadline. The provider therefore never shares the
node's connection - it opens its own **read-only** transaction, binds the tenant the broker
resolved, and establishes the retrieval principal from trusted configuration: the tenant's
grant for ``knowledge.search`` may name access-label clearances under
``scope_overrides["knowledge_acl_clearances"]``. Nothing in a query or a document can add a
clearance.

It returns labels (title and section) as the result's ``documents`` and a
:class:`~asic.knowledge.contracts.RetrievalManifest` of ids and scores. It does not return
chunk text: the receiving node re-verifies the manifest against the database and loads the
text itself, so a revocation between retrieval and use is honoured.

**Registry label.** The ``knowledge.search`` definition seeded in migration ``0005``
still declares ``provider_kind = simulator``. Correcting that label requires changing the
catalogue, and migration ``0005`` derives its rows from the live catalogue module - an
ADR-0018 defect recorded in ADR-0020 and deliberately not fixed in this phase. The broker
selects providers by :meth:`supports`, so behaviour is unaffected; the label is stale.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from asic.db.models import Environment, Service, TenantToolGrant, ToolDefinition
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.enums import RetrievalPrincipalKind, ToolProviderKind
from asic.domain.errors import ToolAdapterError
from asic.knowledge.contracts import (
    LABEL_PATTERN,
    RetrievalPrincipal,
    RetrievalQuery,
    RetrievalScope,
)
from asic.knowledge.errors import EmbeddingFailure, RetrievalRefused
from asic.knowledge.retrieval import KnowledgeRetriever
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ProviderHealth

TOOL_NAME: Final[str] = "knowledge.search"
CAPABILITY: Final[str] = "read.knowledge"
#: Key in a tenant grant's ``scope_overrides`` naming the investigation's clearances.
CLEARANCE_OVERRIDE_KEY: Final[str] = "knowledge_acl_clearances"
SOURCE_LABEL: Final[str] = "asic-knowledge-store"

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


class KnowledgeStoreProvider:
    """Serves ``knowledge.search`` from PostgreSQL. Read-only by construction."""

    __slots__ = ("_factory", "_retriever")

    def __init__(
        self, session_factory: Callable[[], Session], retriever: KnowledgeRetriever
    ) -> None:
        self._factory = session_factory
        self._retriever = retriever

    @property
    def kind(self) -> ToolProviderKind:
        return ToolProviderKind.NATIVE

    def list_tools(self) -> tuple[str, ...]:
        return (TOOL_NAME,)

    def supports(self, descriptor: ToolDescriptor) -> bool:
        return descriptor.name == TOOL_NAME and descriptor.capability == CAPABILITY

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=True)

    def invoke(
        self,
        descriptor: ToolDescriptor,
        arguments: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        if not self.supports(descriptor):
            raise ToolAdapterError(f"{descriptor.name} is not served by this provider")
        tenant_id = arguments.get("tenant_id")
        if tenant_id != context.tenant_id:
            # The broker resolves both from the same bound scope. A difference is a
            # programming error, and serving either tenant would be wrong.
            raise ToolAdapterError("tenant scope mismatch", transient=False)
        try:
            with self._factory() as session, session.begin():
                session.execute(sa.text("SET TRANSACTION READ ONLY"))
                bind_tenant(session, context.tenant_id)
                apply_statement_timeouts(session)
                environment_id = session.scalar(
                    sa.select(Environment.id).where(
                        Environment.tenant_id == context.tenant_id,
                        Environment.name == arguments["environment"],
                    )
                )
                service_id = session.scalar(
                    sa.select(Service.id).where(
                        Service.tenant_id == context.tenant_id,
                        Service.name == arguments["service"],
                    )
                )
                if environment_id is None or service_id is None:
                    raise RetrievalRefused("unknown_scope")
                principal = investigation_principal(
                    session,
                    tenant_id=context.tenant_id,
                    environment_id=environment_id,
                    principal_id=f"investigation:{context.correlation_id}",
                )
                result_set = self._retriever.retrieve(
                    session,
                    principal=principal,
                    scope=RetrievalScope(environment_id=environment_id, service_ids=(service_id,)),
                    query=RetrievalQuery(
                        text=str(arguments["topic"]), limit=int(arguments.get("limit", 5))
                    ),
                )
        except RetrievalRefused as exc:
            raise ToolAdapterError(f"knowledge retrieval refused: {exc.code}") from exc
        except EmbeddingFailure as exc:
            raise ToolAdapterError(
                f"knowledge query embedding failed: {exc.code}", transient=exc.transient
            ) from exc
        except SQLAlchemyError as exc:
            raise ToolAdapterError("knowledge store unavailable", transient=True) from exc

        return {
            "documents": [result.label() for result in result_set.results],
            "source": SOURCE_LABEL,
            "schema_version": 1,
            "retrieval": result_set.to_manifest(
                idempotency_key=context.idempotency_key, correlation_id=context.correlation_id
            ),
        }


__all__ = [
    "CAPABILITY",
    "CLEARANCE_OVERRIDE_KEY",
    "SOURCE_LABEL",
    "TOOL_NAME",
    "KnowledgeStoreProvider",
    "investigation_principal",
]
