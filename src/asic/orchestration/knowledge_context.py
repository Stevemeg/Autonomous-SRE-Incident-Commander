"""Knowledge evidence inside the investigation: verification, recording and rendering.

Three responsibilities, each a boundary:

* :func:`validate_manifest` - a provider's retrieval manifest is **untrusted input, and
  providing one at all is mandatory** (P6-02): a knowledge result with no manifest is
  refused, never treated as an empty-but-valid answer. Every claim in it is re-checked
  against the database and against independently-recomputed trusted facts before anything
  is recorded - never accepted merely because the manifest is internally consistent:

  - identity: tenant, correlation id and idempotency key must match this call's own
    :class:`~asic.db.models.tools.ToolExecution` row, and the retrieval id must not already
    belong to a recorded retrieval (this or any other tenant's - reuse is refused).
  - principal and policy: the manifest's claimed principal and policy version are compared
    against values *this function recomputes itself* from trusted configuration
    (:func:`asic.knowledge.authorization.investigation_principal`) and the deployed
    retrieval policy - never taken from the provider on trust.
  - the query: the digest is recomputed from the query text the orchestration layer itself
    sent, not from the manifest's copy of it.
  - every result: the chunk must exist, belong to the named version and source, still carry
    the content hash the manifest claims, **and currently be authorized** for the
    recomputed principal and scope (:func:`asic.knowledge.authorization.current_access`) -
    a provider cannot smuggle in content that is real but not authorized.

  A manifest that fails any check is refused and the domain degrades; nothing from it is
  recorded. What a provider is *not* independently re-verified for is which authorized,
  unmodified chunks it chose to report and in what order - that would require re-running
  the governed retrieval a second time, which adds no additional trust guarantee over the
  checks above, only cost. That is a retrieval-quality bound (see ADR-0008, ADR-0021), not
  an authorization one: nothing unauthorized, unmodified, or misattributed can pass.
* :func:`record_manifest` - the verified retrieval is recorded append-only, linked to the
  tool execution and the evidence row, in the node's own transaction, using the
  independently recomputed principal and scope rather than the manifest's copies of them.
* :func:`knowledge_evidence_blocks` - retrieved content enters a model prompt only here,
  only as fenced :class:`~asic.domain.untrusted.UntrustedBlock` data labelled
  ``RETRIEVED``, bounded in count and size, and **withheld if access was withdrawn** after
  the retrieval - re-checked against the *current* principal and scope, not the historical
  ones the retrieval recorded (P6-03: historical traceability is not historical
  authorization). The block's source label is the citation token, taken from the database
  row - never from document text.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.contracts.state import EvidenceRef
from asic.db.models import (
    Evidence,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeRetrieval,
    KnowledgeRetrievalResult,
    KnowledgeSource,
    ToolExecution,
)
from asic.domain.enums import EvidenceDomain, ProvenanceLabel
from asic.domain.errors import DomainError
from asic.domain.untrusted import UntrustedBlock, scan
from asic.knowledge.authorization import current_access, investigation_principal
from asic.knowledge.contracts import (
    MAX_RESULT_CONTENT_CHARS,
    KnowledgeCitation,
    RetrievalManifest,
    RetrievalPrincipal,
    RetrievalScope,
)
from asic.knowledge.retrieval import DEFAULT_POLICY_IDENTIFIER, current_content
from asic.tools.broker import ToolResult

#: At most this many knowledge blocks in one prompt, across all knowledge evidence.
MAX_KNOWLEDGE_BLOCKS: Final[int] = 10


class KnowledgeManifestInvalid(DomainError):
    """A provider manifest did not survive verification. Carries a safe code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class VerifiedRetrieval:
    retrieval_id: uuid.UUID
    manifest: RetrievalManifest | None
    citations: tuple[str, ...]
    injection_flags: tuple[str, ...]
    #: True when the broker replayed a recorded call and the retrieval already exists.
    replayed: bool
    #: The trusted principal/scope this retrieval was verified against - recomputed, never
    #: the manifest's own claim. ``None`` for a replay, which persists nothing new.
    principal: RetrievalPrincipal | None = None
    scope: RetrievalScope | None = None


def recompute_investigation_context(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    environment_id: uuid.UUID,
    service_ids: Sequence[uuid.UUID],
    correlation_id: uuid.UUID,
) -> tuple[RetrievalPrincipal, RetrievalScope]:
    """The investigation's trusted principal and scope, derived fresh from configuration.

    Never compute this once and thread the result through a later check: call it again at
    the moment authorization must actually be evaluated - manifest verification, citation
    resolution, or prompt rendering - each of which may happen at a different time, in a
    different node execution, possibly after a resume. Caching it across that gap is
    exactly the "historical authorization overrides current authorization" defect P6-03
    exists to close.
    """
    principal = investigation_principal(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        principal_id=f"investigation:{correlation_id}",
    )
    scope = RetrievalScope(environment_id=environment_id, service_ids=tuple(service_ids))
    return principal, scope


def validate_manifest(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    correlation_id: uuid.UUID,
    principal: RetrievalPrincipal,
    scope: RetrievalScope,
    query_text: str,
    result: ToolResult,
) -> VerifiedRetrieval | None:
    """Verify a knowledge result. A manifest is mandatory; there is no valid empty case.

    ``None`` only for the narrow replay edge case where the broker reports a deduplicated
    call but no retrieval was ever recorded against it (inconsistent historical state, not
    a security failure) - see :func:`_replayed`.

    ``principal`` and ``scope`` are the caller's own trusted recomputation of who is
    asking and within what bounds - typically
    :func:`asic.knowledge.authorization.investigation_principal` plus the incident's
    resolved scope - never anything read from ``result``. ``query_text`` is the exact text
    the orchestration layer sent as the query, so the manifest's digest can be checked
    against it rather than against itself.

    Raises:
        KnowledgeManifestInvalid: no manifest was returned, or it is malformed, disagrees
            with the database, or disagrees with the recomputed trusted facts.
    """
    if result.deduplicated:
        return _replayed(session, tenant_id, result)
    raw = result.payload.get("retrieval")
    if raw is None:
        # A knowledge result with no manifest establishes nothing: fail closed rather than
        # silently treating an unverifiable answer as if it were an empty, valid one.
        raise KnowledgeManifestInvalid("manifest_missing")
    try:
        manifest = RetrievalManifest.model_validate(raw)
    except ValidationError as exc:
        raise KnowledgeManifestInvalid("manifest_malformed") from exc

    if manifest.tenant_id != tenant_id:
        raise KnowledgeManifestInvalid("manifest_tenant_mismatch")
    if manifest.correlation_id != correlation_id:
        raise KnowledgeManifestInvalid("manifest_correlation_mismatch")
    execution_key = session.scalar(
        sa.select(ToolExecution.idempotency_key).where(
            ToolExecution.tenant_id == tenant_id, ToolExecution.id == result.tool_execution_id
        )
    )
    if execution_key is None or execution_key != manifest.idempotency_key:
        raise KnowledgeManifestInvalid("manifest_not_from_this_call")

    # Identity and policy: recomputed from trusted state, never taken from the manifest on
    # trust. A provider that claims a different principal, clearance set or policy version
    # than what the tenant's own grant and the deployed retrieval policy establish is
    # refused here, before any of its results are even looked at.
    if (
        manifest.principal_kind is not principal.kind
        or manifest.principal_id != principal.principal_id
        or set(manifest.clearances) != set(principal.clearances)
    ):
        raise KnowledgeManifestInvalid("manifest_principal_mismatch")
    if manifest.policy_version != DEFAULT_POLICY_IDENTIFIER:
        raise KnowledgeManifestInvalid("manifest_policy_mismatch")
    expected_digest = hashlib.sha256(query_text.encode("utf-8")).hexdigest()
    if manifest.query_digest != expected_digest:
        raise KnowledgeManifestInvalid("manifest_query_digest_mismatch")

    # Retrieval identity must be fresh: reusing an id already recorded - this tenant's or
    # (structurally, via the global primary key) any other's - is refused rather than
    # silently accepted as a second, different retrieval wearing the same name.
    if (
        session.scalar(
            sa.select(KnowledgeRetrieval.id).where(
                KnowledgeRetrieval.tenant_id == tenant_id,
                KnowledgeRetrieval.id == manifest.retrieval_id,
            )
        )
        is not None
    ):
        raise KnowledgeManifestInvalid("manifest_retrieval_id_reused")

    if [r.rank for r in manifest.results] != list(range(1, len(manifest.results) + 1)):
        raise KnowledgeManifestInvalid("manifest_ranks_not_contiguous")
    if len({r.chunk_id for r in manifest.results}) != len(manifest.results):
        raise KnowledgeManifestInvalid("manifest_duplicate_chunk")
    documents = result.payload.get("documents") or []
    if not isinstance(documents, list) or len(documents) != len(manifest.results):
        raise KnowledgeManifestInvalid("manifest_document_count_mismatch")

    stored = {
        chunk.id: (chunk, document, source)
        for chunk, document, source in session.execute(
            sa.select(KnowledgeChunk, KnowledgeDocument, KnowledgeSource)
            .join(
                KnowledgeDocument,
                sa.and_(
                    KnowledgeDocument.tenant_id == KnowledgeChunk.tenant_id,
                    KnowledgeDocument.id == KnowledgeChunk.document_id,
                ),
            )
            .join(
                KnowledgeSource,
                sa.and_(
                    KnowledgeSource.tenant_id == KnowledgeDocument.tenant_id,
                    KnowledgeSource.id == KnowledgeDocument.source_id,
                ),
            )
            .where(
                KnowledgeChunk.tenant_id == tenant_id,
                KnowledgeChunk.id.in_([r.chunk_id for r in manifest.results]),
            )
        ).all()
    }
    flags: set[str] = set()
    for item in manifest.results:
        found = stored.get(item.chunk_id)
        if found is None:
            raise KnowledgeManifestInvalid("manifest_unknown_chunk")
        chunk, document, source = found
        if chunk.document_id != item.document_version_id or source.id != item.source_id:
            raise KnowledgeManifestInvalid("manifest_version_mismatch")
        if chunk.content_hash != item.content_hash:
            raise KnowledgeManifestInvalid("manifest_content_mismatch")
        if current_access(source=source, document=document, principal=principal, scope=scope):
            # Real chunk, correct hash - but not within what the recomputed trusted
            # principal and scope currently authorize. A provider cannot make unauthorized
            # content authorized merely by naming it in a manifest.
            raise KnowledgeManifestInvalid("manifest_unauthorized_result")
        flags.update(scan(chunk.text))
    return VerifiedRetrieval(
        retrieval_id=manifest.retrieval_id,
        manifest=manifest,
        citations=tuple(
            KnowledgeCitation(manifest.retrieval_id, r.chunk_id, r.document_version_id).token
            for r in manifest.results
        ),
        injection_flags=tuple(sorted(flags)),
        replayed=False,
        principal=principal,
        scope=scope,
    )


def _replayed(
    session: Session, tenant_id: uuid.UUID, result: ToolResult
) -> VerifiedRetrieval | None:
    retrieval = session.scalars(
        sa.select(KnowledgeRetrieval).where(
            KnowledgeRetrieval.tenant_id == tenant_id,
            KnowledgeRetrieval.tool_execution_id == result.tool_execution_id,
        )
    ).first()
    if retrieval is None:
        return None
    rows = session.execute(
        sa.select(KnowledgeRetrievalResult.chunk_id, KnowledgeRetrievalResult.document_version_id)
        .where(
            KnowledgeRetrievalResult.tenant_id == tenant_id,
            KnowledgeRetrievalResult.retrieval_id == retrieval.id,
        )
        .order_by(KnowledgeRetrievalResult.rank)
    ).all()
    return VerifiedRetrieval(
        retrieval_id=retrieval.id,
        manifest=None,
        citations=tuple(KnowledgeCitation(retrieval.id, c, v).token for c, v in rows),
        injection_flags=(),
        replayed=True,
    )


def _scope_dict(scope: RetrievalScope) -> dict[str, object]:
    return {
        "environment_id": str(scope.environment_id),
        "service_ids": sorted(str(s) for s in scope.service_ids),
        "document_types": sorted(t.value for t in scope.document_types),
    }


def record_manifest(
    session: Session,
    verified: VerifiedRetrieval,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    workflow_run_id: uuid.UUID,
    tool_execution_id: uuid.UUID | None,
    evidence_id: uuid.UUID,
) -> None:
    """Record a verified retrieval. A broker replay was recorded the first time.

    Identity fields (principal, clearances) come from ``verified.principal`` - the caller's
    recomputed trusted value - never from the manifest, even though
    :func:`validate_manifest` already checked the two agree: this is what makes that check
    load-bearing rather than decorative.

    Raises:
        KnowledgeManifestInvalid: ``manifest_retrieval_id_reused`` if the retrieval id
            collides with one recorded under another tenant - structurally impossible to
            see coming via a tenant-scoped pre-check, so the resulting primary-key conflict
            is caught here and translated rather than left as a raw database error.
    """
    manifest = verified.manifest
    if manifest is None or verified.replayed:
        return
    assert verified.principal is not None and verified.scope is not None  # set by validate_manifest
    try:
        with session.begin_nested():
            session.add(
                KnowledgeRetrieval(
                    id=manifest.retrieval_id,
                    tenant_id=tenant_id,
                    principal_kind=verified.principal.kind,
                    principal_id=verified.principal.principal_id,
                    clearances=sorted(verified.principal.clearances),
                    incident_id=incident_id,
                    workflow_run_id=workflow_run_id,
                    tool_execution_id=tool_execution_id,
                    evidence_id=evidence_id,
                    correlation_id=manifest.correlation_id,
                    idempotency_key=manifest.idempotency_key,
                    policy_version=manifest.policy_version,
                    embedding_model_id=manifest.embedding_model_id,
                    embedding_dimensions=manifest.embedding_dimensions,
                    query_text=manifest.query_text,
                    query_digest=manifest.query_digest,
                    scope=_scope_dict(verified.scope),
                    as_of=manifest.as_of,
                    include_stale=manifest.include_stale,
                    eligible_chunks=manifest.eligible_chunks,
                    lexical_matches=manifest.lexical_matches,
                    vector_candidates=manifest.vector_candidates,
                    excluded=dict(manifest.excluded),
                    result_count=len(manifest.results),
                    latency_ms=manifest.latency_ms,
                )
            )
            session.flush()
            session.add_all(
                KnowledgeRetrievalResult(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    retrieval_id=manifest.retrieval_id,
                    rank=item.rank,
                    chunk_id=item.chunk_id,
                    document_version_id=item.document_version_id,
                    source_id=item.source_id,
                    lexical_rank=item.lexical_rank,
                    lexical_score=item.lexical_score,
                    vector_rank=item.vector_rank,
                    vector_similarity=item.vector_similarity,
                    fused_score=item.fused_score,
                    stale=item.stale,
                    content_hash=item.content_hash,
                )
                for item in manifest.results
            )
            session.flush()
    except IntegrityError as exc:
        # The tenant-scoped pre-check in validate_manifest cannot see a retrieval id
        # belonging to another tenant (row-level security hides it); the global primary
        # key still refuses the collision. Translate rather than let a raw database error
        # about a security-relevant refusal escape as an unhandled exception.
        raise KnowledgeManifestInvalid("manifest_retrieval_id_reused") from exc


def knowledge_evidence_blocks(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    evidence: Sequence[EvidenceRef],
    principal: RetrievalPrincipal,
    scope: RetrievalScope,
    max_blocks: int = MAX_KNOWLEDGE_BLOCKS,
) -> tuple[UntrustedBlock, ...]:
    """Retrieved chunks for the knowledge evidence in ``evidence``, as untrusted data.

    ``principal`` and ``scope`` must be the caller's current trusted context - the same
    recomputation :func:`validate_manifest` uses, not anything carried over from when the
    evidence was originally gathered - so a prompt built after an authorization change never
    receives content that change would now refuse (P6-03).
    """
    evidence_ids = [
        uuid.UUID(ref.evidence_id) for ref in evidence if ref.domain is EvidenceDomain.KNOWLEDGE
    ]
    if not evidence_ids:
        return ()
    retrieval_ids: list[uuid.UUID] = []
    for citation in session.scalars(
        sa.select(Evidence.citation)
        .where(Evidence.tenant_id == tenant_id, Evidence.id.in_(evidence_ids))
        .order_by(Evidence.gathered_at, Evidence.id)
    ):
        value = (citation or {}).get("retrieval_id")
        if isinstance(value, str):
            try:
                retrieval_ids.append(uuid.UUID(value))
            except ValueError:
                continue
    if not retrieval_ids:
        return ()
    rows = session.execute(
        sa.select(
            KnowledgeRetrievalResult.retrieval_id,
            KnowledgeRetrievalResult.chunk_id,
            KnowledgeRetrievalResult.document_version_id,
        )
        .where(
            KnowledgeRetrievalResult.tenant_id == tenant_id,
            KnowledgeRetrievalResult.retrieval_id.in_(retrieval_ids),
        )
        .order_by(KnowledgeRetrievalResult.retrieval_id, KnowledgeRetrievalResult.rank)
    ).all()
    order = {rid: position for position, rid in enumerate(retrieval_ids)}
    citations = [
        KnowledgeCitation(retrieval_id, chunk_id, version_id)
        for retrieval_id, chunk_id, version_id in sorted(rows, key=lambda r: order.get(r[0], 0))
    ][:max_blocks]
    content = current_content(session, citations, principal=principal, scope=scope)
    return tuple(
        UntrustedBlock(
            source=citation.token,
            provenance=ProvenanceLabel.RETRIEVED,
            content=(content[citation.chunk_id] or "[content withheld: access withdrawn]")[
                :MAX_RESULT_CONTENT_CHARS
            ],
        )
        for citation in citations
    )


__all__ = [
    "MAX_KNOWLEDGE_BLOCKS",
    "KnowledgeManifestInvalid",
    "VerifiedRetrieval",
    "knowledge_evidence_blocks",
    "recompute_investigation_context",
    "record_manifest",
    "validate_manifest",
]
