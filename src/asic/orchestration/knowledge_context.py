"""Knowledge evidence inside the investigation: verification, recording and rendering.

Three responsibilities, each a boundary:

* :func:`validate_manifest` - a provider's retrieval manifest is **untrusted input**. Every
  claim in it is re-checked against the database before anything is recorded: the tenant,
  the run's correlation id, the broker's idempotency key for this very call, and for every
  result that the chunk exists, belongs to the named version and source, and still has the
  content hash the manifest claims. A manifest that fails any check is refused and the
  domain degrades; nothing from it is recorded.
* :func:`record_manifest` - the verified retrieval is recorded append-only, linked to the
  tool execution and the evidence row, in the node's own transaction.
* :func:`knowledge_evidence_blocks` - retrieved content enters a model prompt only here,
  only as fenced :class:`~asic.domain.untrusted.UntrustedBlock` data labelled
  ``RETRIEVED``, bounded in count and size, and **withheld if access was withdrawn** after
  the retrieval. The block's source label is the citation token, taken from the database
  row - never from document text.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy.orm import Session

from asic.contracts.state import EvidenceRef
from asic.db.models import (
    Evidence,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeRetrieval,
    KnowledgeRetrievalResult,
    ToolExecution,
)
from asic.domain.enums import EvidenceDomain, ProvenanceLabel
from asic.domain.errors import DomainError
from asic.domain.untrusted import UntrustedBlock, scan
from asic.knowledge.contracts import (
    MAX_RESULT_CONTENT_CHARS,
    KnowledgeCitation,
    RetrievalManifest,
)
from asic.knowledge.retrieval import current_content
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


def validate_manifest(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    correlation_id: uuid.UUID,
    result: ToolResult,
) -> VerifiedRetrieval | None:
    """Verify a knowledge result. ``None`` for a provider that returns no manifest.

    Raises:
        KnowledgeManifestInvalid: the manifest is malformed or disagrees with the database.
    """
    if result.deduplicated:
        return _replayed(session, tenant_id, result)
    raw = result.payload.get("retrieval")
    if raw is None:
        return None  # a fixture provider without a store; nothing to record
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
    if [r.rank for r in manifest.results] != list(range(1, len(manifest.results) + 1)):
        raise KnowledgeManifestInvalid("manifest_ranks_not_contiguous")
    if len({r.chunk_id for r in manifest.results}) != len(manifest.results):
        raise KnowledgeManifestInvalid("manifest_duplicate_chunk")
    documents = result.payload.get("documents") or []
    if not isinstance(documents, list) or len(documents) != len(manifest.results):
        raise KnowledgeManifestInvalid("manifest_document_count_mismatch")

    stored = {
        chunk.id: (chunk, source_id)
        for chunk, source_id in session.execute(
            sa.select(KnowledgeChunk, KnowledgeDocument.source_id)
            .join(
                KnowledgeDocument,
                sa.and_(
                    KnowledgeDocument.tenant_id == KnowledgeChunk.tenant_id,
                    KnowledgeDocument.id == KnowledgeChunk.document_id,
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
        chunk, source_id = found
        if chunk.document_id != item.document_version_id or source_id != item.source_id:
            raise KnowledgeManifestInvalid("manifest_version_mismatch")
        if chunk.content_hash != item.content_hash:
            raise KnowledgeManifestInvalid("manifest_content_mismatch")
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
    """Record a verified retrieval. A broker replay was recorded the first time."""
    manifest = verified.manifest
    if manifest is None or verified.replayed:
        return
    session.add(
        KnowledgeRetrieval(
            id=manifest.retrieval_id,
            tenant_id=tenant_id,
            principal_kind=manifest.principal_kind,
            principal_id=manifest.principal_id,
            clearances=list(manifest.clearances),
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
            scope=dict(manifest.scope),
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


def knowledge_evidence_blocks(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    evidence: Sequence[EvidenceRef],
    max_blocks: int = MAX_KNOWLEDGE_BLOCKS,
) -> tuple[UntrustedBlock, ...]:
    """Retrieved chunks for the knowledge evidence in ``evidence``, as untrusted data."""
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
    content = current_content(session, citations)
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
    "record_manifest",
    "validate_manifest",
]
