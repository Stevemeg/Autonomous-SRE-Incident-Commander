"""Citations: stable references a human can follow back to the exact source location.

A citation names one chunk of one version as returned by one retrieval:
``knowledge:<retrieval_id>/<chunk_id>@<version_id>``. It is **valid only if that chunk was
actually returned by that retrieval** - resolution goes through the append-only
``knowledge_retrieval_result`` row, not merely through the chunk table. So a citation cannot
be minted for content that was never retrieved, a model cannot invent one that resolves,
and text inside a document that *looks like* a citation is just text: the parser is never
pointed at document content, and even a well-formed token must match a recorded row in the
caller's own tenant.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeRetrievalResult,
    KnowledgeSource,
)
from asic.db.session import require_tenant
from asic.domain.enums import KnowledgeSourceStatus, KnowledgeVersionState
from asic.knowledge.contracts import KnowledgeCitation
from asic.knowledge.errors import CitationInvalid

_UUID: Final[str] = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_TOKEN: Final = re.compile(rf"^knowledge:({_UUID})/({_UUID})@({_UUID})$")


@dataclass(frozen=True, slots=True)
class ResolvedCitation:
    citation: KnowledgeCitation
    source_id: uuid.UUID
    provider: str
    source_ref: str
    version: int
    section_path: tuple[str, ...]
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int
    content_hash: str
    stale_at_retrieval: bool
    #: False when the source has since been revoked or deleted, or the version revoked.
    content_available: bool


def parse_citation(token: str) -> KnowledgeCitation:
    """Parse a citation token. Strict: exactly the canonical form, lowercase UUIDs."""
    match = _TOKEN.match(token)
    if match is None:
        raise CitationInvalid("malformed_citation")
    retrieval_id, chunk_id, version_id = (uuid.UUID(part) for part in match.groups())
    return KnowledgeCitation(retrieval_id=retrieval_id, chunk_id=chunk_id, version_id=version_id)


def resolve_citation(session: Session, citation: KnowledgeCitation | str) -> ResolvedCitation:
    """Resolve a citation within the session's bound tenant.

    Raises:
        CitationInvalid: ``malformed_citation``, ``unknown_citation`` (the retrieval did
            not return that chunk, or it belongs to another tenant) or ``version_mismatch``.
    """
    parsed = parse_citation(citation) if isinstance(citation, str) else citation
    tenant_id = require_tenant(session)
    row = session.execute(
        sa.select(KnowledgeRetrievalResult, KnowledgeChunk, KnowledgeDocument, KnowledgeSource)
        .join(
            KnowledgeChunk,
            sa.and_(
                KnowledgeChunk.tenant_id == KnowledgeRetrievalResult.tenant_id,
                KnowledgeChunk.id == KnowledgeRetrievalResult.chunk_id,
            ),
        )
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
            KnowledgeRetrievalResult.tenant_id == tenant_id,
            KnowledgeRetrievalResult.retrieval_id == parsed.retrieval_id,
            KnowledgeRetrievalResult.chunk_id == parsed.chunk_id,
        )
    ).one_or_none()
    if row is None:
        raise CitationInvalid("unknown_citation")
    result, chunk, version, source = row
    if result.document_version_id != parsed.version_id or chunk.document_id != parsed.version_id:
        raise CitationInvalid("version_mismatch")
    if chunk.content_hash != result.content_hash:  # pragma: no cover - chunks are immutable
        raise CitationInvalid("content_changed")
    return ResolvedCitation(
        citation=parsed,
        source_id=source.id,
        provider=source.provider,
        source_ref=source.source_ref,
        version=version.version,
        section_path=tuple(chunk.section_path),
        start_line=int(chunk.start_line or 0),
        end_line=int(chunk.end_line or 0),
        start_offset=int(chunk.start_offset or 0),
        end_offset=int(chunk.end_offset or 0),
        content_hash=result.content_hash,
        stale_at_retrieval=result.stale,
        content_available=(
            source.status is KnowledgeSourceStatus.ACTIVE
            and version.lifecycle is not KnowledgeVersionState.REVOKED
        ),
    )


__all__ = ["ResolvedCitation", "parse_citation", "resolve_citation"]
