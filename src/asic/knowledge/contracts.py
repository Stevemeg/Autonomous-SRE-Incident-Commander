"""Typed boundaries of the knowledge layer.

The same split as Phase 5 ingestion, for the same reason: **trusted context and untrusted
content arrive in different types.**

* :class:`ImportContext` and :class:`SourceAccessPolicy` are built by trusted wiring - the
  configured connector or an authenticated operator. Tenant, scope and access labels come
  from here and nowhere else.
* :class:`SourceDocument` is the document itself. Its title and body are data. A body that
  contains front matter claiming an ACL, a tenant or a trust level is simply a body.
* :class:`RetrievalPrincipal` and :class:`RetrievalScope` say who is asking and within what
  bounds. They are established before any content is read, so retrieved text cannot modify
  them.

Retrieval returns typed :class:`RetrievedChunk` values, never rows or dictionaries, and
their content leaves only as a fenced :class:`~asic.domain.untrusted.UntrustedBlock`.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Final, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from asic.domain.enums import (
    ActorType,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    KnowledgeIngestionOutcome,
    ProvenanceLabel,
    RetrievalPrincipalKind,
    TrustClass,
)
from asic.domain.untrusted import UntrustedBlock

#: An access label or clearance: lowercase, bounded, no whitespace.
LABEL_PATTERN: Final[str] = r"^[a-z][a-z0-9_.:-]{0,63}$"
Label = Annotated[str, Field(pattern=LABEL_PATTERN)]

_NO_CONTROL: Final[str] = r"^[^\x00-\x1f\x7f]+$"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_HEX64 = r"^[0-9a-f]{64}$"

#: Upper bound on the text of one result handed to a model.
MAX_RESULT_CONTENT_CHARS: Final[int] = 2000
#: Upper bound on the one-line label stored as an evidence item.
MAX_LABEL_CHARS: Final[int] = 240


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------- ingestion


class ImportActor(_Frozen):
    """Who imported a document. Attribution, not authority."""

    actor_type: ActorType
    actor_id: Annotated[str, Field(min_length=1, max_length=128, pattern=_NO_CONTROL)] | None = None


class SourceAccessPolicy(_Frozen):
    """Scope and access for a source. Set by the importer; never read from the document."""

    document_type: KnowledgeDocumentType
    trust_class: TrustClass
    #: Empty means tenant-wide.
    service_ids: tuple[uuid.UUID, ...] = Field(default=(), max_length=64)
    environment_ids: tuple[uuid.UUID, ...] = Field(default=(), max_length=16)
    #: Required clearances, any-of. Empty means visible to every principal in the tenant.
    acl_labels: tuple[Label, ...] = Field(default=(), max_length=32)
    review_interval_days: int | None = Field(default=None, ge=1, le=3650)

    def canonical(self) -> SourceAccessPolicy:
        """Order-insensitive form, so equal policies compare equal."""
        return self.model_copy(
            update={
                "service_ids": tuple(sorted(set(self.service_ids), key=str)),
                "environment_ids": tuple(sorted(set(self.environment_ids), key=str)),
                "acl_labels": tuple(sorted(set(self.acl_labels))),
            }
        )


class ImportContext(_Frozen):
    """Trusted: constructed by wiring, never from a document."""

    tenant_id: uuid.UUID
    provider: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    source_ref: Annotated[str, Field(min_length=1, max_length=900, pattern=_NO_CONTROL)]
    policy: SourceAccessPolicy
    actor: ImportActor


class SourceDocument(_Frozen):
    """Untrusted: the document as the source delivered it.

    The body is deliberately not size-bounded here. An oversized body must produce a
    durable, typed rejection recorded by the ingestion service - not a validation error
    raised before anything is recorded.
    """

    title: Annotated[str, Field(min_length=1, max_length=1000)]
    body: bytes
    content_format: KnowledgeContentFormat
    source_revision: (
        Annotated[str, Field(min_length=1, max_length=128, pattern=_NO_CONTROL)] | None
    ) = None
    source_updated_at: AwareDatetime | None = None


@dataclass(frozen=True, slots=True)
class IngestionResult:
    outcome: KnowledgeIngestionOutcome
    reason: str
    receipt_id: uuid.UUID
    source_id: uuid.UUID | None
    version_id: uuid.UUID | None
    version: int | None
    chunk_count: int
    content_hash: str | None
    injection_flags: tuple[str, ...] = ()


# ---------------------------------------------------------------------- retrieval


class RetrievalPrincipal(_Frozen):
    """Who a retrieval is for. Established by trusted wiring before any content is read."""

    tenant_id: uuid.UUID
    kind: RetrievalPrincipalKind
    principal_id: Annotated[str, Field(min_length=1, max_length=128, pattern=_NO_CONTROL)]
    clearances: frozenset[Label] = Field(default_factory=frozenset, max_length=32)


class RetrievalScope(_Frozen):
    """The bounds of one retrieval, resolved from the incident or the caller's context."""

    environment_id: uuid.UUID
    service_ids: tuple[uuid.UUID, ...] = Field(min_length=1, max_length=16)
    document_types: tuple[KnowledgeDocumentType, ...] = Field(
        default=tuple(KnowledgeDocumentType), min_length=1
    )


class RetrievalQuery(_Frozen):
    """What to look for. The text may be model-authored; it is a query, not authority."""

    text: Annotated[str, Field(min_length=1, max_length=512)]
    limit: int = Field(default=5, ge=1, le=20)
    #: Stale versions are excluded unless explicitly requested, and flagged when returned.
    include_stale: bool = False
    #: Retrieve the corpus as it stood at this instant. ``None`` means now.
    as_of: AwareDatetime | None = None

    @field_validator("text")
    @classmethod
    def _single_line(cls, value: str) -> str:
        cleaned = _CONTROL.sub(" ", value).strip()
        if not cleaned:
            raise ValueError("query text is empty once control characters are removed")
        return cleaned


@dataclass(frozen=True, slots=True)
class KnowledgeCitation:
    """A stable reference to one chunk of one version, as returned by one retrieval."""

    retrieval_id: uuid.UUID
    chunk_id: uuid.UUID
    version_id: uuid.UUID

    @property
    def token(self) -> str:
        return f"knowledge:{self.retrieval_id}/{self.chunk_id}@{self.version_id}"


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """Why a result ranked where it did. Every contribution is reproducible from these."""

    lexical_rank: int | None
    lexical_score: float | None
    vector_rank: int | None
    vector_similarity: float | None
    lexical_contribution: float
    vector_contribution: float
    fused_score: float


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    rank: int
    citation: KnowledgeCitation
    source_id: uuid.UUID
    provider: str
    source_ref: str
    document_type: KnowledgeDocumentType
    trust_class: TrustClass
    #: Source-derived, untrusted.
    title: str
    #: Source-derived, untrusted.
    section_path: tuple[str, ...]
    version: int
    stale: bool
    effective_at: datetime
    fresh_until: datetime | None
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int
    content_hash: str
    scores: ScoreBreakdown
    #: Untrusted operational text, bounded.
    content: str

    def label(self) -> str:
        """A one-line, bounded description. Still untrusted: it is made of source text."""
        section = " > ".join(self.section_path)
        text = f"{self.title} > {section}" if section else self.title
        return _CONTROL.sub(" ", text)[:MAX_LABEL_CHARS]

    def untrusted_block(self) -> UntrustedBlock:
        return UntrustedBlock(
            source=self.citation.token,
            provenance=ProvenanceLabel.RETRIEVED,
            content=self.content[:MAX_RESULT_CONTENT_CHARS],
        )


@dataclass(frozen=True, slots=True)
class RetrievalResultSet:
    retrieval_id: uuid.UUID
    principal: RetrievalPrincipal
    scope: RetrievalScope
    query_text: str
    query_digest: str
    policy_version: str
    mode: str
    embedding_model_id: str
    embedding_dimensions: int
    as_of: datetime
    include_stale: bool
    eligible_chunks: int
    lexical_matches: int
    vector_candidates: int
    excluded: Mapping[str, int]
    results: tuple[RetrievedChunk, ...]
    latency_ms: int

    def to_manifest(self, *, idempotency_key: str, correlation_id: uuid.UUID) -> dict[str, Any]:
        """The structured record handed across the broker. Ids and scores - no content."""
        return RetrievalManifest(
            retrieval_id=self.retrieval_id,
            tenant_id=self.principal.tenant_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            principal_kind=self.principal.kind,
            principal_id=self.principal.principal_id,
            clearances=sorted(self.principal.clearances),
            policy_version=self.policy_version,
            embedding_model_id=self.embedding_model_id,
            embedding_dimensions=self.embedding_dimensions,
            query_text=self.query_text,
            query_digest=self.query_digest,
            scope={
                "environment_id": str(self.scope.environment_id),
                "service_ids": sorted(str(s) for s in self.scope.service_ids),
                "document_types": sorted(t.value for t in self.scope.document_types),
            },
            as_of=self.as_of,
            include_stale=self.include_stale,
            eligible_chunks=self.eligible_chunks,
            lexical_matches=self.lexical_matches,
            vector_candidates=self.vector_candidates,
            excluded=dict(self.excluded),
            latency_ms=self.latency_ms,
            results=[
                ManifestResult(
                    rank=r.rank,
                    chunk_id=r.citation.chunk_id,
                    document_version_id=r.citation.version_id,
                    source_id=r.source_id,
                    lexical_rank=r.scores.lexical_rank,
                    lexical_score=r.scores.lexical_score,
                    vector_rank=r.scores.vector_rank,
                    vector_similarity=r.scores.vector_similarity,
                    fused_score=r.scores.fused_score,
                    stale=r.stale,
                    content_hash=r.content_hash,
                )
                for r in self.results
            ],
        ).model_dump(mode="json")


class ManifestResult(_Frozen):
    rank: int = Field(ge=1)
    chunk_id: uuid.UUID
    document_version_id: uuid.UUID
    source_id: uuid.UUID
    lexical_rank: int | None = Field(default=None, ge=1)
    lexical_score: float | None = None
    vector_rank: int | None = Field(default=None, ge=1)
    vector_similarity: float | None = None
    fused_score: float
    stale: bool
    content_hash: Annotated[str, Field(pattern=_HEX64)]


class RetrievalManifest(_Frozen):
    """What a knowledge provider returns alongside its result, validated on receipt.

    The receiving node does not trust it: every id is re-checked against the database and
    every content hash against the stored chunk before anything is recorded.
    """

    schema_version: Literal[1] = 1
    retrieval_id: uuid.UUID
    tenant_id: uuid.UUID
    idempotency_key: Annotated[str, Field(min_length=1, max_length=64)]
    correlation_id: uuid.UUID
    principal_kind: RetrievalPrincipalKind
    principal_id: Annotated[str, Field(min_length=1, max_length=128)]
    clearances: list[Label] = Field(max_length=32)
    policy_version: Annotated[str, Field(min_length=1, max_length=64)]
    embedding_model_id: Annotated[str, Field(min_length=1, max_length=128)]
    embedding_dimensions: int = Field(ge=1)
    query_text: Annotated[str, Field(min_length=1, max_length=512)]
    query_digest: Annotated[str, Field(pattern=_HEX64)]
    scope: dict[str, Any]
    as_of: AwareDatetime
    include_stale: bool
    eligible_chunks: int = Field(ge=0)
    lexical_matches: int = Field(ge=0)
    vector_candidates: int = Field(ge=0)
    excluded: dict[str, int]
    latency_ms: int = Field(ge=0)
    results: list[ManifestResult] = Field(max_length=20)


__all__ = [
    "LABEL_PATTERN",
    "MAX_LABEL_CHARS",
    "MAX_RESULT_CONTENT_CHARS",
    "ImportActor",
    "ImportContext",
    "IngestionResult",
    "KnowledgeCitation",
    "ManifestResult",
    "RetrievalManifest",
    "RetrievalPrincipal",
    "RetrievalQuery",
    "RetrievalResultSet",
    "RetrievalScope",
    "RetrievedChunk",
    "ScoreBreakdown",
    "SourceAccessPolicy",
    "SourceDocument",
]
