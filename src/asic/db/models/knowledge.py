"""Knowledge base, governed memory and postmortems.

All knowledge content is ``RETRIEVED`` provenance: human-authored text of unknown current
accuracy, and a known prompt-injection vector. It informs; it never authorises.

**Knowledge is versioned, never overwritten (INV-14).** :class:`KnowledgeSource` is the
stable identity of a document in its provider; each :class:`KnowledgeDocument` row is one
immutable *version* of it, with its deterministic chunks and embeddings. A new source
revision with different content is a new row, and the previous one is marked superseded -
so a retrieval that cited version 3 is still explicable after version 4 lands. The
application role holds column-level ``UPDATE`` on lifecycle fields only: content, hashes
and chunks cannot be rewritten by application code at all.

**Authorization lives on the source, not the chunk.** Scope and access labels are read from
:class:`KnowledgeSource` at query time, so tightening a source's access takes effect for
every existing version immediately. The scope columns on documents and chunks are the
scope *as ingested*, kept for replay and audit, and are deliberately never consulted for
authorization.

**The promotion path is the important part of memory.** There is no automatic route from
"this worked once" to durable operational knowledge: :class:`MemoryPromotion` requires a
human decision, :class:`MemoryEntry` names the promotion that created it, and only an entry
backed by a ``verified`` verification record may carry ``VERIFIED_FACT`` provenance. Every
write request - including the refused ones - leaves a :class:`MemoryWriteDecision`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import (
    Base,
    CreatedAtMixin,
    TenantScoped,
    TimestampMixin,
    enum_column,
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import (
    ActorType,
    ChunkStrategy,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    KnowledgeIngestionOutcome,
    KnowledgeSourceStatus,
    KnowledgeVersionState,
    MemoryCategory,
    MemoryDecisionOutcome,
    MemoryKind,
    MemoryPromotionStatus,
    MemoryVerificationStatus,
    PostmortemStatus,
    ProvenanceLabel,
    RetrievalPrincipalKind,
    TrustClass,
)
from asic.domain.idempotency import KEY_LENGTH

#: Embedding width. A column-level constant because changing it is a re-index, not a
#: configuration tweak: every stored vector must have the same dimensionality.
EMBEDDING_DIMENSIONS = 1536

#: Provenance a piece of memory content may carry. SYSTEM and HUMAN confer authority
#: (SEC-I4) and are therefore never a label on remembered content.
_MEMORY_PROVENANCE = "('retrieved', 'model_claim', 'verified_fact')"

_EMPTY_UUIDS = sa.text("'{}'::uuid[]")
_EMPTY_LABELS = sa.text("'{}'::varchar[]")


class KnowledgeSource(Base, TenantScoped, TimestampMixin):
    """The stable identity of one document in one provider, and its access policy.

    Everything here is set by the trusted importer - never read from the document. A
    source cannot promote itself: front matter claiming an ACL is document *content*.
    """

    __tablename__ = "knowledge_source"

    id: Mapped[uuid.UUID] = uuid_pk()
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(sa.String(900), nullable=False)
    document_type: Mapped[KnowledgeDocumentType] = mapped_column(
        enum_column(KnowledgeDocumentType, "knowledge_document_type"), nullable=False
    )
    trust_class: Mapped[TrustClass] = mapped_column(
        enum_column(TrustClass, "trust_class"), nullable=False
    )
    #: Empty means "every service in the tenant". Consulted at query time.
    service_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    #: Empty means "every environment in the tenant".
    environment_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    #: Required clearances, any-of. Empty means visible to every principal in the tenant.
    acl_labels: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=_EMPTY_LABELS
    )
    #: How long a version stays fresh after the source says it was updated. ``None``
    #: means versions of this source never go stale (e.g. a postmortem of a closed event).
    review_interval_days: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    status: Mapped[KnowledgeSourceStatus] = mapped_column(
        enum_column(KnowledgeSourceStatus, "knowledge_source_status"),
        nullable=False,
        server_default=sa.text("'active'"),
    )
    status_reason: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_by_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    created_by_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_source"),
        sa.UniqueConstraint(
            "tenant_id", "provider", "source_ref", name="uq_knowledge_source_identity"
        ),
        sa.CheckConstraint(
            "review_interval_days IS NULL OR review_interval_days BETWEEN 1 AND 3650",
            name="review_interval_bounded",
        ),
        sa.CheckConstraint(
            "status = 'active' OR (status_reason IS NOT NULL AND status_changed_at IS NOT NULL)",
            name="inactive_source_records_why",
        ),
        sa.CheckConstraint(
            "cardinality(acl_labels) <= 32 AND cardinality(service_ids) <= 64"
            " AND cardinality(environment_ids) <= 16",
            name="scope_bounded",
        ),
        sa.Index("ix_knowledge_source_status", "tenant_id", "status"),
    )


class KnowledgeDocument(Base, TenantScoped, TimestampMixin):
    """One immutable version of a knowledge source.

    The class keeps its Phase 3 name; since Phase 6 each row is a *version* of the
    :class:`KnowledgeSource` it references. Versioned rather than overwritten (INV-14): a
    retrieval that cited version 3 must still be explicable after version 4 lands, and
    staleness must be visible rather than silently corrected.
    """

    __tablename__ = "knowledge_document"

    id: Mapped[uuid.UUID] = uuid_pk()
    source_uri: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    document_type: Mapped[KnowledgeDocumentType] = mapped_column(
        enum_column(KnowledgeDocumentType, "knowledge_document_type"), nullable=False
    )
    trust_class: Mapped[TrustClass] = mapped_column(
        enum_column(TrustClass, "trust_class"), nullable=False
    )

    version: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("1"))
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    #: Scope as ingested. Kept for replay; authorization reads :class:`KnowledgeSource`.
    service_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    environment_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    acl_labels: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=_EMPTY_LABELS
    )

    #: Freshness is computed from these, never assumed.
    source_updated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    #: SHA-256 of the canonical text. Change detection; avoids needless re-embedding.
    content_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Injection patterns found at ingestion. A recorded signal, not the defence.
    injection_flagged: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("false")
    )

    # ---- Phase 6: version identity and pipeline provenance. Nullable only because rows
    # ---- written before Phase 6 cannot have them; the ``versioned_source`` constraint is
    # ---- added NOT VALID, so every row written from now on must carry all of them.
    source_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    lifecycle: Mapped[KnowledgeVersionState] = mapped_column(
        enum_column(KnowledgeVersionState, "knowledge_version_state"),
        nullable=False,
        server_default=sa.text("'current'"),
    )
    content_format: Mapped[KnowledgeContentFormat | None] = mapped_column(
        enum_column(KnowledgeContentFormat, "knowledge_content_format"), nullable=True
    )
    source_revision: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    chunker_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    embedding_model_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    embedding_dimensions: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    byte_size: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    chunk_count: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    #: When this version became current. Replay-at-time filters on it.
    effective_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    #: After this instant the version is stale. ``None`` = never stale.
    fresh_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_document"),
        tenant_fk(
            "superseded_by_id",
            "knowledge_document",
            ondelete="SET NULL",
            name="fk_knowledge_document_superseded_by",
        ),
        tenant_fk(
            "source_id",
            "knowledge_source",
            ondelete="RESTRICT",
            name="fk_knowledge_document_source",
        ),
        sa.UniqueConstraint(
            "tenant_id", "source_uri", "version", name="uq_knowledge_document_version"
        ),
        sa.UniqueConstraint(
            "tenant_id", "source_id", "version", name="uq_knowledge_document_source_version"
        ),
        sa.CheckConstraint("version >= 1", name="version_starts_at_one"),
        sa.CheckConstraint("superseded_by_id <> id", name="no_self_supersede"),
        # Superseding happens in one transaction: the old version is marked superseded, the
        # new one inserted, then the successor link written. The one-current-per-source
        # index forbids the reverse order, so the link may land after the state change.
        sa.CheckConstraint(
            "lifecycle <> 'superseded' OR superseded_at IS NOT NULL",
            name="superseded_version_has_timestamp",
        ),
        sa.CheckConstraint(
            "superseded_by_id IS NULL OR lifecycle <> 'current'",
            name="successor_implies_not_current",
        ),
        sa.CheckConstraint(
            "(chunk_count IS NULL OR chunk_count >= 0) AND (byte_size IS NULL OR byte_size >= 0)",
            name="sizes_non_negative",
        ),
        # Added NOT VALID by migration 0008: enforced for every row written since.
        sa.CheckConstraint(
            "source_id IS NOT NULL AND content_format IS NOT NULL AND parser_version IS NOT NULL"
            " AND chunker_version IS NOT NULL AND embedding_model_id IS NOT NULL"
            " AND embedding_dimensions IS NOT NULL AND byte_size IS NOT NULL"
            " AND chunk_count IS NOT NULL",
            name="versioned_source",
        ),
        sa.Index("ix_knowledge_document_type", "tenant_id", "document_type"),
        sa.Index(
            "ix_knowledge_document_current",
            "tenant_id",
            "document_type",
            postgresql_where=sa.text("superseded_by_id IS NULL"),
        ),
        sa.Index("ix_knowledge_document_services", "service_ids", postgresql_using="gin"),
        # At most one current version per source: the database backstop behind the
        # per-source advisory lock in the ingestion service.
        sa.Index(
            "uq_knowledge_document_current_source",
            "tenant_id",
            "source_id",
            unique=True,
            postgresql_where=sa.text("lifecycle = 'current' AND source_id IS NOT NULL"),
        ),
    )


class KnowledgeChunk(Base, TenantScoped, CreatedAtMixin):
    """A retrievable unit of one document version, with its embedding.

    Immutable once written: the application role holds no ``UPDATE`` or ``DELETE`` here.
    ``embedding_model_id`` is stored per chunk because changing the embedding model is a
    versioned behaviour change requiring a re-index and a fresh retrieval evaluation - not
    a configuration edit that silently changes what the system retrieves. Retrieval only
    ever compares vectors produced by the same model.
    """

    __tablename__ = "knowledge_chunk"

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    #: Sensitivity: CUSTOMER_CONTENT. Untrusted, delimited when placed in any prompt.
    text: Mapped[str] = mapped_column(sa.Text, nullable=False)
    embedding: Mapped[Any | None] = mapped_column(Vector(EMBEDDING_DIMENSIONS), nullable=True)
    embedding_model_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    chunk_strategy: Mapped[ChunkStrategy] = mapped_column(
        enum_column(ChunkStrategy, "chunk_strategy"), nullable=False
    )
    token_count: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    #: Scope as ingested (see module docstring). Not consulted for authorization.
    service_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    acl_labels: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=_EMPTY_LABELS
    )

    # ---- Phase 6: citation location and integrity. ``located_chunk`` is NOT VALID.
    #: SHA-256 of ``text``. Lets a citation prove the content it points at is unchanged.
    content_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    #: Heading breadcrumb, outermost first. Source-derived and untrusted, like the text.
    section_path: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(200)), nullable=False, server_default=_EMPTY_LABELS
    )
    #: Character offsets into the version's canonical text, end exclusive.
    start_offset: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    end_offset: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    #: 1-based line numbers into the canonical text, inclusive.
    start_line: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    char_count: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_chunk"),
        tenant_fk(
            "document_id",
            "knowledge_document",
            ondelete="CASCADE",
            name="fk_knowledge_chunk_document",
        ),
        sa.UniqueConstraint(
            "tenant_id", "document_id", "sequence", name="uq_knowledge_chunk_sequence"
        ),
        sa.CheckConstraint("sequence >= 0", name="sequence_non_negative"),
        sa.CheckConstraint(
            "(embedding IS NULL) = (embedding_model_id IS NULL)",
            name="embedding_names_its_model",
        ),
        sa.CheckConstraint(
            "start_offset IS NULL OR (start_offset >= 0 AND end_offset > start_offset"
            " AND start_line >= 1 AND end_line >= start_line)",
            name="location_ordered",
        ),
        sa.CheckConstraint("cardinality(section_path) <= 6", name="section_depth_bounded"),
        # Added NOT VALID by migration 0008.
        sa.CheckConstraint(
            "content_hash IS NOT NULL AND start_offset IS NOT NULL AND end_offset IS NOT NULL"
            " AND start_line IS NOT NULL AND end_line IS NOT NULL AND char_count IS NOT NULL"
            " AND embedding IS NOT NULL",
            name="located_chunk",
        ),
        sa.Index("ix_knowledge_chunk_document", "tenant_id", "document_id"),
        sa.Index("ix_knowledge_chunk_services", "service_ids", postgresql_using="gin"),
        sa.Index("ix_knowledge_chunk_acl", "acl_labels", postgresql_using="gin"),
        # Lexical half of hybrid retrieval (ADR-0008): operational text is dense with
        # exact tokens - error codes, service names - where lexical search beats dense.
        sa.Index(
            "ix_knowledge_chunk_fts",
            sa.text("to_tsvector('english', text)"),
            postgresql_using="gin",
        ),
        # Dense half. Declared here rather than only in the migration so the models stay
        # the single source of truth: an index that exists in the database but not in the
        # metadata is one that the next autogenerate run would silently try to drop.
        # Cosine distance matches the normalised embeddings we intend to store.
        sa.Index(
            "ix_knowledge_chunk_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
            postgresql_with={"m": "16", "ef_construction": "64"},
        ),
    )


class KnowledgeIngestion(Base, TenantScoped, CreatedAtMixin):
    """One ingestion attempt and its outcome. Append-only.

    Rejections and dependency failures are recorded here rather than raised into the void,
    so "the runbook was never imported" is distinguishable from "the runbook was imported
    and nothing matched".
    """

    __tablename__ = "knowledge_ingestion"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    source_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    document_version_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    provider: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(sa.String(900), nullable=False)
    outcome: Mapped[KnowledgeIngestionOutcome] = mapped_column(
        enum_column(KnowledgeIngestionOutcome, "knowledge_ingestion_outcome"), nullable=False
    )
    #: A safe reason code; never source text.
    reason: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    raw_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    source_revision: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    byte_size: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    chunk_count: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    parser_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    chunker_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    embedding_model_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    actor_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    correlation_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_ingestion"),
        tenant_fk(
            "source_id",
            "knowledge_source",
            ondelete="RESTRICT",
            name="fk_knowledge_ingestion_source",
        ),
        tenant_fk(
            "document_version_id",
            "knowledge_document",
            ondelete="RESTRICT",
            name="fk_knowledge_ingestion_version",
        ),
        sa.CheckConstraint(
            "(outcome IN ('created', 'unchanged')) = (document_version_id IS NOT NULL)",
            name="committed_outcome_names_version",
        ),
        sa.CheckConstraint("byte_size >= 0", name="byte_size_non_negative"),
        sa.Index("ix_knowledge_ingestion_source", "tenant_id", "source_id", "created_at"),
    )


class KnowledgeRetrieval(Base, TenantScoped, CreatedAtMixin):
    """One retrieval: who asked, under which policy, what was eligible, what came back.

    Append-only, and the anchor for citations: a citation is valid only if it names a
    chunk recorded in :class:`KnowledgeRetrievalResult` for this retrieval. Exclusion
    counts are corpus counts within the principal's authorized scope, plus one aggregate
    for unauthorized content - never query-dependent counts over content the principal
    could not read, which would leak its existence.
    """

    __tablename__ = "knowledge_retrieval"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    principal_kind: Mapped[RetrievalPrincipalKind] = mapped_column(
        enum_column(RetrievalPrincipalKind, "retrieval_principal_kind"), nullable=False
    )
    principal_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    clearances: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=_EMPTY_LABELS
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    workflow_run_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    tool_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(sa.String(KEY_LENGTH), nullable=True)
    policy_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    embedding_model_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    embedding_dimensions: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: The bounded query as issued. Generated or model-authored text, never document text.
    query_text: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    query_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Resolved filters: service ids, environment id, document types.
    scope: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    as_of: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    include_stale: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    eligible_chunks: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    lexical_matches: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    vector_candidates: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    excluded: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    result_count: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_retrieval"),
        tenant_fk(
            "incident_id", "incident", ondelete="RESTRICT", name="fk_knowledge_retrieval_incident"
        ),
        tenant_fk(
            "workflow_run_id",
            "workflow_run",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_run",
        ),
        tenant_fk(
            "tool_execution_id",
            "tool_execution",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_tool_execution",
        ),
        tenant_fk(
            "evidence_id", "evidence", ondelete="RESTRICT", name="fk_knowledge_retrieval_evidence"
        ),
        sa.CheckConstraint(
            "eligible_chunks >= 0 AND lexical_matches >= 0 AND vector_candidates >= 0"
            " AND result_count >= 0 AND latency_ms >= 0",
            name="counts_non_negative",
        ),
        sa.Index("ix_knowledge_retrieval_tool_execution", "tenant_id", "tool_execution_id"),
        sa.Index("ix_knowledge_retrieval_incident", "tenant_id", "incident_id"),
    )


class KnowledgeRetrievalResult(Base, TenantScoped, CreatedAtMixin):
    """One ranked result of one retrieval. Append-only; the citation anchor."""

    __tablename__ = "knowledge_retrieval_result"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    retrieval_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    rank: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    chunk_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    document_version_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    lexical_rank: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    lexical_score: Mapped[float | None] = mapped_column(pg.DOUBLE_PRECISION, nullable=True)
    vector_rank: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    vector_similarity: Mapped[float | None] = mapped_column(pg.DOUBLE_PRECISION, nullable=True)
    fused_score: Mapped[float] = mapped_column(pg.DOUBLE_PRECISION, nullable=False)
    stale: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    content_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("knowledge_retrieval_result"),
        tenant_fk(
            "retrieval_id",
            "knowledge_retrieval",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_result_retrieval",
        ),
        tenant_fk(
            "chunk_id",
            "knowledge_chunk",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_result_chunk",
        ),
        tenant_fk(
            "document_version_id",
            "knowledge_document",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_result_version",
        ),
        tenant_fk(
            "source_id",
            "knowledge_source",
            ondelete="RESTRICT",
            name="fk_knowledge_retrieval_result_source",
        ),
        sa.UniqueConstraint(
            "tenant_id", "retrieval_id", "rank", name="uq_knowledge_retrieval_result_rank"
        ),
        sa.UniqueConstraint(
            "tenant_id", "retrieval_id", "chunk_id", name="uq_knowledge_retrieval_result_chunk"
        ),
        sa.CheckConstraint("rank >= 1", name="rank_positive"),
        sa.CheckConstraint(
            "lexical_rank IS NOT NULL OR vector_rank IS NOT NULL",
            name="result_has_a_signal",
        ),
    )


class MemoryEntry(Base, TenantScoped, TimestampMixin):
    """Durable operational memory: a verified outcome or a promoted operational fact.

    ``support_count`` is the guard against over-generalising from one incident. A count of
    one is never sufficient for automatic promotion, and the promotion itself still
    requires a human (SI-15).
    """

    __tablename__ = "memory_entry"

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[MemoryKind] = mapped_column(enum_column(MemoryKind, "memory_kind"), nullable=False)
    #: Cause class this memory applies to, matching the hypothesis vocabulary.
    root_cause_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Normalised description of the situation this applies to: service shape, symptom
    #: pattern, environment. Used to decide whether a past outcome is relevant now.
    context_signature: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    statement: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: The action and observed effect, for a verified outcome.
    action_reference: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    observed_effect: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    #: How many independently verified incidents support this. Never auto-promoted at 1.
    support_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default=sa.text("1")
    )
    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    version: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default=sa.text("1"))
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )

    # ---- Phase 6 governance. ``governed_entry`` is added NOT VALID.
    #: What the remembered content *is*: retrieved/human-authored text, a model claim, or
    #: a verified fact. Never SYSTEM or HUMAN - remembered content confers no authority.
    provenance: Mapped[ProvenanceLabel | None] = mapped_column(
        enum_column(ProvenanceLabel, "provenance_label"), nullable=True
    )
    verification_status: Mapped[MemoryVerificationStatus | None] = mapped_column(
        enum_column(MemoryVerificationStatus, "memory_verification_status"), nullable=True
    )
    #: The human-approved promotion that created this entry (INV-15).
    promotion_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    #: The verification record a verified outcome rests on.
    verification_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    #: Incident, evidence and citation references resolved at approval time.
    source_refs: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    policy_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    effective_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("memory_entry"),
        tenant_fk(
            "superseded_by_id",
            "memory_entry",
            ondelete="SET NULL",
            name="fk_memory_entry_superseded_by",
        ),
        # use_alter: memory_promotion already references memory_entry (Phase 3), so this
        # closes a cycle that the metadata must not try to order.
        sa.ForeignKeyConstraint(
            ["tenant_id", "promotion_id"],
            ["memory_promotion.tenant_id", "memory_promotion.id"],
            ondelete="RESTRICT",
            name="fk_memory_entry_promotion",
            use_alter=True,
        ),
        tenant_fk(
            "verification_id",
            "verification",
            ondelete="RESTRICT",
            name="fk_memory_entry_verification",
        ),
        sa.UniqueConstraint("tenant_id", "promotion_id", name="uq_memory_entry_promotion"),
        sa.CheckConstraint("support_count >= 1", name="support_count_positive"),
        sa.CheckConstraint("last_seen_at >= first_seen_at", name="seen_window_ordered"),
        sa.CheckConstraint("superseded_by_id <> id", name="no_self_supersede"),
        sa.CheckConstraint(
            f"provenance IS NULL OR provenance IN {_MEMORY_PROVENANCE}",
            name="memory_confers_no_authority",
        ),
        sa.CheckConstraint(
            "provenance IS NULL OR ((provenance = 'verified_fact') = (kind = 'verified_outcome'))",
            name="verified_fact_only_for_outcomes",
        ),
        sa.CheckConstraint(
            "verification_status IS NULL"
            " OR ((verification_status = 'verified') = (provenance = 'verified_fact'))",
            name="verified_status_matches_provenance",
        ),
        sa.CheckConstraint(
            "verification_status IS NULL OR verification_status <> 'verified'"
            " OR verification_id IS NOT NULL",
            name="verified_entry_names_verification",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > effective_at", name="expiry_after_effect"
        ),
        # Added NOT VALID by migration 0008.
        sa.CheckConstraint(
            "provenance IS NOT NULL AND verification_status IS NOT NULL"
            " AND promotion_id IS NOT NULL AND policy_version IS NOT NULL",
            name="governed_entry",
        ),
        sa.Index("ix_memory_entry_lookup", "tenant_id", "root_cause_class", "is_active"),
        sa.Index("ix_memory_entry_context", "context_signature", postgresql_using="gin"),
    )


class MemoryPromotion(Base, TenantScoped, TimestampMixin):
    """A governed write into durable memory.

    ``approver_user_id`` is NOT NULL once decided, and no code path writes
    :class:`MemoryEntry` without a corresponding approved row here (INV-15). This is what
    makes "production behaviour is never silently modified from a single incident"
    (section 10) a structural property.
    """

    __tablename__ = "memory_promotion"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: The incident that prompted the proposal.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    #: The entry this promotion creates or updates. Set once applied.
    memory_entry_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    target_kind: Mapped[MemoryKind] = mapped_column(
        enum_column(MemoryKind, "memory_kind"), nullable=False
    )
    #: The proposed content, held here until a human approves it.
    proposed_payload: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(sa.Text, nullable=False)
    supporting_incident_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )

    status: Mapped[MemoryPromotionStatus] = mapped_column(
        enum_column(MemoryPromotionStatus, "memory_promotion_status"),
        nullable=False,
        default=MemoryPromotionStatus.PROPOSED,
    )
    approver_user_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    # ---- Phase 6 governance. ``governed_promotion`` is added NOT VALID.
    category: Mapped[MemoryCategory | None] = mapped_column(
        enum_column(MemoryCategory, "memory_category"), nullable=True
    )
    #: Provenance of the proposed content, derived from who proposed it - never declared.
    origin_provenance: Mapped[ProvenanceLabel | None] = mapped_column(
        enum_column(ProvenanceLabel, "provenance_label"), nullable=True
    )
    #: Deterministic digest of the proposal, so identical open proposals collapse to one.
    proposal_key: Mapped[str | None] = mapped_column(sa.String(KEY_LENGTH), nullable=True)
    proposed_by_type: Mapped[ActorType | None] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=True
    )
    proposed_by_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    verification_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=_EMPTY_UUIDS
    )
    knowledge_citations: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    policy_version: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("memory_promotion"),
        tenant_fk(
            "incident_id", "incident", ondelete="SET NULL", name="fk_memory_promotion_incident"
        ),
        tenant_fk(
            "memory_entry_id",
            "memory_entry",
            ondelete="SET NULL",
            name="fk_memory_promotion_entry",
        ),
        tenant_fk(
            "approver_user_id",
            "app_user",
            ondelete="RESTRICT",
            name="fk_memory_promotion_approver",
        ),
        # A decided promotion names its human and when. SI-15 in constraint form.
        sa.CheckConstraint(
            "(status = 'proposed') = (approver_user_id IS NULL)",
            name="decided_promotion_names_approver",
        ),
        sa.CheckConstraint(
            "(status = 'proposed') = (decided_at IS NULL)",
            name="decided_promotion_has_timestamp",
        ),
        sa.CheckConstraint(
            "(status <> 'approved') OR (memory_entry_id IS NOT NULL)",
            name="approved_promotion_has_entry",
        ),
        sa.CheckConstraint(
            f"origin_provenance IS NULL OR origin_provenance IN {_MEMORY_PROVENANCE}",
            name="proposal_origin_confers_no_authority",
        ),
        sa.CheckConstraint(
            "category IS NULL OR target_kind <> 'verified_outcome'"
            " OR cardinality(verification_ids) >= 1",
            name="verified_outcome_cites_verification",
        ),
        sa.CheckConstraint(
            "approver_user_id IS NULL OR proposed_by_id IS NULL"
            " OR proposed_by_id <> approver_user_id::text",
            name="approver_is_not_proposer",
        ),
        sa.CheckConstraint(
            "cardinality(verification_ids) <= 32 AND cardinality(evidence_ids) <= 64",
            name="references_bounded",
        ),
        # Added NOT VALID by migration 0008.
        sa.CheckConstraint(
            "category IS NOT NULL AND origin_provenance IS NOT NULL AND proposal_key IS NOT NULL"
            " AND proposed_by_type IS NOT NULL AND policy_version IS NOT NULL",
            name="governed_promotion",
        ),
        sa.Index("ix_memory_promotion_status", "tenant_id", "status"),
        sa.Index(
            "uq_memory_promotion_open_proposal",
            "tenant_id",
            "proposal_key",
            unique=True,
            postgresql_where=sa.text("status = 'proposed' AND proposal_key IS NOT NULL"),
        ),
    )


class MemoryWriteDecision(Base, TenantScoped, CreatedAtMixin):
    """Every memory write decision, including refusals. Append-only.

    A poisoning attempt that the policy refused leaves a record here; one that nobody
    noticed would otherwise leave nothing at all.
    """

    __tablename__ = "memory_write_decision"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    category: Mapped[MemoryCategory] = mapped_column(
        enum_column(MemoryCategory, "memory_category"), nullable=False
    )
    outcome: Mapped[MemoryDecisionOutcome] = mapped_column(
        enum_column(MemoryDecisionOutcome, "memory_decision_outcome"), nullable=False
    )
    #: A safe reason code; never the proposed text.
    reason: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, "actor_type"), nullable=False
    )
    actor_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    promotion_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    memory_entry_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    references_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("memory_write_decision"),
        tenant_fk(
            "promotion_id",
            "memory_promotion",
            ondelete="RESTRICT",
            name="fk_memory_write_decision_promotion",
        ),
        tenant_fk(
            "memory_entry_id",
            "memory_entry",
            ondelete="RESTRICT",
            name="fk_memory_write_decision_entry",
        ),
        tenant_fk(
            "incident_id",
            "incident",
            ondelete="RESTRICT",
            name="fk_memory_write_decision_incident",
        ),
        sa.CheckConstraint(
            "(outcome = 'rejected') = (promotion_id IS NULL)",
            name="refusal_creates_no_promotion",
        ),
        sa.CheckConstraint(
            "(outcome = 'approved') = (memory_entry_id IS NOT NULL)",
            name="only_approval_writes_memory",
        ),
        sa.Index("ix_memory_write_decision_time", "tenant_id", "created_at"),
    )


class Postmortem(Base, TenantScoped, TimestampMixin):
    """A cited postmortem draft.

    Cannot reach ``published`` without a named human reviewer: the constraint below makes
    autonomous publication impossible rather than merely discouraged.
    """

    __tablename__ = "postmortem"

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    content: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Event and evidence ids backing each claim. Uncited claims are stripped before the
    #: draft is written, so this is never empty for a non-trivial draft.
    citations: Mapped[list[Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    status: Mapped[PostmortemStatus] = mapped_column(
        enum_column(PostmortemStatus, "postmortem_status"),
        nullable=False,
        default=PostmortemStatus.DRAFT,
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("postmortem"),
        tenant_fk("incident_id", "incident", ondelete="CASCADE", name="fk_postmortem_incident"),
        tenant_fk(
            "reviewed_by_user_id",
            "app_user",
            ondelete="RESTRICT",
            name="fk_postmortem_reviewer",
        ),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_postmortem_incident"),
        sa.CheckConstraint(
            "status = 'draft' OR reviewed_by_user_id IS NOT NULL",
            name="reviewed_postmortem_names_reviewer",
        ),
        sa.Index("ix_postmortem_status", "tenant_id", "status"),
    )
