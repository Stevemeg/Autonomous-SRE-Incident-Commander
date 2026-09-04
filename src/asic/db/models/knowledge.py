"""Knowledge base, governed memory and postmortems.

All knowledge content is ``RETRIEVED`` provenance: human-authored text of unknown current
accuracy, and a known prompt-injection vector. It informs; it never authorises.

The promotion path is the important part. There is no automatic route from "this worked
once" to durable operational knowledge: :class:`MemoryPromotion` requires an approval, and
:class:`MemoryEntry` carries a ``support_count`` because a single incident is never
sufficient evidence for a general rule (master specification section 10, SI-12).
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
    ChunkStrategy,
    KnowledgeDocumentType,
    MemoryKind,
    MemoryPromotionStatus,
    PostmortemStatus,
    TrustClass,
)

#: Embedding width. A column-level constant because changing it is a re-index, not a
#: configuration tweak: every stored vector must have the same dimensionality.
EMBEDDING_DIMENSIONS = 1536


class KnowledgeDocument(Base, TenantScoped, TimestampMixin):
    """A source document: runbook, service doc, known error or postmortem.

    Versioned rather than overwritten (INV-14). A retrieval that cited version 3 must
    still be explicable after version 4 lands, and staleness must be visible rather than
    silently corrected.
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

    #: Scoping applied as query predicates *before* search, never as a post-filter.
    service_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=sa.text("'{}'::uuid[]")
    )
    environment_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=sa.text("'{}'::uuid[]")
    )
    #: Access-control labels, filtered on at query time (FR-KNW-03).
    acl_labels: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )

    #: Freshness is computed from these, never assumed.
    source_updated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    #: Change detection; avoids needless re-embedding.
    content_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Injection patterns found at ingestion. A recorded signal, not the defence.
    injection_flagged: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("false")
    )

    __table_args__ = (
        *tenant_identity_constraints("knowledge_document"),
        tenant_fk(
            "superseded_by_id",
            "knowledge_document",
            ondelete="SET NULL",
            name="fk_knowledge_document_superseded_by",
        ),
        sa.UniqueConstraint(
            "tenant_id", "source_uri", "version", name="uq_knowledge_document_version"
        ),
        sa.CheckConstraint("version >= 1", name="version_starts_at_one"),
        sa.CheckConstraint("superseded_by_id <> id", name="no_self_supersede"),
        sa.Index("ix_knowledge_document_type", "tenant_id", "document_type"),
        sa.Index(
            "ix_knowledge_document_current",
            "tenant_id",
            "document_type",
            postgresql_where=sa.text("superseded_by_id IS NULL"),
        ),
        sa.Index("ix_knowledge_document_services", "service_ids", postgresql_using="gin"),
    )


class KnowledgeChunk(Base, TenantScoped, CreatedAtMixin):
    """A retrievable unit of a document, with its embedding.

    ``embedding_model_id`` is stored per chunk because changing the embedding model is a
    versioned behaviour change requiring a re-index and a fresh retrieval evaluation - not
    a configuration edit that silently changes what the system retrieves.
    """

    __tablename__ = "knowledge_chunk"

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    sequence: Mapped[int] = mapped_column(sa.Integer, nullable=False)

    #: Sensitivity: CUSTOMER_CONTENT. Untrusted, delimited when placed in any prompt.
    text: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: Nullable so a chunk can exist before the embedding job runs, and so a re-index can
    #: proceed in batches without deleting retrievable content.
    embedding: Mapped[Any | None] = mapped_column(Vector(EMBEDDING_DIMENSIONS), nullable=True)
    embedding_model_id: Mapped[str | None] = mapped_column(sa.String(128), nullable=True)
    chunk_strategy: Mapped[ChunkStrategy] = mapped_column(
        enum_column(ChunkStrategy, "chunk_strategy"), nullable=False
    )
    token_count: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)

    #: Denormalised from the document so scope filtering is a single-table predicate on
    #: the hot retrieval path.
    service_ids: Mapped[list[uuid.UUID]] = mapped_column(
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=sa.text("'{}'::uuid[]")
    )
    acl_labels: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(64)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )

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


class MemoryEntry(Base, TenantScoped, TimestampMixin):
    """Durable operational memory: a verified outcome or a promoted operational fact.

    ``support_count`` is the guard against over-generalising from one incident. A count of
    one is never sufficient for automatic promotion, and the promotion itself still
    requires a human (SI-12).
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

    __table_args__ = (
        *tenant_identity_constraints("memory_entry"),
        tenant_fk(
            "superseded_by_id",
            "memory_entry",
            ondelete="SET NULL",
            name="fk_memory_entry_superseded_by",
        ),
        sa.CheckConstraint("support_count >= 1", name="support_count_positive"),
        sa.CheckConstraint("last_seen_at >= first_seen_at", name="seen_window_ordered"),
        sa.CheckConstraint("superseded_by_id <> id", name="no_self_supersede"),
        sa.Index("ix_memory_entry_lookup", "tenant_id", "root_cause_class", "is_active"),
        sa.Index("ix_memory_entry_context", "context_signature", postgresql_using="gin"),
    )


class MemoryPromotion(Base, TenantScoped, TimestampMixin):
    """A governed write into durable memory.

    ``approval_user_id`` is NOT NULL once approved, and no code path writes
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
        pg.ARRAY(pg.UUID(as_uuid=True)), nullable=False, server_default=sa.text("'{}'::uuid[]")
    )

    status: Mapped[MemoryPromotionStatus] = mapped_column(
        enum_column(MemoryPromotionStatus, "memory_promotion_status"),
        nullable=False,
        default=MemoryPromotionStatus.PROPOSED,
    )
    approver_user_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

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
        # A decided promotion names its human and when. SI-12 in constraint form.
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
        sa.Index("ix_memory_promotion_status", "tenant_id", "status"),
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
