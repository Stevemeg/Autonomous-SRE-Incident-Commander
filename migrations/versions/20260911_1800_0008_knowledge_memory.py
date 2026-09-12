"""Operational knowledge, retrieval records and governed memory.

Phase 6. Reuses the Phase 3 knowledge and memory tables and adds only what they could not
express: a stable source identity with its access policy, version lifecycle and pipeline
provenance, citation locations on chunks, append-only ingestion and retrieval records, and
the governance columns that make memory writes auditable.

Three properties are enforced by the database rather than left to application code:

* **Knowledge is not rewritten (INV-14).** The application role keeps column-level
  ``UPDATE`` on lifecycle fields only; chunk text, hashes and embeddings cannot be changed
  by it at all, and nothing can be deleted.
* **Memory confers no authority.** A memory entry may carry ``retrieved``, ``model_claim``
  or ``verified_fact`` provenance and nothing else, and ``verified_fact`` requires a
  verification record.
* **Every write decision is kept.** Ingestion attempts, retrievals and memory decisions are
  append-only.

Governance checks on the pre-existing tables are added ``NOT VALID``: rows written before
this migration (none exist in any known database) are not retroactively rejected, and every
row written or updated from now on must satisfy them.

Table and value lists are literal, per ADR-0018.

Revision ID: 0008_knowledge_memory
Revises: 0007_phase5_hardening
Create Date: 2026-09-11 18:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_knowledge_memory"
down_revision: str | None = "0007_phase5_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "asic_app"
AUDITOR_ROLE = "asic_auditor"

#: Tenant-scoped tables created here.
TENANT_TABLES = (
    "knowledge_source",
    "knowledge_ingestion",
    "knowledge_retrieval",
    "knowledge_retrieval_result",
    "memory_write_decision",
)

#: Of those, the ones whose rows are history and never change.
APPEND_ONLY_TABLES = (
    "knowledge_ingestion",
    "knowledge_retrieval",
    "knowledge_retrieval_result",
    "memory_write_decision",
)

#: The only columns the application role may update on these tables.
UPDATABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "knowledge_source": (
        "status",
        "status_reason",
        "status_changed_at",
        "service_ids",
        "environment_ids",
        "acl_labels",
        "review_interval_days",
        "updated_at",
    ),
    "knowledge_document": ("lifecycle", "superseded_by_id", "superseded_at", "updated_at"),
    "memory_entry": ("is_active", "superseded_by_id", "updated_at"),
    "memory_promotion": (
        "status",
        "approver_user_id",
        "decided_at",
        "decision_note",
        "memory_entry_id",
        "updated_at",
    ),
}

#: Pre-existing tables whose rows become fully immutable to the application.
IMMUTABLE_TABLES = ("knowledge_chunk",)

NEW_ENUMS: dict[str, tuple[str, ...]] = {
    "knowledge_source_status": ("active", "revoked", "deleted"),
    "knowledge_version_state": ("current", "superseded", "revoked"),
    "knowledge_content_format": ("markdown", "text", "html"),
    "knowledge_ingestion_outcome": ("created", "unchanged", "rejected", "failed"),
    "retrieval_principal_kind": ("investigation", "user", "service"),
    "memory_category": (
        "working_state",
        "operational_knowledge",
        "incident_history",
        "verified_outcome",
        "model_inference",
    ),
    "memory_verification_status": ("verified", "unverified"),
    "memory_decision_outcome": ("proposed", "rejected", "approved", "declined"),
}

#: Pre-existing enum types referenced by new columns, with their values at this revision.
EXISTING_ENUMS: dict[str, tuple[str, ...]] = {
    "actor_type": ("human", "agent_node", "system", "external_system"),
    "knowledge_document_type": ("runbook", "service_doc", "known_error", "postmortem"),
    "trust_class": (
        "official_runbook",
        "service_documentation",
        "historical_postmortem",
        "community",
    ),
    "provenance_label": ("system", "human", "verified_fact", "retrieved", "model_claim"),
}

MEMORY_PERMISSION_KEY = "memory.promotion.decide"

_MEMORY_PROVENANCE = "('retrieved', 'model_claim', 'verified_fact')"


def _enum(name: str) -> postgresql.ENUM:
    values = NEW_ENUMS.get(name) or EXISTING_ENUMS[name]
    return postgresql.ENUM(*values, name=name, create_type=False)


def _uuid_array() -> postgresql.ARRAY:
    return postgresql.ARRAY(sa.UUID())


def _label_array(length: int = 64) -> postgresql.ARRAY:
    return postgresql.ARRAY(sa.String(length=length))


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
    )


def _tenant_columns(table: str) -> tuple[sa.Column, sa.ForeignKeyConstraint]:
    return (
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            name=op.f(f"fk_{table}_tenant_id_tenant"),
            ondelete="RESTRICT",
        ),
    )


def _composite_fk(
    name: str, column: str, target: str, *, ondelete: str = "RESTRICT"
) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id", column],
        [f"{target}.tenant_id", f"{target}.id"],
        name=name,
        ondelete=ondelete,
    )


def _not_valid_check(table: str, name: str, condition: str) -> None:
    op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({condition}) NOT VALID")


def upgrade() -> None:
    bind = op.get_bind()
    for name, values in NEW_ENUMS.items():
        postgresql.ENUM(*values, name=name).create(bind, checkfirst=False)

    # ------------------------------------------------------------ knowledge_source
    tenant_col, tenant_fk = _tenant_columns("knowledge_source")
    op.create_table(
        "knowledge_source",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("source_ref", sa.String(length=900), nullable=False),
        sa.Column("document_type", _enum("knowledge_document_type"), nullable=False),
        sa.Column("trust_class", _enum("trust_class"), nullable=False),
        sa.Column(
            "service_ids", _uuid_array(), server_default=sa.text("'{}'::uuid[]"), nullable=False
        ),
        sa.Column(
            "environment_ids",
            _uuid_array(),
            server_default=sa.text("'{}'::uuid[]"),
            nullable=False,
        ),
        sa.Column(
            "acl_labels", _label_array(), server_default=sa.text("'{}'::varchar[]"), nullable=False
        ),
        sa.Column("review_interval_days", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            _enum("knowledge_source_status"),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column("status_reason", sa.String(length=64), nullable=True),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_type", _enum("actor_type"), nullable=False),
        sa.Column("created_by_id", sa.String(length=128), nullable=True),
        tenant_col,
        _created_at(),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "review_interval_days IS NULL OR review_interval_days BETWEEN 1 AND 3650",
            name=op.f("ck_knowledge_source_review_interval_bounded"),
        ),
        sa.CheckConstraint(
            "status = 'active' OR (status_reason IS NOT NULL AND status_changed_at IS NOT NULL)",
            name=op.f("ck_knowledge_source_inactive_source_records_why"),
        ),
        sa.CheckConstraint(
            "cardinality(acl_labels) <= 32 AND cardinality(service_ids) <= 64"
            " AND cardinality(environment_ids) <= 16",
            name=op.f("ck_knowledge_source_scope_bounded"),
        ),
        tenant_fk,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_source")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_knowledge_source_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "provider", "source_ref", name="uq_knowledge_source_identity"
        ),
    )
    op.create_index(op.f("ix_knowledge_source_tenant_id"), "knowledge_source", ["tenant_id"])
    op.create_index("ix_knowledge_source_status", "knowledge_source", ["tenant_id", "status"])

    # ---------------------------------------------------- knowledge_document (versions)
    op.add_column("knowledge_document", sa.Column("source_id", sa.UUID(), nullable=True))
    op.add_column(
        "knowledge_document",
        sa.Column(
            "lifecycle",
            _enum("knowledge_version_state"),
            server_default=sa.text("'current'"),
            nullable=False,
        ),
    )
    op.add_column(
        "knowledge_document",
        sa.Column("content_format", _enum("knowledge_content_format"), nullable=True),
    )
    op.add_column(
        "knowledge_document", sa.Column("source_revision", sa.String(length=128), nullable=True)
    )
    op.add_column(
        "knowledge_document", sa.Column("parser_version", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "knowledge_document", sa.Column("chunker_version", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "knowledge_document",
        sa.Column("embedding_model_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "knowledge_document", sa.Column("embedding_dimensions", sa.Integer(), nullable=True)
    )
    op.add_column("knowledge_document", sa.Column("byte_size", sa.Integer(), nullable=True))
    op.add_column("knowledge_document", sa.Column("chunk_count", sa.Integer(), nullable=True))
    op.add_column(
        "knowledge_document",
        sa.Column(
            "effective_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column(
        "knowledge_document",
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "knowledge_document", sa.Column("fresh_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_foreign_key(
        "fk_knowledge_document_source",
        "knowledge_document",
        "knowledge_source",
        ["tenant_id", "source_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "uq_knowledge_document_source_version",
        "knowledge_document",
        ["tenant_id", "source_id", "version"],
    )
    op.create_check_constraint(
        op.f("ck_knowledge_document_superseded_version_has_timestamp"),
        "knowledge_document",
        "lifecycle <> 'superseded' OR superseded_at IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_knowledge_document_successor_implies_not_current"),
        "knowledge_document",
        "superseded_by_id IS NULL OR lifecycle <> 'current'",
    )
    op.create_check_constraint(
        op.f("ck_knowledge_document_sizes_non_negative"),
        "knowledge_document",
        "(chunk_count IS NULL OR chunk_count >= 0) AND (byte_size IS NULL OR byte_size >= 0)",
    )
    _not_valid_check(
        "knowledge_document",
        "ck_knowledge_document_versioned_source",
        "source_id IS NOT NULL AND content_format IS NOT NULL AND parser_version IS NOT NULL"
        " AND chunker_version IS NOT NULL AND embedding_model_id IS NOT NULL"
        " AND embedding_dimensions IS NOT NULL AND byte_size IS NOT NULL"
        " AND chunk_count IS NOT NULL",
    )
    op.create_index(
        "uq_knowledge_document_current_source",
        "knowledge_document",
        ["tenant_id", "source_id"],
        unique=True,
        postgresql_where=sa.text("lifecycle = 'current' AND source_id IS NOT NULL"),
    )

    # -------------------------------------------------------------- knowledge_chunk
    op.add_column("knowledge_chunk", sa.Column("content_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "knowledge_chunk",
        sa.Column(
            "section_path",
            _label_array(200),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
    )
    for column in ("start_offset", "end_offset", "start_line", "end_line", "char_count"):
        op.add_column("knowledge_chunk", sa.Column(column, sa.Integer(), nullable=True))
    op.create_check_constraint(
        op.f("ck_knowledge_chunk_location_ordered"),
        "knowledge_chunk",
        "start_offset IS NULL OR (start_offset >= 0 AND end_offset > start_offset"
        " AND start_line >= 1 AND end_line >= start_line)",
    )
    op.create_check_constraint(
        op.f("ck_knowledge_chunk_section_depth_bounded"),
        "knowledge_chunk",
        "cardinality(section_path) <= 6",
    )
    _not_valid_check(
        "knowledge_chunk",
        "ck_knowledge_chunk_located_chunk",
        "content_hash IS NOT NULL AND start_offset IS NOT NULL AND end_offset IS NOT NULL"
        " AND start_line IS NOT NULL AND end_line IS NOT NULL AND char_count IS NOT NULL"
        " AND embedding IS NOT NULL",
    )

    # ---------------------------------------------------------- knowledge_ingestion
    tenant_col, tenant_fk = _tenant_columns("knowledge_ingestion")
    op.create_table(
        "knowledge_ingestion",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=True),
        sa.Column("document_version_id", sa.UUID(), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("source_ref", sa.String(length=900), nullable=False),
        sa.Column("outcome", _enum("knowledge_ingestion_outcome"), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("raw_digest", sa.String(length=64), nullable=False),
        sa.Column("source_revision", sa.String(length=128), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=True),
        sa.Column("parser_version", sa.String(length=64), nullable=True),
        sa.Column("chunker_version", sa.String(length=64), nullable=True),
        sa.Column("embedding_model_id", sa.String(length=128), nullable=True),
        sa.Column("actor_type", _enum("actor_type"), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=False),
        tenant_col,
        _created_at(),
        sa.CheckConstraint(
            "(outcome IN ('created', 'unchanged')) = (document_version_id IS NOT NULL)",
            name=op.f("ck_knowledge_ingestion_committed_outcome_names_version"),
        ),
        sa.CheckConstraint(
            "byte_size >= 0", name=op.f("ck_knowledge_ingestion_byte_size_non_negative")
        ),
        _composite_fk("fk_knowledge_ingestion_source", "source_id", "knowledge_source"),
        _composite_fk(
            "fk_knowledge_ingestion_version", "document_version_id", "knowledge_document"
        ),
        tenant_fk,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_ingestion")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_knowledge_ingestion_tenant_id_id"),
    )
    op.create_index(op.f("ix_knowledge_ingestion_tenant_id"), "knowledge_ingestion", ["tenant_id"])
    op.create_index(
        "ix_knowledge_ingestion_source",
        "knowledge_ingestion",
        ["tenant_id", "source_id", "created_at"],
    )

    # ---------------------------------------------------------- knowledge_retrieval
    tenant_col, tenant_fk = _tenant_columns("knowledge_retrieval")
    op.create_table(
        "knowledge_retrieval",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("principal_kind", _enum("retrieval_principal_kind"), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column(
            "clearances", _label_array(), server_default=sa.text("'{}'::varchar[]"), nullable=False
        ),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("workflow_run_id", sa.UUID(), nullable=True),
        sa.Column("tool_execution_id", sa.UUID(), nullable=True),
        sa.Column("evidence_id", sa.UUID(), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        sa.Column("idempotency_key", sa.String(length=64), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("embedding_model_id", sa.String(length=128), nullable=False),
        sa.Column("embedding_dimensions", sa.Integer(), nullable=False),
        sa.Column("query_text", sa.String(length=512), nullable=False),
        sa.Column("query_digest", sa.String(length=64), nullable=False),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("include_stale", sa.Boolean(), nullable=False),
        sa.Column("eligible_chunks", sa.Integer(), nullable=False),
        sa.Column("lexical_matches", sa.Integer(), nullable=False),
        sa.Column("vector_candidates", sa.Integer(), nullable=False),
        sa.Column("excluded", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        tenant_col,
        _created_at(),
        sa.CheckConstraint(
            "eligible_chunks >= 0 AND lexical_matches >= 0 AND vector_candidates >= 0"
            " AND result_count >= 0 AND latency_ms >= 0",
            name=op.f("ck_knowledge_retrieval_counts_non_negative"),
        ),
        _composite_fk("fk_knowledge_retrieval_incident", "incident_id", "incident"),
        _composite_fk("fk_knowledge_retrieval_run", "workflow_run_id", "workflow_run"),
        _composite_fk(
            "fk_knowledge_retrieval_tool_execution", "tool_execution_id", "tool_execution"
        ),
        _composite_fk("fk_knowledge_retrieval_evidence", "evidence_id", "evidence"),
        tenant_fk,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_retrieval")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_knowledge_retrieval_tenant_id_id"),
    )
    op.create_index(op.f("ix_knowledge_retrieval_tenant_id"), "knowledge_retrieval", ["tenant_id"])
    op.create_index(
        "ix_knowledge_retrieval_tool_execution",
        "knowledge_retrieval",
        ["tenant_id", "tool_execution_id"],
    )
    op.create_index(
        "ix_knowledge_retrieval_incident", "knowledge_retrieval", ["tenant_id", "incident_id"]
    )

    # --------------------------------------------------- knowledge_retrieval_result
    tenant_col, tenant_fk = _tenant_columns("knowledge_retrieval_result")
    op.create_table(
        "knowledge_retrieval_result",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("retrieval_id", sa.UUID(), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("chunk_id", sa.UUID(), nullable=False),
        sa.Column("document_version_id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=False),
        sa.Column("lexical_rank", sa.Integer(), nullable=True),
        sa.Column("lexical_score", postgresql.DOUBLE_PRECISION(), nullable=True),
        sa.Column("vector_rank", sa.Integer(), nullable=True),
        sa.Column("vector_similarity", postgresql.DOUBLE_PRECISION(), nullable=True),
        sa.Column("fused_score", postgresql.DOUBLE_PRECISION(), nullable=False),
        sa.Column("stale", sa.Boolean(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        tenant_col,
        _created_at(),
        sa.CheckConstraint("rank >= 1", name=op.f("ck_knowledge_retrieval_result_rank_positive")),
        sa.CheckConstraint(
            "lexical_rank IS NOT NULL OR vector_rank IS NOT NULL",
            name=op.f("ck_knowledge_retrieval_result_result_has_a_signal"),
        ),
        _composite_fk(
            "fk_knowledge_retrieval_result_retrieval", "retrieval_id", "knowledge_retrieval"
        ),
        _composite_fk("fk_knowledge_retrieval_result_chunk", "chunk_id", "knowledge_chunk"),
        _composite_fk(
            "fk_knowledge_retrieval_result_version", "document_version_id", "knowledge_document"
        ),
        _composite_fk("fk_knowledge_retrieval_result_source", "source_id", "knowledge_source"),
        tenant_fk,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_retrieval_result")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_knowledge_retrieval_result_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "retrieval_id", "rank", name="uq_knowledge_retrieval_result_rank"
        ),
        sa.UniqueConstraint(
            "tenant_id", "retrieval_id", "chunk_id", name="uq_knowledge_retrieval_result_chunk"
        ),
    )
    op.create_index(
        op.f("ix_knowledge_retrieval_result_tenant_id"),
        "knowledge_retrieval_result",
        ["tenant_id"],
    )

    # ------------------------------------------------------------------ memory_entry
    op.add_column("memory_entry", sa.Column("provenance", _enum("provenance_label"), nullable=True))
    op.add_column(
        "memory_entry",
        sa.Column("verification_status", _enum("memory_verification_status"), nullable=True),
    )
    op.add_column("memory_entry", sa.Column("promotion_id", sa.UUID(), nullable=True))
    op.add_column("memory_entry", sa.Column("verification_id", sa.UUID(), nullable=True))
    op.add_column(
        "memory_entry",
        sa.Column(
            "source_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("memory_entry", sa.Column("policy_version", sa.String(length=64), nullable=True))
    op.add_column(
        "memory_entry",
        sa.Column(
            "effective_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column(
        "memory_entry", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_foreign_key(
        "fk_memory_entry_promotion",
        "memory_entry",
        "memory_promotion",
        ["tenant_id", "promotion_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_memory_entry_verification",
        "memory_entry",
        "verification",
        ["tenant_id", "verification_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "uq_memory_entry_promotion", "memory_entry", ["tenant_id", "promotion_id"]
    )
    op.create_check_constraint(
        op.f("ck_memory_entry_memory_confers_no_authority"),
        "memory_entry",
        f"provenance IS NULL OR provenance IN {_MEMORY_PROVENANCE}",
    )
    op.create_check_constraint(
        op.f("ck_memory_entry_verified_fact_only_for_outcomes"),
        "memory_entry",
        "provenance IS NULL OR ((provenance = 'verified_fact') = (kind = 'verified_outcome'))",
    )
    op.create_check_constraint(
        op.f("ck_memory_entry_verified_status_matches_provenance"),
        "memory_entry",
        "verification_status IS NULL"
        " OR ((verification_status = 'verified') = (provenance = 'verified_fact'))",
    )
    op.create_check_constraint(
        op.f("ck_memory_entry_verified_entry_names_verification"),
        "memory_entry",
        "verification_status IS NULL OR verification_status <> 'verified'"
        " OR verification_id IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_memory_entry_expiry_after_effect"),
        "memory_entry",
        "expires_at IS NULL OR expires_at > effective_at",
    )
    _not_valid_check(
        "memory_entry",
        "ck_memory_entry_governed_entry",
        "provenance IS NOT NULL AND verification_status IS NOT NULL"
        " AND promotion_id IS NOT NULL AND policy_version IS NOT NULL",
    )

    # -------------------------------------------------------------- memory_promotion
    op.add_column(
        "memory_promotion", sa.Column("category", _enum("memory_category"), nullable=True)
    )
    op.add_column(
        "memory_promotion",
        sa.Column("origin_provenance", _enum("provenance_label"), nullable=True),
    )
    op.add_column(
        "memory_promotion", sa.Column("proposal_key", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "memory_promotion", sa.Column("proposed_by_type", _enum("actor_type"), nullable=True)
    )
    op.add_column(
        "memory_promotion", sa.Column("proposed_by_id", sa.String(length=128), nullable=True)
    )
    for column in ("verification_ids", "evidence_ids"):
        op.add_column(
            "memory_promotion",
            sa.Column(
                column, _uuid_array(), server_default=sa.text("'{}'::uuid[]"), nullable=False
            ),
        )
    op.add_column(
        "memory_promotion",
        sa.Column(
            "knowledge_citations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "memory_promotion", sa.Column("policy_version", sa.String(length=64), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_memory_promotion_proposal_origin_confers_no_authority"),
        "memory_promotion",
        f"origin_provenance IS NULL OR origin_provenance IN {_MEMORY_PROVENANCE}",
    )
    op.create_check_constraint(
        op.f("ck_memory_promotion_verified_outcome_cites_verification"),
        "memory_promotion",
        "category IS NULL OR target_kind <> 'verified_outcome'"
        " OR cardinality(verification_ids) >= 1",
    )
    op.create_check_constraint(
        op.f("ck_memory_promotion_approver_is_not_proposer"),
        "memory_promotion",
        "approver_user_id IS NULL OR proposed_by_id IS NULL"
        " OR proposed_by_id <> approver_user_id::text",
    )
    op.create_check_constraint(
        op.f("ck_memory_promotion_references_bounded"),
        "memory_promotion",
        "cardinality(verification_ids) <= 32 AND cardinality(evidence_ids) <= 64",
    )
    _not_valid_check(
        "memory_promotion",
        "ck_memory_promotion_governed_promotion",
        "category IS NOT NULL AND origin_provenance IS NOT NULL AND proposal_key IS NOT NULL"
        " AND proposed_by_type IS NOT NULL AND policy_version IS NOT NULL",
    )
    op.create_index(
        "uq_memory_promotion_open_proposal",
        "memory_promotion",
        ["tenant_id", "proposal_key"],
        unique=True,
        postgresql_where=sa.text("status = 'proposed' AND proposal_key IS NOT NULL"),
    )

    # ------------------------------------------------------------ memory_write_decision
    tenant_col, tenant_fk = _tenant_columns("memory_write_decision")
    op.create_table(
        "memory_write_decision",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("category", _enum("memory_category"), nullable=False),
        sa.Column("outcome", _enum("memory_decision_outcome"), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("actor_type", _enum("actor_type"), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("promotion_id", sa.UUID(), nullable=True),
        sa.Column("memory_entry_id", sa.UUID(), nullable=True),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("references_digest", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        tenant_col,
        _created_at(),
        sa.CheckConstraint(
            "(outcome = 'rejected') = (promotion_id IS NULL)",
            name=op.f("ck_memory_write_decision_refusal_creates_no_promotion"),
        ),
        sa.CheckConstraint(
            "(outcome = 'approved') = (memory_entry_id IS NOT NULL)",
            name=op.f("ck_memory_write_decision_only_approval_writes_memory"),
        ),
        _composite_fk("fk_memory_write_decision_promotion", "promotion_id", "memory_promotion"),
        _composite_fk("fk_memory_write_decision_entry", "memory_entry_id", "memory_entry"),
        _composite_fk("fk_memory_write_decision_incident", "incident_id", "incident"),
        tenant_fk,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memory_write_decision")),
        sa.UniqueConstraint("tenant_id", "id", name="uq_memory_write_decision_tenant_id_id"),
    )
    op.create_index(
        op.f("ix_memory_write_decision_tenant_id"), "memory_write_decision", ["tenant_id"]
    )
    op.create_index(
        "ix_memory_write_decision_time", "memory_write_decision", ["tenant_id", "created_at"]
    )

    # ------------------------------------------------------ isolation and privileges
    for table in TENANT_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")
        op.execute(f"GRANT SELECT ON {table} TO {AUDITOR_ROLE}")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app.current_tenant_id()) "
            "WITH CHECK (tenant_id = app.current_tenant_id())"
        )
    for table in APPEND_ONLY_TABLES:
        op.execute(f"REVOKE UPDATE, DELETE ON {table} FROM {APP_ROLE}")
    for table in IMMUTABLE_TABLES:
        op.execute(f"REVOKE UPDATE, DELETE ON {table} FROM {APP_ROLE}")
    for table, columns in UPDATABLE_COLUMNS.items():
        op.execute(f"REVOKE UPDATE, DELETE ON {table} FROM {APP_ROLE}")
        op.execute(f"GRANT UPDATE ({', '.join(columns)}) ON {table} TO {APP_ROLE}")

    # The single permission a human needs to decide a memory promotion. Roles that carry
    # it are tenant administration (Phase 9); seeding the permission itself is platform data.
    op.execute(
        "INSERT INTO permission (id, key, description, resource, action) VALUES ("
        f"gen_random_uuid(), '{MEMORY_PERMISSION_KEY}', "
        "'Approve or decline a proposal to write durable operational memory.', "
        "'memory', 'decide') ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    # Refuse to erase knowledge versions, retrieval history or memory decisions. Nothing
    # here weakens a constraint so that a downgrade can succeed.
    op.execute("SET LOCAL row_security = off")
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM knowledge_source)
           OR EXISTS (SELECT 1 FROM knowledge_ingestion)
           OR EXISTS (SELECT 1 FROM knowledge_retrieval)
           OR EXISTS (SELECT 1 FROM memory_write_decision)
           OR EXISTS (SELECT 1 FROM knowledge_document WHERE source_id IS NOT NULL)
           OR EXISTS (SELECT 1 FROM memory_entry WHERE promotion_id IS NOT NULL)
           OR EXISTS (SELECT 1 FROM memory_promotion WHERE category IS NOT NULL)
        THEN RAISE EXCEPTION 'Phase 6 knowledge or memory history exists; downgrade refused';
        END IF;
        END $$""")

    for table, columns in UPDATABLE_COLUMNS.items():
        if table in TENANT_TABLES:
            continue
        op.execute(f"REVOKE UPDATE ({', '.join(columns)}) ON {table} FROM {APP_ROLE}")
        op.execute(f"GRANT UPDATE, DELETE ON {table} TO {APP_ROLE}")
    for table in IMMUTABLE_TABLES:
        op.execute(f"GRANT UPDATE, DELETE ON {table} TO {APP_ROLE}")
    op.execute(f"DELETE FROM permission WHERE key = '{MEMORY_PERMISSION_KEY}'")

    op.drop_table("memory_write_decision")

    op.drop_index("uq_memory_promotion_open_proposal", table_name="memory_promotion")
    for column in (
        "policy_version",
        "knowledge_citations",
        "evidence_ids",
        "verification_ids",
        "proposed_by_id",
        "proposed_by_type",
        "proposal_key",
        "origin_provenance",
        "category",
    ):
        op.drop_column("memory_promotion", column)

    op.drop_constraint("uq_memory_entry_promotion", "memory_entry", type_="unique")
    op.drop_constraint("fk_memory_entry_verification", "memory_entry", type_="foreignkey")
    op.drop_constraint("fk_memory_entry_promotion", "memory_entry", type_="foreignkey")
    for column in (
        "expires_at",
        "effective_at",
        "policy_version",
        "source_refs",
        "verification_id",
        "promotion_id",
        "verification_status",
        "provenance",
    ):
        op.drop_column("memory_entry", column)

    op.drop_table("knowledge_retrieval_result")
    op.drop_table("knowledge_retrieval")
    op.drop_table("knowledge_ingestion")

    for column in (
        "char_count",
        "end_line",
        "start_line",
        "end_offset",
        "start_offset",
        "section_path",
        "content_hash",
    ):
        op.drop_column("knowledge_chunk", column)

    op.drop_index("uq_knowledge_document_current_source", table_name="knowledge_document")
    op.drop_constraint("uq_knowledge_document_source_version", "knowledge_document", type_="unique")
    op.drop_constraint("fk_knowledge_document_source", "knowledge_document", type_="foreignkey")
    for column in (
        "fresh_until",
        "superseded_at",
        "effective_at",
        "chunk_count",
        "byte_size",
        "embedding_dimensions",
        "embedding_model_id",
        "chunker_version",
        "parser_version",
        "source_revision",
        "content_format",
        "lifecycle",
        "source_id",
    ):
        op.drop_column("knowledge_document", column)

    op.drop_table("knowledge_source")

    for name in reversed(tuple(NEW_ENUMS)):
        op.execute(f"DROP TYPE IF EXISTS {name}")
