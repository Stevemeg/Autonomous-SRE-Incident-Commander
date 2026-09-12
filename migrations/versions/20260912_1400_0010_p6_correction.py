"""Phase 6 correction: access-management permission, and validating governance constraints.

Two independent corrections, bundled because both are Phase 6 governance follow-ups and
both are forward-only, additive changes over the current head:

1. **P6-04.** ``KnowledgeIngestionService.update_source_access`` now requires the caller to
   hold ``knowledge.source.access.manage`` through a current role assignment, the same
   pattern migration 0008 used for ``memory.promotion.decide``. This migration seeds the
   permission; nothing here grants it to anyone; grants are administrative data.

2. **P6-08.** Migration 0008 added four governance constraints ``NOT VALID`` (rows written
   before Phase 6 could not have Phase-6-only pipeline provenance, so grandfathering them
   was the correct move *then*): ``knowledge_document.versioned_source``,
   ``knowledge_chunk.located_chunk``, ``memory_entry.governed_entry`` and
   ``memory_promotion.governed_promotion``. Its own docstring recorded that no such legacy
   row was known to exist in any database at the time. This migration does not take that on
   faith: for each constraint it counts rows that would fail it *before* validating, using
   the constraint's own stored definition (``pg_get_constraintdef``) rather than a
   hand-copied condition string that could quietly drift from what is actually enforced.
   Zero violations validates immediately; any violation refuses the migration outright with
   the count and the constraint, because there is no safe, honest way to backfill
   Phase-6-only pipeline metadata (parser version, chunker version, embedding model, chunk
   offsets, ...) for a row a pre-Phase-6 pipeline wrote - inventing it would misrepresent
   history, which is exactly what ADR-0018 forbids. A future migration would need to either
   supersede/revoke those specific rows first or extend the constraint with an explicit,
   reviewed exemption - not blindly validate over them.

Migration 0008 remains unmodified, per ADR-0018; this is a new, independent revision.

Revision ID: 0010_p6_correction
Revises: 0009_phase5_cleanup
Create Date: 2026-09-12 14:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_p6_correction"
down_revision: str | None = "0009_phase5_cleanup"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACCESS_MANAGE_PERMISSION_KEY = "knowledge.source.access.manage"

#: (table, constraint name, condition literal - kept identical to migration 0008's, per
#: ADR-0018's literal-values discipline, and used only for `downgrade`'s NOT VALID
#: re-creation; `upgrade` reads the live definition back from the catalogue instead of
#: trusting this copy, so the two can never silently diverge in the direction that matters).
_GOVERNANCE_CONSTRAINTS: tuple[tuple[str, str, str], ...] = (
    (
        "knowledge_document",
        "ck_knowledge_document_versioned_source",
        "source_id IS NOT NULL AND content_format IS NOT NULL AND parser_version IS NOT NULL"
        " AND chunker_version IS NOT NULL AND embedding_model_id IS NOT NULL"
        " AND embedding_dimensions IS NOT NULL AND byte_size IS NOT NULL"
        " AND chunk_count IS NOT NULL",
    ),
    (
        "knowledge_chunk",
        "ck_knowledge_chunk_located_chunk",
        "content_hash IS NOT NULL AND start_offset IS NOT NULL AND end_offset IS NOT NULL"
        " AND start_line IS NOT NULL AND end_line IS NOT NULL AND char_count IS NOT NULL"
        " AND embedding IS NOT NULL",
    ),
    (
        "memory_entry",
        "ck_memory_entry_governed_entry",
        "provenance IS NOT NULL AND verification_status IS NOT NULL"
        " AND promotion_id IS NOT NULL AND policy_version IS NOT NULL",
    ),
    (
        "memory_promotion",
        "ck_memory_promotion_governed_promotion",
        "category IS NOT NULL AND origin_provenance IS NOT NULL AND proposal_key IS NOT NULL"
        " AND proposed_by_type IS NOT NULL AND policy_version IS NOT NULL",
    ),
)


def _constraint_expression(conn: sa.Connection, table: str, constraint: str) -> str:
    """The condition Postgres actually enforces, read back from the catalogue.

    Not the literal above: if migration 0008's constraint were ever altered by some other
    path, validating against a stale hand-copied condition would prove the wrong thing.
    """
    definition = conn.execute(
        sa.text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
            " WHERE conname = :name AND conrelid = CAST(:table AS regclass)"
        ),
        {"name": constraint, "table": table},
    ).scalar_one()
    # A NOT VALID constraint's definition is "CHECK ((expr)) NOT VALID"; a validated one
    # (if this ever re-runs after validating) is just "CHECK ((expr))". Strip the trailing
    # marker first, then exactly one layer of "CHECK ( ... )" - the remaining outer
    # parenthesisation around ``expr`` is harmless inside ``WHERE NOT (...)`` regardless of
    # how many parentheses the expression itself contains.
    inner = definition.removesuffix(" NOT VALID")
    inner = inner.removeprefix("CHECK (").removesuffix(")")
    return inner


def upgrade() -> None:
    conn = op.get_bind()

    # ---------------------------------------------------------------------- P6-04
    op.execute(
        "INSERT INTO permission (id, key, description, resource, action) VALUES ("
        f"gen_random_uuid(), '{ACCESS_MANAGE_PERMISSION_KEY}', "
        "'Change a knowledge source''s access policy: service scope, environment scope, "
        "or ACL labels.', 'knowledge_source', 'access_manage'"
        ") ON CONFLICT (key) DO NOTHING"
    )

    # ---------------------------------------------------------------------- P6-08
    for table, constraint, _literal in _GOVERNANCE_CONSTRAINTS:
        expr = _constraint_expression(conn, table, constraint)
        violating = conn.execute(
            sa.text(f"SELECT count(*) FROM {table} WHERE NOT ({expr})")
        ).scalar_one()
        if violating:
            raise RuntimeError(
                f"{table}.{constraint}: {violating} retained row(s) do not satisfy this "
                "Phase 6 governance constraint (added NOT VALID by migration 0008). There "
                "is no safe way to backfill Phase-6-only pipeline provenance for a "
                "pre-Phase-6 row, so this migration refuses to validate blindly. "
                "Remediate (supersede or revoke) the affected rows, or extend the "
                "constraint with a reviewed, explicit exemption, before re-running this "
                "migration."
            )
        op.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {constraint}")


def downgrade() -> None:
    # VALIDATE CONSTRAINT has no inverse in PostgreSQL: a validated CHECK constraint and a
    # freshly-added NOT VALID one enforce identically for every row from this point
    # forward, and Postgres has no "believe it again as NOT VALID" operation. The closest
    # honest downgrade is drop-and-re-add NOT VALID, which restores the exact state
    # migration 0008 left: enforced for new/updated rows, not retroactively checked.
    for table, constraint, literal in _GOVERNANCE_CONSTRAINTS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {constraint}")
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {constraint} CHECK ({literal}) NOT VALID")

    op.execute(f"DELETE FROM permission WHERE key = '{ACCESS_MANAGE_PERMISSION_KEY}'")
