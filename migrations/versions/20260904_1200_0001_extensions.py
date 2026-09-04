"""Required PostgreSQL extensions.

Separated from the schema migration because extensions are a database-level prerequisite
that a DBA may need to install by hand in an environment where the migration role is not
permitted to ``CREATE EXTENSION``.

Revision ID: 0001_extensions
Revises:
Create Date: 2026-09-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0001_extensions"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # pgvector: embedding storage for the knowledge base (ADR-0004). Declared now so the
    # column type exists when the schema migration runs, even though retrieval is Phase 6.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # gen_random_uuid() is built into PostgreSQL 13+, so pgcrypto is not required.
    # Recorded here so the absence is a decision rather than an oversight.


def downgrade() -> None:
    # Deliberately not dropped. Another schema in the same database may depend on it, and
    # dropping an extension cascades to every column using its types.
    pass
