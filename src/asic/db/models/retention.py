"""Durable receipts of the data-retention lifecycle executor (Phase 15, NFR-SEC-14).

One row per executed (or dry-run) batch: which tenant, which class and table, the cutoff the
tenant policy produced, whether a hold suspended it, how many rows were eligible and how many
were deleted, and who ran it. Written in the *same transaction* as the deletion it describes,
so a deletion without its receipt - or a receipt for a deletion that was rolled back - cannot
exist.

Append-only and protected evidence: the application runtime may read receipts; only the
separate ``asic_maintenance`` role may write them, and nothing may update or delete them.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import Base, CreatedAtMixin, TenantScoped, tenant_identity_constraints, uuid_pk


class RetentionRun(Base, TenantScoped, CreatedAtMixin):
    """One lifecycle batch and its outcome. Immutable."""

    __tablename__ = "retention_run"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Groups the batches of one executor invocation.
    execution_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    retention_class: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    table_name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    policy_days: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    cutoff: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    held: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    dry_run: Mapped[bool] = mapped_column(sa.Boolean, nullable=False)
    batch_limit: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    eligible_rows: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    deleted_rows: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    #: The maintenance identity that ran it (a service account name, never a credential).
    executed_by: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    reason: Mapped[str] = mapped_column(sa.String(256), nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("retention_run"),
        sa.CheckConstraint("deleted_rows >= 0 AND eligible_rows >= 0", name="counts_non_negative"),
        sa.CheckConstraint("NOT dry_run OR deleted_rows = 0", name="dry_run_deletes_nothing"),
        sa.CheckConstraint("NOT held OR deleted_rows = 0", name="held_deletes_nothing"),
        sa.CheckConstraint("deleted_rows <= batch_limit", name="deleted_within_batch"),
        sa.CheckConstraint("batch_limit BETWEEN 1 AND 10000", name="batch_limit_bounded"),
        sa.Index("ix_retention_run_execution", "tenant_id", "execution_id"),
    )


__all__ = ["RetentionRun"]
