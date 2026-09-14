"""Durable API mutation replay records."""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import Base, CreatedAtMixin, TenantScoped, tenant_identity_constraints, uuid_pk


class ApiIdempotencyRecord(Base, TenantScoped, CreatedAtMixin):
    """One immutable completed mutation response, unique per principal and key."""

    __tablename__ = "api_idempotency_record"
    __append_only__ = True

    id: Mapped[uuid.UUID] = uuid_pk()
    principal_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    operation: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    response_body: Mapped[dict[str, Any]] = mapped_column(pg.JSONB, nullable=False)

    __table_args__ = (
        *tenant_identity_constraints("api_idempotency_record"),
        sa.UniqueConstraint(
            "tenant_id", "principal_id", "idempotency_key", name="uq_api_idempotency_principal_key"
        ),
        sa.CheckConstraint("length(request_digest) = 64", name="request_digest_is_sha256"),
        sa.Index("ix_api_idempotency_created", "tenant_id", "created_at"),
    )


__all__ = ["ApiIdempotencyRecord"]
