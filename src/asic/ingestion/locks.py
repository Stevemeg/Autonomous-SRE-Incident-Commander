"""Stable PostgreSQL advisory-lock domains for ingestion coordination."""

from __future__ import annotations

import hashlib
from typing import Final
from uuid import UUID

INGESTION_TENANT_LOCK_NAMESPACE: Final[str] = "asic.ingestion.tenant.v1"


def advisory_lock_key(namespace: str, tenant_id: UUID) -> tuple[int, int]:
    """Return PostgreSQL's two signed-int32 advisory key with explicit domain separation."""
    namespace_key = int.from_bytes(
        hashlib.sha256(namespace.encode("utf-8")).digest()[:4], "big", signed=True
    )
    tenant_key = int.from_bytes(hashlib.sha256(tenant_id.bytes).digest()[:4], "big", signed=True)
    return namespace_key, tenant_key


__all__ = ["INGESTION_TENANT_LOCK_NAMESPACE", "advisory_lock_key"]
