"""The retention lifecycle executor (Phase 15, NFR-SEC-14): bounded, tenant-bound, receipted.

The decision recorded in docs/security/DATA_RETENTION.md: early enterprise operation needs an
executor for data whose value genuinely expires, but only where deletion cannot break
evidence, replay, verification lineage or memory governance. Exactly one class qualifies
today - the API idempotency replay cache - and this module deletes nothing else. Every other
class stays with ``plan_retention``'s ``retain``/``held``/``owner_lifecycle`` answer; their
deletion prerequisites (lineage-aware cascades, backup/PITR coordination, legal-hold
integration) are listed in the production gap register.

Properties, each enforced here *and* by the database:

* **Separate identity.** Runs as a login holding ``asic_maintenance`` (migration 0019), never
  mounted into API pods. The application role cannot delete; this role can delete only
  ``api_idempotency_record`` and write only ``retention_run`` receipts.
* **Tenant-bound.** One tenant per transaction, bound with the same row-level security the
  runtime uses; a batch cannot touch another tenant's rows.
* **Policy and holds respected.** The tenant policy is validated with the same rules as the
  planner; a hold (or no time-based policy) produces a receipt with nothing deleted.
* **Bounded and restartable.** Each batch deletes at most ``batch_limit`` rows (oldest first)
  and commits together with its receipt. No row lock is requested (``FOR UPDATE`` would need
  UPDATE privilege the role deliberately lacks); two concurrent runs stay correct because a
  DELETE blocked on a row another run deleted skips it once that run commits. A crash loses at most an
  uncommitted batch - which then deleted nothing and has no receipt - and a re-run continues.
* **Dry run by default.** ``execute=False`` counts and records a dry-run receipt.
* **No arbitrary SQL.** The table and predicate are fixed in code; callers choose only the
  tenant, bounds and mode.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ApiIdempotencyRecord, RetentionRun, Tenant
from asic.db.session import bind_tenant
from asic.retention.policy import (
    RetentionAction,
    RetentionClass,
    plan_retention,
)

#: The only class this executor may ever act on, and its table.
EXECUTABLE_CLASS = RetentionClass.OPERATIONAL_CACHE
EXECUTABLE_TABLE = ApiIdempotencyRecord.__tablename__
MAX_BATCH_LIMIT = 10_000
MAX_BATCHES = 1_000


@dataclass(frozen=True, slots=True)
class RetentionReceipt:
    receipt_id: uuid.UUID
    execution_id: uuid.UUID
    tenant_id: uuid.UUID
    retention_class: str
    table: str
    held: bool
    dry_run: bool
    policy_days: int | None
    cutoff: datetime | None
    eligible_rows: int
    deleted_rows: int
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "receipt_id": str(self.receipt_id),
            "execution_id": str(self.execution_id),
            "tenant_id": str(self.tenant_id),
            "retention_class": self.retention_class,
            "table": self.table,
            "held": self.held,
            "dry_run": self.dry_run,
            "policy_days": self.policy_days,
            "cutoff": self.cutoff.isoformat() if self.cutoff else None,
            "eligible_rows": self.eligible_rows,
            "deleted_rows": self.deleted_rows,
            "reason": self.reason,
        }


def _validate_bounds(batch_limit: int, max_batches: int) -> None:
    if not 1 <= batch_limit <= MAX_BATCH_LIMIT:
        raise ValueError(f"batch_limit must be between 1 and {MAX_BATCH_LIMIT}")
    if not 1 <= max_batches <= MAX_BATCHES:
        raise ValueError(f"max_batches must be between 1 and {MAX_BATCHES}")


def execute_retention(
    factory: Callable[[], Session],
    *,
    tenant_id: uuid.UUID,
    now: datetime,
    executed_by: str,
    execute: bool = False,
    batch_limit: int = 1000,
    max_batches: int = 10,
) -> list[RetentionReceipt]:
    """Run the lifecycle for one tenant; return one receipt per batch (at least one).

    Stops early when a batch finds nothing more to delete. Raises on any database refusal
    (for example when run under a role without the maintenance grants) - never partially
    succeeds without a receipt.
    """
    _validate_bounds(batch_limit, max_batches)
    if not executed_by or len(executed_by) > 128:
        raise ValueError("executed_by must name the maintenance identity (1-128 characters)")
    execution_id = uuid.uuid4()
    receipts: list[RetentionReceipt] = []
    for _ in range(max_batches):
        receipt = _one_batch(
            factory,
            tenant_id=tenant_id,
            now=now,
            execution_id=execution_id,
            executed_by=executed_by,
            execute=execute,
            batch_limit=batch_limit,
        )
        receipts.append(receipt)
        if not execute or receipt.held or receipt.deleted_rows < batch_limit:
            break
    return receipts


def _one_batch(
    factory: Callable[[], Session],
    *,
    tenant_id: uuid.UUID,
    now: datetime,
    execution_id: uuid.UUID,
    executed_by: str,
    execute: bool,
    batch_limit: int,
) -> RetentionReceipt:
    with factory() as session, session.begin():
        policy = session.scalar(sa.select(Tenant.retention_policy).where(Tenant.id == tenant_id))
        if (
            policy is None
            and session.scalar(sa.select(Tenant.id).where(Tenant.id == tenant_id)) is None
        ):
            raise ValueError("tenant does not exist")
        bind_tenant(session, tenant_id)
        plan = plan_retention(
            session, tenant_id=tenant_id, policy=policy, now=now, batch_limit=batch_limit
        )
        (row,) = [r for r in plan.rows if r.table == EXECUTABLE_TABLE]
        if row.retention_class is not EXECUTABLE_CLASS:  # a reclassification must be reviewed
            raise RuntimeError(f"{EXECUTABLE_TABLE} is no longer {EXECUTABLE_CLASS.value}")
        held = row.action is RetentionAction.HELD
        eligible = row.eligible_rows if row.action is RetentionAction.PREVIEW_ELIGIBLE else 0
        deleted = 0
        if execute and not held and eligible and row.cutoff is not None:
            doomed = (
                sa.select(ApiIdempotencyRecord.id)
                .where(
                    ApiIdempotencyRecord.tenant_id == tenant_id,
                    ApiIdempotencyRecord.created_at < row.cutoff,
                )
                .order_by(ApiIdempotencyRecord.created_at, ApiIdempotencyRecord.id)
                .limit(batch_limit)
                .scalar_subquery()
            )
            result = session.execute(
                sa.delete(ApiIdempotencyRecord)
                .where(
                    ApiIdempotencyRecord.tenant_id == tenant_id,
                    ApiIdempotencyRecord.id.in_(doomed),
                )
                .returning(ApiIdempotencyRecord.id)
            )
            deleted = len(result.fetchall())
        days = int((now - row.cutoff).days) if row.cutoff is not None else None
        receipt = RetentionRun(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            execution_id=execution_id,
            retention_class=EXECUTABLE_CLASS.value,
            table_name=EXECUTABLE_TABLE,
            policy_days=days,
            cutoff=row.cutoff,
            held=held,
            dry_run=not execute,
            batch_limit=batch_limit,
            eligible_rows=eligible,
            deleted_rows=deleted,
            executed_by=executed_by,
            reason=row.reason[:256],
        )
        session.add(receipt)
        session.flush()
        return RetentionReceipt(
            receipt_id=receipt.id,
            execution_id=execution_id,
            tenant_id=tenant_id,
            retention_class=EXECUTABLE_CLASS.value,
            table=EXECUTABLE_TABLE,
            held=held,
            dry_run=not execute,
            policy_days=days,
            cutoff=row.cutoff,
            eligible_rows=eligible,
            deleted_rows=deleted,
            reason=row.reason,
        )


__all__ = [
    "EXECUTABLE_CLASS",
    "EXECUTABLE_TABLE",
    "MAX_BATCHES",
    "MAX_BATCH_LIMIT",
    "RetentionReceipt",
    "execute_retention",
]
