"""Controlled retention maintenance: ``python -m asic.retention``.

Dry run unless ``--execute`` is given. Connects with ``ASIC_MAINTENANCE_DATABASE_URL`` - a login
holding the ``asic_maintenance`` role, never the application's or the migration owner's URL.
Prints one JSON receipt per batch; exits 0 on success and 2 on any refusal (bad bounds, unknown
tenant, missing grants), never with a traceback or a credential.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Tenant
from asic.db.session import create_app_engine
from asic.domain.enums import TenantStatus
from asic.observability.redaction import scrub_text
from asic.retention.executor import MAX_BATCH_LIMIT, MAX_BATCHES, execute_retention

MAINTENANCE_URL_ENV = "ASIC_MAINTENANCE_DATABASE_URL"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded retention lifecycle.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--tenant-id", type=uuid.UUID)
    target.add_argument(
        "--all-tenants", action="store_true", help="every active tenant, one at a time"
    )
    parser.add_argument("--execute", action="store_true", help="delete (default: dry run)")
    parser.add_argument("--batch-limit", type=int, default=1000, help=f"1..{MAX_BATCH_LIMIT}")
    parser.add_argument("--max-batches", type=int, default=10, help=f"1..{MAX_BATCHES}")
    parser.add_argument(
        "--executed-by", default=os.environ.get("ASIC_MAINTENANCE_IDENTITY", "asic-maintenance")
    )
    args = parser.parse_args(argv)
    url = os.environ.get(MAINTENANCE_URL_ENV)
    if not url:
        print(f"retention: {MAINTENANCE_URL_ENV} is required", file=sys.stderr)
        return 2
    engine = create_app_engine(url, pool_size=1, max_overflow=0)

    def factory() -> Session:
        return Session(bind=engine, expire_on_commit=False, autoflush=False)

    try:
        if args.all_tenants:
            with factory() as session:
                tenants = list(
                    session.scalars(
                        sa.select(Tenant.id)
                        .where(Tenant.status == TenantStatus.ACTIVE)
                        .order_by(Tenant.id)
                    )
                )
        else:
            tenants = [args.tenant_id]
        now = datetime.now(UTC)
        receipts = [
            receipt
            for tenant_id in tenants
            for receipt in execute_retention(
                factory,
                tenant_id=tenant_id,
                now=now,
                executed_by=args.executed_by,
                execute=args.execute,
                batch_limit=args.batch_limit,
                max_batches=args.max_batches,
            )
        ]
    except Exception as exc:  # a refusal is a controlled, redacted exit - never a traceback
        print(f"retention: refused: {scrub_text(f'{type(exc).__name__}: {exc}')}", file=sys.stderr)
        return 2
    finally:
        engine.dispose()
    for receipt in receipts:
        print(json.dumps(receipt.as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
