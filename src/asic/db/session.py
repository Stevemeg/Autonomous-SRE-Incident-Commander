"""Tenant context binding, sessions, and the helpers that carry tenancy off-thread.

Row-level security decides what a query can see by reading a session variable. This module
is the only place that variable is written, and it writes it *transaction-locally*, so a
pooled connection can never leak one request's tenant into the next.

The chain is:

.. code-block:: text

    tenant_scope(session, tenant_id)
        -> SELECT set_config('app.tenant_id', <uuid>, true)   -- transaction-local
        -> RLS policy: tenant_id = app.current_tenant_id()
        -> rows outside the tenant are not visible, and cannot be written

``set_config(..., true)`` is the load-bearing detail. The third argument makes the setting
local to the current transaction, so it is discarded on commit or rollback. A
session-level ``SET`` would persist on the pooled connection and be inherited by whatever
request picked that connection up next - the classic multi-tenant data leak.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from asic.domain.errors import TenantContextMismatch, TenantContextMissing

#: The PostgreSQL setting RLS policies read. Namespaced so it cannot collide with a
#: built-in GUC, and named in exactly one place.
TENANT_SETTING: Final[str] = "app.tenant_id"

#: Environment variable holding the application connection string. The application role
#: is deliberately *not* the table owner and does not hold ``BYPASSRLS``.
DATABASE_URL_ENV: Final[str] = "ASIC_DATABASE_URL"

#: Environment variable used by the test suite. Kept separate so a misconfigured test run
#: can never point at a real database.
TEST_DATABASE_URL_ENV: Final[str] = "ASIC_TEST_DATABASE_URL"


@dataclass(frozen=True, slots=True)
class TenantContext:
    """The tenant a unit of work belongs to.

    Carried explicitly rather than stored in a thread-local. Background jobs, event
    handlers and test fixtures all receive it as a value, which is what makes tenancy
    survive the boundary between a request and the work it schedules.
    """

    tenant_id: uuid.UUID

    def cache_key(self, *parts: object) -> str:
        """Namespace a cache key by tenant.

        Every cache key in the system must go through this. A cache is a second store
        with no row-level security, so a key that omits the tenant is a cross-tenant read
        waiting to happen - the one place where the database backstop does not protect us.
        """
        rendered = ":".join(str(part) for part in parts)
        return f"t:{self.tenant_id}:{rendered}"

    def job_envelope(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Wrap a background-job payload so the worker can rebind the tenant.

        A worker starts with no tenant context. It must call :func:`tenant_scope` with the
        tenant from this envelope before touching any tenant-scoped table; with no
        context bound, RLS makes every query return nothing, which fails loudly in tests
        rather than silently in production.
        """
        if "tenant_id" in payload:
            raise ValueError("job payload must not carry its own tenant_id key")
        return {"tenant_id": str(self.tenant_id), "payload": payload}


def create_app_engine(url: str | None = None, **kwargs: Any) -> Engine:
    """Engine for the application role.

    ``pool_pre_ping`` is on because a stale pooled connection surfaces as a confusing
    error deep inside a transaction otherwise.
    """
    resolved = url or os.environ.get(DATABASE_URL_ENV)
    if not resolved:
        raise RuntimeError(f"no database URL: pass one explicitly or set {DATABASE_URL_ENV}")
    kwargs.setdefault("pool_pre_ping", True)
    kwargs.setdefault("future", True)
    return create_engine(resolved, **kwargs)


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        future=True,
    )


def bind_tenant(session: Session, tenant_id: uuid.UUID) -> None:
    """Bind the tenant for the current transaction.

    Must be called inside a transaction. SQLAlchemy begins one implicitly on first use,
    so calling this as the first statement of a unit of work is sufficient.
    """
    session.execute(
        sa.text("SELECT set_config(:setting, :value, true)"),
        {"setting": TENANT_SETTING, "value": str(tenant_id)},
    )


def clear_tenant(session: Session) -> None:
    """Unbind the tenant, returning the transaction to deny-all.

    Used between assertions in tests, and by any code path that deliberately drops
    privilege before doing something it should not be able to do.
    """
    session.execute(
        sa.text("SELECT set_config(:setting, '', true)"),
        {"setting": TENANT_SETTING},
    )


def current_tenant(session: Session) -> uuid.UUID | None:
    """Read back the bound tenant, or ``None`` when unbound."""
    raw = session.execute(
        sa.text("SELECT current_setting(:setting, true)"), {"setting": TENANT_SETTING}
    ).scalar()
    if not raw:
        return None
    return uuid.UUID(raw)


def require_tenant(session: Session) -> uuid.UUID:
    """Read the bound tenant, or raise.

    Fails fast with a useful message. Without it, an unbound query simply returns nothing
    - correct, but indistinguishable from "no such data", which is a miserable thing to
    debug.
    """
    tenant_id = current_tenant(session)
    if tenant_id is None:
        raise TenantContextMissing(
            "no tenant bound to this transaction; call tenant_scope() before touching "
            "tenant-scoped tables. Row-level security is denying all rows."
        )
    return tenant_id


@contextmanager
def tenant_scope(session: Session, tenant_id: uuid.UUID) -> Iterator[TenantContext]:
    """Run a unit of work as one tenant.

    On exit the binding is discarded with the transaction. Nesting with a *different*
    tenant is refused rather than silently re-bound: switching tenant mid-transaction is
    almost always a bug, and where it is genuinely wanted (a platform maintenance job) the
    caller should use separate transactions.
    """
    existing = current_tenant(session)
    if existing is not None and existing != tenant_id:
        raise TenantContextMismatch(
            f"transaction is already bound to tenant {existing}; refusing to rebind to "
            f"{tenant_id}. Use a separate transaction per tenant."
        )
    bind_tenant(session, tenant_id)
    try:
        yield TenantContext(tenant_id=tenant_id)
    finally:
        # The setting is transaction-local, so commit/rollback discards it. Clearing here
        # additionally protects the case where the caller keeps the transaction open.
        if session.is_active:
            clear_tenant(session)


@contextmanager
def tenant_session(
    factory: sessionmaker[Session], tenant_id: uuid.UUID
) -> Iterator[tuple[Session, TenantContext]]:
    """Open a session, bind the tenant, commit on success, roll back on error."""
    session = factory()
    try:
        with tenant_scope(session, tenant_id) as ctx:
            yield session, ctx
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
