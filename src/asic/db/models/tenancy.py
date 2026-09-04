"""Tenancy and identity: tenant, user, role, permission.

``tenant``, ``role``, ``permission`` and ``role_permission`` are **global** tables with no
row-level security. That is deliberate and worth stating plainly:

* ``tenant`` is the table that *defines* the boundary; it cannot be inside it.
* ``role`` and ``permission`` are a platform-owned catalogue reviewed like code. Letting a
  tenant define its own permission semantics would let a tenant widen its own authority.

Everything else here is tenant-scoped and protected by RLS.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import (
    Base,
    TenantScoped,
    TimestampMixin,
    enum_column,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import RiskTier, TenantStatus, UserStatus


class Tenant(Base, TimestampMixin):
    """An isolation boundary. Global table: it defines the boundary rather than sitting
    inside one.

    Retention and budget policy live here because both are per-tenant commitments that
    other subsystems must read without a tenant context already bound.
    """

    __tablename__ = "tenant"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Stable, human-usable identifier. Immutable once issued: it appears in audit
    #: records and external references.
    slug: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[TenantStatus] = mapped_column(
        enum_column(TenantStatus, "tenant_status"),
        nullable=False,
        default=TenantStatus.ACTIVE,
    )
    #: Per-data-class retention, overriding platform defaults where the tenant's
    #: obligations are stricter.
    retention_policy: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    #: Hard limits on investigation spend: tokens, cost, concurrent incidents.
    budget_limits: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    deprovisioned_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        sa.UniqueConstraint("slug", name="uq_tenant_slug"),
        sa.CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'",
            name="slug_format",
        ),
    )


class Permission(Base):
    """An atomic capability in the authorization model. Global catalogue."""

    __tablename__ = "permission"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: e.g. ``incident.read``, ``approval.decide``, ``registry.write``.
    key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: The resource family this permission acts on, for grouping and review.
    resource: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Highest risk tier this permission may authorise. ``None`` for non-action
    #: permissions. Never ``R3``: destructive actions are not expressible (SI-5).
    max_risk_tier: Mapped[RiskTier | None] = mapped_column(
        enum_column(RiskTier, "risk_tier"), nullable=True
    )

    __table_args__ = (
        sa.UniqueConstraint("key", name="uq_permission_key"),
        sa.CheckConstraint(
            "max_risk_tier IS NULL OR max_risk_tier <> 'r3'",
            name="no_destructive_permission",
        ),
    )


class Role(Base):
    """A named bundle of permissions. Global catalogue, versioned in migrations."""

    __tablename__ = "role"

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    #: System roles cannot be edited or deleted through the admin API.
    is_system: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )

    __table_args__ = (sa.UniqueConstraint("key", name="uq_role_key"),)


class RolePermission(Base):
    """Role-to-permission grant. Global."""

    __tablename__ = "role_permission"

    role_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        sa.ForeignKey("role.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        sa.ForeignKey("permission.id", ondelete="CASCADE"),
        primary_key=True,
    )


class User(Base, TenantScoped, TimestampMixin):
    """A human principal within one tenant.

    Users belong to exactly one tenant. A person who operates two tenants has two user
    records; conflating them would make "which tenant is this actor acting for" ambiguous
    at exactly the moment it matters - an approval decision.
    """

    __tablename__ = "app_user"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Subject claim from the organisation's identity provider. We never store
    #: credentials; authentication happens at the IdP.
    external_idp_subject: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    #: Sensitivity: RESTRICTED. Subject to the tenant's retention and erasure policy.
    email: Mapped[str] = mapped_column(sa.String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        enum_column(UserStatus, "user_status"),
        nullable=False,
        default=UserStatus.ACTIVE,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("app_user"),
        sa.UniqueConstraint(
            "tenant_id", "external_idp_subject", name="uq_app_user_tenant_id_idp_subject"
        ),
        sa.UniqueConstraint("tenant_id", "email", name="uq_app_user_tenant_id_email"),
    )


class UserRoleAssignment(Base, TenantScoped, TimestampMixin):
    """Grant of a role to a user, optionally narrowed to one environment.

    Authority is per tenant **and** per environment: an approver in staging is not an
    approver in production. ``environment_id IS NULL`` means the grant applies to every
    environment in the tenant, which is why the uniqueness constraint below treats NULLs
    as equal - otherwise the same tenant-wide grant could be inserted repeatedly.
    """

    __tablename__ = "user_role_assignment"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        sa.ForeignKey("role.id", ondelete="RESTRICT"),
        nullable=False,
    )
    environment_id: Mapped[uuid.UUID | None] = mapped_column(pg.UUID(as_uuid=True), nullable=True)
    granted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        pg.UUID(as_uuid=True), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    #: Time-bounded grants support break-glass access that expires on its own.
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("user_role_assignment"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["app_user.tenant_id", "app_user.id"],
            ondelete="CASCADE",
            name="fk_user_role_assignment_user",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "environment_id"],
            ["environment.tenant_id", "environment.id"],
            ondelete="CASCADE",
            name="fk_user_role_assignment_environment",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "user_id",
            "role_id",
            "environment_id",
            name="uq_user_role_assignment_grant",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > granted_at",
            name="expiry_after_grant",
        ),
        sa.Index("ix_user_role_assignment_user", "tenant_id", "user_id"),
    )
