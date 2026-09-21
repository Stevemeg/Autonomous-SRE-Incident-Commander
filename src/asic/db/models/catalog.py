"""Service catalogue: services, environments and the dependency topology.

This is the taxonomy every other table scopes against. Permission scope for a remediation
action is *resolved* from service ownership recorded here rather than supplied by a
caller, which is what stops a proposal from naming a namespace it was never granted.
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column

from asic.db.base import (
    Base,
    CreatedAtMixin,
    TenantScoped,
    TimestampMixin,
    enum_column,
    tenant_fk,
    tenant_identity_constraints,
    uuid_pk,
)
from asic.domain.enums import DependencyKind, IntegrationKind, ServiceCriticality


class Environment(Base, TenantScoped, TimestampMixin):
    """A deployment context within a tenant.

    ``is_production`` is a first-class column rather than a naming convention because the
    autonomy matrix keys off it: the same action is autonomous in staging and requires
    approval in production.
    """

    __tablename__ = "environment"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    is_production: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("false")
    )
    #: Per-environment overrides of the tenant approval policy. Narrowing only; the
    #: policy gate takes the stricter of tenant and environment settings.
    approval_policy: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )

    __table_args__ = (
        *tenant_identity_constraints("environment"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_environment_tenant_id_name"),
        sa.CheckConstraint("name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'", name="name_format"),
    )


class Service(Base, TenantScoped, TimestampMixin):
    """A deployable customer service.

    ``owner_team`` and ``namespaces`` are how a remediation action's blast radius gets
    resolved. They are configuration, changed through the admin API with an audit record,
    never inferred at runtime.
    """

    __tablename__ = "service"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    owner_team: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    criticality: Mapped[ServiceCriticality] = mapped_column(
        enum_column(ServiceCriticality, "service_criticality"),
        nullable=False,
        default=ServiceCriticality.TIER_3,
    )
    #: Kubernetes namespaces this service occupies. The resolved permission scope for any
    #: action against this service is bounded by this list.
    namespaces: Mapped[list[str]] = mapped_column(
        pg.ARRAY(sa.String(253)), nullable=False, server_default=sa.text("'{}'::varchar[]")
    )
    #: Free-form labels used for correlation signals (team, product, region).
    labels: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )

    __table_args__ = (
        *tenant_identity_constraints("service"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_service_tenant_id_name"),
        sa.CheckConstraint("name ~ '^[a-z0-9][a-z0-9_-]{0,126}$'", name="name_format"),
        sa.Index("ix_service_tenant_active", "tenant_id", "is_active"),
    )


class ServiceDependency(Base, TenantScoped, TimestampMixin):
    """A directed edge in the service dependency graph.

    Feeds deterministic alert correlation: two alerts on services connected by a
    synchronous edge within a short window are far more likely to be one incident. The
    edge carries a confidence because topology is often discovered rather than declared.
    """

    __tablename__ = "service_dependency"

    id: Mapped[uuid.UUID] = uuid_pk()
    from_service_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    to_service_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    kind: Mapped[DependencyKind] = mapped_column(
        enum_column(DependencyKind, "dependency_kind"), nullable=False
    )
    #: 0.0 - 1.0. Declared topology is 1.0; discovered topology is lower.
    confidence: Mapped[float] = mapped_column(
        sa.Numeric(4, 3), nullable=False, server_default=sa.text("1.000")
    )
    discovered_from: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("service_dependency"),
        tenant_fk("from_service_id", "service", name="fk_service_dependency_from_service"),
        tenant_fk("to_service_id", "service", name="fk_service_dependency_to_service"),
        sa.UniqueConstraint(
            "tenant_id",
            "from_service_id",
            "to_service_id",
            "kind",
            name="uq_service_dependency_edge",
        ),
        sa.CheckConstraint("from_service_id <> to_service_id", name="no_self_dependency"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        sa.Index("ix_service_dependency_from", "tenant_id", "from_service_id"),
        sa.Index("ix_service_dependency_to", "tenant_id", "to_service_id"),
    )


class ConnectorScopeBinding(Base, TenantScoped, CreatedAtMixin):
    """Server-owned authority for one connector/service/environment tuple."""

    __tablename__ = "connector_scope_binding"

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    service_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )
    revoked_at: Mapped[Any | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("connector_scope_binding"),
        tenant_fk("service_id", "service", ondelete="CASCADE", name="fk_connector_binding_service"),
        tenant_fk(
            "environment_id",
            "environment",
            ondelete="CASCADE",
            name="fk_connector_binding_environment",
        ),
        # F-13: a binding must name a connector that exists in the same tenant. RESTRICT:
        # authority history must never be cascaded away by deleting a connector.
        sa.ForeignKeyConstraint(
            ["tenant_id", "connector_id"],
            ["integration_connector.tenant_id", "integration_connector.connector_id"],
            ondelete="RESTRICT",
            name="fk_connector_scope_binding_connector",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "connector_id",
            "source",
            "service_id",
            "environment_id",
            name="uq_connector_scope_binding_tuple",
        ),
        sa.CheckConstraint(
            "(is_enabled AND revoked_at IS NULL) OR (NOT is_enabled)",
            name="enabled_binding_not_revoked",
        ),
        sa.Index(
            "ix_connector_scope_binding_lookup",
            "tenant_id",
            "connector_id",
            "source",
            "service_id",
            "environment_id",
            "is_enabled",
        ),
    )


class IntegrationConnector(Base, TenantScoped, CreatedAtMixin):
    """One tenant's configured external system, per environment (Phase 10, ADR-0026).

    Holds *where* and *which credential reference*, never a secret. The application role
    may only read it: a process that could rewrite a connector's endpoint could redirect
    authenticated traffic. Whether a connector may serve a given service is a separate,
    revocable :class:`ConnectorScopeBinding` row, checked before every call.
    """

    __tablename__ = "integration_connector"

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    kind: Mapped[IntegrationKind] = mapped_column(
        enum_column(IntegrationKind, "integration_kind"), nullable=False
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(pg.UUID(as_uuid=True), nullable=False)
    #: Base URL of the external API. Validated again in code before any request.
    endpoint_url: Mapped[str | None] = mapped_column(sa.String(512), nullable=True)
    #: Read-path credential reference. A name, never a secret.
    credential_ref: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    #: Separate write-path credential reference (Kubernetes mutations). Never shared with
    #: reads, so an investigation credential is physically incapable of mutation (SI-4).
    write_credential_ref: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    #: Bounded, non-secret settings (project key, channel id, dashboard uid).
    settings: Mapped[dict[str, Any]] = mapped_column(
        pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    is_enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.text("true")
    )
    revoked_at: Mapped[Any | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        *tenant_identity_constraints("integration_connector"),
        tenant_fk(
            "environment_id",
            "environment",
            ondelete="CASCADE",
            name="fk_integration_connector_environment",
        ),
        sa.UniqueConstraint("tenant_id", "connector_id", name="uq_integration_connector_id"),
        sa.CheckConstraint(
            "(is_enabled AND revoked_at IS NULL) OR (NOT is_enabled)",
            name="enabled_connector_not_revoked",
        ),
        sa.CheckConstraint(
            "credential_ref IS NULL OR credential_ref ~ '^asic/[a-z0-9][a-z0-9/_.-]{0,200}$'",
            name="credential_ref_is_reference",
        ),
        sa.CheckConstraint(
            "write_credential_ref IS NULL OR "
            "write_credential_ref ~ '^asic/[a-z0-9][a-z0-9/_.-]{0,200}$'",
            name="write_credential_ref_is_reference",
        ),
        sa.CheckConstraint(
            "write_credential_ref IS NULL OR write_credential_ref IS DISTINCT FROM credential_ref",
            name="write_credential_separate_from_read",
        ),
        sa.CheckConstraint(
            r"endpoint_url IS NULL OR endpoint_url ~ '^https?://[^\s@]+$'",
            name="endpoint_url_has_no_userinfo",
        ),
        sa.CheckConstraint(
            "connector_id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'", name="connector_id_format"
        ),
        sa.Index(
            "uq_integration_connector_active_kind",
            "tenant_id",
            "environment_id",
            "kind",
            unique=True,
            postgresql_where=sa.text("is_enabled"),
        ),
    )
