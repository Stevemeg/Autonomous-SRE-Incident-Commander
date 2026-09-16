"""Connector scope authority for outbound native integrations (Phase 10, ADR-0026).

Reuses the pre-Phase-10 authority model for connectors: a tenant, a connector identity,
a source, a service and an environment must all be bound by server-side rows. Inbound
ingestion checks the binding before accepting a signal; the broker checks the same kind
of binding before sending a request.

Resolution happens on every call, inside the caller's tenant-bound transaction, with no
cache. Revoking a binding or disabling a connector therefore refuses the very next
request, and no earlier success confers anything on a later one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.catalog import ConnectorScopeBinding, IntegrationConnector, Service
from asic.domain.enums import IntegrationKind
from asic.domain.errors import ConnectorScopeDenied
from asic.domain.safety import is_forbidden_secret_field
from asic.observability.redaction import looks_like_secret
from asic.tools.capability import IncidentScope
from asic.tools.provider import ConnectorGrant

#: Settings are small, flat, non-secret configuration. Anything else is refused.
MAX_SETTINGS_KEYS: Final[int] = 16
MAX_SETTING_CHARS: Final[int] = 256


def resolve_connector(
    session: Session,
    *,
    scope: IncidentScope,
    service_name: str,
    kind: IntegrationKind,
) -> ConnectorGrant:
    """Return the connector authorised for this tenant/environment/service, or refuse.

    Raises:
        ConnectorScopeDenied: no enabled connector of this kind in the environment, no
            enabled and unrevoked binding for the service, an inactive service, or unsafe
            connector settings.
    """
    service = scope.service(service_name)
    active = session.scalar(
        sa.select(Service.is_active).where(
            Service.tenant_id == scope.tenant_id, Service.id == service.service_id
        )
    )
    if not active:
        raise ConnectorScopeDenied(f"service {service_name!r} is not active")
    connector = session.execute(
        sa.select(IntegrationConnector).where(
            IntegrationConnector.tenant_id == scope.tenant_id,
            IntegrationConnector.environment_id == scope.environment_id,
            IntegrationConnector.kind == kind,
            IntegrationConnector.is_enabled.is_(True),
            IntegrationConnector.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if connector is None:
        raise ConnectorScopeDenied(
            f"no enabled {kind.value} connector is configured for this environment"
        )
    binding = session.scalar(
        sa.select(ConnectorScopeBinding.id).where(
            ConnectorScopeBinding.tenant_id == scope.tenant_id,
            ConnectorScopeBinding.connector_id == connector.connector_id,
            ConnectorScopeBinding.source == kind.value,
            ConnectorScopeBinding.service_id == service.service_id,
            ConnectorScopeBinding.environment_id == scope.environment_id,
            ConnectorScopeBinding.is_enabled.is_(True),
            ConnectorScopeBinding.revoked_at.is_(None),
        )
    )
    if binding is None:
        raise ConnectorScopeDenied(
            f"{kind.value} connector {connector.connector_id!r} is not bound to service "
            f"{service_name!r} in this environment"
        )
    return ConnectorGrant(
        connector_id=connector.connector_id,
        kind=kind,
        endpoint_url=connector.endpoint_url,
        credential_ref=connector.credential_ref,
        write_credential_ref=connector.write_credential_ref,
        service_name=service.name,
        environment_name=scope.environment_name,
        settings=_safe_settings(connector.settings),
        namespaces=service.namespaces,
    )


def _safe_settings(settings: Mapping[str, Any] | None) -> dict[str, str | int | bool]:
    raw = dict(settings or {})
    if len(raw) > MAX_SETTINGS_KEYS:
        raise ConnectorScopeDenied("connector settings exceed the permitted size")
    safe: dict[str, str | int | bool] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or is_forbidden_secret_field(key):
            raise ConnectorScopeDenied("connector settings contain a secret-shaped key")
        if isinstance(value, str) and looks_like_secret(value):
            raise ConnectorScopeDenied("connector settings contain a secret-shaped value")
        if isinstance(value, bool | int) or (
            isinstance(value, str) and len(value) <= MAX_SETTING_CHARS
        ):
            safe[key] = value
        else:
            raise ConnectorScopeDenied("connector settings must be flat, bounded scalars")
    return safe


__all__ = ["resolve_connector"]
