"""Least-privilege capability resolution: building the menu, and resolving scope.

The design inverts the usual arrangement. A model does not name a capability it would like
and receive a verdict; it is handed a menu that was resolved *before it was invoked*, from
five independent inputs that must all agree:

===================  =========================================================
Input                Where it comes from
===================  =========================================================
Tenant               The tenant bound to the transaction, enforced by RLS
Environment          The incident's environment
Node contract        ``NodeContract.capabilities`` for the calling node
Tool grant           ``tenant_tool_grant``, per tenant and environment
Risk classification  ``tool_definition.risk_tier``, refused above the ceiling
===================  =========================================================

Two consequences are worth stating explicitly, because they are the answers to the two
questions this layer exists to answer.

**Retrieved content and model output cannot grant authorization.** Nothing in this module
reads either. The resolver's inputs are a bound tenant, database rows and a node contract -
all ``SYSTEM`` provenance. There is no parameter through which a log line or a model
response could reach it, which is what makes SEC-I4 structural rather than aspirational.

**Scope is resolved, not supplied.** :meth:`IncidentScope.resolve_arguments` fills the
scope arguments from the incident's own tenant, environment and registered service
ownership. A caller naming a service outside the incident's scope is refused; a caller
supplying a scope argument at all is refused earlier still, by the descriptor.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import NodeContract
from asic.db.models.catalog import Environment, Service
from asic.db.models.tools import TenantToolGrant, ToolDefinition
from asic.domain.enums import RiskTier
from asic.domain.errors import (
    CapabilityNotGranted,
    RiskTierNotPermitted,
    TenantContextMismatch,
)
from asic.tools.descriptor import ToolDescriptor
from asic.tools.registry import RegisteredTool, ToolRegistry


@dataclass(frozen=True, slots=True)
class ServiceScope:
    """One service the incident is about, with the namespaces it owns."""

    service_id: uuid.UUID
    name: str
    namespaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IncidentScope:
    """The bounds within which every tool call for this incident must fall."""

    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    environment_id: uuid.UUID
    environment_name: str
    services: tuple[ServiceScope, ...]

    @property
    def service_names(self) -> tuple[str, ...]:
        return tuple(s.name for s in self.services)

    def service(self, name: str) -> ServiceScope:
        for candidate in self.services:
            if candidate.name == name:
                return candidate
        raise CapabilityNotGranted(
            f"service {name!r} is not in scope for this incident; in scope: "
            f"{sorted(self.service_names)}. Scope is resolved from the incident, so a "
            "caller cannot reach a service the incident is not about."
        )

    def resolve_arguments(self, descriptor: ToolDescriptor, *, service_name: str) -> dict[str, Any]:
        """Fill every ``scope_resolved`` argument of ``descriptor`` from this scope.

        Raises:
            CapabilityNotGranted: if the service is out of scope, or the descriptor needs a
                scope value this incident cannot supply.
        """
        service = self.service(service_name)
        available: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "environment": self.environment_name,
            "service": service.name,
        }
        if service.namespaces:
            available["namespace"] = service.namespaces[0]

        resolved: dict[str, Any] = {}
        for name in sorted(descriptor.scope_argument_names):
            if name not in available:
                raise CapabilityNotGranted(
                    f"{descriptor.name} requires scope value {name!r}, which this incident "
                    f"cannot resolve for service {service_name!r}; refusing rather than "
                    "falling back to a broader default"
                )
            resolved[name] = available[name]
        return resolved


@dataclass(frozen=True, slots=True)
class GrantedCapability:
    """One capability this run may exercise, with the grant that permitted it."""

    capability: str
    descriptor: ToolDescriptor
    tool_definition_id: uuid.UUID
    grant_id: uuid.UUID
    credential_ref: str | None
    #: Tenant-level narrowing. The broker takes the intersection of tool scope and this;
    #: a grant can only narrow, never widen.
    scope_overrides: Mapping[str, Any]
    blast_radius_limits: Mapping[str, Any]


class CapabilityMenu:
    """The immutable set of capabilities resolved for one run and one node."""

    __slots__ = ("_by_capability", "_by_tool_name")

    def __init__(self, granted: Sequence[GrantedCapability]) -> None:
        self._by_capability = {g.capability: g for g in granted}
        #: A tool name is what a remediation proposal actually names (tool-registry.md §2:
        #: a capability is a *class* of operation; a proposal picks one registered tool).
        #: Keyed separately so a caller can validate a proposed tool name without needing
        #: to already know which capability it maps to.
        self._by_tool_name = {g.descriptor.name: g for g in granted}

    def __contains__(self, capability: object) -> bool:
        return capability in self._by_capability

    def __len__(self) -> int:
        return len(self._by_capability)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_capability))

    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_tool_name))

    def get(self, capability: str) -> GrantedCapability:
        try:
            return self._by_capability[capability]
        except KeyError as exc:
            raise CapabilityNotGranted(
                f"capability {capability!r} is not on this run's menu; available: "
                f"{list(self.names())}. The menu is resolved before any model is invoked, "
                "so a capability absent from it was never offered and cannot be requested."
            ) from exc

    def get_by_tool_name(self, tool_name: str) -> GrantedCapability | None:
        """``None``, not an exception: the caller decides how to treat an unknown name."""
        return self._by_tool_name.get(tool_name)


def load_incident_scope(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    environment_id: uuid.UUID,
    service_ids: Sequence[uuid.UUID],
) -> IncidentScope:
    """Build the scope for an incident from durable rows only."""
    environment = session.execute(
        sa.select(Environment).where(
            Environment.tenant_id == tenant_id, Environment.id == environment_id
        )
    ).scalar_one_or_none()
    if environment is None:
        raise CapabilityNotGranted(
            f"environment {environment_id} is not visible in tenant {tenant_id}; "
            "row-level security is denying it, or it does not exist"
        )

    services: list[ServiceScope] = []
    if service_ids:
        rows = list(
            session.execute(
                sa.select(Service)
                .where(Service.tenant_id == tenant_id, Service.id.in_(list(service_ids)))
                .order_by(Service.name)
            ).scalars()
        )
        missing = set(service_ids) - {row.id for row in rows}
        if missing:
            raise CapabilityNotGranted(
                f"service(s) {sorted(str(m) for m in missing)} are not visible in tenant "
                f"{tenant_id}; an incident cannot be scoped to a service it does not own"
            )
        services = [
            ServiceScope(
                service_id=row.id,
                name=row.name,
                namespaces=tuple(row.namespaces or ()),
            )
            for row in rows
        ]

    return IncidentScope(
        tenant_id=tenant_id,
        incident_id=incident_id,
        environment_id=environment_id,
        environment_name=environment.name,
        services=tuple(services),
    )


class CapabilityResolver:
    """Resolves the capability menu. The only component that decides what may be invoked."""

    __slots__ = ("_max_risk_tier", "_registry")

    def __init__(self, registry: ToolRegistry, *, max_risk_tier: RiskTier = RiskTier.RO) -> None:
        # Phase 8 (ADR-0023): the ceiling now admits R1/R2, because the policy gate and
        # approval service that authorise them now exist. R3 remains structurally refused
        # here independent of the registry: no descriptor can declare it (SI-5), so a
        # ceiling that named it would be a resolver that could never resolve anything at
        # that tier - the refusal is for the caller's benefit, not a safety boundary this
        # line alone provides.
        if max_risk_tier is RiskTier.R3:
            raise ValueError(
                "risk tier r3 is destructive/irreversible and is never expressible as a "
                "resolvable ceiling; no descriptor can be registered at that tier (SI-5)"
            )
        self._registry = registry
        self._max_risk_tier = max_risk_tier

    @property
    def max_risk_tier(self) -> RiskTier:
        return self._max_risk_tier

    @property
    def registry(self) -> ToolRegistry:
        """The registry this resolver resolves against.

        Exposed so the broker joins code descriptors to database identities through the
        same registry instance rather than caching a second copy that could drift.
        """
        return self._registry

    def resolve(
        self,
        session: Session,
        *,
        scope: IncidentScope,
        contract: NodeContract,
    ) -> CapabilityMenu:
        """Resolve the menu for one node, in one tenant, in one environment.

        Fails closed at every step: an unreadable grant table, a missing environment or a
        capability above the risk ceiling all yield fewer capabilities, never more.
        """
        joined = self._registry.assert_matches_database(session)

        grants = list(
            session.execute(
                sa.select(TenantToolGrant, ToolDefinition)
                .join(
                    ToolDefinition,
                    ToolDefinition.id == TenantToolGrant.tool_definition_id,
                )
                .where(
                    TenantToolGrant.tenant_id == scope.tenant_id,
                    TenantToolGrant.is_enabled.is_(True),
                    ToolDefinition.is_enabled.is_(True),
                    sa.or_(
                        TenantToolGrant.environment_id == scope.environment_id,
                        TenantToolGrant.environment_id.is_(None),
                    ),
                )
                .order_by(ToolDefinition.name)
            ).all()
        )

        granted: list[GrantedCapability] = []
        for grant, definition in grants:
            registered: RegisteredTool | None = joined.get(definition.name)
            if registered is None:
                # A grant naming a tool the code catalogue does not describe is skipped,
                # not honoured. assert_matches_database would already have raised, so this
                # is a belt-and-braces refusal rather than an expected path.
                continue
            if definition.risk_tier.rank > self._max_risk_tier.rank:
                continue
            if not contract.permits_capability(definition.capability):
                continue
            granted.append(
                GrantedCapability(
                    capability=definition.capability,
                    descriptor=registered.descriptor,
                    tool_definition_id=registered.tool_definition_id,
                    grant_id=grant.id,
                    credential_ref=registered.credential_ref,
                    scope_overrides=dict(grant.scope_overrides or {}),
                    blast_radius_limits=dict(grant.blast_radius_limits or {}),
                )
            )
        return CapabilityMenu(granted)

    def assert_tier_permitted(self, descriptor: ToolDescriptor) -> None:
        """Refuse anything above the configured risk ceiling.

        Separate from menu resolution so the refusal happens again immediately before
        dispatch. Checking once at menu time would leave a window in which a mutated or
        stale menu entry could reach an adapter.
        """
        if descriptor.risk_tier.rank > self._max_risk_tier.rank:
            raise RiskTierNotPermitted(
                f"{descriptor.name} is risk tier {descriptor.risk_tier.value}; this "
                f"resolver's ceiling is {self._max_risk_tier.value}. A request above the "
                "ceiling is refused, never downgraded to the nearest permitted tier."
            )


def assert_tenant_matches(bound_tenant: uuid.UUID, requested_tenant: uuid.UUID) -> None:
    """Guard against a request naming a tenant other than the bound one.

    Row-level security already makes the rows invisible; this raises instead, so an attempt
    is loud rather than merely fruitless.
    """
    if bound_tenant != requested_tenant:
        raise TenantContextMismatch(
            f"request names tenant {requested_tenant} while the transaction is bound to "
            f"{bound_tenant}; tenant context comes from the session, never from a request"
        )


__all__ = [
    "CapabilityMenu",
    "CapabilityResolver",
    "GrantedCapability",
    "IncidentScope",
    "ServiceScope",
    "assert_tenant_matches",
    "load_incident_scope",
]
