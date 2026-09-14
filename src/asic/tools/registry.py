"""The tool registry: the authoritative in-process view of what exists.

The registry answers exactly two questions - *is this a registered capability?* and *which
descriptor implements it?* - and it answers them from a catalogue that is versioned in Git
and mirrored into the global ``tool_definition`` table.

The mirroring matters. Two copies of the catalogue that can disagree are worse than one,
so :meth:`ToolRegistry.assert_matches_database` compares them field by field and refuses
to run when they diverge. A registry describing a tool the database has never heard of
would let an execution record point at a definition that does not exist; a database row
the code does not know about would let a tool run with no descriptor to validate it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.tools import ToolDefinition
from asic.domain.errors import UnregisteredCapability
from asic.tools.catalogue import CATALOGUE_VERSION, READ_ONLY_CATALOGUE
from asic.tools.descriptor import ToolDescriptor, assert_no_write_capability


class RegistryDrift(RuntimeError):
    """The code catalogue and the database catalogue disagree.

    Not a domain error: it is a deployment defect, detected at start-up, and the correct
    response is to refuse to run rather than to reconcile at runtime.
    """


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """A descriptor together with the database identity execution records point at."""

    descriptor: ToolDescriptor
    tool_definition_id: uuid.UUID
    credential_ref: str | None


class ToolRegistry:
    """Name and capability lookup over a fixed set of descriptors."""

    __slots__ = ("_by_capability", "_by_name", "_version")

    def __init__(self, descriptors: Sequence[ToolDescriptor], *, version: str) -> None:
        by_name: dict[str, ToolDescriptor] = {}
        by_capability: dict[str, list[ToolDescriptor]] = {}
        for descriptor in descriptors:
            if descriptor.name in by_name:
                raise RegistryDrift(f"duplicate tool name in catalogue: {descriptor.name}")
            by_name[descriptor.name] = descriptor
            by_capability.setdefault(descriptor.capability, []).append(descriptor)
        self._by_name = by_name
        self._by_capability = {k: tuple(v) for k, v in by_capability.items()}
        self._version = version

    @classmethod
    def read_only(cls) -> ToolRegistry:
        """The read-only catalogue every investigation kernel uses. Unchanged since Phase 4.

        Asserts the catalogue's read-only property on construction, so a write tool
        arriving in this catalogue fails at start-up rather than at first use. This
        assertion is unaffected by Phase 8: the read-only catalogue is a fixed module-level
        tuple that Phase 8 never appends to - it added a *second*, separate catalogue
        instead (:meth:`remediation`), which is exactly what ADR-0023 requires: the
        investigation kernel's ceiling stays provably RO regardless of what remediation
        adds elsewhere.
        """
        assert_no_write_capability(READ_ONLY_CATALOGUE)
        return cls(READ_ONLY_CATALOGUE, version=CATALOGUE_VERSION)

    @classmethod
    def remediation(cls) -> ToolRegistry:
        """The write catalogue Phase 8 adds, alongside - never replacing - the read-only one.

        Deliberately does not call :func:`assert_no_write_capability`: this catalogue's
        entire purpose is R1/R2 write tools. What it does still assert, via
        :class:`~asic.tools.descriptor.ToolDescriptor`'s own validators (SI-5), is that
        nothing in it is R3.
        """
        from asic.tools.remediation_catalogue import (
            REMEDIATION_CATALOGUE_VERSION,
            WRITE_CATALOGUE,
        )

        return cls(WRITE_CATALOGUE, version=REMEDIATION_CATALOGUE_VERSION)

    @classmethod
    def remediation_full(cls) -> ToolRegistry:
        """Read *and* write descriptors together, for the remediation kernel's one broker.

        The remediation graph has both a read-only node (G10, observing independently of
        the executor) and a write node (G9). ADR-0023's answer to "one broker or two" is
        one: each node's own contract already restricts what it can see and call
        (:meth:`CapabilityResolver.resolve` filters by ``contract.permits_capability``), so
        a combined registry does not widen either node's reach - it only lets them share
        one broker instance instead of duplicating the tool-broker pathway per node.
        """
        from asic.tools.remediation_catalogue import (
            REMEDIATION_CATALOGUE_VERSION,
            WRITE_CATALOGUE,
        )

        return cls(
            (*READ_ONLY_CATALOGUE, *WRITE_CATALOGUE),
            version=f"{CATALOGUE_VERSION}+{REMEDIATION_CATALOGUE_VERSION}",
        )

    @property
    def version(self) -> str:
        return self._version

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self._by_capability)

    def descriptors(self) -> tuple[ToolDescriptor, ...]:
        return tuple(self._by_name[name] for name in sorted(self._by_name))

    def by_name(self, name: str) -> ToolDescriptor:
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise UnregisteredCapability(
                f"tool {name!r} is not registered. Unregistered tools are rejected, never "
                "repaired: repairing would teach a planning loop to negotiate for "
                "capability it was not granted."
            ) from exc

    def for_capability(self, capability: str) -> ToolDescriptor:
        """The single enabled tool implementing ``capability``.

        A capability with more than one implementation would require a selection rule, and
        a selection rule in this position is a policy decision hiding in a lookup. If that
        becomes necessary the rule gets written down; until then, ambiguity is an error.
        """
        candidates = [d for d in self._by_capability.get(capability, ()) if d.is_enabled]
        if not candidates:
            raise UnregisteredCapability(
                f"capability {capability!r} is not registered or has no enabled tool; "
                f"registered capabilities are {sorted(self.capabilities)}"
            )
        if len(candidates) > 1:
            raise RegistryDrift(
                f"capability {capability!r} has {len(candidates)} enabled implementations "
                f"({sorted(c.name for c in candidates)}); selection between them would be "
                "an unwritten policy decision"
            )
        return candidates[0]

    def assert_matches_database(self, session: Session) -> Mapping[str, RegisteredTool]:
        """Compare *this registry's own* catalogue with ``tool_definition``.

        Checks only that every descriptor this registry declares has a matching, field-
        correct database row - not that the database contains nothing else. Since Phase 8
        (ADR-0023) more than one registry's catalogue can be live in the same database at
        once (the read-only one and the remediation one), a row belonging to a sibling
        catalogue is not this registry's business to judge. The combined check that no row
        anywhere is unexplained by *any* known catalogue is
        :func:`assert_no_orphan_tool_rows`, run once across every registry rather than
        repeated on every call site that only ever needed its own tools resolved.

        Raises:
            RegistryDrift: on a missing row, or any disagreement on the fields that
                determine what a tool this registry describes may do.
        """
        rows = list(
            session.execute(
                sa.select(ToolDefinition).order_by(ToolDefinition.name, ToolDefinition.version)
            ).scalars()
        )
        by_key = {(row.name, row.version): row for row in rows}

        problems: list[str] = []
        joined: dict[str, RegisteredTool] = {}

        for descriptor in self.descriptors():
            row = by_key.get((descriptor.name, descriptor.version))
            if row is None:
                problems.append(
                    f"{descriptor.name}@{descriptor.version} is in the code catalogue but "
                    "not in tool_definition; run the seeding migration"
                )
                continue
            problems.extend(_compare(descriptor, row))
            joined[descriptor.name] = RegisteredTool(
                descriptor=descriptor,
                tool_definition_id=row.id,
                credential_ref=row.credential_ref,
            )

        if problems:
            raise RegistryDrift(
                "tool registry drift between code and database:\n  - " + "\n  - ".join(problems)
            )
        return joined


def _compare(descriptor: ToolDescriptor, row: ToolDefinition) -> Iterable[str]:
    """Field-by-field comparison of the properties that govern authority."""
    checks: tuple[tuple[str, object, object], ...] = (
        ("capability", descriptor.capability, row.capability),
        ("risk_tier", descriptor.risk_tier, row.risk_tier),
        ("major_version", descriptor.major_version, row.major_version),
        ("timeout_seconds", descriptor.timeout_seconds, row.timeout_seconds),
        ("settling_seconds", descriptor.settling_seconds, row.settling_seconds),
        ("is_idempotent", descriptor.is_idempotent, row.is_idempotent),
        ("rollback_tool_name", descriptor.rollback_tool_name, row.rollback_tool_name),
        ("provider_kind", descriptor.provider_kind, row.provider_kind),
        ("input_schema", descriptor.to_input_schema(), row.input_schema),
        (
            "idempotency_key_fields",
            list(descriptor.idempotency_key_fields),
            list(row.idempotency_key_fields),
        ),
    )
    for field, expected, actual in checks:
        if expected != actual:
            yield f"{descriptor.name}: {field} is {actual!r} in the database, {expected!r} in code"


def assert_no_orphan_tool_rows(session: Session, *registries: ToolRegistry) -> None:
    """Assert every ``tool_definition`` row is explained by *some* known registry.

    The per-registry check in :meth:`ToolRegistry.assert_matches_database` deliberately
    does not do this - a registry only speaks for its own catalogue. This is the combined
    check: a row that belongs to none of the registries passed here is a capability with no
    descriptor anywhere to validate it, which is exactly the state ADR-0017 layer 1 exists
    to make unreachable. Call it with every registry the deployment actually constructs
    (today: :meth:`ToolRegistry.read_only` and :meth:`ToolRegistry.remediation`).

    Raises:
        RegistryDrift: naming every orphaned row.
    """
    known: set[tuple[str, str]] = set()
    for registry in registries:
        known.update((d.name, d.version) for d in registry.descriptors())

    rows = list(
        session.execute(
            sa.select(ToolDefinition.name, ToolDefinition.version).order_by(
                ToolDefinition.name, ToolDefinition.version
            )
        ).all()
    )
    orphans = [f"{name}@{version}" for name, version in rows if (name, version) not in known]
    if orphans:
        raise RegistryDrift(
            "tool_definition row(s) with no descriptor in any known registry: " + ", ".join(orphans)
        )


__all__ = [
    "RegisteredTool",
    "RegistryDrift",
    "ToolRegistry",
    "assert_no_orphan_tool_rows",
]
