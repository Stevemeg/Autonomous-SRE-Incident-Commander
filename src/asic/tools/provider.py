"""The tool provider seam.

ADR-0003 chose native adapters behind an MCP-ready boundary. This is that boundary: the
broker depends on :class:`ToolProvider`, never on an adapter class, so a future MCP
provider is an implementation of this protocol rather than a redesign.

Three rules keep the seam honest, and they are stated here because they are easy to lose
later:

1. **A provider's own descriptors are untrusted.** A provider reports what it can do; the
   *registry* decides what it is allowed to do. A remote server cannot declare its own
   capability, scope or risk tier.
2. **The policy boundary is unchanged.** Every provider's tools pass the same broker
   pipeline. There is no fast path.
3. **Credentials stay with the broker.** A provider receives a resolved, scoped credential
   reference for the call it is making; it never holds an ambient credential and never
   resolves one for itself.

The provider is also the only place a tool failure originates. It raises the typed failures
in :mod:`asic.domain.errors` - never a bare exception, and never a plausible-looking
success value in place of a failure.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from asic.domain.enums import ToolProviderKind
from asic.tools.descriptor import ToolDescriptor


@dataclass(frozen=True, slots=True)
class InvocationContext:
    """Everything a provider is told about the call it is making.

    Deliberately narrow. A provider is given the resolved scope and the identifiers needed
    for correlation and idempotency, and nothing about the incident's reasoning: an adapter
    that could see the hypothesis it is being asked to support would be an adapter that
    could be biased by it.
    """

    tenant_id: UUID
    correlation_id: UUID
    idempotency_key: str
    #: Name of the credential in the secret manager. Never the credential itself.
    credential_ref: str | None
    timeout_seconds: int
    attempt: int


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Whether a provider is usable, and why not when it is not."""

    available: bool
    detail: str = ""


@runtime_checkable
class ToolProvider(Protocol):
    """A source of tool implementations."""

    @property
    def kind(self) -> ToolProviderKind:
        """Which provider family this is. Recorded on every execution record."""

    def list_tools(self) -> tuple[str, ...]:
        """Names of the tools this provider implements.

        Advisory: the registry, not the provider, decides what may be invoked.
        """

    def supports(self, descriptor: ToolDescriptor) -> bool:
        """Whether this provider implements the given registered tool."""

    def invoke(
        self,
        descriptor: ToolDescriptor,
        arguments: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        """Execute one call and return its raw result.

        The result is validated by the broker against ``descriptor``; a provider is not
        trusted to have produced the right shape.

        Raises:
            ToolTimeout: the upstream did not answer within the deadline.
            ToolAdapterError: the upstream refused or failed.
        """

    def health(self) -> ProviderHealth:
        """Current availability, used to degrade rather than abort an investigation."""


__all__ = ["InvocationContext", "ProviderHealth", "ToolProvider"]
