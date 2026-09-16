"""Explicit provider composition per execution mode. No mode mixes live and fixture data.

``LIVE``
    Native adapters (plus the governed knowledge store). Requires a production credential
    provider; refuses test credentials and plain-http loopback endpoints. There is no
    simulator anywhere in the returned set, so a failing Prometheus is reported as a failing
    Prometheus - never answered by scenario fixtures.

``SIMULATOR``
    The deterministic scenario simulator (plus the knowledge store). Refused in a
    production deployment by the simulator itself.

``REPLAY``
    Recorded tool results. Built by the evaluation harness (Phase 11), not here.

``compose_local_integration_test_providers`` is explicit test infrastructure: native
adapters pointed at local deterministic HTTP servers with static test credentials. It is
refused in production and its result is labelled so it can never be reported as live.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from asic.domain.clock import Clock
from asic.domain.enums import ExecutionMode
from asic.integrations.base import AdapterRuntime
from asic.integrations.credentials import CredentialProvider, is_production_deployment
from asic.integrations.provider import NativeIntegrationProvider
from asic.integrations.transport import HttpClientTransport, HttpTransport
from asic.tools.provider import ToolProvider


class CompositionRefused(RuntimeError):
    """A provider set was requested that would blur live and fixture data."""


@dataclass(frozen=True, slots=True)
class ProviderComposition:
    mode: ExecutionMode
    providers: tuple[ToolProvider, ...]
    #: True when any part is test infrastructure. Such a composition is never "live".
    is_test_infrastructure: bool


def compose_live_providers(
    *,
    credentials: CredentialProvider,
    clock: Clock,
    extra_native: Sequence[ToolProvider] = (),
    transport: HttpTransport | None = None,
) -> ProviderComposition:
    if credentials.is_test_infrastructure:
        raise CompositionRefused("live composition refuses a test credential provider")
    for provider in extra_native:
        if provider.kind.value != "native":
            raise CompositionRefused(
                f"live composition refuses a {provider.kind.value} provider; a live failure "
                "must never be answered by fixture data"
            )
    native = NativeIntegrationProvider(
        AdapterRuntime(
            transport=transport or HttpClientTransport(),
            credentials=credentials,
            clock=clock,
            allow_loopback_http=False,
        )
    )
    return ProviderComposition(
        mode=ExecutionMode.LIVE,
        providers=(*extra_native, native),
        is_test_infrastructure=False,
    )


def compose_local_integration_test_providers(
    *,
    credentials: CredentialProvider,
    clock: Clock,
    transport: HttpTransport | None = None,
) -> ProviderComposition:
    """Native adapters against local deterministic servers. Test infrastructure only."""
    if is_production_deployment():
        raise CompositionRefused("local integration test composition cannot run in production")
    native = NativeIntegrationProvider(
        AdapterRuntime(
            transport=transport or HttpClientTransport(),
            credentials=credentials,
            clock=clock,
            allow_loopback_http=True,
        )
    )
    return ProviderComposition(
        mode=ExecutionMode.LIVE, providers=(native,), is_test_infrastructure=True
    )


__all__ = [
    "CompositionRefused",
    "ProviderComposition",
    "compose_live_providers",
    "compose_local_integration_test_providers",
]
