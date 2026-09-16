from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

from asic.domain.clock import FrozenClock
from asic.domain.enums import IntegrationKind
from asic.integrations.base import AdapterRuntime
from asic.integrations.credentials import StaticCredentialProvider
from asic.integrations.transport import HttpClientTransport
from asic.tools.provider import ConnectorGrant, InvocationContext
from tests.integrations.local_http import LocalHttpServer, local_server

#: Fake, test-only secrets. Distinctive so a leak is easy to grep for.
READ_TOKEN = "test-read-token-5e1f0c2a-DO-NOT-LEAK"
WRITE_TOKEN = "test-write-token-9b77d31e-DO-NOT-LEAK"
SECRETS = {
    "asic/test/read": READ_TOKEN,
    "asic/test/write": WRITE_TOKEN,
    "asic/test/basic": "bot@example.invalid:jira-token-4c1d-DO-NOT-LEAK",
}

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def server() -> Iterator[LocalHttpServer]:
    with local_server() as running:
        yield running


@pytest.fixture
def runtime() -> AdapterRuntime:
    return AdapterRuntime(
        transport=HttpClientTransport(),
        credentials=StaticCredentialProvider(SECRETS),
        clock=FrozenClock(start=NOW),
        allow_loopback_http=True,
    )


def grant(
    kind: IntegrationKind,
    endpoint: str | None,
    *,
    credential_ref: str | None = "asic/test/read",
    write_credential_ref: str | None = "asic/test/write",
    settings: dict[str, Any] | None = None,
) -> ConnectorGrant:
    return ConnectorGrant(
        connector_id=f"{kind.value}-test",
        kind=kind,
        endpoint_url=endpoint,
        credential_ref=credential_ref,
        write_credential_ref=write_credential_ref,
        service_name="checkout-api",
        environment_name="production",
        settings=settings or {},
        namespaces=("checkout",),
    )


def context(connector: ConnectorGrant | None, *, timeout: int = 10) -> InvocationContext:
    return InvocationContext(
        tenant_id=uuid.uuid4(),
        correlation_id=uuid.uuid4(),
        idempotency_key="k" * 64,
        credential_ref=connector.credential_ref if connector else None,
        timeout_seconds=timeout,
        attempt=1,
        connector=connector,
        traceparent="00-" + "a" * 32 + "-" + "b" * 16 + "-01",
    )
