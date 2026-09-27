"""Fixtures shared by the end-to-end suites (span/metric capture and adapter runtime)."""

from __future__ import annotations

from tests.integrations.conftest import runtime, server  # noqa: F401 - adapter fixtures
from tests.integrations.test_crash_recovery import crash_after_response  # noqa: F401
from tests.observability.conftest import (  # noqa: F401 - telemetry capture fixtures
    span_exporter,
    spans,
    telemetry,
)
