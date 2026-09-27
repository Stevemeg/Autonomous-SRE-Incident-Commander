"""Shared fixtures for the Phase 13 security suite.

The API arrangement fixtures already exist in ``tests/api/test_auth.py``; they are re-exported
here so security modules use them by name without redefining them.
"""

from __future__ import annotations

from tests.api.test_auth import (  # noqa: F401 - registered as fixtures for this directory
    api_arranger,
    api_factory,
    worlds,
)
from tests.integrations.conftest import runtime  # noqa: F401 - adapter fixture
from tests.observability.conftest import (  # noqa: F401 - span capture fixtures
    span_exporter,
    spans,
    telemetry,
)
