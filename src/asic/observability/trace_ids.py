"""The one authoritative W3C trace-id validity rule (Phase 13, carry-forward F-11).

A trace id is 32 lowercase hexadecimal characters and is not all zeros. The all-zero id is
the W3C "invalid" value: OpenTelemetry drops spans that carry it, which would silently turn
a linked trace into a disconnected one. A non-hex value would raise deep inside span
construction.

The rule is enforced three times, deliberately: here at every construction boundary, in the
database by ``ck_execution_trace_trace_id_is_w3c_trace_id`` (migration 0018), and again where
a *persisted* id is turned into a span context, because a historical row may predate the
constraint. In that last place an invalid id fails loudly (:class:`InvalidTraceId`); the
caller never receives a freshly minted substitute pretending linkage was preserved.
"""

from __future__ import annotations

import re
from typing import Final

from asic.domain.errors import DomainError

TRACE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")
SPAN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{16}")
_ZERO_TRACE: Final[str] = "0" * 32


class InvalidTraceId(DomainError):
    """A trace id that is not 32 lowercase hex characters, or is all zero."""


def is_valid_trace_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and TRACE_ID_PATTERN.fullmatch(value) is not None
        and value != _ZERO_TRACE
    )


def require_valid_trace_id(value: object) -> str:
    """Return ``value`` unchanged, or raise :class:`InvalidTraceId` (never the value)."""
    if not isinstance(value, str) or not is_valid_trace_id(value):
        raise InvalidTraceId("trace id must be 32 lowercase hex characters and not all zero")
    return value


def is_valid_span_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and SPAN_ID_PATTERN.fullmatch(value) is not None
        and value != "0" * 16
    )


__all__ = [
    "SPAN_ID_PATTERN",
    "TRACE_ID_PATTERN",
    "InvalidTraceId",
    "is_valid_span_id",
    "is_valid_trace_id",
    "require_valid_trace_id",
]
