"""Redaction applied before anything is written to an audit record, span or log.

SEC-I6 requires that secrets never enter prompts, traces, logs or the database, and
``docs/architecture/observability.md`` adds that prompt content is recorded by reference
rather than inline. Both are enforced here, at *emission*, because filtering on read cannot
un-leak something already written.

The rule set is deliberately blunt:

* a key whose name matches :data:`asic.domain.safety.FORBIDDEN_SECRET_FIELDS` is replaced
  with a marker, not truncated - a truncated secret is still a leaked prefix;
* a value that looks like a bearer token, private key or connection string is replaced
  even when its key name is innocuous, because the dangerous case is the one that arrived
  inside a payload nobody labelled;
* every remaining string is truncated, because an unbounded attribute is how untrusted log
  content ends up in telemetry with a different retention policy from the incident record.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from asic.domain.safety import is_forbidden_secret_field, is_secret_reference

#: What replaces a redacted value. Distinctive enough to grep for in a trace.
REDACTED: Final[str] = "[redacted]"

#: Longest string retained in an attribute or audit payload.
MAX_VALUE_CHARS: Final[int] = 512

#: Longest collection retained.
MAX_ITEMS: Final[int] = 50

#: How deep the walker descends before collapsing the remainder.
MAX_DEPTH: Final[int] = 6

_SECRET_SHAPED: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{16,}"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@"),  # credentials in a URL
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
)


def looks_like_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_SHAPED)


def redact_value(value: object, *, depth: int = 0) -> Any:
    """Redact and bound one value of any shape."""
    if depth > MAX_DEPTH:
        return f"[depth>{MAX_DEPTH}]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if looks_like_secret(value):
            return REDACTED
        return (
            value if len(value) <= MAX_VALUE_CHARS else value[:MAX_VALUE_CHARS] + "...[truncated]"
        )
    if isinstance(value, Mapping):
        return redact_mapping(value, depth=depth + 1)
    if isinstance(value, Sequence):
        items = list(value)[:MAX_ITEMS]
        rendered = [redact_value(item, depth=depth + 1) for item in items]
        if len(list(value)) > MAX_ITEMS:
            rendered.append(f"[+{len(list(value)) - MAX_ITEMS} more]")
        return rendered
    return redact_value(str(value), depth=depth)


def redact_mapping(payload: Mapping[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Redact a mapping by key name and by value shape.

    A key naming a *reference* to a secret - ``credential_ref``, ``secret_manager_path`` -
    is kept: the whole point of a reference is that it is safe to record.
    """
    result: dict[str, Any] = {}
    for raw_key, value in payload.items():
        key = str(raw_key)
        if is_secret_reference(key):
            result[key] = redact_value(value, depth=depth)
        elif is_forbidden_secret_field(key):
            result[key] = REDACTED
        else:
            result[key] = redact_value(value, depth=depth)
    return result


def redact_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Prepare tool arguments for the ``arguments_redacted`` column.

    Named for what it produces. The column holds arguments that were redacted before the
    row was constructed, not arguments that a reader is trusted to filter.
    """
    return redact_mapping(arguments)


__all__ = [
    "MAX_DEPTH",
    "MAX_ITEMS",
    "MAX_VALUE_CHARS",
    "REDACTED",
    "looks_like_secret",
    "redact_arguments",
    "redact_mapping",
    "redact_value",
]
