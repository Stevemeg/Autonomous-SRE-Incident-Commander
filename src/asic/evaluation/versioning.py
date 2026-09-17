"""Canonical digests and the evaluator version.

Every stored evaluation artefact - scenario definitions, replay fixtures, suite reports - is
sealed by a SHA-256 over canonical JSON (sorted keys, no insignificant whitespace, ISO-8601
datetimes, UUIDs as strings). Changing a checked-in scenario without bumping its version, or
editing a stored fixture or report, changes the digest and is refused on load.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Final

#: Bumped whenever a deterministic check or metric definition changes meaning. A result is
#: only comparable with a baseline produced by the same evaluator version.
EVALUATOR_VERSION: Final[str] = "2026.09.17-eval-1"

#: Replay fixture format.
REPLAY_FORMAT_VERSION: Final[int] = 1


def canonical(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return canonical(asdict(value))
    if isinstance(value, Enum):
        return canonical(value.value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): canonical(v) for k, v in sorted(value.items(), key=lambda i: str(i[0]))}
    if isinstance(value, (list, tuple)):
        return [canonical(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(canonical(v) for v in value)
    if isinstance(value, float) and value != value:  # NaN is not canonical JSON
        raise ValueError("NaN cannot be canonicalised")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Sequence):
        return [canonical(v) for v in value]
    raise TypeError(f"cannot canonicalise {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


__all__ = ["EVALUATOR_VERSION", "REPLAY_FORMAT_VERSION", "canonical", "canonical_json", "digest"]
