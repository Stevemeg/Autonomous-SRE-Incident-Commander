"""UNIT: every status an alert or panel selects on can actually occur (Phase 15, F-07).

F-07 was an alert and a panel on ``status="compensation_failed"``: a real enum value that no
code path ever assigns, because automated compensation is not implemented. The PromQL checker
proved the *label* existed, not that the *value* could. This test closes that gap statically:
each exact value selected for a lifecycle label (``status``, ``outcome``, ``verdict``) must be
a member of a domain enum that source code outside ``enums.py`` actually references, or a
literal the source emits.
"""

from __future__ import annotations

import enum
import re
from pathlib import Path

from asic.domain import enums
from tests.observability.test_config_artifacts import _promql_exprs

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "src" / "asic"
_SELECTOR = re.compile(r'\b(status|outcome|verdict)\s*(=~|=)\s*"([^"]*)"')


def _source_text() -> str:
    return "\n".join(
        path.read_text("utf-8")
        for path in SOURCE.rglob("*.py")
        if path.name != "enums.py" and "__pycache__" not in path.parts
    )


def _reachable(value: str, source: str) -> bool:
    for _, klass in vars(enums).items():
        if isinstance(klass, type) and issubclass(klass, enum.Enum):
            for member in klass:
                if member.value == value and f"{klass.__name__}.{member.name}" in source:
                    return True
    return f'"{value}"' in source


def _selected_values() -> set[str]:
    values: set[str] = set()
    for expr in _promql_exprs():
        for _label, operator, raw in _SELECTOR.findall(expr):
            parts = raw.split("|") if operator == "=~" else [raw]
            values.update(part for part in parts if part and not any(c in part for c in ".*+?[("))
    return values


def test_every_selected_lifecycle_value_is_reachable() -> None:
    source = _source_text()
    selected = _selected_values()
    assert {"failed_partial", "dead_lettered", "unknown"} <= selected  # non-vacuous
    unreachable = sorted(value for value in selected if not _reachable(value, source))
    assert unreachable == [], f"alerts/panels select values no code path sets: {unreachable}"


def test_the_check_would_have_caught_f07() -> None:
    source = _source_text()
    assert not _reachable("compensation_failed", source)
    assert _reachable("failed_partial", source)
