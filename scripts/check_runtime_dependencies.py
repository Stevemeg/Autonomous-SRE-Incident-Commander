#!/usr/bin/env python3
"""Verify every third-party import under ``src/`` is a declared runtime dependency.

Exists because P6-01: ``src/asic/db/models/knowledge.py`` imported ``pgvector`` at module
load time while ``pyproject.toml`` never declared it, so a clean install of the project's
own metadata could not import the application or run migrations. That class of drift is
cheap to catch mechanically and easy to miss in review, because the package is usually
present anyway in whatever environment the reviewer is running - a developer virtualenv,
CI cache, or globally installed toolchain.

This is a static check, not a substitute for actually installing into an empty
environment (see ``scripts/verify_clean_install.py`` for that). It maps every top-level
import found in application source to the distribution that provides it (via
``importlib.metadata.packages_distributions``, which reflects what is *actually
installed* in the current interpreter) and asserts that distribution is named in
``[project.dependencies]``. A module that cannot be resolved to an installed distribution
is itself a finding: either it is missing from the current environment (so the import
would fail here too), or it is a typo.

Standard library only. Exit code 0 = clean, 1 = findings.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "asic"
PYPROJECT = REPO / "pyproject.toml"

#: Import roots that are part of this project, not a third-party dependency.
INTERNAL_ROOTS = {"asic"}

#: Modules whose owning distribution is deliberately not listed in
#: ``[project.dependencies]`` directly, because a *declared* dependency already pins it
#: transitively with no independent version freedom - so it can never be present-but-
#: incompatible or absent-while-the-declared-dependency-is-installed. ``pydantic_core`` is
#: pydantic's own compiled engine: every ``pydantic`` release requires an exact matching
#: ``pydantic-core`` range, so declaring ``pydantic`` already guarantees it. This is
#: unlike P6-01's ``pgvector``, which had no such relationship to anything declared.
NO_DIRECT_IMPORT: frozenset[str] = frozenset({"pydantic_core"})


def normalize(name: str) -> str:
    """PEP 503 normalisation: case- and separator-insensitive distribution comparison."""
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_dependency_names() -> set[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    raw = data["project"]["dependencies"]
    names = set()
    for requirement in raw:
        # A PEP 508 requirement string: name, then optional extras/version/markers.
        match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
        if match:
            names.add(normalize(match.group(1)))
    return names


def top_level_imports(tree: ast.Module) -> set[str]:
    """Every module imported by this file, excluding ``TYPE_CHECKING``-guarded imports."""
    found: set[str] = set()

    def in_type_checking_guard(node: ast.AST, guards: set[int]) -> bool:
        return id(node) in guards

    type_checking_bodies: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            is_type_checking = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            )
            if is_type_checking:
                for child in ast.walk(node):
                    type_checking_bodies.add(id(child))

    for node in ast.walk(tree):
        if in_type_checking_guard(node, type_checking_bodies):
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


def collect_third_party_imports() -> set[str]:
    modules: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        modules |= top_level_imports(tree)
    stdlib = sys.stdlib_module_names
    return {m for m in modules if m not in INTERNAL_ROOTS and m not in stdlib}


def check() -> list[str]:
    findings: list[str] = []
    declared = declared_dependency_names()
    distributions = metadata.packages_distributions()

    for module in sorted(collect_third_party_imports()):
        if module in NO_DIRECT_IMPORT:
            continue
        owners = distributions.get(module)
        if not owners:
            findings.append(
                f"import {module!r} could not be resolved to any installed distribution "
                "(missing from this environment, or a typo)"
            )
            continue
        normalized_owners = {normalize(o) for o in owners}
        if not normalized_owners & declared:
            findings.append(
                f"import {module!r} is provided by {sorted(owners)}, none of which is "
                "declared in [project.dependencies]"
            )
    return findings


def main() -> int:
    findings = check()
    print(f"third-party imports checked under {SRC.relative_to(REPO)}")
    if findings:
        print(f"RESULT: {len(findings)} finding(s).")
        for finding in findings:
            print(f"  - {finding}")
        return 1
    print("RESULT: CLEAN - every third-party import is a declared runtime dependency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
