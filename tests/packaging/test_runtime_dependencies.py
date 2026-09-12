"""P6-01: every third-party import under ``src/`` must be a declared runtime dependency.

``src/asic/db/models/knowledge.py`` imports ``pgvector.sqlalchemy`` at module load time.
Before this fix, ``pgvector`` was reachable only because it happened to be present in the
developer environment - it was never declared in ``[project.dependencies]``, so a clean
install of the project's own metadata could not import the knowledge models or run the
Alembic migration that creates the ``vector`` column. This suite proves the static
checker (``scripts/check_runtime_dependencies.py``) both passes against the real
repository and is non-vacuous: it fails when the pgvector declaration is removed.
"""

from __future__ import annotations

import ast

from scripts.check_runtime_dependencies import (
    check,
    collect_third_party_imports,
    declared_dependency_names,
    normalize,
    top_level_imports,
)


def test_repository_declares_every_third_party_import_it_uses() -> None:
    findings = check()
    assert findings == [], f"undeclared runtime imports: {findings}"


def test_pgvector_is_imported_by_knowledge_models_and_is_declared() -> None:
    """Reproduces P6-01 directly: the exact import site and the exact dependency."""
    assert "pgvector" in collect_third_party_imports()
    assert "pgvector" in declared_dependency_names()


def test_checker_is_non_vacuous_without_the_pgvector_declaration(monkeypatch: object) -> None:
    """Mutation test: undeclaring pgvector must be caught, proving the check isn't vacuous."""
    import scripts.check_runtime_dependencies as checker
    from pytest import MonkeyPatch

    assert isinstance(monkeypatch, MonkeyPatch)
    original = checker.declared_dependency_names

    def declared_without_pgvector() -> set[str]:
        return original() - {"pgvector"}

    monkeypatch.setattr(checker, "declared_dependency_names", declared_without_pgvector)
    findings = checker.check()
    assert any("pgvector" in f for f in findings)


def test_normalize_treats_case_and_separators_as_equivalent() -> None:
    assert normalize("SQLAlchemy") == normalize("sqlalchemy")
    assert normalize("opentelemetry-api") == normalize("opentelemetry_api")


def test_type_checking_only_imports_are_not_required_as_runtime_dependencies() -> None:
    tree = ast.parse(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import definitely_not_a_real_package\n"
    )
    assert "definitely_not_a_real_package" not in top_level_imports(tree)
