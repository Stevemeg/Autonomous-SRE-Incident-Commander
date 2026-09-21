"""Phase 13 static-analysis policy, enforced as tests.

The SAST gate is ``ruff check --select S`` (flake8-bandit rules) over ``src`` - no new scanner,
because ruff is already the project's linter and the ``S`` rules cover the classes that matter
here: unsafe subprocess/shell, ``eval``/``exec``, weak hashes, hard-coded credentials,
insecure temp files, unverified TLS, unsafe deserialisation. Nothing is suppressed inline.

One rule is handled by policy instead of suppression: ``S101`` (``assert``). Every ``assert`` in
``src`` was reviewed; all are internal invariants or type narrowing. Under ``python -O`` they
would vanish, and each would then fail on the very next attribute access - none guards
authority, validates external input or enforces a limit. That reasoning is only safe while it
stays true, so the tests below pin it: an ``assert`` must be a narrowing form, and a new one of
any other shape must be written as an explicit ``raise``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

SRC = Path(__file__).resolve().parents[2] / "src" / "asic"

#: Modules that enforce authentication, authorization, scope, limits or secrets. An ``assert``
#: is not acceptable there in any form: their checks must survive ``python -O``.
SECURITY_CRITICAL = (
    "api/auth.py",
    "api/tokens.py",
    "api/limits.py",
    "api/rate_limit.py",
    "remediation/authorization.py",
    "remediation/approval_service.py",
    "tools/connector_scope.py",
    "integrations/credentials.py",
    "integrations/transport.py",
    "observability/redaction.py",
    "db/tenancy_audit.py",
    "domain/permissions.py",
    "domain/safety.py",
    "retention/policy.py",
)


def _is_none_narrowing(test: ast.expr) -> bool:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return all(_is_none_narrowing(value) for value in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        operator, right = test.ops[0], test.comparators[0]
        if isinstance(operator, ast.IsNot) and isinstance(right, ast.Constant):
            return right.value is None
        if isinstance(operator, ast.Is) and isinstance(right, ast.Attribute):
            return True  # narrowing to a specific enum member
    return False


def _asserts() -> list[tuple[str, int, ast.Assert]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                found.append((path.relative_to(SRC).as_posix(), node.lineno, node))
    return found


def test_every_assert_in_src_is_an_internal_narrowing_invariant() -> None:
    offenders = [
        f"{path}:{line}: {ast.unparse(node.test)}"
        for path, line, node in _asserts()
        if not _is_none_narrowing(node.test)
    ]
    assert offenders == [], (
        f"an assert that is not a None/enum narrowing must be an explicit `raise`: {offenders}"
    )


def test_no_assert_appears_in_a_security_critical_module() -> None:
    offenders = [f"{path}:{line}" for path, line, _ in _asserts() if path in SECURITY_CRITICAL]
    assert offenders == []
    for module in SECURITY_CRITICAL:
        assert (SRC / module).is_file(), f"stale entry in SECURITY_CRITICAL: {module}"


def test_the_sast_gate_has_no_inline_suppressions() -> None:
    pattern = re.compile(r"#\s*noqa\s*:\s*[^#\n]*\bS\d{3}\b")
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{number}")
    assert offenders == [], "security findings must be fixed or reviewed here, not silenced"


def test_no_dynamic_code_execution_or_unsafe_deserialisation_primitives_in_src() -> None:
    """A precise AST backstop for the highest-consequence S-rules, independent of ruff."""
    banned_calls = {"eval", "exec", "compile", "__import__"}
    banned_attrs = {
        ("pickle", "loads"),
        ("pickle", "load"),
        ("marshal", "loads"),
        ("os", "system"),
        ("os", "popen"),
        ("yaml", "load"),
        ("subprocess", "run"),
        ("subprocess", "Popen"),
        ("subprocess", "call"),
        ("subprocess", "check_output"),
    }
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in banned_calls:
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}: {func.id}")
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and (func.value.id, func.attr) in banned_attrs
            ):
                offenders.append(
                    f"{path.relative_to(SRC).as_posix()}:{node.lineno}: {func.value.id}.{func.attr}"
                )
    assert offenders == [], offenders


def test_tls_verification_is_never_disabled() -> None:
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
    for needle in (
        "verify=False",
        "CERT_NONE",
        "check_hostname = False",
        "_create_unverified_context",
    ):
        assert needle not in text, needle


def test_hash_functions_used_for_security_are_not_weak() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in {"md5", "sha1"}
            ):
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    assert offenders == []


def test_source_contains_no_invisible_or_bidirectional_control_characters() -> None:
    """'Trojan Source' (CVE-2021-42574): reordering characters can make code read differently
    from how it executes. Any such character in a source file is a finding."""
    forbidden = {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0x00AD}
    forbidden |= set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
    offenders = []
    repo = SRC.parents[1]
    for root in (repo / "src", repo / "tests", repo / "scripts", repo / "migrations"):
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                if any(ord(ch) in forbidden for ch in line):
                    offenders.append(f"{path.relative_to(repo).as_posix()}:{number}")
    assert offenders == [], offenders
