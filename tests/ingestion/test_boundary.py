"""Non-vacuous Phase 5 import boundary, with deliberately planted violations."""

import ast
from pathlib import Path

from scripts.validate_docs import Findings, check_phase_boundary, check_safety_invariant_ids


def test_phase_validator_rejects_planted_future_phase(tmp_path: Path, monkeypatch: object) -> None:
    import scripts.validate_docs as validator
    from pytest import MonkeyPatch

    assert isinstance(monkeypatch, MonkeyPatch)
    source = tmp_path / "src" / "asic" / "ingestion"
    source.mkdir(parents=True)
    (source / "bad.py").write_text("import mcp\nimport kafka\n", encoding="utf-8")
    (tmp_path / "src" / "asic" / "rag").mkdir()
    monkeypatch.setattr(validator, "REPO", tmp_path)
    findings = Findings()
    check_phase_boundary(findings)
    messages = " ".join(findings.report("phase"))
    assert "mcp" in messages and "kafka" in messages and "rag" in messages


def test_normalization_and_correlation_have_no_model_or_external_execution_imports() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "asic" / "ingestion"
    checked = 0
    for name in ("contracts.py", "normalizers.py", "correlation.py", "service.py"):
        tree = ast.parse((root / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imports = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            for module in imports:
                assert not any(
                    word in module.split(".")
                    for word in (
                        "llm",
                        "orchestration",
                        "tools",
                        "subprocess",
                        "requests",
                        "httpx",
                        "urllib",
                        "socket",
                    )
                )
        checked += 1
    assert checked == 4


def test_duplicate_safety_invariant_ids_are_rejected(tmp_path: Path) -> None:
    document = tmp_path / "safety.md"
    document.write_text(
        "| **SI-1** | first | enforcement | failure |\n"
        "| **SI-1** | duplicate | enforcement | failure |\n",
        encoding="utf-8",
    )
    findings = Findings()
    assert check_safety_invariant_ids([document], findings) == 2
    assert len(findings.report("invariants")) == 1
