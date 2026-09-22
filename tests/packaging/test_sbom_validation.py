from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_sbom", REPO / "scripts" / "validate_sbom.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _write(path: Path, components: list[dict[str, str]]) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"name": "asic-backend"}},
                "components": components,
            }
        ),
        encoding="utf-8",
    )


def test_actual_final_image_sbom_contract_is_non_vacuous(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    _write(path, [{"name": "asic"}, {"name": "SQLAlchemy"}])
    assert MODULE.main([str(path), "--expect", "asic", "--expect", "SQLAlchemy"]) == 0


def test_empty_or_wrong_stage_sbom_fails_closed(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    _write(empty, [])
    assert MODULE.main([str(empty), "--expect", "asic"]) == 1
    wrong = tmp_path / "wrong.json"
    _write(wrong, [{"name": "npm"}])
    assert MODULE.main([str(wrong), "--expect", "asic"]) == 1


def test_sbom_must_bind_to_the_final_image_identity(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    _write(path, [{"name": "fastapi"}])
    image_id = "sha256:" + "a" * 64
    document = json.loads(path.read_text("utf-8"))
    document["metadata"]["component"]["properties"] = [
        {"name": "aquasecurity:trivy:ImageID", "value": image_id}
    ]
    path.write_text(json.dumps(document), "utf-8")
    assert MODULE.validate(path, ("fastapi",), image_id) == []
    assert MODULE.validate(path, ("fastapi",), "sha256:" + "b" * 64)
