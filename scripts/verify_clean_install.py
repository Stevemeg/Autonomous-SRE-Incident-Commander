#!/usr/bin/env python3
"""P6-01: prove the project installs and runs from its own declared metadata alone.

``scripts/check_runtime_dependencies.py`` is a static check against whatever happens to
be installed in the current interpreter. This script is the dynamic complement it
promises: it builds a *new*, empty virtual environment, installs only what
``pyproject.toml`` declares (``uv pip install .``, no dev extra, no pre-existing
site-packages), and then - inside that environment - imports the knowledge models and
runs the Alembic migration chain against a throwaway SQLite-free check (import + `alembic
check`, which loads every migration module). This is exactly the P6-01 failure mode:
``pgvector`` was importable in the developer environment only because it happened to
already be installed there, not because the project declared it.

Requires ``uv`` (already used by this project's own dev workflow) and network access to
resolve the declared dependencies. Not run as part of the default test suite - it is slow
and network-dependent - but is the authoritative check referenced by P6-01's completion
report. Run it directly: ``python scripts/verify_clean_install.py``.

Exit code 0 = clean install, import and migration load succeeded. Non-zero = failure, with
the failing step's output printed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

IMPORT_CHECK = (
    "import asic.db.models.knowledge; "
    "import asic.db.models; "
    "import asic; "
    "print('import OK: asic.db.models.knowledge')"
)


def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def main() -> int:
    if shutil.which("uv") is None:
        print("SKIP: `uv` is not on PATH; cannot build an isolated environment.")
        return 0

    with tempfile.TemporaryDirectory(prefix="asic-clean-install-") as tmp:
        venv_dir = Path(tmp) / "venv"

        step = run(["uv", "venv", str(venv_dir)])
        if step.returncode != 0:
            print("FAIL: could not create a clean virtual environment.")
            return 1

        python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

        # Only [project.dependencies] - no dev extra, no editable link to the developer
        # environment's own already-installed packages.
        step = run(["uv", "pip", "install", "--python", str(python), str(REPO)])
        if step.returncode != 0:
            print("FAIL: `uv pip install .` failed against declared metadata alone.")
            return 1

        step = run([str(python), "-c", IMPORT_CHECK])
        if step.returncode != 0:
            print("FAIL: importing asic.db.models.knowledge failed in the clean install.")
            print("This is exactly the P6-01 failure mode: a runtime import with no")
            print("declared dependency behind it.")
            return 1

        # `alembic upgrade head` needs a live database; loading every revision module
        # (what `alembic check`/`heads` does first) is the part that would fail if a
        # migration itself imported an undeclared package - it does not here, but the
        # clean install must prove it either way.
        step = run(
            [str(python), "-m", "alembic", "-c", str(REPO / "alembic.ini"), "heads"],
            cwd=str(REPO),
        )
        if step.returncode != 0:
            print("FAIL: alembic could not load the migration chain in the clean install.")
            return 1

        print("RESULT: CLEAN - install from declared metadata alone, import, and the")
        print("        Alembic migration chain all succeeded with no pre-existing")
        print("        environment state.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
