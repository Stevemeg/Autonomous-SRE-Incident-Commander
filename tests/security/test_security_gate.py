"""Phase 13 security gate and supply-chain policy: behaviour under failure, not just success.

A gate that can only say "passed" proves nothing, so every test here is about a way the gate
or the lock policy could be fooled: a missing scanner, a scanner that exits 0 without a clean
report, a skipped check in CI, an unhashed requirement, a dependency-confusion index line, a
stale prerelease exception, a widened secret-scan allowance.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load("security_gate")
locks = _load("check_dependency_lock")


# ------------------------------------------------------------------------ the gate


def clean_runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
    """Answers every scanner with a genuinely clean report."""
    joined = " ".join(command)
    if "pip-audit" in joined or "pip_audit" in joined:
        return gate.CommandResult(0, "", "No known vulnerabilities found")
    if "npm" in joined and "audit" in joined:
        return gate.CommandResult(0, "found 0 vulnerabilities", "")
    if "gitleaks" in joined:
        return gate.CommandResult(0, "", "INF no leaks found")
    if "pytest" in joined:
        return gate.CommandResult(0, "700 passed in 5s", "")
    if "FINDINGS" in joined:
        return gate.CommandResult(0, "FINDINGS 0", "")
    return gate.CommandResult(0, "", "")


def context(runner: object, **overrides: object) -> object:
    values: dict[str, object] = {
        "repo": REPO,
        "runner": runner,
        "python": sys.executable,
        "strict": False,
        "offline": False,
        "database_url": "postgresql://unused",
    }
    values.update(overrides)
    return gate.Context(**values)


@pytest.fixture(autouse=True)
def _tools_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every scanner look installed so the *runner's* answer is what is being tested."""
    monkeypatch.setenv("ASIC_PIP_AUDIT", "pip-audit")
    real = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *a, **k: {"npm": "npm", "gitleaks": "gitleaks"}.get(name, real(name)),
    )


def statuses(verdict: dict[str, object]) -> dict[str, str]:
    return {c["name"]: c["status"] for c in verdict["checks"]}  # type: ignore[index]


class TestGateVerdict:
    def test_everything_clean_passes_and_the_container_scan_is_reported_not_faked(self) -> None:
        verdict = gate.run_gate(context(clean_runner))
        assert verdict["passed"] is True
        by_name = statuses(verdict)
        assert by_name["container_scan"] == "not_executable"
        assert {v for k, v in by_name.items() if k != "container_scan"} == {"passed"}
        reason = next(c for c in verdict["checks"] if c["name"] == "container_scan")["detail"]  # type: ignore[index]
        assert "CONTAINER IMAGE NOT SUPPLIED" in reason

    def test_the_container_scan_can_be_made_mandatory_for_phase_14(self) -> None:
        verdict = gate.run_gate(context(clean_runner), require_container_scan=True)
        assert verdict["passed"] is False

    def test_a_real_container_scan_satisfies_the_phase_14_requirement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASIC_TRIVY", "trivy")

        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            assert command[-1] == "asic-backend:phase14-test"
            return gate.CommandResult(
                0,
                json.dumps(
                    {
                        "ArtifactName": "asic-backend:phase14-test",
                        "ArtifactType": "container_image",
                        "Metadata": {"ImageID": "sha256:" + "a" * 64},
                        "Results": [
                            {"Target": "debian", "Class": "os-pkgs", "Vulnerabilities": None}
                        ],
                    }
                ),
                "",
            )

        verdict = gate.run_gate(
            context(runner, container_images=("asic-backend:phase14-test",)),
            only=["container_scan"],
            require_container_scan=True,
        )
        assert verdict["passed"] is True
        assert statuses(verdict)["container_scan"] == "passed"

    def test_required_container_check_cannot_be_excluded(self) -> None:
        verdict = gate.run_gate(
            context(clean_runner), only=["dependency_lock"], require_container_scan=True
        )
        assert verdict["passed"] is False
        assert statuses(verdict)["container_scan"] == "failed"

    @pytest.mark.parametrize(
        "mutation", ["wrong_image", "empty_target", "wrong_type", "empty_targets"]
    )
    def test_scanner_success_without_image_evidence_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mutation: str,
    ) -> None:
        monkeypatch.setenv("ASIC_TRIVY", "trivy")
        report: dict[str, object] = {
            "ArtifactName": "asic-backend:phase14-test",
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": "sha256:" + "a" * 64},
            "Results": [{"Target": "alpine", "Class": "os-pkgs"}],
        }
        if mutation == "wrong_image":
            report["ArtifactName"] = "unrelated:phase14-test"
        elif mutation == "wrong_type":
            report["ArtifactType"] = "filesystem"
        else:
            report["Results"] = [{}] if mutation == "empty_target" else []
        verdict = gate.run_gate(
            context(
                lambda *_args: gate.CommandResult(0, json.dumps(report), ""),
                container_images=("asic-backend:phase14-test",),
            ),
            only=["container_scan"],
            require_container_scan=True,
        )
        assert verdict["passed"] is False

    @pytest.mark.parametrize(
        ("result", "detail"),
        [
            (gate.CommandResult(0, "not json", ""), "not valid JSON"),
            (
                gate.CommandResult(0, json.dumps({"Metadata": {}, "Results": []}), ""),
                "did not identify",
            ),
            (
                gate.CommandResult(
                    1,
                    json.dumps(
                        {
                            "ArtifactName": "asic-backend:phase14-test",
                            "ArtifactType": "container_image",
                            "Metadata": {"ImageID": "sha256:" + "b" * 64},
                            "Results": [
                                {
                                    "Target": "python",
                                    "Class": "lang-pkgs",
                                    "Vulnerabilities": [{"Severity": "HIGH"}],
                                }
                            ],
                        }
                    ),
                    "",
                ),
                "blocking container vulnerabilities",
            ),
        ],
    )
    def test_container_scan_output_fails_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        result: object,
        detail: str,
    ) -> None:
        monkeypatch.setenv("ASIC_TRIVY", "trivy")
        verdict = gate.run_gate(
            context(lambda *_args: result, container_images=("asic-backend:phase14-test",)),
            only=["container_scan"],
            require_container_scan=True,
        )
        check = verdict["checks"][0]  # type: ignore[index]
        assert verdict["passed"] is False
        assert detail in check["detail"]  # type: ignore[index]

    def test_a_missing_scanner_fails_closed(self) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            if "gitleaks" in " ".join(command):
                raise FileNotFoundError("gitleaks")
            return clean_runner(command, cwd, timeout)

        verdict = gate.run_gate(context(runner))
        assert verdict["passed"] is False
        assert statuses(verdict)["gitleaks_history"] == "failed"
        assert (
            "not available"
            in next(
                c
                for c in verdict["checks"]
                if c["name"] == "gitleaks_history"  # type: ignore[index]
            )["detail"]
        )

    def test_no_scanner_binary_at_all_is_a_failure_not_a_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        monkeypatch.delenv("ASIC_PIP_AUDIT", raising=False)
        verdict = gate.run_gate(
            context(clean_runner), only=["pip_audit", "gitleaks_tree", "npm_audit"]
        )
        assert set(statuses(verdict).values()) == {"failed"}
        assert verdict["passed"] is False

    @pytest.mark.parametrize(
        ("needle", "check"),
        [
            ("pip-audit", "pip_audit"),
            ("gitleaks", "gitleaks_history"),
            ("audit", "npm_audit"),
        ],
    )
    def test_a_scanner_that_exits_zero_without_a_clean_report_is_not_a_pass(
        self, needle: str, check: str
    ) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            if (needle in " ".join(command) and check != "npm_audit") or (
                check == "npm_audit" and "npm" in " ".join(command)
            ):
                return gate.CommandResult(0, "", "")  # silence is not a verdict
            return clean_runner(command, cwd, timeout)

        result = statuses(gate.run_gate(context(runner), only=[check]))
        # npm exits 0 = clean by contract; pip-audit and gitleaks must *say* so.
        expected = "passed" if check == "npm_audit" else "failed"
        assert result[check] == expected

    @pytest.mark.parametrize(
        "check",
        [
            "pip_audit",
            "gitleaks_history",
            "gitleaks_tree",
            "npm_audit",
            "sast_ruff",
            "dependency_lock",
        ],
    )
    def test_a_nonzero_scanner_exit_fails_the_gate_with_evidence(self, check: str) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            return gate.CommandResult(1, "finding: something bad", "")

        verdict = gate.run_gate(context(runner), only=[check])
        assert verdict["passed"] is False
        entry = verdict["checks"][0]  # type: ignore[index]
        assert entry["status"] == "failed" and entry["evidence"]

    def test_a_timeout_is_a_failure(self) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            raise subprocess.TimeoutExpired(command, timeout)

        verdict = gate.run_gate(context(runner), only=["sast_ruff"])
        assert statuses(verdict) == {"sast_ruff": "failed"}

    def test_a_crashing_check_is_a_failure_not_an_exception(self) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            raise RuntimeError("boom")

        verdict = gate.run_gate(context(runner), only=["repo_hygiene"])
        assert verdict["passed"] is False

    def test_skips_are_reported_and_only_fail_in_strict_mode(self) -> None:
        loose = gate.run_gate(context(clean_runner, offline=True, database_url=None))
        assert statuses(loose)["pip_audit"] == "skipped"
        assert statuses(loose)["npm_audit"] == "skipped"
        assert statuses(loose)["tenancy_schema"] == "skipped"
        assert loose["passed"] is True
        strict = gate.run_gate(context(clean_runner, offline=True, database_url=None, strict=True))
        assert strict["passed"] is False

    def test_strict_mode_fails_when_security_tests_were_skipped(self) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            if "pytest" in " ".join(command):
                return gate.CommandResult(0, "600 passed, 120 skipped in 9s", "")
            return clean_runner(command, cwd, timeout)

        assert (
            statuses(gate.run_gate(context(runner), only=["security_tests"]))["security_tests"]
            == "skipped"
        )
        strict = gate.run_gate(context(runner, strict=True), only=["security_tests"])
        assert statuses(strict)["security_tests"] == "failed"

    def test_tenancy_findings_fail_the_gate(self) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            return gate.CommandResult(1, "rls_not_forced: incident\nFINDINGS 1", "")

        verdict = gate.run_gate(context(runner), only=["tenancy_schema"])
        assert verdict["passed"] is False

    def test_evaluate_is_the_single_pass_rule(self) -> None:
        ok, bad = gate.Check("a", "passed", ""), gate.Check("b", "failed", "")
        skipped, ne = gate.Check("c", "skipped", ""), gate.Check("d", "not_executable", "")
        assert gate.evaluate([ok], strict=True, require_container_scan=True)
        assert not gate.evaluate([ok, bad], strict=False, require_container_scan=False)
        assert gate.evaluate([ok, skipped, ne], strict=False, require_container_scan=False)
        assert not gate.evaluate([ok, skipped], strict=True, require_container_scan=False)
        assert not gate.evaluate([ok, ne], strict=False, require_container_scan=True)


class TestGateInterface:
    def test_it_prints_machine_readable_json_and_sets_the_exit_code(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        target = tmp_path / "verdict.json"
        code = gate.main(
            ["--offline", "--json", str(target), "--only", "container_scan"], runner=clean_runner
        )
        out = capsys.readouterr().out
        document = json.loads(out)
        assert (
            code == 0 and document["gate"] == "phase13-security" and document["schema_version"] == 1
        )
        assert json.loads(target.read_text(encoding="utf-8")) == document
        assert document["summary"] == {"passed": 0, "failed": 0, "skipped": 0, "not_executable": 1}

    def test_failure_is_exit_code_one(self, capsys: pytest.CaptureFixture[str]) -> None:
        def runner(command: Sequence[str], cwd: Path, timeout: int) -> object:
            return gate.CommandResult(2, "", "error")

        assert gate.main(["--only", "sast_ruff"], runner=runner) == 1
        assert json.loads(capsys.readouterr().out)["passed"] is False

    def test_container_scan_requirement_changes_the_exit_code(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert gate.main(["--only", "container_scan"], runner=clean_runner) == 0
        assert (
            gate.main(["--only", "container_scan", "--require-container-scan"], runner=clean_runner)
            == 1
        )
        capsys.readouterr()


# ----------------------------------------------------------- dependency lock policy


def _digest(char: str) -> str:
    return "--hash=sha256:" + char * 64


def _write(tmp: Path, name: str, body: str) -> None:
    path = tmp / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


POLICY = {
    "python": {
        "runtime_lock": "requirements/runtime.lock",
        "dev_lock": "requirements/dev.lock",
        "security_tools_lock": "requirements/security-tools.lock",
        "prerelease_allowlist": {},
    }
}


def _repo(
    tmp: Path,
    *,
    runtime: str,
    dev: str | None = None,
    dependencies: str = '"alpha>=1.0,<2.0"',
) -> None:
    _write(
        tmp, "pyproject.toml", f"[project]\nname='x'\nversion='1'\ndependencies=[{dependencies}]\n"
    )
    _write(tmp, "requirements/runtime.lock", runtime)
    _write(tmp, "requirements/dev.lock", dev if dev is not None else runtime)
    _write(tmp, "requirements/security-tools.lock", f"tool==1.0 \\\n    {_digest('c')}\n")


GOOD = f"alpha==1.2.3 \\\n    {_digest('a')} \\\n    {_digest('b')}\n"


def kinds(findings: list[object]) -> set[str]:
    return {f.check for f in findings}  # type: ignore[attr-defined]


class TestDependencyLockPolicy:
    def test_the_repositorys_own_locks_are_clean(self) -> None:
        assert locks.run() == []

    def test_a_correct_lock_passes(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=GOOD)
        assert locks.check_python(tmp_path, POLICY) == []

    def test_an_unhashed_requirement_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime="alpha==1.2.3\n")
        assert "lock-hash" in kinds(locks.check_python(tmp_path, POLICY))

    @pytest.mark.parametrize(
        "line",
        [
            "--index-url https://evil.example.invalid/simple",
            "--extra-index-url https://evil.example.invalid/simple",
            "--find-links https://evil.example.invalid/wheels",
            "git+https://github.com/x/y.git#egg=alpha",
            "https://evil.example.invalid/alpha-1.0.tar.gz",
            "file:///tmp/alpha",
        ],
    )
    def test_a_dependency_confusion_source_is_refused(self, tmp_path: Path, line: str) -> None:
        _repo(tmp_path, runtime=GOOD + line + "\n")
        assert "lock-source" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_range_not_pinned_exactly_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=f"alpha>=1.0 \\\n    {_digest('a')}\n")
        assert "lock-format" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_direct_dependency_missing_from_the_lock_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=GOOD, dependencies='"alpha>=1.0,<2.0", "beta>=1.0,<2.0"')
        assert "lock-coverage" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_locked_version_outside_the_declared_range_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=f"alpha==2.5.0 \\\n    {_digest('a')}\n")
        assert "lock-range" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_direct_dependency_without_an_upper_bound_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=GOOD, dependencies='"alpha>=1.0"')
        assert "range-unbounded" in kinds(locks.check_python(tmp_path, POLICY))

    def test_an_unexplained_prerelease_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=f"alpha==1.2.3b0 \\\n    {_digest('a')}\n")
        assert "prerelease" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_reasoned_prerelease_is_accepted(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=f"alpha==1.2.3b0 \\\n    {_digest('a')}\n")
        policy = {
            "python": {
                **POLICY["python"],
                "prerelease_allowlist": {"alpha": {"reason": "no stable release exists"}},
            }
        }
        assert locks.check_python(tmp_path, policy) == []

    def test_a_prerelease_exception_without_a_reason_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=f"alpha==1.2.3b0 \\\n    {_digest('a')}\n")
        policy = {
            "python": {**POLICY["python"], "prerelease_allowlist": {"alpha": {"reason": "  "}}}
        }
        assert "prerelease" in kinds(locks.check_python(tmp_path, policy))

    def test_a_stale_prerelease_exception_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=GOOD)  # alpha is stable now: the exception must be removed
        policy = {
            "python": {
                **POLICY["python"],
                "prerelease_allowlist": {"alpha": {"reason": "was beta"}},
            }
        }
        assert "prerelease-stale" in kinds(locks.check_python(tmp_path, policy))

    def test_a_dev_lock_that_disagrees_with_the_runtime_lock_is_refused(
        self, tmp_path: Path
    ) -> None:
        _repo(tmp_path, runtime=GOOD, dev=f"alpha==1.9.0 \\\n    {_digest('a')}\n")
        assert "lock-consistency" in kinds(locks.check_python(tmp_path, POLICY))

    def test_a_runtime_package_missing_entirely_from_the_dev_lock_is_refused(
        self, tmp_path: Path
    ) -> None:
        alembic = f"alembic==1.16.5 \\\n    {_digest('d')}\n"
        _repo(tmp_path, runtime=GOOD + alembic, dev=GOOD)
        findings = locks.check_python(tmp_path, POLICY)
        assert "lock-consistency" in kinds(findings)
        assert any("alembic==1.16.5 is missing" in finding.detail for finding in findings)

    def test_an_invalid_runtime_hash_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime="alpha==1.2.3 \\\n    --hash=sha256:not-a-digest\n")
        assert "lock-hash" in kinds(locks.check_python(tmp_path, POLICY))

    def test_extra_dev_only_packages_are_allowed(self, tmp_path: Path) -> None:
        dev_only = f"pytest==8.4.2 \\\n    {_digest('d')}\n"
        _repo(tmp_path, runtime=GOOD, dev=GOOD + dev_only)
        assert locks.check_python(tmp_path, POLICY) == []

    def test_a_missing_lock_file_is_refused(self, tmp_path: Path) -> None:
        _repo(tmp_path, runtime=GOOD)
        (tmp_path / "requirements" / "dev.lock").unlink()
        assert "lock-missing" in kinds(locks.check_python(tmp_path, POLICY))

    def test_the_repository_locks_keep_the_beta_exception_narrow(self) -> None:
        policy = tomllib.loads(
            (REPO / "configs/security/supply-chain-policy.toml").read_text(encoding="utf-8")
        )
        allowed = set(policy["python"]["prerelease_allowlist"])
        assert allowed == {
            "opentelemetry-exporter-prometheus",
            "opentelemetry-semantic-conventions",
        }
        for entry in policy["python"]["prerelease_allowlist"].values():
            assert len(entry["reason"].strip()) > 40


NODE_POLICY = {
    "node": {
        "lockfile": "package-lock.json",
        "manifest": "package.json",
        "exact_production_dependencies": True,
    }
}


def _node(
    tmp: Path, *, packages: dict[str, object], dependencies: dict[str, str], version: int = 3
) -> None:
    _write(
        tmp,
        "package-lock.json",
        json.dumps({"lockfileVersion": version, "packages": {"": {}, **packages}}),
    )
    _write(tmp, "package.json", json.dumps({"dependencies": dependencies}))


class TestNodeLockPolicy:
    ENTRY: ClassVar[dict[str, str]] = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
        "integrity": "sha512-abc",
    }

    def test_a_correct_lock_passes(self, tmp_path: Path) -> None:
        _node(tmp_path, packages={"node_modules/a": self.ENTRY}, dependencies={"a": "1.0.0"})
        assert locks.check_node(tmp_path, NODE_POLICY) == []

    def test_a_package_without_an_integrity_digest_is_refused(self, tmp_path: Path) -> None:
        _node(
            tmp_path, packages={"node_modules/a": {"version": "1.0.0"}}, dependencies={"a": "1.0.0"}
        )
        assert "node-integrity" in kinds(locks.check_node(tmp_path, NODE_POLICY))

    def test_a_package_resolving_outside_the_registry_is_refused(self, tmp_path: Path) -> None:
        entry = {**self.ENTRY, "resolved": "git+https://github.com/x/a.git"}
        _node(tmp_path, packages={"node_modules/a": entry}, dependencies={"a": "1.0.0"})
        assert "node-source" in kinds(locks.check_node(tmp_path, NODE_POLICY))

    @pytest.mark.parametrize("range_", ["^1.0.0", "~1.0.0", "*", "latest", ">=1"])
    def test_a_floating_production_dependency_is_refused(self, tmp_path: Path, range_: str) -> None:
        _node(tmp_path, packages={"node_modules/a": self.ENTRY}, dependencies={"a": range_})
        assert "node-range" in kinds(locks.check_node(tmp_path, NODE_POLICY))

    def test_an_old_lockfile_format_is_refused(self, tmp_path: Path) -> None:
        _node(
            tmp_path,
            packages={"node_modules/a": self.ENTRY},
            dependencies={"a": "1.0.0"},
            version=1,
        )
        assert "node-lock" in kinds(locks.check_node(tmp_path, NODE_POLICY))


# ------------------------------------------------------------ secret-scan allowance


class TestSecretScanConfiguration:
    def _config(self) -> dict[str, object]:
        return tomllib.loads((REPO / ".gitleaks.toml").read_text(encoding="utf-8"))

    def test_the_default_ruleset_is_fully_enabled(self) -> None:
        config = self._config()
        assert config["extend"] == {"useDefault": True}
        assert "rules" not in config  # nothing redefined or disabled

    def test_the_one_false_positive_is_allowed_by_rule_path_and_text_together(self) -> None:
        first, second = self._config()["allowlists"]  # type: ignore[misc]
        assert first["condition"] == "AND"
        assert first["targetRules"] == ["generic-api-key"]
        assert len(first["paths"]) == 1 and first["paths"][0].endswith(
            r"src/asic/llm/accounting\.py$"
        )
        assert first["regexTarget"] == "match", "line-level matching hides an appended secret"
        assert len(first["regexes"]) == 1
        allowed = first["regexes"][0]
        assert allowed.startswith("^") and allowed.endswith("$"), "the allowance must be anchored"
        assert allowed == r"^estimate\.max_total_tokens, cost_usd=estimate\.max_cost_usd$"
        # The only other allowance is git-ignored tooling; nothing under src, tests or docs.
        for path in second["paths"]:
            assert not any(
                part in path for part in ("src", "tests", "docs", "scripts", "migrations")
            )

    @pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not available")
    def test_the_allowance_does_not_hide_a_real_secret_beside_or_on_the_allowed_line(
        self, tmp_path: Path
    ) -> None:
        """Non-vacuity, with the real scanner, against the *real* reviewed file. The file as it
        is passes; a real secret on another line, or *appended to an allowed line itself*, is
        caught. (The reviewed text is read at runtime so this file holds no secret-shaped
        literal of its own.)"""
        probe = subprocess.run(["docker", "info"], capture_output=True, check=False)
        if probe.returncode != 0:
            pytest.skip("docker daemon is not running")
        # Bytes, not text: write_text() would rewrite line endings and change what matches.
        real = (REPO / "src" / "asic" / "llm" / "accounting.py").read_bytes()
        marker = b"cost_usd=estimate.max_cost_usd"
        assert real.count(marker) >= 2, "the reviewed false-positive lines have moved"
        target = tmp_path / "src" / "asic" / "llm"
        target.mkdir(parents=True)
        shutil.copy(REPO / ".gitleaks.toml", tmp_path / ".gitleaks.toml")
        # Assembled from fragments so no scanner sees a secret-shaped literal here.
        plant = 'api_key = "' + "Xk9Qm2Zp7Rt4" + "Vb8Nc3Wd6Ye1" + "Ug5Fh0Jl" + '"'
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}

        def scan() -> int:
            return subprocess.run(
                ["docker", "run", "--rm", "-v", f"{tmp_path}:/repo", gate.GITLEAKS_IMAGE,
                 "dir", "/repo", "--config", "/repo/.gitleaks.toml", "--no-banner", "--redact"],
                capture_output=True, check=False, env=env,
            ).returncode  # fmt: skip

        accounting = target / "accounting.py"
        newline = bytes([10])
        accounting.write_bytes(real)
        assert scan() == 0, "the one reviewed false positive must stay allowed"
        accounting.write_bytes(real + newline + plant.encode() + newline)
        assert scan() != 0, "a real secret on another line was hidden"
        appended = real.replace(marker, marker + b", " + plant.encode(), 1)
        accounting.write_bytes(appended)
        assert scan() != 0, "a real secret appended to the allowed line was hidden"
