#!/usr/bin/env python3
"""The Phase 13 security gate: one command, one machine-readable verdict.

Orchestrates the repository's security controls so Phase 14 CI can invoke a single entry point.
It owns *no* new detection logic - each check delegates to a repository-native validator or a
pinned scanner - and it owns the one property that matters for a gate: **fail closed**.

* A scanner that is missing, times out, crashes or prints something unparseable is ``failed``,
  never ``passed``. Absence of evidence is not evidence of absence.
* A check that legitimately cannot run here (no database URL, offline) is ``skipped`` with a
  stated reason; ``--strict`` (what CI must use) turns every skip into a failure.
* Container scanning requires supplied production image references. No reference is
  ``not_executable``, never passed; Phase 14 release paths require the check explicitly.

Output: a JSON document on stdout (``--json PATH`` also writes it to a file) and a one-line
summary per check on stderr. Exit code: 0 = every executed check passed (and, with
``--strict``, none skipped); 1 = at least one failure; 2 = usage/internal error.

Nothing here weakens or replaces a test: ``security_tests`` runs the ``security`` marker suite,
and the tests themselves fail (rather than skip) where a control is missing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

REPO: Final[Path] = Path(__file__).resolve().parent.parent
PASSED, FAILED, SKIPPED, NOT_EXECUTABLE = "passed", "failed", "skipped", "not_executable"

CONTAINER_REASON: Final[str] = (
    "CONTAINER IMAGE NOT SUPPLIED: provide --container-image for each production artifact. "
    "Phase 14 releases must use --require-container-scan; absence is never a passed scan."
)
TRIVY_IMAGE: Final[str] = (
    "aquasec/trivy@sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08"
)
GITLEAKS_IMAGE: Final[str] = (
    "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], Path, int], CommandResult]


def subprocess_runner(command: Sequence[str], cwd: Path, timeout: int) -> CommandResult:
    """Run a command without a shell. A missing tool raises ``FileNotFoundError``."""
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass
class Check:
    name: str
    status: str
    detail: str
    seconds: float = 0.0
    evidence: list[str] = field(default_factory=list)


@dataclass
class Context:
    repo: Path
    runner: Runner
    python: str
    strict: bool
    offline: bool
    database_url: str | None
    timeout: int = 900
    container_images: tuple[str, ...] = ()


def _run(ctx: Context, command: Sequence[str], *, cwd: Path | None = None) -> CommandResult:
    return ctx.runner(command, cwd or ctx.repo, ctx.timeout)


def _guard(name: str, ctx: Context, body: Callable[[Context], Check]) -> Check:
    """Execute one check and convert any crash into a failure (fail closed)."""
    started = time.monotonic()
    try:
        result = body(ctx)
    except FileNotFoundError as exc:
        result = Check(name, FAILED, f"required tool is not available: {exc.filename or exc}")
    except subprocess.TimeoutExpired:
        result = Check(name, FAILED, f"timed out after {ctx.timeout}s")
    except Exception as exc:  # a broken check must never read as a pass
        result = Check(name, FAILED, f"check crashed: {type(exc).__name__}")
    result.seconds = round(time.monotonic() - started, 2)
    return result


def _tail(text: str, lines: int = 6) -> list[str]:
    return [line for line in text.strip().splitlines() if line.strip()][-lines:]


# ------------------------------------------------------------------------------- checks


def check_tenancy_schema(ctx: Context) -> Check:
    if not ctx.database_url:
        return Check(
            "tenancy_schema",
            SKIPPED,
            "no ASIC_TEST_DATABASE_URL / ASIC_MIGRATION_DATABASE_URL: the live-schema audit "
            "needs a migrated PostgreSQL",
        )
    script = (
        "import sys, sqlalchemy as sa\n"
        "from asic.db.tenancy_audit import audit_schema\n"
        "e = sa.create_engine(sys.argv[1])\n"
        "with e.connect() as c:\n"
        "    f = audit_schema(c)\n"
        "for x in f: print(x.render())\n"
        "print('FINDINGS', len(f))\n"
        "sys.exit(1 if f else 0)\n"
    )
    result = _run(ctx, [ctx.python, "-c", script, ctx.database_url])
    if result.returncode == 0 and "FINDINGS 0" in result.stdout:
        return Check(
            "tenancy_schema",
            PASSED,
            "RLS/FORCE, canonical policies, required tenant FKs, role and grants clean",
        )
    return Check(
        "tenancy_schema",
        FAILED,
        "tenancy/privilege audit reported findings",
        evidence=_tail(result.stdout + result.stderr, 12),
    )


def check_security_tests(ctx: Context) -> Check:
    env_note = "" if ctx.database_url else " (database-backed security tests will skip)"
    command = [ctx.python, "-m", "pytest", "-m", "security", "-q", "-p", "no:cacheprovider", "-rs"]
    result = _run(ctx, command)
    summary = _tail(result.stdout, 3)
    text = result.stdout
    skipped = re.search(r"(\d+) skipped", text)
    if result.returncode != 0:
        return Check(
            "security_tests", FAILED, "security test suite failed", evidence=_tail(text, 15)
        )
    if skipped and ctx.strict:
        return Check(
            "security_tests",
            FAILED,
            f"{skipped.group(1)} security test(s) skipped in strict mode",
            evidence=summary,
        )
    if skipped:
        return Check(
            "security_tests",
            SKIPPED,
            f"{skipped.group(1)} security test(s) skipped{env_note}",
            evidence=summary,
        )
    return Check("security_tests", PASSED, "security marker suite passed", evidence=summary)


def check_sast(ctx: Context) -> Check:
    command = [
        ctx.python,
        "-m",
        "ruff",
        "check",
        "--select",
        "S",
        "--ignore",
        "S101",
        "--no-cache",
        "src",
    ]
    result = _run(ctx, command)
    if result.returncode == 0:
        return Check(
            "sast_ruff",
            PASSED,
            "ruff S (flake8-bandit) rules clean over src; S101 is governed by tests/security/test_sast_policy.py",
        )
    return Check(
        "sast_ruff",
        FAILED,
        "static security findings",
        evidence=_tail(result.stdout + result.stderr, 20),
    )


def check_dependency_lock(ctx: Context) -> Check:
    result = _run(ctx, [ctx.python, "scripts/check_dependency_lock.py"])
    if result.returncode == 0:
        return Check("dependency_lock", PASSED, "hash-pinned locks agree with pyproject and policy")
    return Check(
        "dependency_lock",
        FAILED,
        "dependency lock policy violated",
        evidence=_tail(result.stdout + result.stderr, 15),
    )


def check_runtime_dependencies(ctx: Context) -> Check:
    result = _run(ctx, [ctx.python, "scripts/check_runtime_dependencies.py"])
    if result.returncode == 0:
        return Check(
            "runtime_dependencies", PASSED, "every import is a declared runtime dependency"
        )
    return Check(
        "runtime_dependencies",
        FAILED,
        "undeclared runtime dependency",
        evidence=_tail(result.stdout + result.stderr),
    )


def check_repo_hygiene(ctx: Context) -> Check:
    result = _run(ctx, [ctx.python, "scripts/check_repo_hygiene.py"])
    if result.returncode == 0:
        return Check("repo_hygiene", PASSED, "no secrets, credentials or generated junk")
    return Check(
        "repo_hygiene",
        FAILED,
        "repository hygiene findings",
        evidence=_tail(result.stdout + result.stderr, 12),
    )


def _pip_audit(ctx: Context) -> list[str] | None:
    explicit = os.environ.get("ASIC_PIP_AUDIT")
    if explicit:
        return [explicit]
    found = shutil.which("pip-audit")
    return [found] if found else None


def check_pip_audit(ctx: Context) -> Check:
    if ctx.offline:
        return Check(
            "pip_audit", SKIPPED, "--offline: the vulnerability database needs network access"
        )
    base = _pip_audit(ctx)
    if base is None:
        return Check(
            "pip_audit",
            FAILED,
            "pip-audit is not installed. Install it from the hash-locked "
            "requirements/security-tools.lock into a separate environment and set ASIC_PIP_AUDIT.",
        )
    command = [
        *base,
        "-r",
        "requirements/runtime.lock",
        "--require-hashes",
        "--no-deps",
        "--disable-pip",
        "--progress-spinner",
        "off",
    ]
    result = _run(ctx, command)
    output = result.stdout + result.stderr
    if result.returncode == 0 and "No known vulnerabilities found" in output:
        return Check(
            "pip_audit",
            PASSED,
            "no known vulnerabilities in the runtime lock (known to the advisory database only)",
        )
    if result.returncode == 0:
        return Check(
            "pip_audit",
            FAILED,
            "pip-audit exited 0 but did not report a clean result",
            evidence=_tail(output),
        )
    return Check(
        "pip_audit",
        FAILED,
        "vulnerable or unauditable runtime dependencies",
        evidence=_tail(output, 15),
    )


def check_npm_audit(ctx: Context) -> Check:
    if ctx.offline:
        return Check("npm_audit", SKIPPED, "--offline: the advisory database needs network access")
    npm = shutil.which("npm")
    if npm is None:
        return Check("npm_audit", FAILED, "npm is not available")
    result = _run(
        ctx, [npm, "audit", "--omit=dev", "--audit-level=high"], cwd=ctx.repo / "frontend"
    )
    output = result.stdout + result.stderr
    if result.returncode == 0:
        return Check(
            "npm_audit",
            PASSED,
            "no high-severity production vulnerabilities (known to the advisory database only)",
            evidence=_tail(output, 2),
        )
    return Check(
        "npm_audit",
        FAILED,
        "npm audit reported vulnerabilities or could not run",
        evidence=_tail(output, 12),
    )


def _gitleaks_command(ctx: Context, mode: str) -> list[str] | None:
    config = ".gitleaks.toml"
    binary = shutil.which("gitleaks")
    if binary:
        return [binary, mode, ".", "--config", config, "--no-banner", "--redact"]
    docker = shutil.which("docker")
    if docker:
        mount = str(ctx.repo)
        return [
            docker, "run", "--rm", "-v", f"{mount}:/repo", GITLEAKS_IMAGE,
            mode, "/repo", "--config", "/repo/" + config, "--no-banner", "--redact",
        ]  # fmt: skip
    return None


def _gitleaks(ctx: Context, name: str, mode: str, label: str) -> Check:
    command = _gitleaks_command(ctx, mode)
    if command is None:
        return Check(
            name, FAILED, "neither gitleaks nor docker is available: cannot scan for secrets"
        )
    result = _run(ctx, command)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    if result.returncode == 0 and "no leaks found" in output:
        return Check(name, PASSED, f"gitleaks found no secrets in the {label}")
    if result.returncode == 0:
        return Check(
            name,
            FAILED,
            "gitleaks exited 0 but did not report a clean result",
            evidence=_tail(output),
        )
    return Check(
        name,
        FAILED,
        f"gitleaks reported leaks in the {label} (values are redacted)",
        evidence=_tail(output, 10),
    )


def check_gitleaks_history(ctx: Context) -> Check:
    return _gitleaks(ctx, "gitleaks_history", "git", "full git history")


def check_gitleaks_tree(ctx: Context) -> Check:
    return _gitleaks(ctx, "gitleaks_tree", "dir", "working tree")


def check_container_scan(ctx: Context) -> Check:
    images = ctx.container_images
    if not images:
        configured = os.environ.get("ASIC_CONTAINER_IMAGES", "")
        images = tuple(value.strip() for value in configured.split(",") if value.strip())
    if not images:
        return Check("container_scan", NOT_EXECUTABLE, CONTAINER_REASON)

    explicit = os.environ.get("ASIC_TRIVY")
    trivy = explicit or shutil.which("trivy")
    docker = shutil.which("docker") if trivy is None else None
    if trivy is None and docker is None:
        return Check(
            "container_scan",
            FAILED,
            "container images were supplied but neither trivy nor docker is available",
        )

    evidence: list[str] = []
    for image in images:
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9./:_-]*(?:@sha256:[0-9a-f]{64}|:phase14-[A-Za-z0-9_.-]+)",
            image,
        ):
            return Check(
                "container_scan",
                FAILED,
                f"container identity is mutable or unrecognised: {image}",
            )
        base = (
            [trivy]
            if trivy is not None
            else [
                docker or "docker",
                "run",
                "--rm",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                "asic-trivy-cache:/root/.cache/trivy",
                TRIVY_IMAGE,
            ]
        )
        result = _run(
            ctx,
            [
                *base,
                "image",
                "--quiet",
                "--scanners",
                "vuln",
                "--severity",
                "HIGH,CRITICAL",
                "--exit-code",
                "1",
                "--format",
                "json",
                image,
            ],
        )
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            return Check(
                "container_scan",
                FAILED,
                f"trivy output for {image} was not valid JSON",
                evidence=_tail(result.stdout + result.stderr, 12),
            )
        if not isinstance(report, dict):
            return Check("container_scan", FAILED, "trivy report must be an object")
        metadata = report.get("Metadata", {})
        results = report.get("Results")
        if not isinstance(metadata, dict) or not metadata.get("ImageID"):
            return Check(
                "container_scan", FAILED, f"trivy did not identify the scanned image {image}"
            )
        if not isinstance(results, list) or not results:
            return Check(
                "container_scan",
                FAILED,
                f"trivy produced no analyzable targets for {image}",
            )
        if report.get("ArtifactName") != image or report.get("ArtifactType") != "container_image":
            return Check("container_scan", FAILED, "trivy report identifies a different artifact")
        if any(
            not isinstance(target, dict)
            or not target.get("Target")
            or target.get("Class") not in {"os-pkgs", "lang-pkgs"}
            or not isinstance(target.get("Vulnerabilities") or [], list)
            for target in results
        ):
            return Check("container_scan", FAILED, "trivy produced malformed scan targets")
        vulnerabilities = [
            vulnerability
            for target in results
            if isinstance(target, dict)
            for vulnerability in (target.get("Vulnerabilities") or [])
        ]
        if result.returncode != 0 or vulnerabilities:
            severities: dict[str, int] = {}
            for vulnerability in vulnerabilities:
                severity = str(vulnerability.get("Severity", "UNKNOWN"))
                severities[severity] = severities.get(severity, 0) + 1
            return Check(
                "container_scan",
                FAILED,
                f"blocking container vulnerabilities in {image}: {severities}",
                evidence=_tail(result.stderr, 8),
            )
        evidence.append(f"{image} -> {metadata['ImageID']} ({len(results)} targets)")
    return Check(
        "container_scan",
        PASSED,
        "trivy found no HIGH or CRITICAL vulnerabilities in the production images",
        evidence=evidence,
    )


CHECKS: Final[tuple[tuple[str, Callable[[Context], Check]], ...]] = (
    ("tenancy_schema", check_tenancy_schema),
    ("security_tests", check_security_tests),
    ("sast_ruff", check_sast),
    ("dependency_lock", check_dependency_lock),
    ("runtime_dependencies", check_runtime_dependencies),
    ("repo_hygiene", check_repo_hygiene),
    ("pip_audit", check_pip_audit),
    ("npm_audit", check_npm_audit),
    ("gitleaks_history", check_gitleaks_history),
    ("gitleaks_tree", check_gitleaks_tree),
    ("container_scan", check_container_scan),
)


def evaluate(checks: Sequence[Check], *, strict: bool, require_container_scan: bool) -> bool:
    """The single pass/fail rule, kept separate so it is unit-testable."""
    for check in checks:
        if check.status == FAILED:
            return False
        if check.status == SKIPPED and strict:
            return False
        if check.status == NOT_EXECUTABLE and require_container_scan:
            return False
    return True


def run_gate(
    ctx: Context,
    *,
    only: Sequence[str] = (),
    skip: Sequence[str] = (),
    require_container_scan: bool = False,
) -> dict[str, object]:
    selected = [(n, f) for n, f in CHECKS if (not only or n in only) and n not in skip]
    results = [_guard(name, ctx, body) for name, body in selected]
    if require_container_scan and not any(check.name == "container_scan" for check in results):
        results.append(Check("container_scan", FAILED, "required container check was excluded"))
    passed = evaluate(results, strict=ctx.strict, require_container_scan=require_container_scan)
    return {
        "gate": "phase13-security",
        "schema_version": 1,
        "passed": passed,
        "strict": ctx.strict,
        "offline": ctx.offline,
        "require_container_scan": require_container_scan,
        "checks": [asdict(c) for c in results],
        "summary": {
            status: sum(1 for c in results if c.status == status)
            for status in (PASSED, FAILED, SKIPPED, NOT_EXECUTABLE)
        },
    }


def main(argv: Sequence[str] | None = None, *, runner: Runner = subprocess_runner) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--strict", action="store_true", help="treat skipped checks as failures (CI)"
    )
    parser.add_argument(
        "--offline", action="store_true", help="skip checks that need network access"
    )
    parser.add_argument(
        "--require-container-scan",
        action="store_true",
        help="fail while container scanning is not executable (Phase 14)",
    )
    parser.add_argument("--only", action="append", default=[], choices=[n for n, _ in CHECKS])
    parser.add_argument("--skip", action="append", default=[], choices=[n for n, _ in CHECKS])
    parser.add_argument(
        "--container-image",
        action="append",
        default=[],
        help="production image reference to scan; repeat for backend/frontend",
    )
    parser.add_argument("--json", type=Path, help="also write the JSON verdict to this path")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)

    ctx = Context(
        repo=REPO,
        runner=runner,
        python=sys.executable,
        strict=args.strict,
        offline=args.offline,
        database_url=os.environ.get("ASIC_TEST_DATABASE_URL")
        or os.environ.get("ASIC_MIGRATION_DATABASE_URL"),
        timeout=args.timeout,
        container_images=tuple(args.container_image),
    )
    verdict = run_gate(
        ctx, only=args.only, skip=args.skip, require_container_scan=args.require_container_scan
    )
    document = json.dumps(verdict, indent=2)
    print(document)
    if args.json:
        args.json.write_text(document + "\n", encoding="utf-8")
    for check in verdict["checks"]:  # type: ignore[attr-defined]
        print(f"{check['status']:>15}  {check['name']:<22} {check['detail']}", file=sys.stderr)
    print(f"security gate: {'PASSED' if verdict['passed'] else 'FAILED'}", file=sys.stderr)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
