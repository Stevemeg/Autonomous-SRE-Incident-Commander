#!/usr/bin/env python3
"""Verify the dependency lock files against pyproject.toml and the supply-chain policy.

Phase 13 (ADR-0030, ``docs/security/SUPPLY_CHAIN.md``). The strategy is *compatibility ranges in
``pyproject.toml``, exact hash-pinned resolution in a committed lock*: ranges keep the project
installable alongside other software, the lock makes an installation reproducible and lets a
scanner name the exact versions in use. This script mechanically checks that the two agree
and that the lock is safe to install with ``--require-hashes``.

Checks (each is an error, not a warning):

* the lock files exist and every requirement is ``name==version`` with at least one
  ``sha256`` hash;
* no requirement resolves from a URL or VCS (``git+``, ``http(s)://``, ``file:``), and no
  ``--index-url``/``--extra-index-url``/``--find-links`` is present (a dependency-confusion
  vector);
* every direct runtime dependency in ``pyproject.toml`` is locked at a version its declared
  specifier accepts;
* a prerelease is locked only if the policy allowlists it with a reason, and an allowlist
  entry that matches no locked prerelease is stale and an error;
* the development lock contains every runtime package at the exact same version;
* the frontend lockfile is v3, every package carries an ``integrity`` digest, none resolves
  outside the npm registry, and production dependencies are exact versions.

Only the standard library plus ``packaging`` (always present: it is in the runtime closure).
Exit code 0 = clean, 1 = findings, 2 = usage or I/O error.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "configs" / "security" / "supply-chain-policy.toml"

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(?P<version>[^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")
_FORBIDDEN_LINE = re.compile(
    r"^\s*(?:-i\b|--index-url|--extra-index-url|--find-links|-f\b|--trusted-host|"
    r"git\+|hg\+|svn\+|bzr\+|https?://|file:)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    check: str
    detail: str

    def render(self) -> str:
        return f"[{self.check}] {self.detail}"


def parse_lock(text: str) -> tuple[dict[str, tuple[str, int]], list[Finding]]:
    """Return ``{canonical name: (version, hash count)}`` and any structural findings."""
    entries: dict[str, tuple[str, int]] = {}
    findings: list[Finding] = []
    # A requirement spans its continuation lines (trailing backslash) up to the next blank/
    # comment-only boundary; join them so hashes belong to the right package.
    blocks: list[str] = []
    current: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            if current and not raw.rstrip().endswith("\\"):
                blocks.append(" ".join(current))
                current = []
            continue
        current.append(stripped.rstrip("\\").strip())
        if not raw.rstrip().endswith("\\"):
            blocks.append(" ".join(current))
            current = []
    if current:
        blocks.append(" ".join(current))
    for block in blocks:
        if _FORBIDDEN_LINE.match(block):
            findings.append(Finding("lock-source", f"forbidden requirement source: {block[:80]!r}"))
            continue
        match = _PIN.match(block)
        if match is None:
            findings.append(Finding("lock-format", f"not an exact pin: {block[:80]!r}"))
            continue
        name = canonicalize_name(match["name"])
        hashes = len(_HASH.findall(block))
        if hashes == 0:
            findings.append(Finding("lock-hash", f"{name} is pinned without a sha256 hash"))
        entries[name] = (match["version"], hashes)
    return entries, findings


def _load_policy() -> dict[str, object]:
    return tomllib.loads(POLICY.read_text(encoding="utf-8"))


def check_python(repo: Path = REPO, policy: dict[str, object] | None = None) -> list[Finding]:
    policy = policy or _load_policy()
    python: dict[str, object] = policy["python"]  # type: ignore[assignment]
    findings: list[Finding] = []
    locks: dict[str, dict[str, tuple[str, int]]] = {}
    for key in ("runtime_lock", "dev_lock", "security_tools_lock"):
        path = repo / str(python[key])
        if not path.is_file():
            findings.append(Finding("lock-missing", f"{python[key]} does not exist"))
            continue
        entries, structural = parse_lock(path.read_text(encoding="utf-8"))
        locks[key] = entries
        findings.extend(Finding(f.check, f"{python[key]}: {f.detail}") for f in structural)
        if not entries:
            findings.append(Finding("lock-empty", f"{python[key]} pins nothing"))
    runtime = locks.get("runtime_lock", {})

    project = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    for spec in project.get("dependencies", []):
        try:
            requirement = Requirement(spec)
        except InvalidRequirement:
            findings.append(Finding("pyproject", f"unparseable dependency {spec!r}"))
            continue
        name = canonicalize_name(requirement.name)
        locked = runtime.get(name)
        if locked is None:
            findings.append(Finding("lock-coverage", f"direct dependency {name} is not locked"))
            continue
        try:
            version = Version(locked[0])
        except InvalidVersion:
            findings.append(Finding("lock-format", f"{name} has an invalid version {locked[0]!r}"))
            continue
        specifier: SpecifierSet = requirement.specifier
        if not specifier.contains(version, prereleases=True):
            findings.append(
                Finding("lock-range", f"{name}=={version} violates pyproject range {specifier}")
            )
        if not any(op in str(specifier) for op in ("<", "==", "~=")):
            findings.append(
                Finding("range-unbounded", f"{name} has no upper bound in pyproject.toml")
            )

    allowlist: dict[str, dict[str, str]] = {
        canonicalize_name(k): v
        for k, v in dict(python.get("prerelease_allowlist", {})).items()  # type: ignore[call-overload]
    }
    locked_prereleases = set()
    for name, (version_text, _) in runtime.items():
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        if version.is_prerelease or version.is_devrelease:
            locked_prereleases.add(name)
            entry = allowlist.get(name)
            if entry is None or not str(entry.get("reason", "")).strip():
                findings.append(
                    Finding(
                        "prerelease",
                        f"{name}=={version_text} is a prerelease without a policy reason",
                    )
                )
    for name in sorted(set(allowlist) - locked_prereleases):
        findings.append(
            Finding("prerelease-stale", f"allowlisted {name} is not a locked prerelease")
        )

    dev = locks.get("dev_lock", {})
    for name, (version, _) in runtime.items():
        if name not in dev:
            findings.append(
                Finding("lock-consistency", f"{name}=={version} is missing from the dev lock")
            )
        elif dev[name][0] != version:
            findings.append(
                Finding("lock-consistency", f"{name}: runtime {version} != dev {dev[name][0]}")
            )
    return findings


def check_node(repo: Path = REPO, policy: dict[str, object] | None = None) -> list[Finding]:
    policy = policy or _load_policy()
    node: dict[str, object] = policy["node"]  # type: ignore[assignment]
    findings: list[Finding] = []
    lockfile = repo / str(node["lockfile"])
    manifest = repo / str(node["manifest"])
    if not lockfile.is_file() or not manifest.is_file():
        return [Finding("node-missing", "package.json or package-lock.json is missing")]
    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    if int(lock.get("lockfileVersion", 0)) < 3:
        findings.append(Finding("node-lock", "package-lock.json is not lockfileVersion 3+"))
    for path, package in lock.get("packages", {}).items():
        if not path or package.get("link"):
            continue
        label = path.removeprefix("node_modules/")
        if "integrity" not in package:
            findings.append(Finding("node-integrity", f"{label} has no integrity digest"))
        resolved = str(package.get("resolved", ""))
        if resolved and not resolved.startswith("https://registry.npmjs.org/"):
            findings.append(Finding("node-source", f"{label} resolves outside the npm registry"))
    if node.get("exact_production_dependencies"):
        dependencies = json.loads(manifest.read_text(encoding="utf-8")).get("dependencies", {})
        for name, version in dependencies.items():
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", str(version)):
                findings.append(
                    Finding(
                        "node-range",
                        f"production dependency {name}@{version} is not an exact version",
                    )
                )
    return findings


def run() -> list[Finding]:
    return [*check_python(), *check_node()]


def main() -> int:
    try:
        findings = run()
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding.render())
    print(f"dependency lock check: {'FAILED' if findings else 'ok'} ({len(findings)} finding(s))")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
