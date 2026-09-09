#!/usr/bin/env python3
"""Scan the repository for secrets, credentials and generated junk before committing.

Implements the mechanical parts of ``docs/security/REPOSITORY_SECURITY_CHECKLIST.md``,
which exists because master specification section 20 requires inspecting for secrets,
credentials, generated junk and sensitive data before every commit and push.

This is a safety net, not a substitute for reading the diff. It is deliberately noisy in
preference to being quiet: a false positive costs a glance, a false negative costs a
credential rotation.

Only the Python standard library is used, so it runs anywhere the repository is checked
out, including CI.

Exit code 0 = clean, 1 = findings, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files whose *content* is not scanned (binary or lock-style), though their presence and
# path are still checked.
BINARY_SUFFIXES = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".svg",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mov",
    ".so",
    ".dll",
    ".dylib",
    ".pyc",
}

# Secret-shaped content. Each entry: (label, compiled pattern).
#: A line carrying this marker is a deliberate synthetic secret - the fixtures that prove
#: the redaction layer recognises a credential. The exemption is per line and must be
#: written on the line itself, so every one of them is visible in review rather than
#: hidden in a path allowlist that grows quietly.
SECRET_FIXTURE_PRAGMA = "hygiene: synthetic-secret-fixture"

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "AWS secret access key",
        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("Slack token", re.compile(r"\bxox[abporsu]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9/+]{20,}")),
    (
        "Microsoft Teams webhook",
        re.compile(r"https://[a-z0-9.-]*webhook\.office\.com/webhookb2/[A-Za-z0-9@/-]{20,}"),
    ),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Google service-account key", re.compile(r'"type"\s*:\s*"service_account"')),
    (
        "PagerDuty API key",
        re.compile(
            r"(?i)\b(?:pd|pagerduty)[_-]?(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_+-]{16,}['\"]"
        ),
    ),
    (
        "JIRA API token",
        re.compile(r"(?i)\bjira.{0,20}token['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]"),
    ),
    (
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    ("JWT", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "Bearer token literal",
        re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._-]{20,}"),
    ),
    (
        "Password assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
    ),
    (
        "Generic secret assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
        ),
    ),
    (
        "Connection string with credentials",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@"
        ),
    ),
]

# Values that look secret-shaped but are obviously placeholders.
PLACEHOLDER_HINTS = re.compile(
    r"(?i)(example|placeholder|changeme|change_me|your[_-]?|dummy|sample|redacted|xxxx+|<[^>]+>|\.\.\.|"
    r"fake|test[_-]?only|not[_-]?a[_-]?real|insert[_-]?|\bTODO\b|\bNNNN\b)"
)

# Paths that should never be tracked, matched against the repo-relative POSIX path.
FORBIDDEN_PATH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("environment file", re.compile(r"(^|/)\.env(\.|$)(?!example)")),
    ("private key file", re.compile(r"\.(?:pem|key|p12|pfx|der)$")),
    ("SSH key", re.compile(r"(^|/)id_(?:rsa|ed25519|ecdsa|dsa)(\.|$)")),
    ("kubeconfig", re.compile(r"(?i)(^|/)(?:kubeconfig|.*\.kubeconfig)$")),
    (
        "cloud credentials",
        re.compile(r"(?i)(^|/)(?:credentials|service-account[^/]*\.json|gcp-[^/]*\.json)$"),
    ),
    ("terraform state", re.compile(r"\.tfstate(\.|$)")),
    ("terraform variables", re.compile(r"\.tfvars$")),
    ("python bytecode cache", re.compile(r"(^|/)__pycache__/|\.pyc$")),
    ("virtual environment", re.compile(r"(^|/)(?:\.venv|venv|env|ENV)/")),
    ("node modules", re.compile(r"(^|/)node_modules/")),
    ("build output", re.compile(r"(^|/)(?:dist|build|out|\.next|\.turbo)/")),
    (
        "tool cache",
        re.compile(r"(^|/)\.(?:pytest_cache|mypy_cache|ruff_cache|eslintcache|nyc_output)(/|$)"),
    ),
    ("coverage artifact", re.compile(r"(^|/)(?:htmlcov/|\.coverage($|\.)|coverage\.xml$)")),
    ("OS junk", re.compile(r"(?i)(^|/)(?:\.DS_Store|Thumbs\.db|Desktop\.ini|ehthumbs\.db)$")),
    ("editor state", re.compile(r"(^|/)\.idea/")),
    ("office lock file", re.compile(r"(^|/)~\$")),
    ("log file", re.compile(r"\.log$")),
    ("local database", re.compile(r"\.(?:sqlite3?|db|rdb)$")),
]


def tracked_files() -> list[Path]:
    """Files Git would commit: tracked plus staged, minus deletions."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"ERROR: could not list Git files: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    paths = []
    for line in listed.splitlines():
        rel = line.strip()
        if not rel or rel.startswith(".git/"):
            continue
        path = REPO_ROOT / rel
        if path.is_file():
            paths.append(path)
    return paths


def scan_content(path: Path, rel: str) -> list[str]:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable; path checks still apply

    # This scanner's own pattern table would otherwise match itself.
    if path.resolve() == Path(__file__).resolve():
        return []

    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            line = line[:4000]
        if SECRET_FIXTURE_PRAGMA in line:
            continue
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            if PLACEHOLDER_HINTS.search(line):
                continue
            snippet = match.group(0)
            if len(snippet) > 40:
                snippet = snippet[:20] + "..." + snippet[-8:]
            findings.append(f"{rel}:{lineno}: possible {label}: {snippet}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="only print findings and the verdict")
    args = parser.parse_args()

    files = tracked_files()
    path_findings: list[str] = []
    content_findings: list[str] = []

    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        for label, pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.search(rel):
                path_findings.append(f"{rel}: {label} should not be committed")
        content_findings.extend(scan_content(path, rel))

    gitignore = REPO_ROOT / ".gitignore"
    structural: list[str] = []
    if not gitignore.is_file():
        structural.append(".gitignore is missing")
    else:
        required = [".env", "__pycache__/", "node_modules/", "*.tfstate", ".venv/"]
        body = gitignore.read_text(encoding="utf-8")
        for rule in required:
            if rule not in body:
                structural.append(f".gitignore is missing a rule for {rule}")
    if not (REPO_ROOT / "README.md").is_file():
        structural.append("README.md is missing")

    if not args.quiet:
        print(f"repository     : {REPO_ROOT}")
        print(f"files scanned  : {len(files)}")
        print(f"path findings  : {len(path_findings)}")
        print(f"secret findings: {len(content_findings)}")
        print(f"structural     : {len(structural)}")
        print()

    for group, findings in (
        ("FORBIDDEN PATHS", path_findings),
        ("POSSIBLE SECRETS", content_findings),
        ("STRUCTURAL", structural),
    ):
        if findings:
            print(f"--- {group} ---")
            for finding in findings:
                print(f"  ! {finding}")
            print()

    total = len(path_findings) + len(content_findings) + len(structural)
    if total:
        print(f"RESULT: {total} finding(s) - review each before committing.")
        print("Confirmed false positives are acceptable; unreviewed findings are not.")
        return 1

    print("RESULT: CLEAN - no forbidden paths, secret-shaped content or structural gaps.")
    print("This is a safety net, not a substitute for reading the diff.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
