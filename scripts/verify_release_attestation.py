#!/usr/bin/env python3
"""Verify a release image's build-provenance attestation against the full trust policy.

``gh attestation verify`` checks the Sigstore signature, repository, signer workflow, source
commit and runner type. This script then re-checks every claim deterministically from the
machine-readable (``--format json``) result, using only fields that come from the Fulcio
certificate (populated from GitHub's OIDC token, not from the workflow) plus the signed subject:

- subject name/digest       == the exact image to be deployed;
- source repository         == this repository;
- signer workflow           == <repo>/.github/workflows/release.yml at the same ref;
- source revision           == the release commit the operator supplied;
- source ref                == refs/heads/main or a refs/tags/v* release tag (release.yml's triggers);
- OIDC issuer / runner      == GitHub Actions / GitHub-hosted.

Every returned attestation must satisfy the policy. Standard library only: it runs before any
dependency installation and long before a cluster credential exists.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SIGNER_WORKFLOW = ".github/workflows/release.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
TRUSTED_REF = re.compile(r"refs/heads/main|refs/tags/v[0-9]+(\.[0-9]+){0,2}([-+][0-9A-Za-z.-]+)?")
IMAGE = re.compile(r"(?P<name>[a-z0-9][a-z0-9./_-]*)@sha256:(?P<digest>[0-9a-f]{64})")
REVISION = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class PolicyViolation(ValueError):
    """The attestation exists but does not prove what deployment requires."""


@dataclass(frozen=True)
class TrustPolicy:
    image: str
    repository: str
    revision: str

    def __post_init__(self) -> None:
        if not IMAGE.fullmatch(self.image):
            raise PolicyViolation("image must be name@sha256:<64 hex>")
        if not REPOSITORY.fullmatch(self.repository):
            raise PolicyViolation("repository must be <owner>/<repo>")
        if not REVISION.fullmatch(self.revision):
            raise PolicyViolation("release revision must be a full 40-hex commit SHA")

    @property
    def name(self) -> str:
        match = IMAGE.fullmatch(self.image)
        assert match is not None
        return match["name"]

    @property
    def digest(self) -> str:
        match = IMAGE.fullmatch(self.image)
        assert match is not None
        return match["digest"]


def _claim(certificate: dict[str, object], key: str) -> str:
    value = certificate.get(key)
    if not isinstance(value, str) or not value:
        raise PolicyViolation(f"attestation certificate lacks the {key} claim")
    return value


def check_attestation(entry: dict[str, object], policy: TrustPolicy) -> str:
    """Validate one verified attestation; return its trusted source ref."""
    result = entry.get("verificationResult")
    if not isinstance(result, dict):
        raise PolicyViolation("verification result missing")
    certificate = (result.get("signature") or {}).get("certificate")
    statement = result.get("statement")
    if not isinstance(certificate, dict) or not isinstance(statement, dict):
        raise PolicyViolation("certificate or statement missing")

    repo_url = f"https://github.com/{policy.repository}"
    if _claim(certificate, "issuer") != OIDC_ISSUER:
        raise PolicyViolation("attestation was not issued by GitHub Actions OIDC")
    if _claim(certificate, "sourceRepositoryURI").lower() != repo_url.lower():
        raise PolicyViolation("attestation belongs to a different source repository")
    if _claim(certificate, "sourceRepositoryDigest") != policy.revision:
        raise PolicyViolation("attestation was built from a different source revision")
    ref = _claim(certificate, "sourceRepositoryRef")
    if not TRUSTED_REF.fullmatch(ref):
        raise PolicyViolation(f"attestation source ref {ref!r} is not main or a v* release tag")
    signer = _claim(certificate, "buildSignerURI")
    if signer.lower() != f"{repo_url}/{SIGNER_WORKFLOW}@{ref}".lower():
        raise PolicyViolation("attestation was not signed by release.yml at the trusted ref")
    if _claim(certificate, "runnerEnvironment") != "github-hosted":
        raise PolicyViolation("attestation was produced on a self-hosted runner")

    if statement.get("predicateType") != SLSA_PROVENANCE:
        raise PolicyViolation("attestation is not SLSA build provenance")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not any(
        isinstance(subject, dict)
        and str(subject.get("name", "")).lower() == policy.name.lower()
        and (subject.get("digest") or {}).get("sha256") == policy.digest
        for subject in subjects
    ):
        raise PolicyViolation("attestation subject does not match the image digest")
    return ref


def check_results(results: object, policy: TrustPolicy) -> list[str]:
    if not isinstance(results, list) or not results:
        raise PolicyViolation("no verified attestation was returned")
    return [check_attestation(entry, policy) for entry in results]


def gh_verify(policy: TrustPolicy, gh: str = "gh") -> object:
    command = [
        gh,
        "attestation",
        "verify",
        f"oci://{policy.image}",
        "--repo",
        policy.repository,
        "--signer-workflow",
        f"{policy.repository}/{SIGNER_WORKFLOW}",
        "--source-digest",
        policy.revision,
        "--cert-oidc-issuer",
        OIDC_ISSUER,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    if result.returncode:
        raise PolicyViolation(f"gh attestation verify failed: {result.stderr.strip()[-2000:]}")
    return json.loads(result.stdout)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, action="append")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument(
        "--verification-json",
        type=Path,
        help="Validate a saved `gh attestation verify --format json` result (offline review).",
    )
    args = parser.parse_args(argv)
    try:
        for image in args.image:
            policy = TrustPolicy(image, args.repository, args.revision)
            results = (
                json.loads(args.verification_json.read_text("utf-8"))
                if args.verification_json
                else gh_verify(policy, args.gh)
            )
            refs = check_results(results, policy)
            print(f"attestation trusted: {image} from {args.revision} at {sorted(set(refs))}")
    except (PolicyViolation, json.JSONDecodeError) as error:
        print(f"ATTESTATION REJECTED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
