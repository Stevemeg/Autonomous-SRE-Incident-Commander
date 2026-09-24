"""Deployment trust policy for release attestations (LOW-5).

Fixtures mirror the shape of ``gh attestation verify --format json`` output: the certificate
summary claims (from GitHub's OIDC token via Fulcio) and the signed in-toto statement.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from scripts.verify_release_attestation import (
    PolicyViolation,
    TrustPolicy,
    check_results,
    main,
)

REPO_NAME = "Stevemeg/Autonomous-SRE-Incident-Commander"
REVISION = "d15722fad9ee96c4e91ec2c3a7e8f1efdca23b07"
DIGEST = "b" * 64
IMAGE = f"ghcr.io/stevemeg/asic-backend@sha256:{DIGEST}"
POLICY = TrustPolicy(IMAGE, REPO_NAME, REVISION)


def attestation(ref: str = "refs/heads/main") -> dict[str, object]:
    repo_url = f"https://github.com/{REPO_NAME}"
    return {
        "attestation": {"bundle": {}},
        "verificationResult": {
            "signature": {
                "certificate": {
                    "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
                    "subjectAlternativeName": f"{repo_url}/.github/workflows/release.yml@{ref}",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "buildSignerURI": f"{repo_url}/.github/workflows/release.yml@{ref}",
                    "runnerEnvironment": "github-hosted",
                    "sourceRepositoryURI": repo_url,
                    "sourceRepositoryDigest": REVISION,
                    "sourceRepositoryRef": ref,
                    "buildTrigger": "workflow_dispatch",
                }
            },
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [
                    {"name": "ghcr.io/stevemeg/asic-backend", "digest": {"sha256": DIGEST}}
                ],
            },
        },
    }


@pytest.mark.parametrize(
    "ref", ["refs/heads/main", "refs/tags/v1", "refs/tags/v1.4.2", "refs/tags/v2.0.0-rc.1"]
)
def test_trusted_repository_workflow_ref_and_digest_are_accepted(ref: str) -> None:
    assert check_results([attestation(ref)], POLICY) == [ref]


def _mutate(path: str, value: object) -> dict[str, object]:
    entry = copy.deepcopy(attestation())
    target: dict[str, object] = entry
    keys = path.split(".")
    for key in keys[:-1]:
        target = target[key]  # type: ignore[assignment]
    if value is None:
        del target[keys[-1]]
    else:
        target[keys[-1]] = value
    return entry


CERT = "verificationResult.signature.certificate"
OTHER_REPO = "https://github.com/attacker/Autonomous-SRE-Incident-Commander"
OWN = f"https://github.com/{REPO_NAME}"


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        # wrong source branch/ref
        (attestation("refs/heads/feature-x"), "not main or a v\\* release tag"),
        (attestation("refs/pull/7/merge"), "not main or a v\\* release tag"),
        (attestation("refs/tags/release-1"), "not main or a v\\* release tag"),
        (attestation("refs/heads/main-backup"), "not main or a v\\* release tag"),
        # signer workflow
        (
            _mutate(
                f"{CERT}.buildSignerURI", f"{OWN}/.github/workflows/quality.yml@refs/heads/main"
            ),
            "not signed by release.yml",
        ),
        (
            _mutate(
                f"{CERT}.buildSignerURI", f"{OWN}/.github/workflows/release.yml@refs/heads/dev"
            ),
            "not signed by release.yml",
        ),
        # repository
        (_mutate(f"{CERT}.sourceRepositoryURI", OTHER_REPO), "different source repository"),
        # revision
        (_mutate(f"{CERT}.sourceRepositoryDigest", "c" * 40), "different source revision"),
        # digest / subject
        (
            _mutate(
                "verificationResult.statement.subject",
                [{"name": "ghcr.io/stevemeg/asic-backend", "digest": {"sha256": "d" * 64}}],
            ),
            "subject does not match",
        ),
        (
            _mutate(
                "verificationResult.statement.subject",
                [{"name": "ghcr.io/stevemeg/asic-frontend", "digest": {"sha256": DIGEST}}],
            ),
            "subject does not match",
        ),
        # missing claims
        (_mutate(f"{CERT}.sourceRepositoryRef", None), "lacks the sourceRepositoryRef claim"),
        (_mutate(f"{CERT}.sourceRepositoryRef", ""), "lacks the sourceRepositoryRef claim"),
        (_mutate(f"{CERT}.buildSignerURI", None), "lacks the buildSignerURI claim"),
        (_mutate(f"{CERT}.sourceRepositoryDigest", None), "lacks the sourceRepositoryDigest"),
        # issuer, runner, predicate
        (_mutate(f"{CERT}.issuer", "https://attacker.example"), "not issued by GitHub Actions"),
        (_mutate(f"{CERT}.runnerEnvironment", "self-hosted"), "self-hosted runner"),
        (
            _mutate("verificationResult.statement.predicateType", "https://example/custom"),
            "not SLSA build provenance",
        ),
    ],
)
def test_untrusted_attestations_are_rejected(entry: dict[str, object], reason: str) -> None:
    with pytest.raises(PolicyViolation, match=reason):
        check_results([entry], POLICY)


def test_wrong_expected_digest_is_rejected() -> None:
    other = TrustPolicy(f"ghcr.io/stevemeg/asic-backend@sha256:{'e' * 64}", REPO_NAME, REVISION)
    with pytest.raises(PolicyViolation, match="subject does not match"):
        check_results([attestation()], other)


def test_every_returned_attestation_must_satisfy_the_policy() -> None:
    with pytest.raises(PolicyViolation, match="not main"):
        check_results([attestation(), attestation("refs/heads/feature")], POLICY)
    with pytest.raises(PolicyViolation, match="no verified attestation"):
        check_results([], POLICY)


@pytest.mark.parametrize(
    ("image", "repository", "revision"),
    [
        ("ghcr.io/stevemeg/asic-backend:latest", REPO_NAME, REVISION),
        (IMAGE, "not-a-repo", REVISION),
        (IMAGE, REPO_NAME, "main"),
        (IMAGE, REPO_NAME, REVISION[:12]),
    ],
)
def test_policy_inputs_must_be_immutable(image: str, repository: str, revision: str) -> None:
    with pytest.raises(PolicyViolation):
        TrustPolicy(image, repository, revision)


def test_cli_offline_accepts_and_rejects(tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps([attestation("refs/tags/v1.0.0")]), "utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([attestation("refs/heads/topic")]), "utf-8")
    base = ["--image", IMAGE, "--repository", REPO_NAME, "--revision", REVISION]
    assert main([*base, "--verification-json", str(good)]) == 0
    assert main([*base, "--verification-json", str(bad)]) == 1


def test_gh_invocation_constrains_signer_and_source_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from scripts import verify_release_attestation as module

    captured: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([attestation()]), "")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    assert main(["--image", IMAGE, "--repository", REPO_NAME, "--revision", REVISION]) == 0
    command = captured[0]
    for flag, value in (
        ("--repo", REPO_NAME),
        ("--signer-workflow", f"{REPO_NAME}/.github/workflows/release.yml"),
        ("--source-digest", REVISION),
        ("--format", "json"),
    ):
        assert command[command.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in command
    assert command[3] == f"oci://{IMAGE}"
