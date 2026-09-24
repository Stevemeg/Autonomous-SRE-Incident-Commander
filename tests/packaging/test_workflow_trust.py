"""Trust-boundary validators for the CI/release/deploy workflow graph (LOW-1/2/5/7/8).

Privileged GitHub behavior cannot run locally, so the trust graph is checked structurally from
the parsed workflows: who holds which permission, where credentials exist, and which code runs
after authority is granted. Each check fails on the specific regression it names.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"


def _load(name: str) -> dict[str, Any]:
    # PyYAML parses the bare key `on` as boolean True.
    return yaml.safe_load((WORKFLOWS / name).read_text("utf-8"))  # type: ignore[no-any-return]


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps", [])  # type: ignore[no-any-return]


def _step_text(step: dict[str, Any]) -> str:
    return yaml.safe_dump(step)


def _writes(permissions: dict[str, str] | None) -> set[str]:
    return {scope for scope, level in (permissions or {}).items() if level == "write"}


RELEASE = _load("release.yml")
DEPLOY = _load("deploy.yml")
QUALITY = _load("quality.yml")


# --------------------------------------------------------------------- LOW-1: release split
def test_build_job_is_unprivileged() -> None:
    build = RELEASE["jobs"]["build-validate"]
    assert build["permissions"] == {"contents": "read"}
    assert "environment" not in build


def test_quality_and_workflow_defaults_are_read_only() -> None:
    for workflow in (RELEASE, DEPLOY, QUALITY):
        assert not _writes(workflow["permissions"])
    for job in QUALITY["jobs"].values():
        assert not _writes(job.get("permissions"))


@pytest.mark.parametrize("name", ["quality.yml", "release.yml", "deploy.yml"])
def test_every_checkout_drops_persisted_credentials(name: str) -> None:
    for job in _load(name)["jobs"].values():
        for step in _steps(job):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, name


def test_publish_job_holds_minimal_authority_and_runs_no_repository_code() -> None:
    publish = RELEASE["jobs"]["publish-attest"]
    assert publish["needs"] == "build-validate"
    assert publish["permissions"] == {
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    text = "\n".join(_step_text(step) for step in _steps(publish))
    assert "actions/checkout" not in text
    assert not re.search(r"docker\s+build\s|buildx\s+build|docker\s+compose", text)
    for forbidden in ("python", "scripts/", "pytest", "npm ", "make "):
        assert forbidden not in text, forbidden
    assert "sha256sum --check --strict" in text
    assert "docker load" in text


def test_only_the_unprivileged_job_builds_and_it_builds_once() -> None:
    for name, job in RELEASE["jobs"].items():
        text = "\n".join(_step_text(step) for step in _steps(job))
        builds = text.count("docker build ")
        assert builds == (2 if name == "build-validate" else 0), name
        if _writes(job.get("permissions")) & {"packages", "id-token"}:
            assert builds == 0


def test_published_artifact_is_the_scanned_artifact() -> None:
    build = RELEASE["jobs"]["build-validate"]
    names = [step.get("name", step.get("uses", "")) for step in _steps(build)]
    joined = "\n".join(_step_text(step) for step in _steps(build))
    # Scan, SBOM and kind smoke all happen before the archive is taken, on the same tag.
    order = [
        joined.index("--require-container-scan"),
        joined.index("--format cyclonedx"),
        joined.index("scripts/deployment_smoke.py"),
        joined.index("docker save"),
    ]
    assert order == sorted(order), names
    outputs = build["outputs"]
    assert set(outputs) == {
        "backend_image_id",
        "frontend_image_id",
        "backend_archive_sha256",
        "frontend_archive_sha256",
    }
    publish = "\n".join(_step_text(step) for step in _steps(RELEASE["jobs"]["publish-attest"]))
    for output in outputs:
        assert f"needs.build-validate.outputs.{output}" in publish
    # The registry manifest's config digest must equal the scanned image ID.
    assert ".config.digest" in publish and "_IMAGE_ID" in publish


def test_release_refs_match_the_deploy_trust_policy() -> None:
    triggers = RELEASE[True]
    assert triggers["push"] == {"tags": ["v*"]}
    assert "workflow_dispatch" in triggers
    guard = "\n".join(_step_text(step) for step in _steps(RELEASE["jobs"]["build-validate"]))
    assert "refs/heads/main" in guard and "refs/tags/v" in guard
    assert "merge-base --is-ancestor" in guard


# ------------------------------------------------------------ LOW-2 / LOW-5: deploy trust
def _deploy_steps() -> list[dict[str, Any]]:
    return _steps(DEPLOY["jobs"]["deploy"])


def _index(predicate: str) -> int:
    for index, step in enumerate(_deploy_steps()):
        if predicate in _step_text(step):
            return index
    raise AssertionError(f"no deploy step contains {predicate!r}")


def test_kubeconfig_is_never_job_or_workflow_scoped() -> None:
    assert "env" not in DEPLOY
    job = DEPLOY["jobs"]["deploy"]
    assert "KUBE_CONFIG_DATA" not in yaml.safe_dump(job.get("env", {}))
    holders = [
        index
        for index, step in enumerate(_deploy_steps())
        if "secrets.KUBE_CONFIG_DATA" in yaml.safe_dump(step.get("env", {}))
    ]
    assert len(holders) == 1
    assert "secrets.KUBE_CONFIG_DATA" not in yaml.safe_dump(
        [step for index, step in enumerate(_deploy_steps()) if index != holders[0]]
    )
    credential_step = _deploy_steps()[holders[0]]
    assert "scripts/deploy_release.py" in credential_step["run"]
    assert "umask 077" in credential_step["run"]
    assert "trap 'rm -f" in credential_step["run"]


def test_attestation_and_dependency_install_happen_before_the_credential_exists() -> None:
    credential = _index("secrets.KUBE_CONFIG_DATA")
    assert _index("verify_release_attestation.py") < credential
    assert _index("pip install") < credential
    assert _index("render_deployment.py") < credential
    for step in _deploy_steps()[:credential]:
        assert "KUBE" not in yaml.safe_dump(step.get("env", {}))


def test_credential_cleanup_always_runs() -> None:
    cleanup = _deploy_steps()[-1]
    assert cleanup["if"] == "always()"
    assert 'rm -f "$RUNNER_TEMP/kubeconfig"' in cleanup["run"]


def test_attestation_verification_constrains_source_ref_and_revision() -> None:
    verify = _deploy_steps()[_index("verify_release_attestation.py")]
    assert "--revision" in verify["run"]
    assert verify["env"]["RELEASE_COMMIT"] == "${{ inputs.release_commit }}"
    inputs = DEPLOY[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_commit"]["required"] is True
    script = (REPO / "scripts/verify_release_attestation.py").read_text("utf-8")
    for claim in (
        "sourceRepositoryRef",
        "sourceRepositoryDigest",
        "buildSignerURI",
        "sourceRepositoryURI",
    ):
        assert claim in script
    assert '"--source-digest"' in script


def test_deploy_is_main_gated_protected_and_serialized() -> None:
    job = DEPLOY["jobs"]["deploy"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["environment"] == "production"
    assert DEPLOY["concurrency"] == {"group": "production-deploy", "cancel-in-progress": False}
    assert RELEASE["concurrency"]["cancel-in-progress"] is False


# -------------------------------------------------- LOW-7 / LOW-8: one authoritative sequence
def test_deploy_uses_only_the_authoritative_sequence() -> None:
    text = (WORKFLOWS / "deploy.yml").read_text("utf-8")
    assert text.count("scripts/deploy_release.py") == 1
    # No independent kubectl sequencing that could drift from the orchestrator.
    assert "kubectl" not in text
    assert "alembic downgrade" not in text


def test_local_smoke_uses_the_same_sequence() -> None:
    smoke = (REPO / "scripts/deployment_smoke.py").read_text("utf-8")
    assert "from deploy_release import" in smoke
    # Both the failing and the successful path go through the orchestrator ...
    assert smoke.count("run_deployment(") >= 3  # failing, mutant, successful
    assert "outcome = run_deployment(recorder, migration, application" in smoke
    # ... and the smoke never applies the migration or application manifests itself.
    assert not re.search(r"content=(bad_migration|migration|application)", smoke)
    assert "--for=condition=complete" not in smoke
    assert "--for=condition=failed" not in smoke


def test_orchestrator_waits_for_terminal_state_and_smokes_by_default() -> None:
    source = (REPO / "scripts/deploy_release.py").read_text("utf-8")
    assert "smoke: Callable[[Kubectl], None] = post_rollout_smoke" in source
    assert "kubectl wait" not in source
    assert 'if outcome.state != "complete":  # migration-success guard' in source


# ------------------------------------------------------------------- general Actions hygiene
@pytest.mark.parametrize("name", ["quality.yml", "release.yml", "deploy.yml"])
def test_actions_hygiene(name: str) -> None:
    text = (WORKFLOWS / name).read_text("utf-8")
    workflow = _load(name)
    triggers = workflow[True]
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers
    assert "continue-on-error" not in text
    for use in re.findall(r"uses:\s*([^\s#]+)", text):
        assert use == "./.github/workflows/quality.yml" or re.search(r"@[0-9a-f]{40}$", use), use
    for job_name, job in workflow["jobs"].items():
        if "uses" not in job:
            assert isinstance(job.get("timeout-minutes"), int), job_name
        for step in _steps(job):
            # Untrusted/dispatch values reach shell only through env, never interpolated.
            assert "${{" not in step.get("run", ""), (job_name, step.get("name"))
