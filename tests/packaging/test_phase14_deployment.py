"""Static contracts for the Phase 14 delivery boundary.

These tests complement (and do not replace) Docker builds, kubeconform/server-side
validation, Terraform validation, and the disposable-kind smoke run in CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
K8S = REPO / "deploy" / "kubernetes"


def _documents(relative: str) -> list[dict[str, object]]:
    documents: list[dict[str, object]] = []
    for path in sorted((K8S / relative).glob("*.yaml")):
        documents.extend(doc for doc in yaml.safe_load_all(path.read_text("utf-8")) if doc)
    return documents


def test_production_images_are_multistage_pinned_and_non_root() -> None:
    for path in (REPO / "Dockerfile", REPO / "frontend" / "Dockerfile"):
        text = path.read_text("utf-8")
        assert len(re.findall(r"^FROM ", text, flags=re.MULTILINE)) >= 2
        assert "@sha256:" in text
        assert "USER 10001:10001" in text
        assert ":latest" not in text
    assert "--require-hashes" in (REPO / "Dockerfile").read_text("utf-8")


def test_runtime_docker_context_excludes_secrets_and_build_junk() -> None:
    root = (REPO / ".dockerignore").read_text("utf-8")
    frontend = (REPO / "frontend" / ".dockerignore").read_text("utf-8")
    for token in (".git", ".env", ".env.*", "tests", ".terraform", "*.tfstate", "*.pem"):
        assert token in root
    for token in (".env", ".env.*", "node_modules", ".next", "*.pem"):
        assert token in frontend


def test_workloads_enforce_the_pod_security_baseline() -> None:
    workloads = [
        doc
        for doc in _documents("base") + _documents("migration")
        if doc["kind"] in {"Deployment", "Job"}
    ]
    assert {doc["kind"] for doc in workloads} == {"Deployment", "Job"}
    for workload in workloads:
        spec = workload["spec"]  # type: ignore[index]
        pod = spec["template"]["spec"]  # type: ignore[index]
        assert pod["automountServiceAccountToken"] is False
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        for container in pod["containers"]:
            security = container["securityContext"]
            assert security["allowPrivilegeEscalation"] is False
            assert security["readOnlyRootFilesystem"] is True
            assert security["capabilities"]["drop"] == ["ALL"]
            assert container["resources"]["requests"]
            assert container["resources"]["limits"]


def test_production_images_are_digest_addressed_and_secrets_are_references() -> None:
    deployments = [doc for doc in _documents("base") if doc["kind"] == "Deployment"]
    assert len(deployments) == 2
    for deployment in deployments:
        containers = deployment["spec"]["template"]["spec"]["containers"]  # type: ignore[index]
        assert all(re.search(r"@sha256:[0-9a-f]{64}$", item["image"]) for item in containers)
    config = next(doc for doc in _documents("base") if doc["kind"] == "ConfigMap")
    serialized = yaml.safe_dump(config)
    assert "DATABASE_URL" not in serialized
    assert "JWT_SECRET" not in serialized
    backend = next(doc for doc in deployments if doc["metadata"]["name"] == "asic-api")  # type: ignore[index]
    env = backend["spec"]["template"]["spec"]["containers"][0]["env"]  # type: ignore[index]
    assert any(
        item.get("name") == "ASIC_DATABASE_URL" and "secretKeyRef" in item["valueFrom"]
        for item in env
    )


def test_network_policy_is_default_deny_with_only_named_paths() -> None:
    policies = [doc for doc in _documents("base") if doc["kind"] == "NetworkPolicy"]
    names = {doc["metadata"]["name"] for doc in policies}  # type: ignore[index]
    assert {"default-deny-ingress", "default-deny-egress", "dns-egress", "frontend-to-api"} <= names
    rendered = yaml.safe_dump_all(policies)
    assert "0.0.0.0/0" not in rendered
    assert "192.0.2.1/32" in rendered  # fail-closed placeholder requiring a production patch


def test_migration_is_a_bounded_one_shot_with_separate_identity() -> None:
    job = next(doc for doc in _documents("migration") if doc["kind"] == "Job")
    spec = job["spec"]  # type: ignore[index]
    pod = spec["template"]["spec"]  # type: ignore[index]
    assert spec["backoffLimit"] == 0
    assert spec["activeDeadlineSeconds"] == 600
    assert pod["restartPolicy"] == "Never"
    assert pod["serviceAccountName"] == "asic-migration"
    assert pod["containers"][0]["command"] == [
        "/usr/local/bin/python",
        "-m",
        "alembic",
        "upgrade",
        "head",
    ]
    assert (
        pod["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]["name"]
        == "asic-migration-database"
    )


def test_release_workflow_is_trusted_pinned_and_container_scan_is_mandatory() -> None:
    workflow = (REPO / ".github" / "workflows" / "release.yml").read_text("utf-8")
    assert "pull_request:" not in workflow
    assert "permissions:" in workflow
    assert "packages: write" in workflow
    assert "id-token: write" in workflow
    assert "--require-container-scan" in workflow
    assert "--suite golden" in workflow
    assert "--mode simulator" in workflow and "--mode replay" in workflow
    assert "environment: production" in workflow
    assert "concurrency:" in workflow
    for use in re.findall(r"uses:\s*([^\s#]+)", workflow):
        assert use == "./.github/workflows/quality.yml" or re.search(r"@[0-9a-f]{40}$", use), use


def test_release_cannot_publish_before_quality_scan_and_same_image_smoke() -> None:
    text = (REPO / ".github/workflows/release.yml").read_text("utf-8")
    workflow = yaml.safe_load(text)
    jobs = workflow["jobs"]
    assert jobs["release"]["needs"] == "quality"
    assert jobs["quality"]["uses"] == "./.github/workflows/quality.yml"
    assert jobs["quality"]["with"]["skip_image_checks"] is True
    assert text.count("docker build ") == 2
    assert (
        text.index("--require-container-scan")
        < text.index("scripts/deployment_smoke.py")
        < text.index("docker/login-action")
    )
    assert "--image-id" in text
    assert "gh attestation verify" in text
    assert "--signer-workflow" in text


def test_deployment_checks_provenance_and_migration_before_rollout() -> None:
    text = (REPO / ".github/workflows/deploy.yml").read_text("utf-8")
    assert text.index("gh attestation verify") < text.index("base64 --decode")
    assert text.index("--for=condition=complete") < text.index("id: rollout")
    assert "environment: production" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "steps.rollout.outcome == 'failure'" in text
    assert "alembic downgrade" not in text


def test_workflow_actions_are_commit_pinned_and_permissions_are_declared() -> None:
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    assert {path.name for path in workflows} >= {"quality.yml", "release.yml"}
    for path in workflows:
        text = path.read_text("utf-8")
        assert "permissions:" in text
        assert ":latest" not in text
        for use in re.findall(r"uses:\s*([^\s#]+)", text):
            assert use == "./.github/workflows/quality.yml" or re.search(r"@[0-9a-f]{40}$", use), (
                f"{path}: {use}"
            )
