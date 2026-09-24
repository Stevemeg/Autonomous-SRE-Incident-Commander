"""N-2: the publish-attest identity binding, executed exactly as committed in release.yml.

The workflow step's shell is extracted from the parsed workflow and run with a stub ``docker``
that serves registry manifests from fixtures, so the real bash/jq logic is what is tested. Both
registry shapes must bind to the scanned image identity, and every mismatch must fail closed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
STEP = "Bind pushed registry digests to the scanned image identities"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(
    BASH is None or shutil.which("jq") is None, reason="needs bash and jq (present on CI runners)"
)

SCANNED = "sha256:" + "1" * 64  # the build-validate image ID
OTHER = "sha256:" + "2" * 64
RUNTIME = "sha256:" + "3" * 64
ATTEST = "sha256:" + "4" * 64
NAME = "ghcr.io/stevemeg/asic-backend"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"


def _step_script() -> str:
    workflow = yaml.safe_load((REPO / ".github/workflows/release.yml").read_text("utf-8"))
    steps = workflow["jobs"]["publish-attest"]["steps"]
    return str(next(step for step in steps if step.get("name") == STEP)["run"])


def manifest(config: str, media: str = OCI_MANIFEST) -> dict[str, Any]:
    return {"mediaType": media, "config": {"digest": config}, "layers": []}


def index(*entries: tuple[str, str, str], media: str = OCI_INDEX) -> dict[str, Any]:
    return {
        "mediaType": media,
        "manifests": [
            {"digest": digest, "platform": {"os": os_, "architecture": arch}}
            for digest, os_, arch in entries
        ],
    }


def run_bind(
    tmp_path: Path, registry: dict[str, Any], ref_digest: str, expected: str = SCANNED
) -> subprocess.CompletedProcess[str]:
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for digest, body in registry.items():
        text = body if isinstance(body, str) else json.dumps(body)
        (fixtures / digest.replace(":", "_")).write_text(text, "utf-8")
    stub = tmp_path / "bin"
    stub.mkdir()
    docker = stub / "docker"
    # docker buildx imagetools inspect --raw <name>@<digest>
    docker.write_bytes(
        b'#!/usr/bin/env bash\nref="${@: -1}"\nd="${ref##*@}"\nf="$FIXTURES/${d/:/_}"\n'
        b'[ -f "$f" ] && cat "$f" || { echo "not found: $ref" >&2; exit 1; }\n'
    )
    docker.chmod(0o755)
    script = tmp_path / "bind.sh"
    script.write_bytes(_step_script().encode("utf-8"))
    ref = f"{NAME}@{ref_digest}"
    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "FIXTURES": str(fixtures),
        "BACKEND_REF": ref,
        "FRONTEND_REF": ref,
        "BACKEND_IMAGE_ID": expected,
        "FRONTEND_IMAGE_ID": expected,
        "RUNTIME_OS": "linux",
        "RUNTIME_ARCH": "amd64",
    }
    assert BASH is not None
    return subprocess.run(
        [BASH, str(script)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


@pytest.mark.parametrize(
    ("registry", "ref_digest"),
    [
        # A. classic Docker store: single manifest whose config digest is the scanned image ID
        ({OTHER: manifest(SCANNED, DOCKER_MANIFEST)}, OTHER),
        # A2. single OCI manifest, same binding
        ({OTHER: manifest(SCANNED)}, OTHER),
        # B. containerd store: the scanned ID is the pushed index digest; one linux/amd64 runtime
        #    manifest plus a buildx attestation manifest (platform unknown/unknown)
        (
            {
                SCANNED: index((RUNTIME, "linux", "amd64"), (ATTEST, "unknown", "unknown")),
                RUNTIME: manifest(OTHER),
                ATTEST: manifest(OTHER),
            },
            SCANNED,
        ),
        # B2. index whose runtime manifest config is the scanned ID (Docker manifest list)
        (
            {
                OTHER: index((RUNTIME, "linux", "amd64"), media=DOCKER_LIST),
                RUNTIME: manifest(SCANNED),
            },
            OTHER,
        ),
    ],
    ids=["A-classic-manifest", "A2-oci-manifest", "B-oci-index-containerd", "B2-list-config"],
)
def test_supported_shapes_bind_to_the_scanned_image(
    tmp_path: Path, registry: dict[str, Any], ref_digest: str
) -> None:
    result = run_bind(tmp_path, registry, ref_digest)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"bound to scanned image {SCANNED}" in result.stdout


@pytest.mark.parametrize(
    ("registry", "ref_digest", "expected", "message"),
    [
        # C. index (not the scanned object) whose runtime config is also not the scanned image
        (
            {OTHER: index((RUNTIME, "linux", "amd64")), RUNTIME: manifest(OTHER)},
            OTHER,
            SCANNED,
            "is not the scanned image",
        ),
        # D. index without the expected runtime platform (even though its digest matches)
        (
            {
                SCANNED: index((RUNTIME, "linux", "arm64"), (ATTEST, "unknown", "unknown")),
                RUNTIME: manifest(SCANNED),
            },
            SCANNED,
            SCANNED,
            "no unique linux/amd64 manifest",
        ),
        # E. malformed registry objects
        ({OTHER: "not json"}, OTHER, SCANNED, "no mediaType"),
        ({OTHER: {"schemaVersion": 2}}, OTHER, SCANNED, "no mediaType"),
        ({OTHER: {"mediaType": OCI_MANIFEST}}, OTHER, SCANNED, "has no config"),
        ({OTHER: {"mediaType": "application/json"}}, OTHER, SCANNED, "unsupported manifest type"),
        # F. wrong local image ID (build-validate output does not match what was pushed)
        ({OTHER: manifest(SCANNED)}, OTHER, "sha256:" + "9" * 64, "is not the scanned image"),
        ({OTHER: manifest(SCANNED)}, OTHER, "not-a-digest", "malformed identity"),
        # G. wrong registry digest: a different pushed object than the scanned one
        ({OTHER: manifest(RUNTIME, DOCKER_MANIFEST)}, OTHER, SCANNED, "is not the scanned image"),
        # H. more than one runtime manifest for the platform: ambiguous, fail closed
        (
            {
                SCANNED: index((RUNTIME, "linux", "amd64"), (OTHER, "linux", "amd64")),
                RUNTIME: manifest(OTHER),
            },
            SCANNED,
            SCANNED,
            "no unique linux/amd64 manifest",
        ),
    ],
    ids=[
        "C-wrong-config",
        "D-no-platform",
        "E-not-json",
        "E-no-mediatype",
        "E-no-config",
        "E-unknown-type",
        "F-wrong-local-id",
        "F-malformed-id",
        "G-wrong-registry-digest",
        "H-ambiguous-runtime",
    ],
)
def test_identity_mismatches_fail_closed(
    tmp_path: Path, registry: dict[str, Any], ref_digest: str, expected: str, message: str
) -> None:
    result = run_bind(tmp_path, registry, ref_digest, expected)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert "bound to scanned image" not in result.stdout


def test_attestation_manifest_is_never_selected_as_runtime(tmp_path: Path) -> None:
    """An index holding only an attestation manifest must not bind, whatever its config."""
    registry = {SCANNED: index((ATTEST, "unknown", "unknown")), ATTEST: manifest(SCANNED)}
    result = run_bind(tmp_path, registry, SCANNED)
    assert result.returncode != 0
