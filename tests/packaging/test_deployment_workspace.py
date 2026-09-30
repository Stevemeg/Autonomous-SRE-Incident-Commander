"""Real filesystem regressions for the disposable Terraform deployment workspace."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from scripts.deployment_workspace import deployment_directory, terraform_user_args

REPO = Path(__file__).resolve().parents[2]
TERRAFORM = (
    "hashicorp/terraform@sha256:dfb1889a8ee74ada3ddacc48f89b8a0d69f3e114de3d8a2ce15f6a8d3dbfdbe2"
)
PROVIDER = Path("providers/registry.terraform.io/hashicorp/kubernetes/2.38.0/linux_amd64")


def snapshot(path: Path) -> tuple[bytes, int]:
    return path.read_bytes(), stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("tree", ["absent", "real", "symlink", "broken", "partial"])
def test_normal_cleanup_preserves_external_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tree: str
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    canary = cache / "canary"
    canary.write_bytes(b"shared cache must survive")
    binary = cache / "terraform-provider-kubernetes_v2.38.0_x5"
    binary.write_bytes(b"provider binary")
    before = (snapshot(canary), snapshot(binary), stat.S_IMODE(cache.stat().st_mode))
    with deployment_directory() as directory:
        scratch = Path(directory)
        # Match both the reported spelling and the actual workflow's platform directory.
        for name in ("platform", "_platform"):
            platform = scratch / name
            platform.mkdir()
            terraform = platform / ".terraform"
            if tree == "absent":
                continue
            provider = terraform / PROVIDER
            provider.parent.mkdir(parents=True)
            if tree == "partial":
                (terraform / "partial-download").write_bytes(b"interrupted init")
            elif tree == "real":
                provider.mkdir()
                (provider / binary.name).write_bytes(b"local provider")
            else:
                try:
                    provider.symlink_to(
                        cache if tree == "symlink" else tmp_path / "missing-cache",
                        target_is_directory=True,
                    )
                except OSError as error:
                    if os.name == "nt" and error.winerror == 1314:
                        pytest.skip("Windows host does not permit creating symlinks")
                    raise
                assert stat.S_ISLNK(provider.lstat().st_mode)
    assert not scratch.exists()
    assert (snapshot(canary), snapshot(binary), stat.S_IMODE(cache.stat().st_mode)) == before


def test_command_failure_still_cleans_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with (
        pytest.raises(subprocess.CalledProcessError) as failure,
        deployment_directory() as directory,
    ):
        scratch = Path(directory)
        (scratch / "platform/.terraform").mkdir(parents=True)
        subprocess.run([sys.executable, "-c", "raise SystemExit(7)"], check=True)
    assert failure.value.returncode == 7
    assert not scratch.exists()


@pytest.mark.parametrize("deployment_failed", [False, True])
def test_cleanup_exception_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deployment_failed: bool
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    original = tempfile.TemporaryDirectory.cleanup
    cleanup_error = PermissionError("cleanup denied")
    deployment_error = subprocess.CalledProcessError(7, ["terraform", "apply"])

    def fail_cleanup(directory: tempfile.TemporaryDirectory[str]) -> None:
        # Leave no leaked fixture: inject only the failure for this precedence test.
        original(directory)
        raise cleanup_error

    monkeypatch.setattr(tempfile.TemporaryDirectory, "cleanup", fail_cleanup)
    expected = deployment_error if deployment_failed else cleanup_error
    with pytest.raises(type(expected)) as failure, deployment_directory() as directory:
        if deployment_failed:
            raise deployment_error
    assert failure.value is expected
    assert any("deployment workspace cleanup failed" in note for note in expected.__notes__)
    assert not Path(directory).exists()


def test_terraform_uses_the_cleanup_process_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "posix":
        assert terraform_user_args() == ["--user", f"{os.getuid()}:{os.getgid()}"]
    monkeypatch.setattr(sys, "platform", "win32")
    assert terraform_user_args() == ["--user", "1000:1000"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux Docker bind-mount ownership regression")
@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("command_failed", [False, True])
def test_real_terraform_init_and_cleanup_as_unprivileged_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached: bool, command_failed: bool
) -> None:
    """Old Docker default-user invocation leaves root-owned 0755 dirs and raises EPERM.

    Use the actual pinned Terraform and real provider installation, not mocked unlink
    or chmod. With caching, additionally prove that init creates a symlink and that
    normal TemporaryDirectory cleanup leaves its external target unchanged.
    """
    if not shutil.which("docker"):
        pytest.skip("Docker is required for the real Terraform ownership regression")
    if os.getuid() == 0:
        pytest.skip("Run this regression as an unprivileged user, as on GitHub runners")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    canary = cache / "canary"
    canary.write_bytes(b"external provider cache canary")
    canary_before = snapshot(canary)
    lock_before = (REPO / "infra/terraform/platform/.terraform.lock.hcl").read_bytes()
    cache_args = ["-v", f"{cache}:{cache}", "-e", f"TF_PLUGIN_CACHE_DIR={cache}"] if cached else []
    outcome = (
        pytest.raises(subprocess.CalledProcessError) if command_failed else contextlib.nullcontext()
    )
    with outcome, deployment_directory() as directory:
        scratch = Path(directory)
        platform = scratch / "platform"
        platform.mkdir()
        for path in (REPO / "infra/terraform/platform").iterdir():
            if path.suffix == ".tf" or path.name == ".terraform.lock.hcl":
                shutil.copy2(path, platform / path.name)
        command = [
            "docker",
            "run",
            "--rm",
            *terraform_user_args(),
            "-v",
            f"{scratch}:/work",
            "-w",
            "/work/platform",
            *cache_args,
            TERRAFORM,
        ]
        subprocess.run(
            [*command, "init", "-backend=false", "-lockfile=readonly"],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        provider = platform / ".terraform" / PROVIDER
        assert provider.is_symlink() is cached
        assert stat.S_ISLNK(provider.lstat().st_mode) is cached
        assert provider.lstat().st_uid == os.getuid()
        assert (platform / ".terraform.lock.hcl").read_bytes() == lock_before
        binary = provider / "terraform-provider-kubernetes_v2.38.0_x5"
        assert binary.is_file()
        if cached:
            cache_provider = cache / PROVIDER.relative_to("providers")
            binary = cache_provider / binary.name
            # Capture the binary and canary, and every cached directory/file mode.
            binary_before = snapshot(binary)
            modes_before = {
                str(path.relative_to(cache)): stat.S_IMODE(path.lstat().st_mode)
                for path in [cache, *cache.rglob("*")]
            }
        subprocess.run(
            [*command, "validate", *(["-invalid-option"] if command_failed else [])],
            check=True,
            capture_output=True,
            timeout=60,
        )
    assert not scratch.exists()
    assert snapshot(canary) == canary_before
    if cached:
        assert snapshot(binary) == binary_before
        assert {
            str(path.relative_to(cache)): stat.S_IMODE(path.lstat().st_mode)
            for path in [cache, *cache.rglob("*")]
        } == modes_before


def test_smoke_applies_identity_to_all_terraform_commands() -> None:
    """The single argv prefix is used for init, validate, apply, plan and destroy."""
    source = (REPO / "scripts/deployment_smoke.py").read_text("utf-8")
    terraform = source[source.index("        terraform = [") : source.index("        tf_vars = [")]
    assert "*terraform_user_args()," in terraform
    assert "with deployment_directory() as directory:" in source
    for operation in ("init", "validate", "apply", "plan", "destroy"):
        assert f'run(*terraform, "{operation}"' in source
