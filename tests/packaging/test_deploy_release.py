"""Behavior of the authoritative deployment sequence against a simulated cluster.

The real sequence is also exercised end to end on disposable kind by deployment_smoke.py; these
tests pin the ordering, fail-fast and smoke semantics deterministically (no cluster, no sleeps).
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import subprocess
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType

import pytest
from scripts import deploy_release
from scripts.deploy_release import (
    Kubectl,
    MigrationFailed,
    RolloutFailed,
    SmokeFailed,
    job_state,
    post_rollout_smoke,
    redact,
    run_deployment,
    wait_for_job,
)

REPO = Path(__file__).resolve().parents[2]
MIGRATION = "kind: Job\nmetadata: {name: asic-migration}\n"
APPLICATION = (
    "kind: Deployment\nmetadata: {name: asic-api}\n---\n"
    "kind: Deployment\nmetadata: {name: asic-frontend}\n"
)
CONDITIONS = {
    "complete": [{"type": "Complete", "status": "True"}],
    "failed": [
        {"type": "FailureTarget", "status": "True", "reason": "BackoffLimitExceeded"},
        {"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"},
    ],
    "running": [],
}


class FakeCluster:
    """Interprets the kubectl commands the orchestrator issues and records them."""

    def __init__(
        self,
        job_states: Sequence[str],
        *,
        failing_rollout: str | None = None,
        ready: int = 1,
    ) -> None:
        self.job_states = list(job_states)
        self.failing_rollout = failing_rollout
        self.ready = ready
        self.calls: list[tuple[list[str], str | None]] = []
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def __call__(
        self, command: Sequence[str], content: str | None, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        args = list(command[3:])  # strip "kubectl -n <namespace>"
        self.calls.append((args, content))
        out, code = "", 0
        if args[:2] == ["get", "job"]:
            state = self.job_states.pop(0) if len(self.job_states) > 1 else self.job_states[0]
            out = json.dumps({"status": {"conditions": CONDITIONS[state]}})
        elif args[:2] == ["get", "pods"]:
            out = json.dumps(
                {
                    "items": [
                        {
                            "metadata": {"name": "asic-migration-x"},
                            "status": {
                                "phase": "Failed",
                                "containerStatuses": [
                                    {
                                        "name": "migrate",
                                        "state": {"terminated": {"reason": "Error", "exitCode": 1}},
                                    }
                                ],
                            },
                        }
                    ]
                }
            )
        elif args[0] == "logs":
            out = "\n".join(f"line {n}" for n in range(100)) + (
                "\nFATAL: password authentication failed for "
                "postgresql+psycopg2://owner:hunter2@db:5432/asic password=hunter2"
            )
        elif args[0] == "rollout":
            code = 1 if self.failing_rollout and self.failing_rollout in args[2] else 0
        elif args[:2] == ["get", "endpointslices"]:
            out = json.dumps(
                {"items": [{"endpoints": [{"conditions": {"ready": True}}] * self.ready}]}
            )
        return subprocess.CompletedProcess(command, code, out, "rollout timed out" if code else "")

    def applies(self) -> list[str]:
        return [
            "migration" if content == MIGRATION else "application"
            for args, content in self.calls
            if args[0] == "apply" and "--dry-run=server" not in args
        ]


def _deploy(
    cluster: FakeCluster, smoke: object = None, module: ModuleType = deploy_release
) -> object:
    kube = module.Kubectl("asic-system", runner=cluster)
    original = module.wait_for_job

    def wait(kube_: Kubectl, **kwargs: float) -> object:
        return original(kube_, clock=cluster.clock, sleep=cluster.sleep, **kwargs)

    module.wait_for_job = wait  # type: ignore[attr-defined]
    try:
        return module.run_deployment(
            kube,
            MIGRATION,
            APPLICATION,
            smoke=smoke or (lambda _kube: None),
            log=lambda _msg: None,
        )
    finally:
        module.wait_for_job = original  # type: ignore[attr-defined]


def test_failed_migration_stops_before_any_application_apply() -> None:
    cluster = FakeCluster(["running", "failed"])
    smoked: list[bool] = []
    with pytest.raises(MigrationFailed, match="NOT applied") as raised:
        _deploy(cluster, smoke=lambda _k: smoked.append(True))
    assert cluster.applies() == ["migration"]
    assert not any(args[0] == "rollout" for args, _ in cluster.calls)
    assert not smoked
    # Fail-fast: detected on the second poll, not after the 600s deadline.
    assert cluster.now == pytest.approx(2)
    assert "reason=BackoffLimitExceeded" in str(raised.value)
    assert "exitCode=1" in str(raised.value)


def test_migration_diagnostics_are_bounded_and_redacted() -> None:
    cluster = FakeCluster(["failed"])
    with pytest.raises(MigrationFailed) as raised:
        _deploy(cluster)
    message = str(raised.value)
    assert "hunter2" not in message
    assert "postgresql+psycopg2://***@db" in message
    assert "password=***" in message
    assert "line 99" in message and "line 50" not in message  # bounded tail
    logs = next(args for args, _ in cluster.calls if args[0] == "logs")
    assert "--tail=40" in logs and "--limit-bytes=8000" in logs


def test_successful_migration_rolls_out_then_smokes() -> None:
    cluster = FakeCluster(["running", "running", "complete"])
    smoked: list[bool] = []
    outcome = _deploy(cluster, smoke=lambda _k: smoked.append(True))
    assert outcome.state == "complete"  # type: ignore[attr-defined]
    assert cluster.applies() == ["migration", "application"]
    rollouts = [args[2] for args, _ in cluster.calls if args[0] == "rollout"]
    assert rollouts == ["deployment/asic-api", "deployment/asic-frontend"]
    assert smoked == [True]
    first_app = next(
        i
        for i, (args, content) in enumerate(cluster.calls)
        if content == APPLICATION and "--dry-run=server" not in args
    )
    last_job_poll = max(
        i for i, (args, _) in enumerate(cluster.calls) if args[:2] == ["get", "job"]
    )
    assert last_job_poll < first_app


def test_hung_migration_times_out_without_rollout() -> None:
    cluster = FakeCluster(["running"])
    kube = Kubectl("asic-system", runner=cluster)
    outcome = wait_for_job(kube, timeout=30, interval=2, clock=cluster.clock, sleep=cluster.sleep)
    assert outcome.state == "timeout"
    assert cluster.now == pytest.approx(30)
    with pytest.raises(MigrationFailed, match="migration timeout"):
        _deploy(FakeCluster(["running"]))


def test_failed_rollout_fails_the_deployment_and_skips_smoke() -> None:
    cluster = FakeCluster(["complete"], failing_rollout="asic-api")
    smoked: list[bool] = []
    with pytest.raises(RolloutFailed, match="asic-api"):
        _deploy(cluster, smoke=lambda _k: smoked.append(True))
    assert not smoked


@pytest.mark.parametrize(
    ("statuses", "failure"),
    [
        ({"/readyz@8000": 503}, "asic-api/readyz: expected 200, got 503"),
        ({"/livez@8000": 500}, "asic-api/livez"),
        ({"/api/v1/incidents@8000": 200}, "asic-api/api/v1/incidents: expected 401"),
        ({"/readyz@3000": 503}, "asic-frontend/readyz: expected 200, got 503"),
        ({"/livez@3000": 0}, "asic-frontend/livez"),
    ],
)
def test_post_rollout_smoke_fails_on_any_bad_check(statuses: dict[str, int], failure: str) -> None:
    cluster = FakeCluster(["complete"])
    kube = Kubectl("asic-system", runner=cluster)

    @contextlib.contextmanager
    def forward(_kube: Kubectl, target: str, port: int) -> Iterator[int]:
        assert target in {"svc/asic-api", "svc/asic-frontend"}
        yield port

    def fetch(url: str) -> int:
        port, path = url.removeprefix("http://127.0.0.1:").split("/", 1)
        default = 401 if path == "api/v1/incidents" else 200
        return statuses.get(f"/{path}@{port}", default)

    with pytest.raises(SmokeFailed, match=failure):
        post_rollout_smoke(kube, forward=forward, fetch=fetch, log=lambda _m: None)
    with pytest.raises(SmokeFailed):
        _deploy(
            FakeCluster(["complete"]),
            smoke=lambda k: post_rollout_smoke(
                k, forward=forward, fetch=fetch, log=lambda _m: None
            ),
        )


def test_post_rollout_smoke_passes_and_requires_ready_endpoints() -> None:
    @contextlib.contextmanager
    def forward(_kube: Kubectl, _target: str, port: int) -> Iterator[int]:
        yield port

    seen: list[str] = []

    def fetch(url: str) -> int:
        seen.append(url)
        return 401 if url.endswith("/api/v1/incidents") else 200

    kube = Kubectl("asic-system", runner=FakeCluster(["complete"]))
    post_rollout_smoke(kube, forward=forward, fetch=fetch, log=lambda _m: None)
    assert seen == [
        "http://127.0.0.1:8000/livez",
        "http://127.0.0.1:8000/readyz",
        "http://127.0.0.1:8000/api/v1/incidents",
        "http://127.0.0.1:3000/livez",
        "http://127.0.0.1:3000/readyz",
    ]
    empty = Kubectl("asic-system", runner=FakeCluster(["complete"], ready=0))
    with pytest.raises(SmokeFailed, match="no ready endpoints"):
        post_rollout_smoke(empty, forward=forward, fetch=fetch, log=lambda _m: None)


def test_default_deployment_runs_the_post_rollout_smoke() -> None:
    import inspect

    default = inspect.signature(run_deployment).parameters["smoke"].default
    assert default is post_rollout_smoke


def test_job_state_treats_failure_target_as_terminal() -> None:
    assert job_state({"status": {"conditions": CONDITIONS["complete"]}}) == "complete"
    assert job_state({"status": {"conditions": [CONDITIONS["failed"][0]]}}) == "failed"
    assert job_state({"status": {"conditions": [{"type": "Failed", "status": "False"}]}}) is None
    assert job_state({"status": {}}) is None


def test_redact_removes_credentials_only() -> None:
    assert redact("https://u:p@host/x token=abc role asic_app") == (
        "https://***@host/x token=*** role asic_app"
    )


def test_guard_mutation_is_detected(tmp_path: Path) -> None:
    """Non-vacuity: with the migration-success guard removed, a failed migration WOULD roll
    out the application, and the ordering assertion above would catch it."""
    source = (REPO / "scripts/deploy_release.py").read_text("utf-8")
    guard = 'if outcome.state != "complete":  # migration-success guard'
    assert source.count(guard) == 1
    mutant_path = tmp_path / "deploy_release_mutant.py"
    mutant_path.write_text(source.replace(guard, "if False:"), "utf-8")
    spec = importlib.util.spec_from_file_location("deploy_release_mutant", mutant_path)
    assert spec and spec.loader
    mutant = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mutant  # dataclass annotation resolution needs the module
    try:
        spec.loader.exec_module(mutant)
    finally:
        del sys.modules[spec.name]
    cluster = FakeCluster(["failed"])
    _deploy(cluster, module=mutant)
    assert cluster.applies() == ["migration", "application"]


def test_cli_exits_nonzero_on_failed_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "m.yaml").write_text(MIGRATION, "utf-8")
    (tmp_path / "a.yaml").write_text(APPLICATION, "utf-8")
    cluster = FakeCluster(["failed"])
    monkeypatch.setattr(
        deploy_release,
        "Kubectl",
        lambda namespace, kubeconfig: Kubectl(namespace, runner=cluster),
    )
    code = deploy_release.main(
        ["--migration", str(tmp_path / "m.yaml"), "--application", str(tmp_path / "a.yaml")]
    )
    assert code == 1
    assert "DEPLOYMENT FAILED" in capsys.readouterr().err
    assert cluster.applies() == ["migration"]
