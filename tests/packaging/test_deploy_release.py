"""Behavior of the authoritative deployment sequence against a simulated cluster.

The real sequence is also exercised end to end on disposable kind by deployment_smoke.py
(including sequential redeployments); these tests pin the ordering, Job-slot, fail-fast and smoke
semantics deterministically (no cluster, no sleeps). The fake enforces the Kubernetes rules that
matter here: a Job's pod template is immutable, ``create`` refuses an existing name, and
foreground deletion can take several polls.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from scripts import deploy_release
from scripts.deploy_release import (
    DeploymentError,
    Kubectl,
    MigrationActive,
    MigrationFailed,
    RolloutFailed,
    SmokeFailed,
    bounded,
    job_state,
    post_rollout_smoke,
    redact,
    run_deployment,
    split_migration,
    wait_for_job,
)

REPO = Path(__file__).resolve().parents[2]


def migration(command: str = "alembic upgrade head") -> str:
    return (
        "kind: Job\nmetadata: {name: asic-migration}\n"
        f"spec:\n  template:\n    spec:\n      containers:\n        - name: migrate\n"
        f"          command: [{command!r}]\n"
        "---\nkind: NetworkPolicy\nmetadata: {name: migration-egress}\n"
    )


MIGRATION = migration()
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
NOT_FOUND = 'Error from server (NotFound): jobs.batch "asic-migration" not found'
IMMUTABLE = (
    'The Job "asic-migration" is invalid: spec.template: Invalid value: '
    + '{"Spec":{"Containers":[' * 200
    + "]}}: field is immutable"
)


def _template(content: str) -> str:
    job = next(doc for doc in yaml.safe_load_all(content) if doc and doc["kind"] == "Job")
    return yaml.safe_dump(job["spec"]["template"], sort_keys=True)


class FakeCluster:
    """Stateful model of the one migration Job plus the calls the orchestrator makes."""

    def __init__(
        self,
        new_job_states: Sequence[str] = ("complete",),
        *,
        previous: tuple[str, str] | None = None,
        delete_polls: int = 0,
        failing_rollout: str | None = None,
        ready: int = 1,
        fail: str | None = None,
        vanish_after: int | None = None,
        transient_get_errors: int = 0,
        terminate_after: int | None = None,
    ) -> None:
        self.new_job_states = list(new_job_states)
        self.job: dict[str, Any] | None = None
        if previous:
            state, content = previous
            self.job = {"uid": "uid-old", "template": _template(content), "states": [state]}
        self.delete_polls = delete_polls
        self.failing_rollout = failing_rollout
        self.ready = ready
        self.fail = fail  # "get" | "delete" | "job-dry-run" | "create"
        self.vanish_after = vanish_after  # created Job is deleted externally after N polls
        self.transient_get_errors = transient_get_errors
        self.terminate_after = terminate_after  # created Job gets a deletionTimestamp after N polls
        self.calls: list[tuple[list[str], str | None]] = []
        self.events: list[str] = []
        self.created = 0
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def _result(
        self, command: Sequence[str], out: str = "", code: int = 0, err: str = ""
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(command), code, out, err)

    def _job_json(self) -> str:
        assert self.job is not None
        states = self.job["states"]
        state = states.pop(0) if len(states) > 1 else states[0]
        metadata: dict[str, Any] = {"uid": self.job["uid"]}
        if self.job.get("terminating"):
            metadata["deletionTimestamp"] = "2026-09-24T12:00:00Z"
        return json.dumps({"metadata": metadata, "status": {"conditions": CONDITIONS[state]}})

    def __call__(
        self, command: Sequence[str], content: str | None, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        args = list(command[3:])  # strip "kubectl -n <namespace>"
        self.calls.append((args, content))
        is_job = content is not None and "kind: Job" in content
        dry = "--dry-run=server" in args
        if args[:2] == ["get", "job"]:
            if self.fail == "get":
                return self._result(command, code=1, err="Unauthorized")
            if self.transient_get_errors and self.created:
                self.transient_get_errors -= 1
                return self._result(command, code=1, err="Unable to connect to the server: EOF")
            if self.terminate_after is not None and self.created and self.job is not None:
                if self.terminate_after == 0:
                    self.job["terminating"] = True
                else:
                    self.terminate_after -= 1
            if self.vanish_after is not None and self.created and self.job is not None:
                if self.vanish_after == 0:
                    self.job = None
                    self.events.append("created job deleted externally")
                else:
                    self.vanish_after -= 1
            if self.job is not None and "deleting" in self.job:
                if self.job["deleting"] > 0:
                    self.job["deleting"] -= 1
                else:
                    self.job = None
                    self.events.append("old job gone")
            if self.job is None:
                return self._result(command, code=1, err=NOT_FOUND)
            return self._result(command, self._job_json())
        if args[:2] == ["delete", "job"]:
            if self.fail == "delete":
                return self._result(command, code=1, err="Forbidden: cannot delete jobs")
            assert self.job is not None, "orchestrator deleted a Job that does not exist"
            self.events.append("delete")
            self.job["deleting"] = self.delete_polls
            return self._result(command)
        if args[0] in {"apply", "create"} and is_job:
            if dry and self.fail == "job-dry-run":
                return self._result(command, code=1, err="admission webhook denied the Job")
            if self.job is not None:
                if args[0] == "create" and not dry:
                    return self._result(command, code=1, err="AlreadyExists")
                if self.job["template"] != _template(content or ""):
                    return self._result(command, code=1, err=IMMUTABLE)
            if dry:
                return self._result(command)
            if self.fail == "create":
                return self._result(command, code=1, err="quota exceeded")
            self.created += 1
            uid = f"uid-new-{self.created}"
            self.events.append(f"create {uid}")
            self.job = {
                "uid": uid,
                "template": _template(content or ""),
                "states": list(self.new_job_states),
            }
            return self._result(command, uid)
        if args[:2] == ["get", "pods"]:
            return self._result(
                command,
                json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "asic-migration-x"},
                                "status": {
                                    "phase": "Failed",
                                    "containerStatuses": [
                                        {
                                            "name": "migrate",
                                            "state": {
                                                "terminated": {"reason": "Error", "exitCode": 1}
                                            },
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                ),
            )
        if args[0] == "logs":
            out = "\n".join(f"line {n}" for n in range(100)) + (
                "\nFATAL: password authentication failed for "
                "postgresql+psycopg2://owner:hunter2@db:5432/asic password=hunter2"
            )
            return self._result(command, out)
        if args[0] == "rollout":
            bad = bool(self.failing_rollout and self.failing_rollout in args[2])
            return self._result(command, code=int(bad), err="rollout timed out" if bad else "")
        if args[:2] == ["get", "endpointslices"]:
            endpoints = [{"conditions": {"ready": True}}] * self.ready
            return self._result(command, json.dumps({"items": [{"endpoints": endpoints}]}))
        if args[0] == "apply" and not dry and content == APPLICATION:
            self.events.append("application")
        return self._result(command)

    def kinds(self) -> list[str]:
        """Mutating (non-dry-run) operations in order."""
        out = []
        for args, content in self.calls:
            if "--dry-run=server" in args:
                continue
            if args[0] == "create":
                out.append("create-job")
            elif args[0] == "apply":
                out.append("application" if content == APPLICATION else "supporting")
            elif args[:2] == ["delete", "job"]:
                out.append("delete-job")
        return out


def _deploy(
    cluster: FakeCluster,
    smoke: Callable[[Kubectl], None] | None = None,
    module: ModuleType = deploy_release,
    manifest: str = MIGRATION,
    log: Callable[[str], None] = lambda _msg: None,
) -> Any:
    kube = module.Kubectl("asic-system", runner=cluster)
    return module.run_deployment(
        kube,
        manifest,
        APPLICATION,
        smoke=smoke or (lambda _kube: None),
        log=log,
        clock=cluster.clock,
        sleep=cluster.sleep,
    )


def _mutant(tmp_path: Path, old: str, new: str) -> ModuleType:
    source = (REPO / "scripts/deploy_release.py").read_text("utf-8")
    assert source.count(old) == 1, old
    path = tmp_path / "deploy_release_mutant.py"
    path.write_text(source.replace(old, new), "utf-8")
    spec = importlib.util.spec_from_file_location("deploy_release_mutant", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclass annotation resolution needs the module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


# ------------------------------------------------------------------ LOW-7 / LOW-8 behavior
def test_failed_migration_stops_before_any_application_apply() -> None:
    cluster = FakeCluster(["running", "failed"])
    smoked: list[bool] = []
    with pytest.raises(MigrationFailed, match="NOT applied") as raised:
        _deploy(cluster, smoke=lambda _k: smoked.append(True))
    assert cluster.kinds() == ["supporting", "create-job"]
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
    assert outcome.state == "complete"
    assert cluster.kinds() == ["supporting", "create-job", "application"]
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
    _deploy_kube = Kubectl("asic-system", runner=cluster)
    cluster.job = {"uid": "u", "template": "", "states": ["running"]}
    outcome = wait_for_job(
        _deploy_kube, timeout=30, interval=2, clock=cluster.clock, sleep=cluster.sleep
    )
    assert outcome.state == "timeout"
    assert cluster.now == pytest.approx(30)
    with pytest.raises(MigrationFailed, match="migration timeout"):
        _deploy(FakeCluster(["running"]))


def test_result_must_come_from_the_created_job() -> None:
    cluster = FakeCluster(["running"])
    kube = Kubectl("asic-system", runner=cluster)
    cluster.job = {"uid": "someone-else", "template": "", "states": ["complete"]}
    outcome = wait_for_job(kube, uid="uid-new-1", clock=cluster.clock, sleep=cluster.sleep)
    assert outcome.state == "replaced"


def test_created_job_disappearing_fails_promptly() -> None:
    """LOW-2: our Job vanishing mid-wait is terminal, not a 600s wait for it to reappear."""
    cluster = FakeCluster(["running"], vanish_after=2)
    with pytest.raises(MigrationFailed, match="migration disappeared") as raised:
        _deploy(cluster)
    assert "was deleted before finishing" in str(raised.value)
    assert cluster.now == pytest.approx(4)  # two running polls, then NotFound
    assert "application" not in cluster.events


def test_created_job_being_deleted_fails_promptly() -> None:
    """A foreground delete keeps the Job visible (deletionTimestamp set) while pods terminate;
    it can no longer complete, so the watcher must not wait out the grace period."""
    cluster = FakeCluster(["running"], terminate_after=1)
    with pytest.raises(MigrationFailed, match="is being deleted before finishing"):
        _deploy(cluster)
    assert cluster.now == pytest.approx(2)
    assert "application" not in cluster.events


def test_transient_lookup_errors_are_not_mistaken_for_deletion() -> None:
    cluster = FakeCluster(["running", "complete"], transient_get_errors=3)
    outcome = _deploy(cluster)
    assert outcome.state == "complete"
    assert "application" in cluster.events


def test_kubectl_timeout_is_a_deployment_error_not_a_traceback() -> None:
    def runner(command: Sequence[str], content: str | None, timeout: float) -> Any:
        raise subprocess.TimeoutExpired(list(command), timeout)

    with pytest.raises(DeploymentError, match="kubectl apply -f timed out after 120s"):
        Kubectl("asic-system", runner=runner)("apply", "-f", "-")


def test_failed_rollout_fails_the_deployment_and_skips_smoke() -> None:
    cluster = FakeCluster(["complete"], failing_rollout="asic-api")
    smoked: list[bool] = []
    with pytest.raises(RolloutFailed, match="asic-api"):
        _deploy(cluster, smoke=lambda _k: smoked.append(True))
    assert not smoked


# --------------------------------------------------------------- N-1: migration Job slot
def test_absent_previous_job_proceeds_without_delete() -> None:
    cluster = FakeCluster(["complete"])
    _deploy(cluster)
    assert "delete-job" not in cluster.kinds()
    assert cluster.events == ["create uid-new-1", "application"]


@pytest.mark.parametrize("previous_state", ["complete", "failed"])
@pytest.mark.parametrize(
    "changed", [False, True], ids=["same-template", "changed-template(new digest/command)"]
)
def test_terminal_previous_job_is_replaced(previous_state: str, changed: bool) -> None:
    """The original N-1 defect: a lingering terminal Job must not block the next release."""
    new = migration("alembic upgrade head --release-b") if changed else MIGRATION
    cluster = FakeCluster(["complete"], previous=(previous_state, MIGRATION), delete_polls=2)
    logs: list[str] = []
    outcome = _deploy(cluster, manifest=new, log=logs.append)
    assert outcome.state == "complete"
    assert cluster.events == ["delete", "old job gone", "create uid-new-1", "application"]
    assert cluster.kinds() == ["delete-job", "supporting", "create-job", "application"]
    if previous_state == "failed":
        # Earlier failure evidence is logged before the object is deleted.
        assert any("previous failed migration evidence" in line for line in logs)


def test_fix_forward_after_failed_migration_recovers() -> None:
    cluster = FakeCluster(["failed"])
    with pytest.raises(MigrationFailed):
        _deploy(cluster, manifest=migration("broken"))
    cluster.new_job_states = ["running", "complete"]
    outcome = _deploy(cluster, manifest=migration("fixed"))
    assert outcome.state == "complete"
    assert cluster.events == [
        "create uid-new-1",
        "delete",
        "old job gone",
        "create uid-new-2",
        "application",
    ]


def test_active_previous_job_fails_closed_and_is_left_running() -> None:
    cluster = FakeCluster(["complete"], previous=("running", MIGRATION))
    with pytest.raises(MigrationActive, match="still active"):
        _deploy(cluster, manifest=migration("next release"))
    assert cluster.job is not None and cluster.job["uid"] == "uid-old"
    assert "deleting" not in cluster.job
    assert cluster.kinds() == []  # no delete, no create, no supporting apply, no application


def test_previous_job_already_being_deleted_is_awaited_not_deleted() -> None:
    """A previous Job with deletionTimestamp (e.g. an interrupted deployment's) is not an active
    migration to protect: wait for the deletion in progress, never issue our own delete."""
    cluster = FakeCluster(["complete"], previous=("running", MIGRATION))
    assert cluster.job is not None
    cluster.job["terminating"] = True
    cluster.job["deleting"] = 3  # disappears after three polls
    logs: list[str] = []
    outcome = _deploy(cluster, manifest=migration("release-b"), log=logs.append)
    assert outcome.state == "complete"
    assert "delete-job" not in cluster.kinds()
    assert cluster.events.index("old job gone") < cluster.events.index("create uid-new-1")
    assert any("already being deleted" in line for line in logs)


def test_delete_waits_for_absence_before_creating_the_replacement() -> None:
    cluster = FakeCluster(["complete"], previous=("complete", MIGRATION), delete_polls=5)
    _deploy(cluster, manifest=migration("release-b"))
    assert cluster.events.index("old job gone") < cluster.events.index("create uid-new-1")
    assert cluster.now == pytest.approx(10)  # 5 polls x 2s, bounded


def test_delete_timeout_fails_without_creating() -> None:
    cluster = FakeCluster(["complete"], previous=("complete", MIGRATION), delete_polls=10_000)
    with pytest.raises(DeploymentError, match="still exists 180s after deletion"):
        _deploy(cluster, manifest=migration("release-b"))
    assert cluster.created == 0 and "application" not in cluster.events
    assert cluster.now == pytest.approx(180)


@pytest.mark.parametrize(
    ("fail", "previous", "match"),
    [
        ("get", None, "cannot inspect previous migration Job"),
        ("delete", ("complete", MIGRATION), "Forbidden"),
        ("job-dry-run", None, "admission webhook denied"),
        ("create", None, "quota exceeded"),
    ],
)
def test_slot_and_replacement_failures_stop_before_migration(
    fail: str, previous: tuple[str, str] | None, match: str
) -> None:
    cluster = FakeCluster(["complete"], previous=previous, fail=fail)
    with pytest.raises(DeploymentError, match=match):
        _deploy(cluster, manifest=migration("release-b"))
    assert cluster.created == 0
    assert "application" not in cluster.events


def test_split_migration_requires_exactly_one_migration_job() -> None:
    job, supporting = split_migration(MIGRATION)
    assert "kind: Job" in job and "NetworkPolicy" in supporting
    with pytest.raises(DeploymentError):
        split_migration("kind: NetworkPolicy\nmetadata: {name: x}\n")
    with pytest.raises(DeploymentError):
        split_migration(MIGRATION + "---\n" + MIGRATION)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # cleanup removed entirely
        (
            '    raw = kube.probe("get", "job", job, "-o", "json")\n'
            "    if _not_found(raw):\n"
            '        return "absent"\n',
            '    return "absent"\n',
        ),
        # the original ordering: validate the new Job before clearing the old one
        (
            "    previous = clear_previous_migration(\n",
            '    kube("apply", "--dry-run=server", "-f", "-", content=job_manifest)\n'
            "    previous = clear_previous_migration(\n",
        ),
    ],
    ids=["cleanup-removed", "validate-before-cleanup"],
)
def test_slot_mutations_recreate_the_immutable_field_regression(
    tmp_path: Path, old: str, new: str
) -> None:
    mutant = _mutant(tmp_path, old, new)
    cluster = FakeCluster(["complete"], previous=("complete", MIGRATION))
    with pytest.raises(mutant.DeploymentError, match="field is immutable"):
        _deploy(cluster, module=mutant, manifest=migration("release-b"))


# ------------------------------------------------------------------ bounded diagnostics
def test_bounded_errors_keep_the_cause_and_the_end() -> None:
    message = IMMUTABLE + " trailing-noise" * 400 + " FINAL-LINE"
    kept = bounded(message)
    assert kept.startswith('The Job "asic-migration" is invalid')
    assert "characters truncated" in kept and kept.endswith("FINAL-LINE")
    assert len(kept) < 3200
    assert bounded("short error") == "short error"


def test_kubectl_error_preserves_immutable_cause_and_redacts() -> None:
    canary = "postgresql+psycopg2://owner:CANARY-9931@db/asic password=CANARY-9931"
    stderr = "cause: field is immutable " + canary + " noise" * 2000 + " " + canary

    def runner(command: Sequence[str], content: str | None, timeout: float) -> Any:
        return subprocess.CompletedProcess(list(command), 1, "", stderr)

    with pytest.raises(DeploymentError) as raised:
        Kubectl("asic-system", runner=runner)("apply", "-f", "-")
    text = str(raised.value)
    assert "field is immutable" in text
    assert "CANARY-9931" not in text
    assert "postgresql+psycopg2://***@db" in text and "password=***" in text


# ------------------------------------------------------------------------ smoke semantics
class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@contextlib.contextmanager
def _forward(_kube: Kubectl, target: str, port: int) -> Iterator[int]:
    assert target in {"svc/asic-api", "svc/asic-frontend"}
    yield port


def _healthy(url: str) -> int:
    return 401 if url.endswith("/api/v1/incidents") else 200


def _smoke(
    kube: Kubectl, fetch: Callable[[str], int], clock: FakeClock, logs: list[str] | None = None
) -> None:
    post_rollout_smoke(
        kube,
        forward=_forward,
        fetch=fetch,
        log=(logs.append if logs is not None else lambda _m: None),
        clock=clock,
        sleep=clock.sleep,
    )


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
def test_persistently_bad_check_fails_at_the_deadline(
    statuses: dict[str, int], failure: str
) -> None:
    """Non-vacuity: retrying never turns a genuinely broken release into a success."""

    def fetch(url: str) -> int:
        port, path = url.removeprefix("http://127.0.0.1:").split("/", 1)
        return statuses.get(f"/{path}@{port}", _healthy(url))

    clock = FakeClock()
    kube = Kubectl("asic-system", runner=FakeCluster(["complete"]))
    with pytest.raises(SmokeFailed, match="did not converge within 60s") as raised:
        _smoke(kube, fetch, clock)
    assert failure in str(raised.value)  # last error is reported
    assert clock.now == pytest.approx(60)  # deadline respected, not exceeded
    assert all(s <= 2 for s in clock.sleeps)  # bounded, deterministic interval
    cluster = FakeCluster(["complete"])
    deploy_clock = FakeClock()
    with pytest.raises(SmokeFailed):
        _deploy(cluster, smoke=lambda k: _smoke(k, fetch, deploy_clock))


def test_first_probe_success_uses_one_attempt_per_service() -> None:
    seen: list[str] = []

    def fetch(url: str) -> int:
        seen.append(url)
        return _healthy(url)

    clock = FakeClock()
    _smoke(Kubectl("asic-system", runner=FakeCluster(["complete"])), fetch, clock)
    assert seen == [
        "http://127.0.0.1:8000/livez",
        "http://127.0.0.1:8000/readyz",
        "http://127.0.0.1:8000/api/v1/incidents",
        "http://127.0.0.1:3000/livez",
        "http://127.0.0.1:3000/readyz",
    ]
    assert clock.sleeps == []


def _flaky(failures: list[object]) -> Callable[[str], int]:
    """frontend /readyz answers with each item of ``failures`` first, then 200."""
    queue = list(failures)

    def fetch(url: str) -> int:
        if url.endswith(":3000/readyz") and queue:
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return int(item)  # type: ignore[call-overload]
        return _healthy(url)

    return fetch


@pytest.mark.parametrize(
    "failures",
    [
        [503, 503],
        [SmokeFailed("http://127.0.0.1:3000/readyz unreachable: [WinError 10061] refused")],
        [SmokeFailed("http://127.0.0.1:3000/readyz unreachable: timed out")],
    ],
    ids=["503-503-200", "connection-refused-then-200", "timeout-then-200"],
)
def test_rollout_convergence_is_tolerated_within_the_allowance(failures: list[object]) -> None:
    """M-1: the frontend readiness dip while old API pods terminate is not a failed release."""
    clock = FakeClock()
    logs: list[str] = []
    _smoke(Kubectl("asic-system", runner=FakeCluster(["complete"])), _flaky(failures), clock, logs)
    assert clock.now == pytest.approx(2 * len(failures))
    assert any(f"converged after {len(failures) + 1} attempts" in line for line in logs)


def test_persistent_connection_failure_fails_at_the_deadline() -> None:
    def fetch(url: str) -> int:
        raise SmokeFailed(f"{url} unreachable: connection refused")

    clock = FakeClock()
    with pytest.raises(SmokeFailed, match="asic-api did not converge within 60s after 31 attempts"):
        _smoke(Kubectl("asic-system", runner=FakeCluster(["complete"])), fetch, clock)


def test_missing_endpoints_and_transient_endpoint_errors_are_retried_then_fail() -> None:
    clock = FakeClock()
    empty = Kubectl("asic-system", runner=FakeCluster(["complete"], ready=0))
    with pytest.raises(SmokeFailed, match="no ready endpoints"):
        _smoke(empty, _healthy, clock)
    assert clock.now == pytest.approx(60)


def test_only_smoke_failures_are_retried() -> None:
    """A programming/contract error is not masked as convergence."""

    def fetch(url: str) -> int:
        raise ValueError("unexpected")

    with pytest.raises(ValueError):
        _smoke(Kubectl("asic-system", runner=FakeCluster(["complete"])), fetch, FakeClock())


def test_convergence_failure_diagnostic_is_bounded_and_redacted() -> None:
    def attempt() -> None:
        raise SmokeFailed("upstream said password=CANARY_31 " + "x" * 10_000)

    clock = FakeClock()
    with pytest.raises(SmokeFailed) as raised:
        deploy_release.converge("svc", attempt, clock=clock, sleep=clock.sleep, log=lambda _m: None)
    text = str(raised.value)
    assert "CANARY_31" not in text and "password=***" in text
    assert len(text) < 3300 and "characters truncated" in text


def test_default_deployment_runs_the_post_rollout_smoke() -> None:
    import inspect

    default = inspect.signature(run_deployment).parameters["smoke"].default
    assert default is post_rollout_smoke


def test_job_state_treats_failure_target_as_terminal() -> None:
    assert job_state({"status": {"conditions": CONDITIONS["complete"]}}) == "complete"
    assert job_state({"status": {"conditions": [CONDITIONS["failed"][0]]}}) == "failed"
    assert job_state({"status": {"conditions": [{"type": "Failed", "status": "False"}]}}) is None
    assert job_state({"status": {}}) is None


CANARY = "CANARY_4419"
# Fixture strings are assembled from parts so the repository secret scanner (which rightly flags
# literal DSNs and password assignments) sees no credential-shaped literal in this file.
PW = "pass" + "word"
DSN = "postgresql" + "://user:"


@pytest.mark.parametrize(
    "form",
    [
        f"PGPASSWORD={CANARY}",
        f'PGPASSWORD="{CANARY}"',
        f'"{PW}":"{CANARY}"',
        f'"{PW}": "{CANARY}"',
        f"{PW}: {CANARY}",
        f'{PW}: "{CANARY}"',
        f"api_key={CANARY}",
        f"api-key={CANARY}",
        f"Authorization: Bearer {CANARY}",
        f"authorization: bearer {CANARY}",
        f"--password {CANARY}",
        f"--password={CANARY}",
        f"{DSN}{CANARY}@host/db",
        f"DATABASE_URL={DSN}{CANARY}@host/db",
        f"{PW}={CANARY}",
    ],
)
def test_redaction_covers_common_credential_forms(form: str) -> None:
    text = f"kubectl said: {form} (exit 1)"
    assert CANARY not in redact(text)

    # Every diagnostic path: kubectl errors, migration diagnostics and smoke failures.
    def runner(command: Sequence[str], content: str | None, timeout: float) -> Any:
        return subprocess.CompletedProcess(list(command), 1, "", text)

    with pytest.raises(DeploymentError) as raised:
        Kubectl("asic-system", runner=runner)("apply", "-f", "-")
    assert CANARY not in str(raised.value)


@pytest.mark.parametrize(
    "prose",
    [
        'FATAL:  password authentication failed for user "asic_nobody"',
        'secrets "asic-migration-database" not found',
        "Authorization header missing",
        "valueFrom: secretKeyRef: {name: asic-runtime-database, key: url}",
        "the token was rejected by the IdP",
    ],
)
def test_redaction_keeps_ordinary_diagnostics(prose: str) -> None:
    assert redact(prose) == prose


def test_redact_removes_credentials_only() -> None:
    assert redact("https://u:p@host/x token=abc role asic_app") == (
        "https://***@host/x token=*** role asic_app"
    )


def test_guard_mutation_is_detected(tmp_path: Path) -> None:
    """Non-vacuity: with the migration-success guard removed, a failed migration WOULD roll
    out the application, and the ordering assertion above would catch it."""
    mutant = _mutant(
        tmp_path, 'if outcome.state != "complete":  # migration-success guard', "if False:"
    )
    cluster = FakeCluster(["failed"])
    _deploy(cluster, module=mutant)
    assert cluster.kinds() == ["supporting", "create-job", "application"]


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
    assert cluster.kinds() == ["supporting", "create-job"]


def test_cli_reports_an_active_migration_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "m.yaml").write_text(MIGRATION, "utf-8")
    (tmp_path / "a.yaml").write_text(APPLICATION, "utf-8")
    cluster = FakeCluster(["complete"], previous=("running", MIGRATION))
    monkeypatch.setattr(
        deploy_release,
        "Kubectl",
        lambda namespace, kubeconfig: Kubectl(namespace, runner=cluster),
    )
    code = deploy_release.main(
        ["--migration", str(tmp_path / "m.yaml"), "--application", str(tmp_path / "a.yaml")]
    )
    assert code == 1
    assert "still active" in capsys.readouterr().err
    assert cluster.kinds() == []
