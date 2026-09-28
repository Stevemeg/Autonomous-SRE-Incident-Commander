#!/usr/bin/env python3
"""Authoritative deployment sequence: migrate -> guard -> roll out -> post-rollout smoke.

This is the ONLY implementation of the ordering. The production workflow (deploy.yml) and the
disposable-kind smoke (deployment_smoke.py) both call ``run_deployment``, so the ordering that is
tested locally is the ordering that runs in production.

1. server-side dry-run of the application manifest;
2. clear the migration Job slot: a previous Job that is Complete/Failed is recorded and deleted
   (foreground) and its absence is confirmed; one already being deleted is only waited for; an
   ACTIVE previous Job fails the deployment closed and is never touched. Job pod templates are
   immutable, so the new Job is validated only after the old one is gone;
2b. wait (bounded, fail closed) until no pod of any previous migration Job is still running:
   a Job object can disappear while its pod is still terminating (Phase 15);
3. server-side dry-run, then ``create`` (never adopt) the new Job and bind to its UID;
4. watch that Job until Complete, Failed, timeout, or it is replaced/deleted; on anything but
   Complete record bounded, redacted diagnostics and stop (application manifests never applied);
5. apply the application manifest and wait for every Deployment rollout;
6. probe backend and frontend health plus an unauthenticated API refusal through the Services,
   retrying within a bounded convergence allowance (rollout completion is not endpoint settling).

A failed rollout or smoke exits nonzero. Nothing here ever downgrades the database.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MIGRATION_JOB = "asic-migration"
LOG_TAIL_LINES = 40
LOG_LIMIT_BYTES = 8000
# Deployment convergence allowance for the post-rollout smoke: `rollout status` returns when the
# new pods are available, but old pods may still be terminating and Service endpoints/port-forward
# targets are still settling, so a dependent readiness check (frontend -> API) can briefly fail on a
# healthy release. Checks are retried until they all pass or this deadline expires (then the
# deployment fails). Measured convergence on kind is a few seconds; this is not an app timeout.
SMOKE_DEADLINE_SECONDS = 60
SMOKE_RETRY_INTERVAL_SECONDS = 2
SMOKE_REQUEST_TIMEOUT_SECONDS = 5
# kubectl errors keep their beginning (the cause, e.g. "field is immutable") and their end.
ERROR_HEAD_CHARS = 1500
ERROR_TAIL_CHARS = 1500
# (service, port, [(path, expected status)]). 401 proves the API router and auth are serving
# without needing a production credential for the smoke.
SMOKE_CHECKS: tuple[tuple[str, int, tuple[tuple[str, int], ...]], ...] = (
    ("asic-api", 8000, (("/livez", 200), ("/readyz", 200), ("/api/v1/incidents", 401))),
    ("asic-frontend", 3000, (("/livez", 200), ("/readyz", 200))),
)
# Deployment diagnostics come from kubectl, Postgres, containers and HTTP clients. These rules
# redact credential VALUES in the forms those tools print while keeping the field name, so the
# diagnostic stays useful. They are defensive, not a universal secret detector.
#
# Linear time (Phase 15): a scheme or key-name run may only START where the run starts
# (negative lookbehind), and runs are consumed possessively. Without that, every position
# inside a long unbroken run (``a.a.a...``, 20 KB of letters) restarted a scan to the end of
# the run: 7 s (DSN rule) and 51 s (key rule) for 20 KB were measured. Any match starting
# mid-run is also a match from the run start, so the redacted output is unchanged.
_SECRET_KEY = r"(?<![\w.-])[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host -> scheme://***@host (DSNs, also inside DATABASE_URL=...)
    (
        re.compile(r"(?i)((?<![a-z0-9+.-])(?>[a-z0-9+.-]*?[a-z][a-z0-9+.-]*+)://)[^/\s@]++@"),
        r"\1***@",
    ),
    # Authorization: Bearer|Basic|Token <credential>
    (
        re.compile(
            r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+)[^\s\"',;]+"
        ),
        r"\1***",
    ),
    # --password secret / --password=secret / --api-key "secret"
    (
        re.compile(
            r"(?i)(--(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)(?:=|\s+))"
            r"(?:\"[^\"]*\"|'[^']*'|\S+)"
        ),
        r"\1***",
    ),
    # key=value, key: value, "key": "value", PGPASSWORD="value", api_key=value
    (
        re.compile(rf"(?i)({_SECRET_KEY}[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&}}\]]+)"),
        r"\1***",
    ),
    # Bare credential shapes that CLIs sometimes echo without any key name (Phase 15): JWTs
    # (the first eyJ at a word boundary in a base64url run - the same linear construction as
    # the telemetry redaction), cloud access keys, API keys, chat and code-host tokens.
    (
        re.compile(
            r"(?<![A-Za-z0-9_-])(?>([A-Za-z0-9_-]*?)\beyJ[A-Za-z0-9_-]{10,}+)"
            r"\.[A-Za-z0-9_-]{10,}+\.[A-Za-z0-9_-]{10,}+"
        ),
        r"\1***",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "***"),
    (re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{16,}+"), "***"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}+"), "***"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}+|github_pat_[A-Za-z0-9_]{20,}+)"), "***"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}+"), "***"),
)


def _monotonic() -> float:
    """Default clock, resolved at CALL time (N-4).

    A default of ``time.monotonic`` would bind the real clock when this module is imported, so
    a test or mutant that forgets to inject a clock would wait out real deadlines (up to the
    600 s migration deadline). Looking ``time`` up per call lets a test replace ``time.sleep``
    once and turn any accidental real wait into an immediate failure.
    """
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class DeploymentError(RuntimeError):
    """The deployment stopped; the message says at which stage and why."""


class MigrationFailed(DeploymentError):
    """The migration Job reached Failed, or never completed within its deadline."""


class MigrationActive(DeploymentError):
    """A migration Job from another deployment is still running; it is never deleted."""


class RolloutFailed(DeploymentError):
    """An application Deployment did not become available."""


class SmokeFailed(DeploymentError):
    """A post-rollout check did not return the expected response."""


def redact(text: str) -> str:
    """Replace credential values (DSN passwords, key/value secrets, bearer tokens, CLI flags)."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def bounded(text: str, head: int = ERROR_HEAD_CHARS, tail: int = ERROR_TAIL_CHARS) -> str:
    """Redact, then keep the first ``head`` and last ``tail`` characters of long output."""
    text = redact(text)
    if len(text) <= head + tail:
        return text
    omitted = len(text) - head - tail
    return f"{text[:head]}\n...[{omitted} characters truncated]...\n{text[-tail:]}"


Runner = Callable[[Sequence[str], str | None, float], "subprocess.CompletedProcess[str]"]


def _subprocess_runner(
    command: Sequence[str], content: str | None, timeout: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        input=content,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


@dataclass
class Kubectl:
    """kubectl bound to one kubeconfig and namespace; every call is bounded."""

    namespace: str
    kubeconfig: str | None = None
    binary: str = "kubectl"
    runner: Runner = field(default=_subprocess_runner)

    def base(self) -> list[str]:
        command = [self.binary]
        if self.kubeconfig:
            command += ["--kubeconfig", self.kubeconfig]
        return [*command, "-n", self.namespace]

    def __call__(self, *args: str, content: str | None = None, timeout: float = 120) -> str:
        try:
            result = self.runner([*self.base(), *args], content, timeout)
        except subprocess.TimeoutExpired as error:
            raise DeploymentError(
                f"kubectl {' '.join(args[:2])} timed out after {timeout:.0f}s"
            ) from error
        if result.returncode:
            raise DeploymentError(f"kubectl {' '.join(args[:2])} failed: {bounded(result.stderr)}")
        return result.stdout

    def probe(self, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        """Like ``__call__`` but never raises; used for diagnostics and polling."""
        try:
            return self.runner([*self.base(), *args], None, timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(list(args), 124, "", "kubectl timed out")


@dataclass(frozen=True)
class JobOutcome:
    state: str  # "complete" | "failed" | "timeout" | "replaced" | "disappeared"
    elapsed_seconds: float
    diagnostics: str = ""


def job_state(job: dict[str, object]) -> str | None:
    """Terminal state of a Job object, or None while it is still running.

    ``FailureTarget`` is set as soon as the controller decides the Job failed (before pod
    termination finishes), so it is treated as failed to avoid waiting for cleanup.
    """
    status = job.get("status")
    conditions = status.get("conditions", []) if isinstance(status, dict) else []
    active = {
        c.get("type") for c in conditions if isinstance(c, dict) and c.get("status") == "True"
    }
    if active & {"Failed", "FailureTarget"}:
        return "failed"
    if "Complete" in active:
        return "complete"
    return None


def migration_diagnostics(kube: Kubectl, job: str = MIGRATION_JOB) -> str:
    """Bounded, redacted summary: Job conditions, pod states and a log tail."""
    lines: list[str] = []
    raw = kube.probe("get", "job", job, "-o", "json")
    if raw.returncode == 0:
        status = json.loads(raw.stdout).get("status", {})
        for condition in status.get("conditions", []):
            lines.append(
                "job condition: {type}={status} reason={reason} message={message}".format(
                    type=condition.get("type"),
                    status=condition.get("status"),
                    reason=condition.get("reason"),
                    message=condition.get("message"),
                )
            )
    pods = kube.probe("get", "pods", "-l", f"job-name={job}", "-o", "json")
    if pods.returncode == 0:
        for pod in json.loads(pods.stdout).get("items", []):
            name = pod["metadata"]["name"]
            lines.append(f"pod {name}: phase={pod.get('status', {}).get('phase')}")
            for container in pod.get("status", {}).get("containerStatuses", []):
                for state_name, state in container.get("state", {}).items():
                    lines.append(
                        f"  container {container.get('name')}: {state_name} "
                        f"reason={state.get('reason')} exitCode={state.get('exitCode')}"
                    )
            logs = kube.probe(
                "logs",
                name,
                f"--tail={LOG_TAIL_LINES}",
                f"--limit-bytes={LOG_LIMIT_BYTES}",
            )
            if logs.returncode == 0 and logs.stdout.strip():
                lines.append(f"  log tail ({LOG_TAIL_LINES} lines max):")
                lines.extend(f"    {line}" for line in logs.stdout.splitlines()[-LOG_TAIL_LINES:])
    return redact("\n".join(lines) or "no diagnostics available")


def _not_found(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode != 0 and "NotFound" in result.stderr


def _job_summary(job: dict[str, Any]) -> str:
    status = job.get("status") or {}
    conditions = ",".join(
        f"{c.get('type')}={c.get('status')}" for c in status.get("conditions") or []
    )
    return f"uid={(job.get('metadata') or {}).get('uid')} conditions=[{conditions or 'none'}]"


def clear_previous_migration(
    kube: Kubectl,
    job: str = MIGRATION_JOB,
    *,
    timeout: float = 180,
    interval: float = 2,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
    log: Callable[[str], None] = print,
) -> str:
    """Free the fixed Job name for this release, or fail closed.

    Returns "absent", "complete", "failed" (the previous Job's terminal state) or "deleting" (it
    was already being deleted by someone else; we only wait). A Job with no terminal condition and
    no deletionTimestamp is ACTIVE: raise MigrationActive and leave it running.
    """
    raw = kube.probe("get", "job", job, "-o", "json")
    if _not_found(raw):
        return "absent"
    if raw.returncode:
        raise DeploymentError(f"cannot inspect previous migration Job: {bounded(raw.stderr)}")
    previous = json.loads(raw.stdout)
    state = job_state(previous)
    summary = _job_summary(previous)
    uid = previous.get("metadata", {}).get("uid")
    terminating = bool(previous.get("metadata", {}).get("deletionTimestamp"))
    if state is None and not terminating:
        raise MigrationActive(
            f"migration Job {job} is still active ({summary}); another deployment may be "
            "migrating. Refusing to delete it or start a second migration."
        )
    if state is None:
        # Already being deleted by someone else (e.g. an interrupted deployment): it can never
        # complete, so wait for that deletion to finish. We never issue a delete for it.
        state = "deleting"
        log(f"previous migration Job is already being deleted ({summary}); waiting for it to go")
    else:
        log(
            f"previous migration Job is terminal ({state}; {summary}); removing it for this release"
        )
        if state == "failed":
            # Keep the earlier failure's evidence in this run's log before the object disappears.
            log("previous failed migration evidence:\n" + migration_diagnostics(kube, job))
        kube("delete", "job", job, "--cascade=foreground", "--wait=false", timeout=60)
    started = clock()
    while True:
        raw = kube.probe("get", "job", job, "-o", "json")
        if _not_found(raw):
            return state
        if raw.returncode == 0:
            current = json.loads(raw.stdout)
            if current.get("metadata", {}).get("uid") != uid:
                raise MigrationActive(f"migration Job {job} was replaced during cleanup")
        if clock() - started >= timeout:
            raise DeploymentError(
                f"previous migration Job {job} still exists {timeout:.0f}s after deletion "
                "(finalizer or controller delay); the replacement was NOT created"
            )
        sleep(interval)


def _running_migration_pods(pods: dict[str, Any]) -> list[str]:
    """Pods still able to run a migration: any phase other than Succeeded/Failed.

    A pod in a terminal phase runs no container, so it cannot overlap with a new migration;
    an orphaned finished pod therefore does not block (it would never disappear on its own).
    A pod that is terminating (``deletionTimestamp``) but still Running DOES block: its
    container may be inside a migration transaction for the whole grace period.
    """
    running: list[str] = []
    for pod in pods.get("items") or []:
        metadata = pod.get("metadata") or {}
        phase = (pod.get("status") or {}).get("phase")
        if phase in ("Succeeded", "Failed"):
            continue
        owner = next(
            (
                ref.get("uid")
                for ref in metadata.get("ownerReferences") or []
                if ref.get("kind") == "Job"
            ),
            None,
        )
        labels = metadata.get("labels") or {}
        controller = owner or labels.get("batch.kubernetes.io/controller-uid") or "orphaned"
        running.append(f"{metadata.get('name')} phase={phase} controller-uid={controller}")
    return running


def wait_for_migration_pods(
    kube: Kubectl,
    job: str = MIGRATION_JOB,
    *,
    timeout: float = 180,
    interval: float = 2,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
    log: Callable[[str], None] = print,
) -> None:
    """Block until no pod of ANY previous ``job`` is still running, or fail closed.

    The Job object disappearing does not mean its pods have stopped: a Job deleted with
    background propagation (or orphaned) vanishes at once while its pod is still inside the
    termination grace period, possibly mid-migration. Pods keep the ``job-name`` label (and
    their controller UID) after the Job is gone, so the check does not need the old UID and
    also covers a Job that was already absent when this deployment started. If a running
    pod remains after ``timeout`` the replacement is NOT created. A pod listing that fails is
    retried until the deadline and then also fails closed.
    """
    started = clock()
    last = "pod listing never succeeded"
    while True:
        raw = kube.probe("get", "pods", "-l", f"job-name={job}", "-o", "json")
        if raw.returncode == 0:
            running = _running_migration_pods(json.loads(raw.stdout))
            if not running:
                return
            last = "; ".join(running)
            log(f"waiting for previous migration pod(s) to stop: {last}")
        else:
            last = f"cannot list migration pods: {bounded(raw.stderr)}"
        if clock() - started >= timeout:
            raise DeploymentError(
                f"previous migration pod(s) still running {timeout:.0f}s after the Job slot was "
                f"freed ({last}); the replacement was NOT created"
            )
        sleep(interval)


def split_migration(manifest: str) -> tuple[str, str]:
    """Separate the one migration Job from its supporting objects (policies, secrets)."""
    documents = [doc for doc in yaml.safe_load_all(manifest) if isinstance(doc, dict)]
    jobs = [doc for doc in documents if doc.get("kind") == "Job"]
    if len(jobs) != 1 or jobs[0].get("metadata", {}).get("name") != MIGRATION_JOB:
        raise DeploymentError(f"migration manifest must contain exactly one Job {MIGRATION_JOB}")
    others = [doc for doc in documents if doc is not jobs[0]]
    supporting = yaml.safe_dump_all(others, sort_keys=False) if others else ""
    return yaml.safe_dump(jobs[0], sort_keys=False), supporting


def wait_for_job(
    kube: Kubectl,
    job: str = MIGRATION_JOB,
    *,
    uid: str | None = None,
    timeout: float = 600,
    interval: float = 2,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
) -> JobOutcome:
    """Poll until the Job is Complete or Failed; a known failure never waits for the timeout.

    With ``uid`` the result must come from that exact Job object, never a predecessor, and the
    Job vanishing before a terminal condition is itself terminal ("disappeared"). Other kubectl
    errors (API unavailable, timeouts) are transient and polled until ``timeout``.
    """
    started = clock()
    while True:
        raw = kube.probe("get", "job", job, "-o", "json")
        current = json.loads(raw.stdout) if raw.returncode == 0 else None
        state = job_state(current) if current is not None else None
        elapsed = clock() - started
        if uid and _not_found(raw):
            return JobOutcome(
                "disappeared", elapsed, f"Job {job} (uid={uid}) was deleted before finishing"
            )
        if current is not None and uid and current.get("metadata", {}).get("uid") != uid:
            return JobOutcome("replaced", elapsed, f"Job {job} is no longer the one created")
        if state == "complete":
            return JobOutcome("complete", elapsed)
        if state == "failed":
            return JobOutcome("failed", elapsed, migration_diagnostics(kube, job))
        if uid and current is not None and current.get("metadata", {}).get("deletionTimestamp"):
            # Being deleted (e.g. foreground cascade while pods terminate): it can no longer
            # complete, so treat it like a vanished Job instead of waiting out the grace period.
            return JobOutcome(
                "disappeared", elapsed, f"Job {job} (uid={uid}) is being deleted before finishing"
            )
        if elapsed >= timeout:
            return JobOutcome("timeout", elapsed, migration_diagnostics(kube, job))
        sleep(min(interval, max(timeout - elapsed, 0)))


def deployments_in(manifest: str) -> list[str]:
    return [
        doc["metadata"]["name"]
        for doc in yaml.safe_load_all(manifest)
        if isinstance(doc, dict) and doc.get("kind") == "Deployment"
    ]


def http_status(url: str, timeout: float = SMOKE_REQUEST_TIMEOUT_SECONDS) -> int:
    request = urllib.request.Request(url, headers={"accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise SmokeFailed(f"{url} unreachable: {error}") from error


@contextlib.contextmanager
def port_forward(
    kube: Kubectl, target: str, port: int, *, ready_timeout: float = 30
) -> Iterator[int]:
    """Forward a random loopback port to a Service. kubectl tunnels into the pod network
    namespace, so this needs no NetworkPolicy exception and no public DNS/TLS."""
    process = subprocess.Popen(
        [*kube.base(), "port-forward", target, f"0:{port}", "--address", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines: queue.Queue[str] = queue.Queue()
    assert process.stdout is not None
    stream = process.stdout
    threading.Thread(target=lambda: [lines.put(line) for line in stream], daemon=True).start()
    try:
        deadline = time.monotonic() + ready_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.poll() is not None:
                raise SmokeFailed(f"port-forward to {target} did not start")
            try:
                match = re.search(r"127\.0\.0\.1:(\d+)", lines.get(timeout=min(remaining, 1)))
            except queue.Empty:
                continue
            if match:
                yield int(match.group(1))
                return
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def ready_endpoints(kube: Kubectl, service: str) -> int:
    slices = json.loads(
        kube("get", "endpointslices", "-l", f"kubernetes.io/service-name={service}", "-o", "json")
    )
    return sum(
        1
        for item in slices.get("items", [])
        for endpoint in item.get("endpoints") or []
        if (endpoint.get("conditions") or {}).get("ready") is True
    )


Forwarder = Callable[[Kubectl, str, int], contextlib.AbstractContextManager[int]]


def converge(
    name: str,
    attempt: Callable[[], None],
    *,
    deadline: float = SMOKE_DEADLINE_SECONDS,
    interval: float = SMOKE_RETRY_INTERVAL_SECONDS,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
    log: Callable[[str], None] = print,
) -> int:
    """Run ``attempt`` until it stops raising SmokeFailed or ``deadline`` expires.

    Returns the number of attempts used. Only SmokeFailed is retried (any other error is a real
    failure); the last failure is reported, redacted, when the deadline expires.
    """
    started = clock()
    attempts = 0
    while True:
        attempts += 1
        try:
            attempt()
        except SmokeFailed as error:
            elapsed = clock() - started
            if elapsed >= deadline:
                raise SmokeFailed(
                    f"{name} did not converge within {deadline:.0f}s after {attempts} attempts; "
                    f"last error: {bounded(str(error))}"
                ) from error
            log(
                f"smoke {name} not converged yet (attempt {attempts}, {elapsed:.1f}s): "
                f"{bounded(str(error))}"
            )
            sleep(min(interval, max(deadline - elapsed, 0)))
            continue
        if attempts > 1:
            log(f"smoke {name} converged after {attempts} attempts ({clock() - started:.1f}s)")
        return attempts


def post_rollout_smoke(
    kube: Kubectl,
    *,
    forward: Forwarder = port_forward,
    fetch: Callable[[str], int] = http_status,
    log: Callable[[str], None] = print,
    deadline: float = SMOKE_DEADLINE_SECONDS,
    interval: float = SMOKE_RETRY_INTERVAL_SECONDS,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
) -> None:
    """Every check must pass within the convergence allowance or the deployment fails.

    Each service is checked as a unit (ready endpoints, then every path through one fresh
    port-forward) and retried as a unit, so a forward bound to a terminating pod is replaced.
    No credential is used.
    """
    for service, port, checks in SMOKE_CHECKS:

        def attempt(service: str = service, port: int = port, checks: tuple = checks) -> None:  # type: ignore[type-arg]
            try:
                ready = ready_endpoints(kube, service)
            except DeploymentError as error:  # transient API error: retry within the allowance
                raise SmokeFailed(f"service {service} endpoints unavailable: {error}") from error
            if ready < 1:
                raise SmokeFailed(f"service {service} has no ready endpoints")
            with forward(kube, f"svc/{service}", port) as local_port:
                for path, expected in checks:
                    status = fetch(f"http://127.0.0.1:{local_port}{path}")
                    if status != expected:
                        raise SmokeFailed(f"{service}{path}: expected {expected}, got {status}")
            for path, expected in checks:
                log(f"smoke {service}{path}: {expected}")

        converge(
            service,
            attempt,
            deadline=deadline,
            interval=interval,
            clock=clock,
            sleep=sleep,
            log=log,
        )


def run_deployment(
    kube: Kubectl,
    migration: str,
    application: str,
    *,
    migration_timeout: float = 600,
    rollout_timeout: float = 600,
    pod_timeout: float = 180,
    poll_interval: float = 2,
    smoke: Callable[[Kubectl], None] = post_rollout_smoke,
    log: Callable[[str], None] = print,
    clock: Callable[[], float] = _monotonic,
    sleep: Callable[[float], None] = _sleep,
    after_migration: Callable[[Kubectl], None] | None = None,
) -> JobOutcome:
    """Run the one authoritative migrate-then-rollout sequence. Raises on any failure.

    ``after_migration`` runs only after the migration succeeded and before any application
    manifest is applied: the place for release registration (for example the behaviour version
    the worker will run as), which needs the new schema but must precede the rollout.
    """
    job_manifest, supporting = split_migration(migration)
    kube("apply", "--dry-run=server", "-f", "-", content=application)
    if supporting:
        kube("apply", "--dry-run=server", "-f", "-", content=supporting)
    previous = clear_previous_migration(
        kube, interval=poll_interval, clock=clock, sleep=sleep, log=log
    )
    log(f"migration Job slot free (previous: {previous})")
    # The Job object being gone is not enough: its pods may still be terminating (Phase 15).
    wait_for_migration_pods(
        kube, timeout=pod_timeout, interval=poll_interval, clock=clock, sleep=sleep, log=log
    )
    # Validated only now: a Job pod template is immutable, so validating the new Job against a
    # predecessor with the same name would fail on any template change.
    kube("apply", "--dry-run=server", "-f", "-", content=job_manifest)
    if supporting:
        kube("apply", "-f", "-", content=supporting)
    uid = kube("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", content=job_manifest).strip()
    log(f"migration Job created (uid={uid}); waiting for a terminal state")
    outcome = wait_for_job(
        kube,
        uid=uid,
        timeout=migration_timeout,
        interval=poll_interval,
        clock=clock,
        sleep=sleep,
    )
    log(f"migration {outcome.state} after {outcome.elapsed_seconds:.1f}s")
    if outcome.state != "complete":  # migration-success guard
        raise MigrationFailed(
            f"migration {outcome.state}; application manifests were NOT applied\n"
            f"{outcome.diagnostics}"
        )
    if after_migration is not None:
        after_migration(kube)
        log("post-migration release registration done")
    kube("apply", "-f", "-", content=application)
    for name in deployments_in(application):
        try:
            kube(
                "rollout",
                "status",
                f"deployment/{name}",
                f"--timeout={int(rollout_timeout)}s",
                timeout=rollout_timeout + 30,
            )
        except (DeploymentError, subprocess.TimeoutExpired) as error:
            raise RolloutFailed(f"deployment/{name} did not become available: {error}") from error
        log(f"deployment/{name} rolled out")
    smoke(kube)
    log("post-rollout smoke passed")
    return outcome


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default="asic-system")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--migration-timeout", type=float, default=600)
    parser.add_argument("--rollout-timeout", type=float, default=600)
    parser.add_argument(
        "--smoke-deadline",
        type=float,
        default=SMOKE_DEADLINE_SECONDS,
        help="deployment convergence allowance for the post-rollout smoke (seconds)",
    )
    args = parser.parse_args(argv)
    kube = Kubectl(args.namespace, args.kubeconfig)
    try:
        run_deployment(
            kube,
            args.migration.read_text("utf-8"),
            args.application.read_text("utf-8"),
            migration_timeout=args.migration_timeout,
            rollout_timeout=args.rollout_timeout,
            smoke=lambda kube_: post_rollout_smoke(kube_, deadline=args.smoke_deadline),
        )
    except DeploymentError as error:
        print(f"DEPLOYMENT FAILED: {error}", file=sys.stderr)
        print(
            "Database downgrade is never automatic. Re-dispatch the previously attested digests "
            "only after confirming schema compatibility (see PHASE14_DEPLOYMENT.md).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
