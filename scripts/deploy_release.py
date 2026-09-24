#!/usr/bin/env python3
"""Authoritative deployment sequence: migrate -> guard -> roll out -> post-rollout smoke.

This is the ONLY implementation of the ordering. The production workflow (deploy.yml) and the
disposable-kind smoke (deployment_smoke.py) both call ``run_deployment``, so the ordering that is
tested locally is the ordering that runs in production.

1. server-side dry-run of both rendered manifests;
2. replace the one-shot migration Job and watch it until Complete, Failed or timeout;
3. on anything but Complete: record bounded, redacted diagnostics and stop (application manifests
   are never applied);
4. apply the application manifest and wait for every Deployment rollout;
5. probe backend and frontend health plus an unauthenticated API refusal through the Services.

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

import yaml

MIGRATION_JOB = "asic-migration"
LOG_TAIL_LINES = 40
LOG_LIMIT_BYTES = 8000
# (service, port, [(path, expected status)]). 401 proves the API router and auth are serving
# without needing a production credential for the smoke.
SMOKE_CHECKS: tuple[tuple[str, int, tuple[tuple[str, int], ...]], ...] = (
    ("asic-api", 8000, (("/livez", 200), ("/readyz", 200), ("/api/v1/incidents", 401))),
    ("asic-frontend", 3000, (("/livez", 200), ("/readyz", 200))),
)
_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|pwd|secret|token)=\S+")


class DeploymentError(RuntimeError):
    """The deployment stopped; the message says at which stage and why."""


class MigrationFailed(DeploymentError):
    """The migration Job reached Failed, or never completed within its deadline."""


class RolloutFailed(DeploymentError):
    """An application Deployment did not become available."""


class SmokeFailed(DeploymentError):
    """A post-rollout check did not return the expected response."""


def redact(text: str) -> str:
    """Strip URL credentials and ``key=value`` secrets from operator diagnostics."""
    return _SECRET_ASSIGNMENT.sub(r"\1=***", _USERINFO.sub(r"\1***@", text))


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
        result = self.runner([*self.base(), *args], content, timeout)
        if result.returncode:
            raise DeploymentError(
                f"kubectl {' '.join(args[:2])} failed: {redact(result.stderr[-2000:])}"
            )
        return result.stdout

    def probe(self, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        """Like ``__call__`` but never raises; used for diagnostics and polling."""
        try:
            return self.runner([*self.base(), *args], None, timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(list(args), 124, "", "kubectl timed out")


@dataclass(frozen=True)
class JobOutcome:
    state: str  # "complete" | "failed" | "timeout"
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


def wait_for_job(
    kube: Kubectl,
    job: str = MIGRATION_JOB,
    *,
    timeout: float = 600,
    interval: float = 2,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> JobOutcome:
    """Poll until the Job is Complete or Failed; a known failure never waits for the timeout."""
    started = clock()
    while True:
        raw = kube.probe("get", "job", job, "-o", "json")
        state = job_state(json.loads(raw.stdout)) if raw.returncode == 0 else None
        elapsed = clock() - started
        if state == "complete":
            return JobOutcome("complete", elapsed)
        if state == "failed":
            return JobOutcome("failed", elapsed, migration_diagnostics(kube, job))
        if elapsed >= timeout:
            return JobOutcome("timeout", elapsed, migration_diagnostics(kube, job))
        sleep(min(interval, max(timeout - elapsed, 0)))


def deployments_in(manifest: str) -> list[str]:
    return [
        doc["metadata"]["name"]
        for doc in yaml.safe_load_all(manifest)
        if isinstance(doc, dict) and doc.get("kind") == "Deployment"
    ]


def http_status(url: str, timeout: float = 5) -> int:
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


def post_rollout_smoke(
    kube: Kubectl,
    *,
    forward: Forwarder = port_forward,
    fetch: Callable[[str], int] = http_status,
    log: Callable[[str], None] = print,
) -> None:
    """Every check must pass or the deployment fails. No credential is used."""
    for service, port, checks in SMOKE_CHECKS:
        if ready_endpoints(kube, service) < 1:
            raise SmokeFailed(f"service {service} has no ready endpoints")
        with forward(kube, f"svc/{service}", port) as local_port:
            for path, expected in checks:
                status = fetch(f"http://127.0.0.1:{local_port}{path}")
                if status != expected:
                    raise SmokeFailed(f"{service}{path}: expected {expected}, got {status}")
                log(f"smoke {service}{path}: {status}")


def run_deployment(
    kube: Kubectl,
    migration: str,
    application: str,
    *,
    migration_timeout: float = 600,
    rollout_timeout: float = 600,
    poll_interval: float = 2,
    smoke: Callable[[Kubectl], None] = post_rollout_smoke,
    log: Callable[[str], None] = print,
) -> JobOutcome:
    """Run the one authoritative migrate-then-rollout sequence. Raises on any failure."""
    kube("apply", "--dry-run=server", "-f", "-", content=migration)
    kube("apply", "--dry-run=server", "-f", "-", content=application)
    # Foreground cascade: old migration pods must be gone so diagnostics describe this run only.
    kube(
        "delete",
        "job",
        MIGRATION_JOB,
        "--ignore-not-found",
        "--cascade=foreground",
        "--wait=true",
        timeout=180,
    )
    kube("apply", "-f", "-", content=migration)
    log("migration Job applied; waiting for a terminal state")
    outcome = wait_for_job(kube, timeout=migration_timeout, interval=poll_interval)
    log(f"migration {outcome.state} after {outcome.elapsed_seconds:.1f}s")
    if outcome.state != "complete":  # migration-success guard
        raise MigrationFailed(
            f"migration {outcome.state}; application manifests were NOT applied\n"
            f"{outcome.diagnostics}"
        )
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
    args = parser.parse_args(argv)
    kube = Kubectl(args.namespace, args.kubeconfig)
    try:
        run_deployment(
            kube,
            args.migration.read_text("utf-8"),
            args.application.read_text("utf-8"),
            migration_timeout=args.migration_timeout,
            rollout_timeout=args.rollout_timeout,
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
