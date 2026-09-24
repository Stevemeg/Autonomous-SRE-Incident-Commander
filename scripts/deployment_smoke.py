#!/usr/bin/env python3
"""Deploy the supplied production artifacts to a disposable kind cluster.

No image is rebuilt here. Terraform state, kubeconfigs and rendered manifests live
in a temporary directory. The cluster is destroyed even when a validation fails.

Migration and rollout go through ``deploy_release.run_deployment``: the same authoritative
sequence the production workflow runs, not a parallel copy of it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from types import ModuleType

import yaml
from deploy_release import (
    MIGRATION_JOB,
    Kubectl,
    MigrationActive,
    MigrationFailed,
    SmokeFailed,
    http_status,
    job_state,
    port_forward,
    post_rollout_smoke,
    ready_endpoints,
    run_deployment,
)

REPO = Path(__file__).resolve().parents[1]
HELM = "alpine/helm@sha256:aef9b56f64e866207d9591d0abd8f6d767b36aadd12edf68f8a719716d9d29c9"
CILIUM_SHA256 = "b2afd87b7f75f875f92a14559f14f59b7babbb479d968e3fd625a20bf30ec20e"
NODE = "kindest/node@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
TERRAFORM = (
    "hashicorp/terraform@sha256:dfb1889a8ee74ada3ddacc48f89b8a0d69f3e114de3d8a2ce15f6a8d3dbfdbe2"
)
NAMESPACE = "asic-system"
GUARD = 'if outcome.state != "complete":  # migration-success guard'
FAST_FAILURE_SECONDS = 180  # far below the 600s migration deadline


def run_process(
    *command: str, timeout: int = 600, content: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO,
        input=content,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def run(*command: str, timeout: int = 600, content: str | None = None) -> str:
    result = run_process(*command, timeout=timeout, content=content)
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} {command[1:3]} failed: {result.stderr[-4000:]} {result.stdout[-4000:]}"
        )
    return result.stdout


def step(message: str) -> None:
    print(f"== {message}", flush=True)


def mutated_orchestrator(scratch: Path) -> ModuleType:
    """Outside-repo copy of deploy_release with the migration-success guard disabled."""
    source = (REPO / "scripts/deploy_release.py").read_text("utf-8")
    if source.count(GUARD) != 1:
        raise RuntimeError("migration-success guard marker not found exactly once")
    path = scratch / "deploy_release_mutated.py"
    path.write_text(source.replace(GUARD, "if False:  # MUTATED: guard bypassed"), "utf-8")
    spec = importlib.util.spec_from_file_location("deploy_release_mutated", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load mutated orchestrator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclass annotation resolution needs the module
    spec.loader.exec_module(module)
    return module


def recording(kube: Kubectl) -> tuple[Kubectl, list[tuple[list[str], str | None]]]:
    """Same kubectl, but every command (and stdin manifest) is recorded for evidence."""
    calls: list[tuple[list[str], str | None]] = []
    inner = kube.runner

    def runner(
        command: object, content: str | None, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        calls.append((list(command), content))  # type: ignore[call-overload]
        return inner(command, content, timeout)  # type: ignore[arg-type]

    return Kubectl(kube.namespace, kube.kubeconfig, kube.binary, runner), calls


def job_created(calls: list[tuple[list[str], str | None]]) -> int:
    """Number of migration Jobs the orchestrator actually created (not dry-run)."""
    return sum(1 for args, _ in calls if "create" in args and "--dry-run=server" not in args)


def job_deleted(calls: list[tuple[list[str], str | None]]) -> bool:
    return any("delete" in args and "job" in args for args, _ in calls)


def applied(calls: list[tuple[list[str], str | None]], manifest: str) -> bool:
    return any(
        "apply" in args and "--dry-run=server" not in args and content == manifest
        for args, content in calls
    )


def migration_variant(migration: str, release: str, command: list[str] | None = None) -> str:
    """Same migration manifest with a changed Job pod template (as a new release would have)."""
    documents = [doc for doc in yaml.safe_load_all(migration) if doc]
    for doc in documents:
        if doc["kind"] == "Job":
            template = doc["spec"]["template"]
            template.setdefault("metadata", {}).setdefault("annotations", {})["asic/release"] = (
                release
            )
            if command:
                template["spec"]["containers"][0]["command"] = command
    return yaml.safe_dump_all(documents, sort_keys=False)


def job_uid_and_state(kube: Kubectl) -> tuple[str, str | None]:
    job = json.loads(kube("get", "job", MIGRATION_JOB, "-o", "json"))
    return job["metadata"]["uid"], job_state(job)


def redeployment_matrix(kube: Kubectl, migration: str, application: str) -> dict[str, object]:
    """N-1: a lingering terminal migration Job must never block the next release."""
    python = "/usr/local/bin/python"
    results: dict[str, object] = {}

    def deploy(name: str, manifest: str) -> list[tuple[list[str], str | None]]:
        recorder, calls = recording(kube)
        begun = time.monotonic()
        logs: list[str] = []
        outcome = run_deployment(
            recorder,
            manifest,
            application_variant(application, name),
            poll_interval=1,
            log=lambda line: (logs.append(line), print(line, flush=True)),
        )
        uid, state = job_uid_and_state(kube)
        results[name] = {
            "seconds": round(time.monotonic() - begun, 1),
            "migration": outcome.state,
            "old_job_deleted": job_deleted(calls),
            "job_uid": uid,
            "job_state": state,
            "api_rolled": True,
            "smoke_retries": sum("not converged yet" in line for line in logs),
            "smoke": "passed",
        }
        return calls

    before, _ = job_uid_and_state(kube)
    deploy("B_same_release_again", migration)
    if job_uid_and_state(kube)[0] == before:
        raise RuntimeError("same-release redeploy did not replace the terminal Job")
    deploy("C_changed_template_over_complete_job", migration_variant(migration, "release-b"))

    recorder, calls = recording(kube)
    begun = time.monotonic()
    try:
        run_deployment(
            recorder,
            migration_variant(migration, "release-c", [python, "-c", "raise SystemExit(7)"]),
            application,
            poll_interval=1,
        )
    except MigrationFailed:
        pass
    else:
        raise RuntimeError("failing migration C did not stop the deployment")
    if applied(calls, application) or job_uid_and_state(kube)[1] != "failed":
        raise RuntimeError("failed migration C applied the application or is not Failed")
    results["D1_failed_migration_changed_template"] = {
        "seconds": round(time.monotonic() - begun, 1),
        "old_job_deleted": job_deleted(calls),
        "application_applied": False,
        "job_state": "failed",
    }
    deploy("D2_fix_forward_over_failed_job", migration_variant(migration, "release-d"))

    # Delete-wait: hold the terminal Job with a finalizer; the replacement must not be created
    # until Kubernetes has actually removed it.
    kube(
        "patch",
        "job",
        MIGRATION_JOB,
        "--type=merge",
        "-p",
        '{"metadata":{"finalizers":["asic.smoke/hold"]}}',
    )
    released: list[float] = []

    def release() -> None:
        time.sleep(20)
        released.append(time.monotonic())
        kube(
            "patch",
            "job",
            MIGRATION_JOB,
            "--type=json",
            "-p",
            '[{"op":"remove","path":"/metadata/finalizers"}]',
        )

    holder = threading.Thread(target=release)
    holder.start()
    recorder, calls = recording(kube)
    created_at: list[float] = []
    inner = recorder.runner

    def timed(command: object, content: str | None, timeout: float) -> object:
        if "create" in command and "--dry-run=server" not in command:  # type: ignore[operator]
            created_at.append(time.monotonic())
        return inner(command, content, timeout)  # type: ignore[arg-type]

    begun = time.monotonic()
    run_deployment(
        Kubectl(kube.namespace, kube.kubeconfig, kube.binary, timed),  # type: ignore[arg-type]
        migration_variant(migration, "release-f"),
        application,
        poll_interval=1,
    )
    holder.join()
    if not created_at or created_at[0] < released[0]:
        raise RuntimeError("replacement Job was created before the old Job was gone")
    results["F_delete_wait_with_finalizer"] = {
        "seconds": round(time.monotonic() - begun, 1),
        "created_after_release_seconds": round(created_at[0] - released[0], 1),
    }

    # Active collision: a still-running migration must never be deleted or duplicated.
    kube("delete", "job", MIGRATION_JOB, "--cascade=foreground", "--wait=true", timeout=180)
    active = next(
        doc
        for doc in yaml.safe_load_all(
            migration_variant(migration, "active", [python, "-c", "import time; time.sleep(900)"])
        )
        if doc and doc["kind"] == "Job"
    )
    active_uid = kube(
        "create", "-f", "-", "-o", "jsonpath={.metadata.uid}", content=yaml.safe_dump(active)
    ).strip()
    recorder, calls = recording(kube)
    try:
        run_deployment(recorder, migration_variant(migration, "release-e"), application)
    except MigrationActive as error:
        refusal = str(error)
    else:
        raise RuntimeError("deployment proceeded over an active migration")
    uid, state = job_uid_and_state(kube)
    if uid != active_uid or state is not None:
        raise RuntimeError("active migration Job was deleted, replaced or stopped")
    if job_deleted(calls) or job_created(calls) or applied(calls, application):
        raise RuntimeError("deployment touched the active migration or applied the app")
    results["E_active_migration_collision"] = {
        "refused": refusal[:160],
        "active_job_untouched": True,
        "application_applied": False,
    }
    kube("delete", "job", MIGRATION_JOB, "--cascade=foreground", "--wait=true", timeout=180)
    deploy("G_recovery_after_collision", migration_variant(migration, "release-g"))

    # LOW-2: our migration Job deleted externally while the watcher waits on its UID.
    def delete_soon(command: object, content: str | None, timeout: float) -> object:
        result = kube.runner(command, content, timeout)  # type: ignore[arg-type]
        if "create" in command and "--dry-run=server" not in command:  # type: ignore[operator]
            threading.Timer(
                5,
                lambda: kube.probe("delete", "job", MIGRATION_JOB, "--cascade=foreground"),
            ).start()
        return result

    begun = time.monotonic()
    try:
        run_deployment(
            Kubectl(kube.namespace, kube.kubeconfig, kube.binary, delete_soon),  # type: ignore[arg-type]
            migration_variant(
                migration, "release-j", [python, "-c", "import time; time.sleep(900)"]
            ),
            application,
            poll_interval=1,
        )
    except MigrationFailed as error:
        if "migration disappeared" not in str(error):
            raise
    else:
        raise RuntimeError("deleted migration Job did not fail the deployment")
    vanished_after = round(time.monotonic() - begun, 1)
    if vanished_after > 30:
        raise RuntimeError(f"deleted Job detected only after {vanished_after}s")
    results["J_job_deleted_mid_wait"] = {"failed_after_seconds": vanished_after}

    # M-1 non-vacuity: a release whose API never becomes ready must still fail the smoke after
    # the bounded convergence allowance (rollout passes because readiness is pointed at /livez).
    broken = [doc for doc in yaml.safe_load_all(application_variant(application, "broken")) if doc]
    for doc in broken:
        if doc["kind"] == "Secret" and doc["metadata"]["name"] == "asic-runtime-database":
            doc.pop("stringData", None)
            doc["data"] = {
                "url": base64.b64encode(
                    b"postgresql+psycopg2://asic_nobody@postgres:5432/asic"
                ).decode("ascii")
            }
        if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "asic-api":
            doc["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"][
                "path"
            ] = "/livez"
    begun = time.monotonic()
    try:
        run_deployment(
            kube,
            migration_variant(migration, "release-k"),
            yaml.safe_dump_all(broken, sort_keys=False),
            poll_interval=1,
        )
    except SmokeFailed as error:
        if "did not converge within" not in str(error):
            raise
        failure = str(error).splitlines()[0][:200]
    else:
        raise RuntimeError("never-ready API release passed the post-rollout smoke")
    results["K_api_never_ready"] = {
        "failed_after_seconds": round(time.monotonic() - begun, 1),
        "failure": failure,
    }
    deploy("L_recovery_after_broken_release", migration_variant(migration, "release-l"))
    return results


def application_variant(application: str, release: str) -> str:
    """Same application with a changed asic-api pod template, so every redeploy rolls the API
    (old pods terminate while new ones become ready: the M-1 convergence window)."""
    documents = [doc for doc in yaml.safe_load_all(application) if doc]
    for doc in documents:
        if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "asic-api":
            template = doc["spec"]["template"]
            template.setdefault("metadata", {}).setdefault("annotations", {})["asic/release"] = (
                release
            )
    return yaml.safe_dump_all(documents, sort_keys=False)


def deployment_exists(kube: Kubectl, name: str) -> bool:
    return kube.probe("get", "deployment", name).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--kind", default="kind")
    parser.add_argument("--name", default="asic-delivery-smoke")
    args = parser.parse_args()
    if not args.name.startswith("asic-") or not args.name.replace("-", "").isalnum():
        parser.error("cluster name must be a task-specific asic-* name")
    existing = run(args.kind, "get", "clusters").splitlines()
    if args.name in existing:
        parser.error("refusing to reuse or delete an existing cluster")
    image_ids = {
        image: run("docker", "image", "inspect", image, "--format", "{{.Id}}").strip()
        for image in (args.backend, args.frontend)
    }
    evidence: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="asic-deployment-") as directory:
        scratch = Path(directory)
        config = scratch / "kubeconfig"
        kind_config = scratch / "kind.yaml"
        kind_config.write_text(
            yaml.safe_dump(
                {
                    "kind": "Cluster",
                    "apiVersion": "kind.x-k8s.io/v1alpha4",
                    "networking": {"disableDefaultCNI": True},
                    "nodes": [{"role": "control-plane"}],
                }
            ),
            "utf-8",
        )
        kube = Kubectl(NAMESPACE, str(config))
        kubectl = ["kubectl", "--kubeconfig", str(config)]
        platform = scratch / "platform"
        platform.mkdir()
        for path in (REPO / "infra/terraform/platform").iterdir():
            if path.suffix == ".tf" or path.name == ".terraform.lock.hcl":
                shutil.copy2(path, platform / path.name)
        terraform = [
            "docker",
            "run",
            "--rm",
            "--network",
            "kind",
            "-v",
            f"{scratch}:/work",
            "-w",
            "/work/platform",
            TERRAFORM,
        ]
        tf_vars = [
            "-var=kubeconfig_path=/work/internal-kubeconfig",
            f"-var=kube_context=kind-{args.name}",
        ]
        created = False
        try:
            created = True
            step("Creating disposable Kubernetes 1.34.0 cluster")
            run(
                args.kind,
                "create",
                "cluster",
                "--name",
                args.name,
                "--kubeconfig",
                str(config),
                "--image",
                NODE,
                "--config",
                str(kind_config),
                "--wait",
                "120s",
            )
            # Terraform connects over the isolated Docker kind network. The cluster's
            # generated CA and client identity remain in this temporary directory.
            internal = yaml.safe_load(config.read_text("utf-8"))
            cluster = internal["clusters"][0]["cluster"]
            cluster["server"] = f"https://{args.name}-control-plane:6443"
            cluster["tls-server-name"] = f"{args.name}-control-plane"
            (scratch / "internal-kubeconfig").write_text(yaml.safe_dump(internal), "utf-8")
            with urllib.request.urlopen(
                "https://helm.cilium.io/cilium-1.20.2.tgz", timeout=60
            ) as response:
                chart = response.read()
            if hashlib.sha256(chart).hexdigest() != CILIUM_SHA256:
                raise RuntimeError("Cilium chart checksum mismatch")
            (scratch / "cilium.tgz").write_bytes(chart)
            step("Installing checksum-pinned Cilium 1.20.2 for policy enforcement")
            run(
                "docker",
                "run",
                "--rm",
                "--network",
                "kind",
                "-v",
                f"{scratch}:/work",
                HELM,
                "install",
                "cilium",
                "/work/cilium.tgz",
                "--kubeconfig",
                "/work/internal-kubeconfig",
                "--namespace",
                "kube-system",
                "--set",
                "ipam.mode=kubernetes",
                "--set",
                "operator.replicas=1",
                "--set",
                "envoy.enabled=false",
                "--wait",
                "--timeout",
                "5m",
            )

            step("Terraform: namespace, Pod Security Admission labels, service accounts")
            run(*terraform, "init", "-backend=false", "-lockfile=readonly")
            run(*terraform, "validate")
            print(run(*terraform, "apply", "-auto-approve", *tf_vars), flush=True)
            # -detailed-exitcode returns 2 on drift, which run() treats as failure.
            run(*terraform, "plan", "-detailed-exitcode", *tf_vars)
            labels = json.loads(run(*kubectl, "get", "namespace", NAMESPACE, "-o", "json"))[
                "metadata"
            ]["labels"]
            psa = {k: v for k, v in labels.items() if k.startswith("pod-security.kubernetes.io/")}
            expected_psa = {
                f"pod-security.kubernetes.io/{mode}{suffix}": value
                for mode in ("enforce", "audit", "warn")
                for suffix, value in (("", "restricted"), ("-version", "v1.34"))
            }
            if psa != expected_psa:
                raise RuntimeError(f"namespace PSA labels are not restricted/v1.34: {psa}")
            evidence["psa_labels"] = psa
            print(run(*kubectl, "get", "namespace", NAMESPACE, "--show-labels"), flush=True)

            step("PSA: a privileged, root, host-namespace pod must be rejected at admission")
            privileged = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "psa-privileged-probe", "namespace": NAMESPACE},
                "spec": {
                    "hostNetwork": True,
                    "hostPID": True,
                    "containers": [
                        {
                            "name": "probe",
                            "image": args.backend,
                            "securityContext": {
                                "privileged": True,
                                "runAsUser": 0,
                                "capabilities": {"add": ["NET_ADMIN", "SYS_ADMIN"]},
                            },
                        }
                    ],
                },
            }
            rejected = run_process(*kubectl, "apply", "-f", "-", content=yaml.safe_dump(privileged))
            if rejected.returncode == 0 or "violates PodSecurity" not in rejected.stderr:
                raise RuntimeError(f"privileged pod was not rejected: {rejected.stderr}")
            if kube.probe("get", "pod", "psa-privileged-probe").returncode == 0:
                raise RuntimeError("rejected privileged pod exists")
            evidence["privileged_pod"] = rejected.stderr.strip().splitlines()[-1][:300]
            print(evidence["privileged_pod"], flush=True)

            step("Renderer: CIDRs that collectively cover 0.0.0.0/0 are refused pre-deploy")
            bad_config = scratch / "full-egress.json"
            bad_config.write_text(
                json.dumps(
                    {
                        "hostname": "asic.example.com",
                        "ingress_class": "nginx",
                        "ingress_namespace": "ingress-nginx",
                        "tls_secret": "asic-tls",
                        "db_cidr": "10.20.0.12/32",
                        "issuer": "https://id.example.com",
                        "audience": "asic",
                        "jwks_url": "https://id.example.com/jwks",
                        "otlp_endpoint": "https://collector.example.com",
                        "https_egress_cidrs": ["0.0.0.0/1", "128.0.0.0/1"],
                    }
                ),
                "utf-8",
            )
            digest = "@sha256:" + "a" * 64
            refused = run_process(
                sys.executable,
                "scripts/render_deployment.py",
                "--config",
                str(bad_config),
                "--backend",
                "ghcr.io/example/asic-backend" + digest,
                "--frontend",
                "ghcr.io/example/asic-frontend" + digest,
                "--output",
                str(scratch / "never-rendered"),
            )
            if refused.returncode == 0 or "collectively permits unrestricted" not in refused.stderr:
                raise RuntimeError("combined full-egress CIDR set was not refused")
            if (scratch / "never-rendered").exists():
                raise RuntimeError("refused configuration still produced manifests")
            evidence["cidr_union"] = "refused_before_render"

            for image in (args.backend, args.frontend):
                run(args.kind, "load", "docker-image", "--name", args.name, image)

            def render(overlay: str) -> str:
                text = run(*kubectl, "kustomize", f"deploy/kubernetes/{overlay}")
                return text.replace("asic-backend:phase14-local", args.backend).replace(
                    "asic-frontend:phase14-local", args.frontend
                )

            database = render("overlays/local-database")
            run(*kubectl, "apply", "-f", "-", content=database)
            kube("rollout", "status", "deployment/postgres", "--timeout=180s", timeout=240)
            migration = render("overlays/local-migration")
            application = render("overlays/local")
            for manifest in (migration, application):
                dry = run_process(
                    *kubectl, "apply", "--dry-run=server", "-f", "-", content=manifest
                )
                if dry.returncode or "PodSecurity" in dry.stderr:
                    raise RuntimeError(f"workloads not admitted under restricted: {dry.stderr}")
            evidence["restricted_workloads_admitted"] = True

            # Bad credential: the real migration Job, pointed at a role that does not exist.
            documents = list(yaml.safe_load_all(migration))
            secrets = [
                doc
                for doc in documents
                if doc
                and doc["kind"] == "Secret"
                and doc["metadata"]["name"] == "asic-migration-database"
            ]
            if len(secrets) != 1:
                raise RuntimeError("could not construct the bad-credential migration")
            secrets[0]["data"]["url"] = base64.b64encode(
                b"postgresql+psycopg2://asic_nobody@postgres:5432/asic"
            ).decode("ascii")
            bad_migration = yaml.safe_dump_all(documents, sort_keys=False)

            step("Authoritative sequence with a failing migration (real orchestrator)")
            recorder, calls = recording(kube)
            started = time.monotonic()
            try:
                run_deployment(recorder, bad_migration, application, poll_interval=1)
            except MigrationFailed as error:
                failed_after = time.monotonic() - started
                print(str(error)[:3000], flush=True)
            else:
                raise RuntimeError("failing migration did not stop the deployment")
            if failed_after >= FAST_FAILURE_SECONDS:
                raise RuntimeError(f"migration failure took {failed_after:.0f}s to detect")
            if job_created(calls) != 1:
                raise RuntimeError("migration Job was never created")
            if applied(calls, application):
                raise RuntimeError("application manifest was applied after a failed migration")
            job = json.loads(kube("get", "job", "asic-migration", "-o", "json"))
            if not any(
                c["type"] == "Failed" and c["status"] == "True"
                for c in job["status"].get("conditions", [])
            ):
                raise RuntimeError("migration Job is not in the Failed state")
            if deployment_exists(kube, "asic-api"):
                raise RuntimeError("asic-api exists after a failed migration")
            evidence["failed_migration"] = {
                "detected_seconds": round(failed_after, 1),
                "job_failed": True,
                "application_apply_executed": False,
                "api_deployment_present": False,
            }

            step("Non-vacuity: the same run with the guard mutated away DOES apply the app")
            mutated = mutated_orchestrator(scratch)
            mutant_recorder, mutant_calls = recording(kube)
            mutant_kube = mutated.Kubectl(NAMESPACE, str(config), "kubectl", mutant_recorder.runner)
            try:
                mutated.run_deployment(
                    mutant_kube,
                    bad_migration,
                    application,
                    poll_interval=1,
                    rollout_timeout=30,
                    smoke=lambda _kube: None,
                )
            except mutated.DeploymentError as error:
                print(f"mutant outcome: {type(error).__name__}", flush=True)
            if not applied(mutant_calls, application) or not deployment_exists(kube, "asic-api"):
                raise RuntimeError("mutation was not detected: guard check is vacuous")
            evidence["guard_mutation_detected"] = True
            kube("delete", "deployment", "asic-api", "asic-frontend", "--wait=true", timeout=180)
            if deployment_exists(kube, "asic-api"):
                raise RuntimeError("mutant application was not cleaned up")

            step("Authoritative sequence with a good migration: migrate, roll out, auto-smoke")
            recorder, calls = recording(kube)
            outcome = run_deployment(recorder, migration, application, poll_interval=1)
            order = [
                "migration" if "create" in args_ else "application"
                for args_, content in calls
                if "--dry-run=server" not in args_
                and ("create" in args_ or ("apply" in args_ and content == application))
            ]
            if order != ["migration", "application"]:
                raise RuntimeError(f"unexpected create/apply order: {order}")
            evidence["successful_migration_seconds"] = round(outcome.elapsed_seconds, 1)
            evidence["post_rollout_smoke"] = "passed_automatically"

            python = "/usr/local/bin/python"
            probe = (
                "import json,os,pathlib,urllib.request,urllib.error; "
                "assert os.getuid()==10001; "
                "assert not pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists(); "
                "assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/livez',timeout=5))['status']=='ok'; "
                "assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/readyz',timeout=5))['status']=='ready'; "
                "assert b'# HELP' in urllib.request.urlopen('http://127.0.0.1:8000/metrics',timeout=5).read(); "
                "print('non-root, tokenless, live, ready, metrics: passed')"
            )
            print(kube("exec", "deployment/asic-api", "--", python, "-c", probe), flush=True)

            step("Network policy regression")
            frontend_probe = (
                "(async()=>{if(process.getuid()!==10001)throw Error('root');"
                "for(const [url,status] of [['http://127.0.0.1:3000/livez',200],['http://127.0.0.1:3000/readyz',200],"
                "[new URL('/livez',process.env.ASIC_API_BASE_URL),200],"
                "[new URL('/api/v1/incidents',process.env.ASIC_API_BASE_URL),401]]){"
                "const r=await fetch(url,{signal:AbortSignal.timeout(5000)});if(r.status!==status)throw Error(url+': '+r.status)}"
                "console.log('frontend health, frontend->API (DNS), unauthenticated refusal: passed')})().catch(e=>{console.error(e);process.exit(1)})"
            )
            print(
                kube(
                    "exec",
                    "deployment/asic-frontend",
                    "--",
                    "/nodejs/bin/node",
                    "-e",
                    frontend_probe,
                ),
                flush=True,
            )

            def node_denied(host: str, port: int) -> bool:
                code = (
                    "const net=require('node:net');"
                    f"const s=net.connect({{host:'{host}',port:{port}}});"
                    "s.setTimeout(3000);s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});"
                    "s.on('timeout',()=>{console.log('DENIED_BY_POLICY');s.destroy()});"
                    "s.on('error',e=>{console.log('ERROR '+e.code)})"
                )
                out = kube("exec", "deployment/asic-frontend", "--", "/nodejs/bin/node", "-e", code)
                return "DENIED_BY_POLICY" in out

            def python_denied(host: str, port: int) -> bool:
                code = (
                    "import socket\n"
                    "try:\n"
                    f"    socket.create_connection(('{host}',{port}),timeout=3); print('CONNECTED')\n"
                    "except TimeoutError: print('DENIED_BY_POLICY')\n"
                    "except OSError as e: print('ERROR', e)\n"
                )
                out = kube("exec", "deployment/asic-api", "--", python, "-c", code)
                return "DENIED_BY_POLICY" in out

            role_probe = (
                "import os,sqlalchemy as s; e=s.create_engine(os.environ['ASIC_DATABASE_URL']); "
                "c=e.connect(); assert c.execute(s.text('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user')).scalar() is False; "
                "assert not c.execute(s.text(\"SELECT has_table_privilege(current_user,'alembic_version','UPDATE')\")).scalar(); "
                "print('API->DB allowed; runtime role is non-owner/non-BYPASSRLS: passed')"
            )
            print(kube("exec", "deployment/asic-api", "--", python, "-c", role_probe), flush=True)
            if not node_denied("postgres", 5432):
                raise RuntimeError("frontend -> database was not denied")
            if not node_denied("1.1.1.1", 443) or not python_denied("1.1.1.1", 443):
                raise RuntimeError("unexpected internet egress was not denied")
            outsider = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "outsider", "namespace": "asic-outsider"},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "probe",
                            "image": args.backend,
                            "imagePullPolicy": "Never",
                            "command": [
                                python,
                                "-c",
                                "import socket\ntry:\n"
                                "    socket.create_connection(('asic-api.asic-system.svc.cluster.local',8000),timeout=4); print('CONNECTED')\n"
                                "except TimeoutError: print('DENIED_BY_POLICY')\n",
                            ],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            }
            run(*kubectl, "create", "namespace", "asic-outsider")
            run(*kubectl, "apply", "-f", "-", content=yaml.safe_dump(outsider))
            run(
                *kubectl,
                "wait",
                "-n",
                "asic-outsider",
                "--for=jsonpath={.status.phase}=Succeeded",
                "pod/outsider",
                "--timeout=120s",
            )
            if "DENIED_BY_POLICY" not in run(*kubectl, "logs", "-n", "asic-outsider", "outsider"):
                raise RuntimeError("unexpected namespace -> API was not denied")
            run(*kubectl, "delete", "namespace", "asic-outsider", "--wait=false")
            evidence["network_policy"] = {
                "frontend_to_api": "allowed",
                "api_to_db": "allowed",
                "dns": "allowed",
                "frontend_to_db": "denied",
                "internet_egress": "denied",
                "other_namespace_to_api": "denied",
            }

            step("API outage: frontend stays live, leaves endpoints, is not restarted")

            def frontend_pod() -> dict[str, object]:
                pods = json.loads(
                    kube("get", "pods", "-l", "app.kubernetes.io/name=asic-frontend", "-o", "json")
                )["items"]
                if len(pods) != 1:
                    raise RuntimeError(f"expected one frontend pod, found {len(pods)}")
                return pods[0]  # type: ignore[no-any-return]

            def restarts(pod: dict[str, object]) -> int:
                return sum(c["restartCount"] for c in pod["status"]["containerStatuses"])  # type: ignore[index]

            pod = frontend_pod()
            pod_name = pod["metadata"]["name"]  # type: ignore[index]
            before = restarts(pod)
            kube("scale", "deployment/asic-api", "--replicas=0")
            kube(
                "wait",
                "--for=delete",
                "pod",
                "-l",
                "app.kubernetes.io/name=asic-api",
                "--timeout=120s",
                timeout=150,
            )
            with port_forward(kube, f"pod/{pod_name}", 3000) as local:
                timings = {}
                for path, expected in (("/livez", 200), ("/readyz", 503)):
                    begun = time.monotonic()
                    status = http_status(f"http://127.0.0.1:{local}{path}", timeout=5)
                    timings[path] = round(time.monotonic() - begun, 2)
                    if status != expected:
                        raise RuntimeError(f"API down: frontend {path} returned {status}")
                if timings["/readyz"] >= 3:
                    raise RuntimeError(f"frontend readiness not bounded: {timings}")
                # Longer than liveness initialDelay + failureThreshold x period (10 + 3x10s).
                time.sleep(45)
                if http_status(f"http://127.0.0.1:{local}/livez", timeout=5) != 200:
                    raise RuntimeError("frontend liveness failed during API outage")
            pod = frontend_pod()
            if pod["metadata"]["name"] != pod_name or restarts(pod) != before:  # type: ignore[index]
                raise RuntimeError("frontend was restarted because the API was down")
            if ready_endpoints(kube, "asic-frontend") != 0:
                raise RuntimeError("unready frontend was not removed from Service endpoints")
            try:
                post_rollout_smoke(kube)
            except SmokeFailed as error:
                smoke_during_outage = str(error)
            else:
                raise RuntimeError("post-rollout smoke passed with the API scaled to zero")
            evidence["api_outage"] = {
                "frontend_probe_seconds": timings,
                "frontend_restarts_before": before,
                "frontend_restarts_after": restarts(pod),
                "frontend_ready_endpoints": 0,
                "post_rollout_smoke": f"failed as required: {smoke_during_outage}",
            }
            kube("scale", "deployment/asic-api", "--replicas=1")
            for name in ("asic-api", "asic-frontend"):
                kube("rollout", "status", f"deployment/{name}", "--timeout=180s", timeout=240)
            kube("wait", "--for=condition=Ready", f"pod/{pod_name}", "--timeout=60s", timeout=90)
            post_rollout_smoke(kube)

            step("Failed application rollout and recovery (never a DB downgrade)")
            kube("set", "image", "deployment/asic-api", "api=asic-invalid:phase14-missing")
            if (
                kube.probe("rollout", "status", "deployment/asic-api", "--timeout=15s").returncode
                == 0
            ):
                raise RuntimeError("deliberately invalid rollout unexpectedly passed")
            kube("rollout", "undo", "deployment/asic-api")
            kube("rollout", "status", "deployment/asic-api", "--timeout=180s", timeout=240)
            post_rollout_smoke(kube)
            evidence["rollback"] = "passed"

            step("Redeployment matrix on one cluster: repeat, new template, fail, fix-forward")
            evidence["redeployment"] = redeployment_matrix(kube, migration, application)

            for image, expected in image_ids.items():
                if (
                    run("docker", "image", "inspect", image, "--format", "{{.Id}}").strip()
                    != expected
                ):
                    raise RuntimeError("supplied image tag changed during smoke")

            step("Terraform destroy")
            run(*terraform, "destroy", "-auto-approve", *tf_vars, timeout=900)
            evidence["terraform"] = "apply, no-drift re-plan, destroy"
            print(
                json.dumps(
                    {
                        "result": "passed",
                        "image_ids": image_ids,
                        "kubernetes": "1.34.0",
                        "cni": "cilium_1.20.2",
                        **evidence,
                        "remote_production": "not_executed",
                    },
                    indent=2,
                )
            )
        finally:
            if created:
                run(args.kind, "delete", "cluster", "--name", args.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
