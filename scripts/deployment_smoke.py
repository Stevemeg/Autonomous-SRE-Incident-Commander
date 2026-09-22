#!/usr/bin/env python3
"""Deploy the supplied production artifacts to a disposable kind cluster.

No image is rebuilt here. Terraform state, kubeconfigs and rendered manifests live
in a temporary directory. The cluster is destroyed even when a validation fails.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
HELM = "alpine/helm@sha256:aef9b56f64e866207d9591d0abd8f6d767b36aadd12edf68f8a719716d9d29c9"
CILIUM_SHA256 = "b2afd87b7f75f875f92a14559f14f59b7babbb479d968e3fd625a20bf30ec20e"
NODE = "kindest/node@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
TERRAFORM = (
    "hashicorp/terraform@sha256:dfb1889a8ee74ada3ddacc48f89b8a0d69f3e114de3d8a2ce15f6a8d3dbfdbe2"
)


def run(*command: str, timeout: int = 600, content: str | None = None) -> str:
    result = subprocess.run(
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
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} {command[1:3]} failed: {result.stderr[-4000:]} {result.stdout[-4000:]}"
        )
    return result.stdout


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
        kube = ["kubectl", "--kubeconfig", str(config)]
        platform = scratch / "platform"
        platform.mkdir()
        for path in (REPO / "infra/terraform/platform").iterdir():
            if path.suffix == ".tf" or path.name == ".terraform.lock.hcl":
                shutil.copy2(path, platform / path.name)
        created = False
        try:
            created = True
            print("Creating disposable Kubernetes 1.34.0 cluster", flush=True)
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
            print("Installing checksum-pinned Cilium 1.20.2 for policy enforcement", flush=True)
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
            run(*terraform, "init", "-backend=false", "-lockfile=readonly")
            run(*terraform, "validate")
            print(
                run(
                    *terraform,
                    "apply",
                    "-auto-approve",
                    "-var=kubeconfig_path=/work/internal-kubeconfig",
                    f"-var=kube_context=kind-{args.name}",
                ),
                flush=True,
            )
            for image in (args.backend, args.frontend):
                run(args.kind, "load", "docker-image", "--name", args.name, image)

            def render(overlay: str) -> str:
                text = run(*kube, "kustomize", f"deploy/kubernetes/{overlay}")
                return text.replace("asic-backend:phase14-local", args.backend).replace(
                    "asic-frontend:phase14-local", args.frontend
                )

            def apply(overlay: str) -> None:
                manifest = render(overlay)
                run(*kube, "apply", "--dry-run=server", "-f", "-", content=manifest)
                run(*kube, "apply", "-f", "-", content=manifest)

            apply("overlays/local-database")
            run(
                *kube,
                "rollout",
                "status",
                "deployment/postgres",
                "-n",
                "asic-system",
                "--timeout=180s",
            )
            # A failed migration Job must be an observed failure before any API rollout.
            failed_job = next(
                doc
                for doc in yaml.safe_load_all(render("overlays/local-migration"))
                if doc["kind"] == "Job"
            )
            failed_job["metadata"]["name"] = "asic-migration-negative-control"
            failed_job["spec"]["template"]["spec"]["containers"][0]["command"] = [
                "/usr/local/bin/python",
                "-c",
                "raise SystemExit(42)",
            ]
            failed_job["spec"]["template"]["spec"]["containers"][0]["env"] = []
            run(*kube, "apply", "-f", "-", content=yaml.safe_dump(failed_job))
            run(
                *kube,
                "wait",
                "--for=condition=failed",
                "job/asic-migration-negative-control",
                "-n",
                "asic-system",
                "--timeout=90s",
            )
            deployments = json.loads(
                run(*kube, "get", "deployments", "-n", "asic-system", "-o", "json")
            )
            if any(item["metadata"]["name"] == "asic-api" for item in deployments["items"]):
                raise RuntimeError("application appeared before migration success")
            run(*kube, "delete", "job", "asic-migration-negative-control", "-n", "asic-system")
            apply("overlays/local-migration")
            run(
                *kube,
                "wait",
                "--for=condition=complete",
                "job/asic-migration",
                "-n",
                "asic-system",
                "--timeout=600s",
            )
            print("Migration complete; rolling out the supplied image identities", flush=True)
            apply("overlays/local")
            for name in ("asic-api", "asic-frontend"):
                run(
                    *kube,
                    "rollout",
                    "status",
                    f"deployment/{name}",
                    "-n",
                    "asic-system",
                    "--timeout=300s",
                )
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
            print(
                run(
                    *kube,
                    "exec",
                    "-n",
                    "asic-system",
                    "deployment/asic-api",
                    "--",
                    python,
                    "-c",
                    probe,
                )
            )
            frontend_probe = (
                "(async()=>{if(process.getuid()!==10001)throw Error('root');"
                "for(const [url,status] of [['http://127.0.0.1:3000/',200],"
                "[new URL('/livez',process.env.ASIC_API_BASE_URL),200],"
                "[new URL('/api/v1/incidents',process.env.ASIC_API_BASE_URL),401]]){"
                "const r=await fetch(url,{signal:AbortSignal.timeout(5000)});if(r.status!==status)throw Error(url+': '+r.status)}"
                "console.log('frontend, API discovery, unauthenticated refusal: passed')})().catch(e=>{console.error(e);process.exit(1)})"
            )
            print(
                run(
                    *kube,
                    "exec",
                    "-n",
                    "asic-system",
                    "deployment/asic-frontend",
                    "--",
                    "/nodejs/bin/node",
                    "-e",
                    frontend_probe,
                )
            )
            # Positive API connectivity above plus a forbidden frontend -> DB path.
            denial_probe = (
                "const net=require('node:net');const s=net.connect({host:'postgres',port:5432});"
                "s.setTimeout(3000);s.on('connect',()=>{console.error('UNEXPECTED_DB_ACCESS');process.exit(1)});"
                "s.on('timeout',()=>{console.log('DENIED_BY_POLICY');s.destroy()});"
                "s.on('error',e=>{console.error(e.code);process.exit(2)})"
            )
            denial = run(
                *kube,
                "exec",
                "-n",
                "asic-system",
                "deployment/asic-frontend",
                "--",
                "/nodejs/bin/node",
                "-e",
                denial_probe,
            )
            if "DENIED_BY_POLICY" not in denial:
                raise RuntimeError("network denial probe produced no positive marker")
            role_probe = (
                "import os,sqlalchemy as s; e=s.create_engine(os.environ['ASIC_DATABASE_URL']); "
                "c=e.connect(); assert c.execute(s.text('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user')).scalar() is False; "
                "assert not c.execute(s.text(\"SELECT has_table_privilege(current_user,'alembic_version','UPDATE')\")).scalar(); "
                "print('runtime role is non-owner/non-BYPASSRLS: passed')"
            )
            print(
                run(
                    *kube,
                    "exec",
                    "-n",
                    "asic-system",
                    "deployment/asic-api",
                    "--",
                    python,
                    "-c",
                    role_probe,
                )
            )
            # Exercise a failed application rollout and recovery, never a DB downgrade.
            run(
                *kube,
                "set",
                "image",
                "deployment/asic-api",
                "api=asic-invalid:phase14-missing",
                "-n",
                "asic-system",
            )
            try:
                run(
                    *kube,
                    "rollout",
                    "status",
                    "deployment/asic-api",
                    "-n",
                    "asic-system",
                    "--timeout=15s",
                )
            except RuntimeError:
                pass
            else:
                raise RuntimeError("deliberately invalid rollout unexpectedly passed")
            run(*kube, "rollout", "undo", "deployment/asic-api", "-n", "asic-system")
            run(
                *kube,
                "rollout",
                "status",
                "deployment/asic-api",
                "-n",
                "asic-system",
                "--timeout=180s",
            )
            for image, expected in image_ids.items():
                if (
                    run("docker", "image", "inspect", image, "--format", "{{.Id}}").strip()
                    != expected
                ):
                    raise RuntimeError("supplied image tag changed during smoke")
            print(
                json.dumps(
                    {
                        "result": "passed",
                        "image_ids": image_ids,
                        "kubernetes": "1.34.0",
                        "network_policy_enforcement": "cilium_1.20.2_frontend_to_database_denied",
                        "rollback": "passed",
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
