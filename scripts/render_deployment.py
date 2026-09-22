#!/usr/bin/env python3
"""Render a production deployment from validated, non-secret platform settings.

Credentials remain pre-provisioned Secret references; this command never reads them.
Outputs are temporary deployment artifacts, not files to commit.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import yaml

REPO = Path(__file__).resolve().parents[1]


def validate(config: dict[str, object], backend: str, frontend: str) -> None:
    for image in (backend, frontend):
        if not re.fullmatch(r"ghcr\.io/[a-z0-9/._-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("images must be immutable GHCR digests")
        if image.endswith("0" * 64):
            raise ValueError("placeholder digest is not deployable")
    required = {
        "hostname",
        "ingress_class",
        "ingress_namespace",
        "tls_secret",
        "db_cidr",
        "issuer",
        "audience",
        "jwks_url",
        "otlp_endpoint",
        "https_egress_cidrs",
    }
    if set(config) != required:
        raise ValueError("configuration keys must exactly match the documented contract")
    for key in ("hostname", "ingress_class", "ingress_namespace", "tls_secret"):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", str(config[key])):
            raise ValueError(f"invalid DNS identifier: {key}")
    if str(config["hostname"]).endswith(".invalid"):
        raise ValueError("placeholder hostname is not deployable")
    for key in ("issuer", "jwks_url", "otlp_endpoint"):
        url = urlsplit(str(config[key]))
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(f"{key} must be a credential-free HTTPS URL")
        hostname = url.hostname or ""
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError(f"{key} cannot use a loopback host")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            if address.is_loopback:
                raise ValueError(f"{key} cannot use a loopback host")
    if not isinstance(config["audience"], str) or not config["audience"]:
        raise ValueError("audience is required")
    egress = config["https_egress_cidrs"]
    if not isinstance(egress, list) or not egress:
        raise ValueError("reviewed HTTPS destination CIDRs are required, including the IdP")
    for cidr in [config["db_cidr"], *egress]:
        network = ipaddress.ip_network(str(cidr), strict=True)
        if (
            network.prefixlen == 0
            or network.is_multicast
            or network.is_loopback
            or str(network).startswith("192.0.2.")
        ):
            raise ValueError("unrestricted or placeholder CIDR is not deployable")


def render(config: dict[str, object], backend: str, frontend: str, overlay: str) -> str:
    validate(config, backend, frontend)
    rendered = subprocess.run(
        ["kubectl", "kustomize", str(REPO / "deploy/kubernetes" / overlay)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    documents = list(yaml.safe_load_all(rendered))
    for doc in documents:
        kind, name = doc["kind"], doc["metadata"]["name"]
        if kind in {"Deployment", "Job"}:
            pod_metadata = doc["spec"]["template"].setdefault("metadata", {})
            pod_metadata.setdefault("annotations", {})["asic/config-sha256"] = hashlib.sha256(
                json.dumps(config, sort_keys=True).encode("utf-8")
            ).hexdigest()
            for container in doc["spec"]["template"]["spec"]["containers"]:
                container["image"] = frontend if name == "asic-frontend" else backend
        elif kind == "ConfigMap" and name == "asic-runtime":
            doc["data"].update(
                {
                    "ASIC_JWT_ISSUER": config["issuer"],
                    "ASIC_JWT_AUDIENCE": config["audience"],
                    "ASIC_OIDC_JWKS_URL": config["jwks_url"],
                    "OTEL_EXPORTER_OTLP_ENDPOINT": config["otlp_endpoint"],
                }
            )
        elif kind == "Ingress":
            doc["spec"]["ingressClassName"] = config["ingress_class"]
            doc["spec"]["rules"][0]["host"] = config["hostname"]
            doc["spec"]["tls"] = [
                {"hosts": [config["hostname"]], "secretName": config["tls_secret"]}
            ]
        elif kind == "NetworkPolicy":
            spec = doc["spec"]
            for direction, peers in (("egress", "to"), ("ingress", "from")):
                for rule in spec.get(direction, []):
                    for peer in rule.get(peers, []):
                        if peer.get("ipBlock", {}).get("cidr") == "192.0.2.1/32":
                            peer["ipBlock"]["cidr"] = config["db_cidr"]
                        labels = peer.get("namespaceSelector", {}).get("matchLabels", {})
                        if labels.get("kubernetes.io/metadata.name") == "ingress-nginx":
                            labels["kubernetes.io/metadata.name"] = config["ingress_namespace"]
            if name == "api-platform-egress":
                spec["egress"].append(
                    {
                        "to": [
                            {"ipBlock": {"cidr": cidr}} for cidr in config["https_egress_cidrs"]
                        ],
                        "ports": [{"protocol": "TCP", "port": 443}],
                    }
                )
    return yaml.safe_dump_all(documents, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text("utf-8"))
    validate(config, args.backend, args.frontend)
    args.output.mkdir(parents=True, exist_ok=True)
    for overlay in ("base", "migration"):
        (args.output / f"{overlay}.yaml").write_text(
            render(config, args.backend, args.frontend, overlay), "utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
