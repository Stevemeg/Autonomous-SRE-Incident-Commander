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
FULL_SPACE = (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))

# Egress CIDR policy (Phase 15, N-3). The invariant is "no effective internet-wide egress",
# not merely "not literally 0.0.0.0/0": a set such as 0.0.0.0/0 minus one /32 is just as open.
#
# * Internal ranges (RFC 1918, RFC 6598 shared space, IPv6 ULA) do not route to the internet;
#   in-cluster and on-premises targets are legitimate, so any prefix wholly inside one is allowed.
# * Globally routed destinations must be no broader than /24 (IPv4) or /48 (IPv6). Those are
#   the most-specific prefixes accepted in the global routing table (RFC 7454 section 6.1.3),
#   i.e. the smallest unit in which internet space is routed to one network. A reviewed
#   destination therefore never needs a broader entry; a vendor spread over large ranges must
#   be reached through the documented DNS-aware egress gateway instead of direct CIDRs.
# * At most MAX_EGRESS_ENTRIES entries: each entry is reviewed by a person, and 64 is ample for
#   the seven declared destination classes (IdP/JWKS, OTLP collector, Slack, Teams, PagerDuty,
#   Jira, Grafana) with several regional endpoints each. With the /24 floor this bounds direct
#   public egress to at most 64 x 256 IPv4 addresses.
# * Never allowed: loopback, link-local (includes the 169.254.169.254 metadata service),
#   multicast, unspecified, reserved and IPv4-mapped IPv6 (which would bypass the IPv4 rules).
INTERNAL_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
#: Documentation ranges (RFC 5737, RFC 3849) are not routed; illustrative configurations use them.
DOCUMENTATION_RANGES = tuple(
    ipaddress.ip_network(cidr) for cidr in ("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
MAX_PUBLIC_PREFIX = {4: 24, 6: 48}
MAX_EGRESS_ENTRIES = 64
_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def _within(network: ipaddress.IPv4Network | ipaddress.IPv6Network, ranges: tuple) -> bool:  # type: ignore[type-arg]
    return any(
        network.version == block.version and network.subnet_of(block)  # type: ignore[arg-type]
        for block in ranges
    )


def check_egress_cidr(cidr: object) -> None:
    """Refuse one CIDR that is special-purpose or broader than one routed public block."""
    network = ipaddress.ip_network(str(cidr), strict=True)
    if (
        network.prefixlen == 0
        or network.is_multicast
        or network.is_loopback
        or network.is_link_local
        or network.is_unspecified
        or network.is_reserved
        or str(network).startswith("192.0.2.")
        or (network.version == 6 and network.subnet_of(_IPV4_MAPPED))  # type: ignore[arg-type]
    ):
        raise ValueError("unrestricted, special-purpose or placeholder CIDR is not deployable")
    if _within(network, INTERNAL_RANGES) or _within(network, DOCUMENTATION_RANGES):
        return
    if network.prefixlen < MAX_PUBLIC_PREFIX[network.version]:
        raise ValueError(
            f"public egress CIDR {network} is broader than /{MAX_PUBLIC_PREFIX[network.version]}; "
            "route broad vendor ranges through the egress gateway"
        )


def _reject_unrestricted_union(cidrs: list[object]) -> None:
    """Refuse a CIDR set whose effective union is an entire address family.

    Each prefix may look narrow (``0.0.0.0/1`` + ``128.0.0.0/1``), so coverage is judged on
    the collapsed union per address family, not entry by entry.
    """
    networks = [ipaddress.ip_network(str(cidr), strict=True) for cidr in cidrs]
    for family in FULL_SPACE:
        members = [net for net in networks if net.version == family.version]
        collapsed = list(ipaddress.collapse_addresses(members))  # type: ignore[arg-type]
        if collapsed == [family]:
            raise ValueError(f"CIDR set collectively permits unrestricted egress ({family})")


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
    # Each egress rule is its own port scope: the database CIDR (5432) and HTTPS set (443).
    # The union check runs first so its explicit message survives the stricter rules below.
    _reject_unrestricted_union([config["db_cidr"]])
    _reject_unrestricted_union(egress)
    if len(egress) > MAX_EGRESS_ENTRIES:
        raise ValueError(f"at most {MAX_EGRESS_ENTRIES} reviewed HTTPS egress CIDRs are allowed")
    for cidr in [config["db_cidr"], *egress]:
        check_egress_cidr(cidr)


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
        if kind in {"Deployment", "Job", "CronJob"}:
            template = (
                doc["spec"]["jobTemplate"]["spec"]["template"]
                if kind == "CronJob"
                else doc["spec"]["template"]
            )
            pod_metadata = template.setdefault("metadata", {})
            pod_metadata.setdefault("annotations", {})["asic/config-sha256"] = hashlib.sha256(
                json.dumps(config, sort_keys=True).encode("utf-8")
            ).hexdigest()
            for container in template["spec"]["containers"]:
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
    for overlay in ("base", "migration", "maintenance"):
        (args.output / f"{overlay}.yaml").write_text(
            render(config, args.backend, args.frontend, overlay), "utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
