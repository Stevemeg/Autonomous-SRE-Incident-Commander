"""Fail-closed production configuration contract (no cluster credentials needed)."""

from __future__ import annotations

import copy

import pytest
from scripts.render_deployment import validate

IMAGE = "ghcr.io/example/asic@sha256:" + "a" * 64
CONFIG: dict[str, object] = {
    "hostname": "asic.example.com",
    "ingress_class": "nginx",
    "ingress_namespace": "ingress-nginx",
    "tls_secret": "asic-tls",
    "db_cidr": "10.20.0.12/32",
    "issuer": "https://id.example.com",
    "audience": "asic",
    "jwks_url": "https://id.example.com/.well-known/jwks.json",
    "otlp_endpoint": "https://collector.example.com",
    "https_egress_cidrs": ["203.0.113.12/32"],
}


def test_explicit_production_contract_passes() -> None:
    validate(CONFIG, IMAGE, IMAGE)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("jwks_url", "http://id.example.com/jwks"),
        ("jwks_url", "https://localhost/jwks"),
        ("jwks_url", "https://127.0.0.1/jwks"),
        ("issuer", "https://[::1]/"),
        ("issuer", "https://user:secret@id.example.com"),
        ("jwks_url", "https://id.example.com/jwks?token=secret"),
        ("hostname", "asic.example.invalid"),
        ("db_cidr", "0.0.0.0/0"),
        ("db_cidr", "192.0.2.1/32"),
        ("https_egress_cidrs", ["::/0"]),
        ("https_egress_cidrs", []),
        ("audience", ""),
        ("secret_value", "must-not-be-in-config"),
    ],
)
def test_invalid_platform_contract_is_refused(key: str, value: object) -> None:
    config = copy.deepcopy(CONFIG)
    config[key] = value
    with pytest.raises(ValueError):
        validate(config, IMAGE, IMAGE)


@pytest.mark.parametrize(
    "image", ["ghcr.io/example/asic:latest", "x@sha256:a", IMAGE[:-64] + "0" * 64]
)
def test_no_mutable_or_placeholder_release_identity(image: str) -> None:
    with pytest.raises(ValueError):
        validate(CONFIG, image, IMAGE)


FULL_V4 = [
    ["0.0.0.0/1", "128.0.0.0/1"],
    ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"],
    ["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/3"],
    # redundant/duplicate prefixes that still collapse to the full space
    ["0.0.0.0/1", "0.0.0.0/1", "10.0.0.0/8", "128.0.0.0/1"],
    # full space hidden among IPv6 entries
    ["2001:db8::/32", "0.0.0.0/1", "128.0.0.0/1"],
]
FULL_V6 = [
    ["::/1", "8000::/1"],
    ["::/2", "4000::/2", "8000::/2", "c000::/2"],
    ["::/1", "8000::/2", "c000::/2", "10.0.0.0/8"],
]


@pytest.mark.parametrize("cidrs", FULL_V4 + FULL_V6)
def test_https_cidrs_whose_union_is_unrestricted_are_refused(cidrs: list[str]) -> None:
    config = copy.deepcopy(CONFIG)
    config["https_egress_cidrs"] = cidrs
    with pytest.raises(ValueError, match="collectively permits unrestricted egress"):
        validate(config, IMAGE, IMAGE)


def test_decomposed_full_ipv4_space_of_many_prefixes_is_refused() -> None:
    config = copy.deepcopy(CONFIG)
    # 98 prefixes, none individually broad, loopback- or multicast-only.
    config["https_egress_cidrs"] = [
        "0.0.0.0/1",
        *(f"{octet}.0.0.0/8" for octet in range(128, 224)),
        "224.0.0.0/3",
    ]
    with pytest.raises(ValueError, match=r"0\.0\.0\.0/0"):
        validate(config, IMAGE, IMAGE)


@pytest.mark.parametrize(
    "cidrs",
    [
        ["203.0.113.12/32"],
        ["10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10"],
        ["203.0.113.0/25", "198.51.100.7/32", "2001:db8::/48"],
        # two adjacent public /24 blocks, each a single routed unit
        ["198.18.0.0/24", "198.18.1.0/24"],
        ["8.8.8.8/32", "2606:4700::/48"],
        # exactly the entry cap of public /24 blocks
        [f"198.19.{n}.0/24" for n in range(64)],
    ],
)
def test_bounded_cidr_sets_are_accepted(cidrs: list[str]) -> None:
    config = copy.deepcopy(CONFIG)
    config["https_egress_cidrs"] = cidrs
    validate(config, IMAGE, IMAGE)


def _all_ipv4_except(host: str) -> list[str]:
    """0.0.0.0/0 minus one /32, as 32 prefixes (the N-3 counterexample)."""
    import ipaddress

    whole = ipaddress.ip_network("0.0.0.0/0")
    return [str(net) for net in whole.address_exclude(ipaddress.ip_network(f"{host}/32"))]


@pytest.mark.parametrize(
    ("cidrs", "match"),
    [
        # N-3: effectively internet-wide although the union is not literally the full space
        (_all_ipv4_except("203.0.113.12"), "broader than /24"),
        (["0.0.0.0/1", "::/1"], "broader than /24"),
        (["128.0.0.0/2", "192.0.0.0/2", "0.0.0.0/2"], "broader than /24"),
        (["8.0.0.0/8"], "broader than /24"),
        (["203.0.112.0/23"], "broader than /24"),
        (["2606:4700::/32"], "broader than /48"),
        # straddles internal and public space, so it is public
        (["10.0.0.0/7"], "broader than /24"),
        # special-purpose destinations are never egress targets
        (["169.254.169.254/32"], "special-purpose"),
        (["fe80::/64"], "special-purpose"),
        (["::ffff:169.254.169.254/128"], "special-purpose"),
        (["::ffff:0:0/96"], "special-purpose"),
        (["240.0.0.0/4"], "special-purpose"),
        (["0.0.0.0/32"], "special-purpose"),
        (["::1/128"], "special-purpose"),
        # more reviewed entries than a person can meaningfully review
        ([f"198.19.{n}.0/24" for n in range(65)], "at most 64"),
    ],
)
def test_effectively_unrestricted_or_special_cidrs_are_refused(
    cidrs: list[str], match: str
) -> None:
    config = copy.deepcopy(CONFIG)
    config["https_egress_cidrs"] = cidrs
    with pytest.raises(ValueError, match=match):
        validate(config, IMAGE, IMAGE)


@pytest.mark.parametrize("cidr", ["8.8.0.0/16", "169.254.0.0/16", "0.0.0.0/1"])
def test_database_cidr_follows_the_same_policy(cidr: str) -> None:
    config = copy.deepcopy(CONFIG)
    config["db_cidr"] = cidr
    with pytest.raises(ValueError):
        validate(config, IMAGE, IMAGE)


def test_single_database_cidr_is_accepted() -> None:
    config = copy.deepcopy(CONFIG)
    config["db_cidr"] = "10.20.0.0/24"
    validate(config, IMAGE, IMAGE)
