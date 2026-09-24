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
        # adjacent ranges that collapse, but only to a /23 -- not the whole space
        ["203.0.112.0/24", "203.0.113.0/24"],
        # half of each family is still restricted
        ["0.0.0.0/1", "::/1"],
        ["128.0.0.0/2", "192.0.0.0/2", "0.0.0.0/2"],
    ],
)
def test_bounded_cidr_sets_are_accepted(cidrs: list[str]) -> None:
    config = copy.deepcopy(CONFIG)
    config["https_egress_cidrs"] = cidrs
    validate(config, IMAGE, IMAGE)


def test_single_database_cidr_is_accepted() -> None:
    config = copy.deepcopy(CONFIG)
    config["db_cidr"] = "10.20.0.0/24"
    validate(config, IMAGE, IMAGE)
