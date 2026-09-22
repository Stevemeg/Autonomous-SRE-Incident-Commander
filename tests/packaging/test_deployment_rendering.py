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
