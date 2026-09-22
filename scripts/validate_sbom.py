#!/usr/bin/env python3
"""Fail closed unless a CycloneDX image SBOM contains expected runtime packages."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path


def validate(path: Path, expected: tuple[str, ...], image_id: str | None = None) -> list[str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"SBOM is unreadable: {type(exc).__name__}"]
    findings: list[str] = []
    if not isinstance(document, dict):
        return ["SBOM must be an object"]
    if document.get("bomFormat") != "CycloneDX":
        findings.append("SBOM is not CycloneDX")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        return [*findings, "SBOM contains no components"]
    names = {
        str(component.get("name", "")).lower()
        for component in components
        if isinstance(component, dict)
    }
    for package in expected:
        if package.lower() not in names:
            findings.append(f"expected final-image package is absent: {package}")
    metadata = document.get("metadata", {})
    component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    if not isinstance(component, dict) or not component.get("name"):
        findings.append("SBOM metadata does not identify the scanned image")
    if image_id is not None:
        properties = component.get("properties", []) if isinstance(component, dict) else []
        if not any(
            isinstance(prop, dict)
            and prop.get("name") == "aquasecurity:trivy:ImageID"
            and prop.get("value") == image_id
            for prop in properties
        ):
            findings.append("SBOM does not match the actual final image ID")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--expect", action="append", required=True)
    parser.add_argument("--image-id", help="bind evidence to docker image inspect .Id")
    args = parser.parse_args(argv)
    findings = validate(args.sbom, tuple(args.expect), args.image_id)
    for finding in findings:
        print(f"[sbom] {finding}")
    print(f"SBOM validation: {'FAILED' if findings else 'ok'} ({len(findings)} finding(s))")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
