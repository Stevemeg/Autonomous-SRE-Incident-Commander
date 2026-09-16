"""Strict interpretation of the simulator read schema for remediation safety checks.

Only exact resource identities and explicit fields count as observations. Missing,
ambiguous or malformed state never establishes a precondition or a completed effect.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def resource(payload: Mapping[str, Any], kind: str, name: object) -> dict[str, str]:
    matches = []
    for line in payload.get("workloads", []):
        if not isinstance(line, str):
            continue
        tokens = line.split()
        if tokens and tokens[0] == f"{kind}/{name}":
            fields = dict(token.split("=", 1) for token in tokens[1:] if "=" in token)
            matches.append(fields)
    return matches[0] if len(matches) == 1 else {}


def precondition_holds(name: str, arguments: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    deployment = resource(payload, "Deployment", arguments.get("deployment"))
    hpa = resource(payload, "HorizontalPodAutoscaler", arguments.get("hpa_name"))
    node = resource(payload, "Node", arguments.get("node"))
    if name == "deployment_exists":
        return bool(deployment)
    if name == "no_other_rollout_in_progress":
        return deployment.get("rollout") == "idle"
    if name == "target_revision_available":
        target = str(arguments.get("to_revision"))
        return any(
            dict(token.split("=", 1) for token in line.split() if "=" in token).get("revision")
            == target
            for line in payload.get("deployments", [])
            if isinstance(line, str)
        )
    if name == "hpa_exists":
        return bool(hpa)
    if name == "bounds_within_registered_maxima":
        low, high = arguments.get("min_replicas"), arguments.get("max_replicas")
        return type(low) is int and type(high) is int and 1 <= low <= high <= 50
    if name == "node_exists":
        return bool(node)
    if name == "node_not_already_cordoned":
        return node.get("schedulable") == "true"
    if name == "node_currently_cordoned":
        return node.get("schedulable") == "false"
    return False


def effect_observed(tool: str, arguments: Mapping[str, Any], payload: Mapping[str, Any]) -> bool:
    if tool == "k8s.deployment.rollback":
        fields = resource(payload, "Deployment", arguments.get("deployment"))
        target = str(arguments.get("to_revision"))
        # A real API server renumbers the ReplicaSet it rolls back to and records the
        # revision it replaced in ``revision_history``. That exact, explicit identity also
        # counts - a missing or malformed history never does.
        history = fields.get("revision_history", "")
        return fields.get("revision") == target or target in history.split(",")
    if tool == "k8s.hpa.adjust":
        fields = resource(payload, "HorizontalPodAutoscaler", arguments.get("hpa_name"))
        return fields.get("min") == str(arguments.get("min_replicas")) and fields.get("max") == str(
            arguments.get("max_replicas")
        )
    if tool in {"k8s.node.cordon", "k8s.node.uncordon"}:
        fields = resource(payload, "Node", arguments.get("node"))
        return fields.get("schedulable") == ("false" if tool == "k8s.node.cordon" else "true")
    return False
