"""Deterministic, tool-specific remediation verification policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Final

from asic.domain.errors import SchemaViolation


@dataclass(frozen=True, slots=True)
class VerificationProfile:
    profile_id: str
    profile_version: int
    source_capability: str
    metric: str
    direction: str
    operator: str
    threshold: float
    window_seconds: int
    minimum_samples: int
    require_improvement: bool
    max_baseline_age_seconds: int
    approved_sources: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["approved_sources"] = list(self.approved_sources)
        return value


_LATENCY_RECOVERY: Final = VerificationProfile(
    profile_id="latency-p95-recovery-v1",
    profile_version=1,
    source_capability="read.metrics",
    metric="http_request_duration_p95_seconds",
    direction="decrease",
    operator="<",
    threshold=0.25,
    window_seconds=300,
    minimum_samples=1,
    require_improvement=True,
    max_baseline_age_seconds=300,
    approved_sources=("prometheus-simulator",),
)

_PROFILES: Final[dict[str, VerificationProfile]] = {
    "k8s.deployment.rollback": _LATENCY_RECOVERY,
    "k8s.hpa.adjust": _LATENCY_RECOVERY,
    "k8s.node.cordon": _LATENCY_RECOVERY,
    "k8s.node.uncordon": _LATENCY_RECOVERY,
}


def profile_for(tool_name: str) -> VerificationProfile:
    try:
        return _PROFILES[tool_name]
    except KeyError as exc:
        raise SchemaViolation(f"no deterministic verification profile for {tool_name!r}") from exc


def require_permitted_proposal(tool_name: str, proposed: dict[str, Any]) -> VerificationProfile:
    """Require the model to select the exact server-defined profile, never author policy."""
    profile = profile_for(tool_name)
    canonical = profile.to_dict()
    # Compatibility input is deliberately narrow: the old four fields must exactly match;
    # a profile id may instead select the complete policy. Unknown fields/operators fail.
    if proposed == canonical:
        return profile
    if proposed == {
        "metric": profile.metric,
        "operator": profile.operator,
        "threshold": profile.threshold,
        "window_seconds": profile.window_seconds,
    }:
        return profile
    if proposed == {"profile_id": profile.profile_id}:
        return profile
    raise SchemaViolation(
        f"verification proposal for {tool_name!r} does not select its deterministic profile"
    )


__all__ = ["VerificationProfile", "profile_for", "require_permitted_proposal"]
