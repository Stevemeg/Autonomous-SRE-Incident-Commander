"""Deterministic, tool-specific remediation verification policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
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


_LATENCY_RECOVERY_V1: Final = VerificationProfile(
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

#: Phase 10 (ADR-0026): identical judgement, with the native Prometheus adapter added to the
#: approved measurement sources. A new version rather than an edit: an action's criteria are
#: frozen when it is proposed, and an action frozen under v1 is judged by v1 forever.
_LATENCY_RECOVERY_V2: Final = replace(
    _LATENCY_RECOVERY_V1,
    profile_id="latency-p95-recovery-v2",
    profile_version=2,
    approved_sources=("prometheus", "prometheus-simulator"),
)

_TOOLS: Final[tuple[str, ...]] = (
    "k8s.deployment.rollback",
    "k8s.hpa.adjust",
    "k8s.node.cordon",
    "k8s.node.uncordon",
)

#: The profile a *new* proposal must select.
_PROFILES: Final[dict[str, VerificationProfile]] = dict.fromkeys(_TOOLS, _LATENCY_RECOVERY_V2)

#: Every profile version ever registered per tool, oldest first. Frozen criteria resolve here.
_HISTORY: Final[dict[str, tuple[VerificationProfile, ...]]] = dict.fromkeys(
    _TOOLS, (_LATENCY_RECOVERY_V1, _LATENCY_RECOVERY_V2)
)


def profile_for(tool_name: str) -> VerificationProfile:
    """The current profile, for new proposals only."""
    try:
        return _PROFILES[tool_name]
    except KeyError as exc:
        raise SchemaViolation(f"no deterministic verification profile for {tool_name!r}") from exc


def profile_for_criteria(tool_name: str, criteria: Mapping[str, Any]) -> VerificationProfile:
    """The registered profile version an action's frozen criteria select - exactly.

    Dispatch, verification and T5 lineage all judge an action by the policy it was
    approved under, never by whatever the current policy happens to be.
    """
    profile_for(tool_name)
    frozen = dict(criteria)
    for profile in _HISTORY[tool_name]:
        if profile.to_dict() == frozen:
            return profile
    raise SchemaViolation(
        f"frozen verification criteria for {tool_name!r} match no registered profile version"
    )


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


__all__ = [
    "VerificationProfile",
    "profile_for",
    "profile_for_criteria",
    "require_permitted_proposal",
]
