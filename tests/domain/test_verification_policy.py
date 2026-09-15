"""The model may select verification intent; server policy defines success."""

from __future__ import annotations

import pytest

from asic.domain.errors import SchemaViolation
from asic.remediation.verification import profile_for, require_permitted_proposal


def test_registered_action_has_a_typed_deterministic_profile() -> None:
    profile = profile_for("k8s.deployment.rollback")
    assert profile.metric == "http_request_duration_p95_seconds"
    assert profile.direction == "decrease"
    assert profile.require_improvement


@pytest.mark.parametrize(
    "proposal",
    [
        {
            "metric": "http_request_duration_p95_seconds",
            "operator": ">=",
            "threshold": -1,
            "window_seconds": 300,
        },
        {
            "metric": "unrelated_metric",
            "operator": "<",
            "threshold": 0.25,
            "window_seconds": 300,
        },
        {
            "metric": "http_request_duration_p95_seconds",
            "operator": ">",
            "threshold": 0.25,
            "window_seconds": 300,
        },
    ],
)
def test_model_authored_thresholds_operators_and_metrics_fail_closed(
    proposal: dict[str, object],
) -> None:
    with pytest.raises(SchemaViolation, match="deterministic profile"):
        require_permitted_proposal("k8s.deployment.rollback", proposal)


def test_exact_profile_selection_is_accepted() -> None:
    profile = profile_for("k8s.deployment.rollback")
    assert (
        require_permitted_proposal("k8s.deployment.rollback", {"profile_id": profile.profile_id})
        == profile
    )
