"""A transport success is not evidence of a precondition or completed effect."""

import pytest

from asic.remediation.observations import effect_observed, precondition_holds


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"workloads": []},
        {"workloads": ["Deployment/other revision=846"]},
        {"workloads": ["Deployment/api revision=847"]},
    ],
)
def test_reconciliation_requires_exact_target_effect(payload: dict) -> None:
    assert not effect_observed(
        "k8s.deployment.rollback", {"deployment": "api", "to_revision": 846}, payload
    )


def test_matching_revision_proves_observable_effect() -> None:
    assert effect_observed(
        "k8s.deployment.rollback",
        {"deployment": "api", "to_revision": 846},
        {"workloads": ["Deployment/api revision=846"]},
    )


def test_unknown_precondition_and_missing_rollout_fail_closed() -> None:
    assert not precondition_holds("invented", {}, {})
    assert not precondition_holds(
        "no_other_rollout_in_progress",
        {"deployment": "api"},
        {"workloads": ["Deployment/api revision=846"]},
    )
    assert precondition_holds(
        "no_other_rollout_in_progress",
        {"deployment": "api"},
        {"workloads": ["Deployment/api revision=846 rollout=idle"]},
    )


@pytest.mark.parametrize("low,high", [(8, 4), (0, 5), (1, 51), (True, 4)])
def test_hpa_bounds_cannot_exceed_blast_radius(low: int, high: int) -> None:
    assert not precondition_holds(
        "bounds_within_registered_maxima", {"min_replicas": low, "max_replicas": high}, {}
    )
