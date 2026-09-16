"""Authoritative persisted lineage for independently verified remediation outcomes.

The verifier and governed-memory service deliberately share this module.  A verification
row saying ``verified`` is not authority by itself: the complete baseline/action/target and
post-action read lineage must agree, and the deterministic profile must reproduce the
verdict from the persisted measurements.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.catalog import Environment, Service
from asic.db.models.remediation import (
    RemediationAction,
    RemediationBaseline,
    RemediationTarget,
    Verification,
)
from asic.db.models.tools import ToolExecution
from asic.domain.enums import NodeId, RemediationActionStatus, RiskTier, ToolExecutionOutcome
from asic.domain.errors import SchemaViolation
from asic.remediation.verification import VerificationProfile, profile_for_criteria


def baseline_json(row: RemediationBaseline) -> dict[str, Any]:
    return {
        "tenant_id": str(row.tenant_id),
        "incident_id": str(row.incident_id),
        "remediation_target_id": str(row.remediation_target_id),
        "remediation_action_id": str(row.remediation_action_id),
        "target_service_id": str(row.service_id),
        "target_environment_id": str(row.environment_id),
        "profile_id": row.profile_id,
        "profile_version": row.profile_version,
        "criteria_hash": row.criteria_hash,
        "metric": row.metric,
        "source_capability": row.source_capability,
        "source": row.source_provider,
        "tool_execution_id": str(row.read_execution_id),
        "observed_at": row.observed_at.isoformat(),
        "captured_at": row.captured_at.isoformat(),
        "observed_value": float(row.observed_value),
        "provenance_hash": row.provenance_hash,
    }


def baseline_provenance(row: RemediationBaseline) -> str:
    value = baseline_json(row)
    value.pop("provenance_hash")
    return _digest(value)


def observation_provenance(
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    remediation_target_id: uuid.UUID,
    remediation_action_id: uuid.UUID,
    remediation_baseline_id: uuid.UUID,
    service_id: uuid.UUID,
    environment_id: uuid.UUID,
    profile_id: str,
    profile_version: int,
    criteria_hash: str,
    metric: str,
    source_capability: str,
    source_provider: str,
    read_execution_id: uuid.UUID,
    observed_at: datetime,
    observed_value: float,
) -> str:
    return _digest(
        {
            "tenant_id": str(tenant_id),
            "incident_id": str(incident_id),
            "remediation_target_id": str(remediation_target_id),
            "remediation_action_id": str(remediation_action_id),
            "remediation_baseline_id": str(remediation_baseline_id),
            "target_service_id": str(service_id),
            "target_environment_id": str(environment_id),
            "profile_id": profile_id,
            "profile_version": profile_version,
            "criteria_hash": criteria_hash,
            "metric": metric,
            "source_capability": source_capability,
            "source": source_provider,
            "tool_execution_id": str(read_execution_id),
            "observed_at": observed_at.isoformat(),
            "observed_value": observed_value,
        }
    )


def trusted_baseline_record(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    profile: VerificationProfile,
    baseline: RemediationBaseline,
    action: RemediationAction,
    target: RemediationTarget,
    service_name: str,
    environment_name: str,
    dispatch_at: datetime,
    as_of: datetime,
) -> bool:
    execution = session.scalar(
        sa.select(ToolExecution).where(
            ToolExecution.tenant_id == tenant_id,
            ToolExecution.id == baseline.read_execution_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.capability == profile.source_capability,
        )
    )
    if (
        execution is None
        or execution.outcome is not ToolExecutionOutcome.SUCCEEDED
        or execution.requested_by_node is not NodeId.G10_VERIFIER
        or execution.risk_tier is not RiskTier.RO
        or execution.completed_at is None
    ):
        return False
    return bool(
        baseline.tenant_id == tenant_id
        and action.tenant_id == target.tenant_id == tenant_id
        and baseline.incident_id == action.incident_id == target.incident_id
        and baseline.remediation_action_id == action.id
        and baseline.remediation_target_id == target.id == action.remediation_target_id
        and baseline.service_id == target.service_id
        and baseline.environment_id == target.environment_id
        and baseline.profile_id == profile.profile_id
        and baseline.profile_version == profile.profile_version
        and baseline.criteria_hash == action.verification_criteria_hash
        and baseline.metric == profile.metric
        and baseline.source_capability == profile.source_capability
        and baseline.source_provider in profile.approved_sources
        and baseline.provenance_hash == baseline_provenance(baseline)
        and execution.resolved_scope.get("service") == service_name
        and execution.resolved_scope.get("environment") == environment_name
        and execution.observed_effect.get("source") == baseline.source_provider
        and _execution_matches_observation(
            execution,
            metric=profile.metric,
            observed_at=baseline.observed_at,
            observed_value=float(baseline.observed_value),
        )
        and execution.started_at <= execution.completed_at <= baseline.captured_at
        and baseline.observed_at <= baseline.captured_at <= dispatch_at <= as_of
        and dispatch_at - baseline.observed_at
        <= timedelta(seconds=profile.max_baseline_age_seconds)
    )


def trusted_verified_outcome(
    session: Session, *, tenant_id: uuid.UUID, verification: Verification
) -> bool:
    """Reconstruct and validate the complete persisted G10 lineage."""
    if (
        verification.remediation_baseline_id is None
        or verification.post_action_read_execution_id is None
        or verification.profile_id is None
        or verification.profile_version is None
        or verification.observed_metric is None
        or verification.observed_value is None
        or verification.observed_at is None
        or verification.observation_source_provider is None
        or verification.observation_source_capability is None
        or verification.observation_provenance_hash is None
    ):
        return False
    action = session.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.id == verification.remediation_action_id,
        )
    )
    if action is None or action.executed_at is None:
        return False
    target = session.scalar(
        sa.select(RemediationTarget).where(
            RemediationTarget.tenant_id == tenant_id,
            RemediationTarget.id == action.remediation_target_id,
        )
    )
    baseline = session.scalar(
        sa.select(RemediationBaseline).where(
            RemediationBaseline.tenant_id == tenant_id,
            RemediationBaseline.id == verification.remediation_baseline_id,
            RemediationBaseline.remediation_action_id == action.id,
        )
    )
    if target is None or baseline is None:
        return False
    service_name = session.scalar(
        sa.select(Service.name).where(
            Service.tenant_id == tenant_id, Service.id == target.service_id
        )
    )
    environment_name = session.scalar(
        sa.select(Environment.name).where(
            Environment.tenant_id == tenant_id, Environment.id == target.environment_id
        )
    )
    if service_name is None or environment_name is None:
        return False
    try:
        profile = profile_for_criteria(action.tool_name, action.verification_criteria)
    except SchemaViolation:
        return False
    if (
        verification.verdict.value != "verified"
        or action.status is not RemediationActionStatus.VERIFIED
        or dict(action.verification_criteria) != profile.to_dict()
        or verification.criteria_hash != action.verification_criteria_hash
        or verification.profile_id != profile.profile_id
        or verification.profile_version != profile.profile_version
        or verification.baseline != baseline_json(baseline)
        or not trusted_baseline_record(
            session,
            tenant_id=tenant_id,
            profile=profile,
            baseline=baseline,
            action=action,
            target=target,
            service_name=service_name,
            environment_name=environment_name,
            dispatch_at=action.executed_at,
            as_of=verification.verified_at,
        )
    ):
        return False
    post = session.scalar(
        sa.select(ToolExecution).where(
            ToolExecution.tenant_id == tenant_id,
            ToolExecution.id == verification.post_action_read_execution_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.capability == profile.source_capability,
        )
    )
    if (
        post is None
        or post.outcome is not ToolExecutionOutcome.SUCCEEDED
        or post.requested_by_node is not NodeId.G10_VERIFIER
        or post.risk_tier is not RiskTier.RO
        or post.completed_at is None
        or post.resolved_scope.get("service") != service_name
        or post.resolved_scope.get("environment") != environment_name
        or post.observed_effect.get("source") != verification.observation_source_provider
        or not _execution_matches_observation(
            post,
            metric=profile.metric,
            observed_at=verification.observed_at,
            observed_value=float(verification.observed_value),
        )
        or verification.observed_metric != profile.metric
        or verification.observation_source_capability != profile.source_capability
        or verification.observation_source_provider not in profile.approved_sources
        or not (
            action.executed_at <= post.started_at <= post.completed_at <= verification.verified_at
        )
        or not (
            verification.observation_window_start
            <= verification.observed_at
            <= verification.observation_window_end
            <= verification.verified_at
        )
        or verification.verified_at - verification.observed_at
        > timedelta(seconds=profile.window_seconds)
    ):
        return False
    expected_hash = observation_provenance(
        tenant_id=tenant_id,
        incident_id=action.incident_id,
        remediation_target_id=target.id,
        remediation_action_id=action.id,
        remediation_baseline_id=baseline.id,
        service_id=target.service_id,
        environment_id=target.environment_id,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        criteria_hash=action.verification_criteria_hash,
        metric=profile.metric,
        source_capability=profile.source_capability,
        source_provider=verification.observation_source_provider,
        read_execution_id=post.id,
        observed_at=verification.observed_at,
        observed_value=float(verification.observed_value),
    )
    if verification.observation_provenance_hash != expected_hash:
        return False
    observed = dict(verification.observed)
    expected_fields: dict[str, Any] = {
        "metric": profile.metric,
        "observed_value": float(verification.observed_value),
        "observed_at": verification.observed_at.isoformat(),
        "source": verification.observation_source_provider,
        "tool_execution_id": str(post.id),
        "target_service_id": str(target.service_id),
        "target_environment_id": str(target.environment_id),
        "source_capability": profile.source_capability,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
    }
    if any(observed.get(key) != value for key, value in expected_fields.items()):
        return False
    baseline_value = float(baseline.observed_value)
    observed_value = float(verification.observed_value)
    threshold_passed = observed_value < profile.threshold
    direction_passed = (
        observed_value < baseline_value
        if profile.direction == "decrease"
        else observed_value > baseline_value
    )
    return bool(
        threshold_passed
        and (direction_passed or not profile.require_improvement)
        and observed.get("baseline_value") == baseline_value
        and observed.get("threshold") == profile.threshold
        and observed.get("threshold_passed") is threshold_passed
        and observed.get("direction_passed") is direction_passed
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _execution_matches_observation(
    execution: ToolExecution,
    *,
    metric: str,
    observed_at: datetime,
    observed_value: float,
) -> bool:
    """Match a normalized verdict value to the broker's immutable result summary."""
    series = execution.observed_effect.get("measurement_series")
    sample = execution.observed_effect.get("latest_sample")
    if not isinstance(series, str) or metric not in series or not isinstance(sample, str):
        return False
    try:
        timestamp_text, value_text = sample.rsplit("=", 1)
        return (
            datetime.fromisoformat(timestamp_text) == observed_at
            and float(value_text) == observed_value
        )
    except (ValueError, IndexError):
        return False


__all__ = [
    "baseline_json",
    "baseline_provenance",
    "observation_provenance",
    "trusted_baseline_record",
    "trusted_verified_outcome",
]
