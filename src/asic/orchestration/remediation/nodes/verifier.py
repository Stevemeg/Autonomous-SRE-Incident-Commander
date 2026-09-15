"""G10 Verifier.

Independent of the executor by construction, not merely by policy: this node never
receives, and this module never even imports, anything from
:mod:`asic.orchestration.remediation.nodes.executor` beyond the persisted
:class:`~asic.db.models.remediation.RemediationAction` row. It re-reads the target system
itself, through the same broker every other read goes through, and judges the result
against criteria that were frozen before the action ever executed
(``RemediationAction.verification_criteria_hash``). An executor's claim of success has no
path into this node's verdict (SI-9).

Verification cannot start before the tool's declared settling window has elapsed - judging
early is exactly how a transient improvement gets mistaken for a fix. If the window has not
elapsed, this node suspends the run precisely as the approval service does, and resumes by
re-checking the clock.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any

import sqlalchemy as sa

from asic.contracts.nodes import G10_VERIFIER
from asic.contracts.remediation_state import (
    RemediationActionRef,
    RemediationGraphState,
    VerificationRef,
)
from asic.db.models.incident import Incident
from asic.db.models.remediation import (
    RemediationAction,
    RemediationBaseline,
    RemediationTarget,
    Verification,
)
from asic.db.models.tools import ToolExecution
from asic.db.projections import append_incident_event, apply_transition
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    TerminationReason,
    TraceSpanKind,
    VerificationVerdict,
)
from asic.domain.idempotency import (
    action_version_hash,
    incident_event_key,
    verification_callback_key,
)
from asic.orchestration.remediation.context import RemediationDependencies
from asic.remediation.verification import VerificationProfile, profile_for
from asic.tools.broker import CapabilityRequest
from asic.tools.registry import ToolRegistry


def verifier_node(deps: RemediationDependencies) -> Any:
    """Build the verifier node."""

    contract = G10_VERIFIER

    def run(state: RemediationGraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.verifier",
            node_id=NodeId.G10_VERIFIER,
            node_version=contract.node_version,
        ) as span:
            action_ref = state.get("remediation_action")
            assert action_ref is not None
            action = deps.session.execute(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == uuid.UUID(action_ref.action_id),
                )
            ).scalar_one()
            descriptor = ToolRegistry.remediation_full().by_name(action.tool_name)
            profile = profile_for(action.tool_name)
            target = deps.session.execute(
                sa.select(RemediationTarget).where(
                    RemediationTarget.id == action.remediation_target_id
                )
            ).scalar_one()
            baseline_row = deps.session.scalar(
                sa.select(RemediationBaseline).where(
                    RemediationBaseline.remediation_action_id == action.id
                )
            )

            # G10 first runs after policy and any required approval to freeze a fresh,
            # independent baseline, then runs again after execution to judge a fresh
            # observation. The node boundary durably commits the baseline before any write.
            if baseline_row is None:
                if action.executed_at is not None:
                    span.fail("executed action has no pre-action baseline")
                    incident = deps.session.execute(
                        sa.select(Incident).where(
                            Incident.tenant_id == deps.context.tenant_id,
                            Incident.id == deps.context.incident_id,
                        )
                    ).scalar_one()
                    apply_transition(
                        deps.session,
                        incident=incident,
                        target=IncidentStatus.ESCALATED,
                        actor_type=ActorType.SYSTEM,
                        source=NodeId.G10_VERIFIER.value,
                        correlation_id=deps.context.correlation_id,
                        termination_reason=TerminationReason.HUMAN_ESCALATION,
                    )
                    baseline_failure_update: dict[str, Any] = {
                        "phase": "terminated",
                        "terminated": True,
                        "termination_reason": "executed action has no trusted pre-action baseline",
                        "target_incident_status": IncidentStatus.ESCALATED.value,
                    }
                    contract.validate_update(baseline_failure_update)
                    return baseline_failure_update
                baseline = _observe(deps, profile, action=action, purpose="pre-action baseline")
                if "observed_value" not in baseline:
                    span.fail(str(baseline.get("reason", "baseline unavailable")))
                    failure_update: dict[str, Any] = {
                        "phase": "terminated",
                        "terminated": True,
                        "termination_reason": "independent pre-action baseline unavailable",
                        "target_incident_status": None,
                    }
                    contract.validate_update(failure_update)
                    return failure_update
                captured_at = deps.clock.now()
                baseline.update(
                    tenant_id=str(deps.context.tenant_id),
                    incident_id=str(action.incident_id),
                    remediation_target_id=str(target.id),
                    remediation_action_id=str(action.id),
                    profile_id=profile.profile_id,
                    profile_version=profile.profile_version,
                    criteria_hash=action.verification_criteria_hash,
                    captured_at=captured_at.isoformat(),
                )
                provenance_hash = hashlib.sha256(
                    json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                baseline_row = RemediationBaseline(
                    id=uuid.uuid4(),
                    tenant_id=deps.context.tenant_id,
                    incident_id=action.incident_id,
                    remediation_target_id=target.id,
                    remediation_action_id=action.id,
                    service_id=target.service_id,
                    environment_id=target.environment_id,
                    profile_id=profile.profile_id,
                    profile_version=profile.profile_version,
                    criteria_hash=action.verification_criteria_hash,
                    metric=profile.metric,
                    source_capability=profile.source_capability,
                    source_provider=str(baseline["source"]),
                    read_execution_id=uuid.UUID(str(baseline["tool_execution_id"])),
                    observed_at=datetime.fromisoformat(str(baseline["observed_at"])),
                    captured_at=captured_at,
                    observed_value=float(baseline["observed_value"]),
                    provenance_hash=provenance_hash,
                )
                deps.session.add(baseline_row)
                action.baseline_snapshot = baseline
                deps.session.flush()
                baseline_update: dict[str, Any] = {
                    "phase": "baseline_captured",
                    "baseline_captured": True,
                    "remediation_action": _action_ref(action, descriptor.capability),
                    "terminated": False,
                }
                contract.validate_update(baseline_update)
                return baseline_update

            if action.executed_at is None:
                baseline_update = {
                    "phase": "baseline_captured",
                    "baseline_captured": True,
                    "remediation_action": _action_ref(action, descriptor.capability),
                    "terminated": False,
                }
                contract.validate_update(baseline_update)
                return baseline_update
            settled_at = action.executed_at + timedelta(seconds=descriptor.settling_seconds)
            if deps.clock.now() < settled_at:
                span.set_decision(settled=False, settled_at=settled_at.isoformat())
                settling_update: dict[str, Any] = {
                    "phase": "awaiting_settling",
                    "terminated": False,
                }
                contract.validate_update(settling_update)
                return settling_update

            attempt = (
                1
                + deps.session.execute(
                    sa.select(sa.func.count())
                    .select_from(Verification)
                    .where(
                        Verification.tenant_id == deps.context.tenant_id,
                        Verification.remediation_action_id == action.id,
                    )
                ).scalar_one()
            )

            criteria = dict(action.verification_criteria)
            criteria_hash = action_version_hash(
                action_id=action.id,
                tool_name="verification_criteria",
                tool_version="1",
                arguments=criteria,
                permission_scope={},
                preconditions=(),
                risk_tier=action.risk_tier.value,
            )
            verdict: VerificationVerdict
            observed: dict[str, Any]
            margin: float | None
            if criteria_hash != action.verification_criteria_hash:  # pragma: no cover - defensive
                verdict, observed, margin = VerificationVerdict.INCONCLUSIVE, {}, None
            else:
                assert baseline_row is not None
                verdict, observed, margin = _evaluate(
                    deps, profile, criteria, baseline_row, action, target
                )

            window_end = deps.clock.now()
            window_seconds = int(criteria.get("window_seconds", 300))
            record = Verification(
                id=uuid.uuid4(),
                tenant_id=deps.context.tenant_id,
                remediation_action_id=action.id,
                attempt=attempt,
                callback_idempotency_key=verification_callback_key(
                    tenant_id=deps.context.tenant_id, action_id=action.id, attempt=attempt
                ),
                criteria_hash=criteria_hash,
                verdict=verdict,
                observed=observed,
                baseline=_baseline_json(baseline_row) if baseline_row else {},
                margin=margin,
                observation_window_start=window_end - timedelta(seconds=window_seconds),
                observation_window_end=window_end,
            )
            deps.session.add(record)
            deps.session.flush()

            deps.audit.record(
                deps.session,
                event_type=AuditEventType.VERIFICATION_RECORDED,
                outcome={
                    VerificationVerdict.VERIFIED: "succeeded",
                    VerificationVerdict.NOT_VERIFIED: "failed",
                    VerificationVerdict.INCONCLUSIVE: "recorded",
                }[verdict],
                actor_type=ActorType.SYSTEM,
                actor_id=NodeId.G10_VERIFIER.value,
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                target_type="remediation_action",
                target_id=str(action.id),
                risk_tier=action.risk_tier,
                payload={"verdict": verdict.value, "observed": observed, "attempt": attempt},
            )

            incident = deps.session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == deps.context.tenant_id,
                    Incident.id == deps.context.incident_id,
                )
            ).scalar_one()
            target_status, reason, termination_reason = {
                VerificationVerdict.VERIFIED: (
                    IncidentStatus.RESOLVED,
                    "verification confirmed the symptoms resolved",
                    TerminationReason.SUCCESS,
                ),
                VerificationVerdict.NOT_VERIFIED: (
                    IncidentStatus.INVESTIGATING,
                    "verification found the criteria not met; investigation resumes",
                    None,
                ),
                VerificationVerdict.INCONCLUSIVE: (
                    IncidentStatus.ESCALATED,
                    "verification could not reach a verdict; escalated rather than assumed",
                    TerminationReason.HUMAN_ESCALATION,
                ),
            }[verdict]
            apply_transition(
                deps.session,
                incident=incident,
                target=target_status,
                actor_type=ActorType.SYSTEM,
                source=NodeId.G10_VERIFIER.value,
                correlation_id=deps.context.correlation_id,
                termination_reason=termination_reason,
            )
            append_incident_event(
                deps.session,
                incident=incident,
                event_type=IncidentEventType.VERIFICATION_RESULT,
                source=NodeId.G10_VERIFIER.value,
                actor_type=ActorType.SYSTEM,
                correlation_id=deps.context.correlation_id,
                payload={"action_id": str(action.id), "verdict": verdict.value},
                idempotency_key=incident_event_key(
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    event_type=IncidentEventType.VERIFICATION_RESULT.value,
                    subject_id=action.id,
                    occurrence_discriminator=str(attempt),
                ),
            )

            span.set_decision(verdict=verdict.value, observed=observed, margin=margin)
            update = {
                "phase": "terminated",
                "verification": VerificationRef(
                    verification_id=str(record.id),
                    attempt=attempt,
                    verdict=verdict,
                    margin=margin,
                ),
                "terminated": True,
                "termination_reason": reason,
                "target_incident_status": target_status.value,
            }
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _evaluate(
    deps: RemediationDependencies,
    profile: VerificationProfile,
    criteria: dict[str, Any],
    baseline: RemediationBaseline,
    action: RemediationAction,
    target: RemediationTarget,
) -> tuple[VerificationVerdict, dict[str, Any], float | None]:
    """Judge server-defined policy against independent baseline and observation."""
    if criteria != profile.to_dict():
        return VerificationVerdict.INCONCLUSIVE, {"reason": "malformed verification criteria"}, None
    assert action.executed_at is not None
    if not trusted_baseline(
        deps, profile, baseline, action, target, dispatch_at=action.executed_at
    ):
        return VerificationVerdict.INCONCLUSIVE, {"reason": "invalid trusted baseline"}, None
    observed = _observe(
        deps, profile, action=action, purpose="independent post-remediation verification"
    )
    if "observed_value" not in observed:
        return VerificationVerdict.INCONCLUSIVE, observed, None
    baseline_value = float(baseline.observed_value)
    observed_value = float(observed["observed_value"])
    threshold_passed = observed_value < profile.threshold
    direction_passed = (
        observed_value < baseline_value
        if profile.direction == "decrease"
        else observed_value > baseline_value
    )
    passed = threshold_passed and (direction_passed or not profile.require_improvement)
    margin = round(observed_value - profile.threshold, 6)
    observed.update(
        {
            "baseline_value": baseline_value,
            "threshold": profile.threshold,
            "threshold_passed": threshold_passed,
            "direction_passed": direction_passed,
            "profile_id": profile.profile_id,
        }
    )
    return (
        VerificationVerdict.VERIFIED if passed else VerificationVerdict.NOT_VERIFIED,
        observed,
        margin,
    )


def _observe(
    deps: RemediationDependencies,
    profile: VerificationProfile,
    *,
    action: RemediationAction,
    purpose: str,
) -> dict[str, Any]:
    now = deps.clock.now()
    window_start = now - timedelta(seconds=profile.window_seconds)
    result = deps.broker.invoke(
        deps.session,
        request=CapabilityRequest(
            node_id=NodeId.G10_VERIFIER,
            capability=profile.source_capability,
            service_name=deps.objective.service_name,
            arguments={
                "window_start": window_start,
                "window_end": now,
                "metric": profile.metric,
            },
            incident_id=deps.context.incident_id,
            correlation_id=deps.context.correlation_id,
            remediation_action_id=action.id,
            purpose=purpose,
        ),
        contract=G10_VERIFIER,
    )
    if not result.succeeded:
        return {"reason": result.failure.message if result.failure else "read failed"}

    samples = result.payload.get("samples") or []
    if len(samples) < profile.minimum_samples:
        return {"reason": "insufficient samples in observation window"}

    try:
        timestamp_text, value_text = str(samples[-1]).rsplit("=", 1)
        sample_time = datetime.fromisoformat(timestamp_text)
        observed_value = float(value_text)
    except (ValueError, IndexError):
        return {"reason": "could not parse observed sample"}
    if sample_time < window_start or sample_time > now:
        return {"reason": "post-action evidence is stale or future-dated"}
    series = str(result.payload.get("series", ""))
    if profile.metric not in series:
        return {"reason": "observation returned an unrelated metric"}
    source = str(result.payload.get("source", "")).strip()
    if not source or result.tool_execution_id is None:
        return {"reason": "observation has no independently attributable source"}
    if (
        result.resolved_scope.get("service") != deps.objective.service_name
        or result.resolved_scope.get("environment") != deps.objective.environment_name
    ):
        return {"reason": "observation scope differs from immutable remediation target"}
    return {
        "metric": profile.metric,
        "observed_value": observed_value,
        "observed_at": sample_time.isoformat(),
        "source": source,
        "tool_execution_id": str(result.tool_execution_id),
        "target_service_id": deps.objective.service_id,
        "target_environment_id": deps.objective.environment_id,
        "source_capability": profile.source_capability,
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
    }


def trusted_baseline(
    deps: RemediationDependencies,
    profile: VerificationProfile,
    baseline: RemediationBaseline,
    action: RemediationAction,
    target: RemediationTarget,
    *,
    dispatch_at: datetime,
) -> bool:
    execution = deps.session.scalar(
        sa.select(ToolExecution).where(
            ToolExecution.id == baseline.read_execution_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.capability == profile.source_capability,
        )
    )
    if execution is None or execution.outcome is None or execution.outcome.value != "succeeded":
        return False
    now = deps.clock.now()
    return bool(
        baseline.tenant_id == deps.context.tenant_id
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
        and baseline.provenance_hash == _baseline_provenance(baseline)
        and execution.resolved_scope.get("service") == deps.objective.service_name
        and execution.resolved_scope.get("environment") == deps.objective.environment_name
        and baseline.observed_at <= baseline.captured_at <= dispatch_at <= now
        and dispatch_at - baseline.observed_at
        <= timedelta(seconds=profile.max_baseline_age_seconds)
    )


def _baseline_json(row: RemediationBaseline) -> dict[str, Any]:
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


def _baseline_provenance(row: RemediationBaseline) -> str:
    value = _baseline_json(row)
    value.pop("provenance_hash")
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _action_ref(action: RemediationAction, capability: str) -> RemediationActionRef:
    return RemediationActionRef(
        action_id=str(action.id),
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        capability=capability,
        risk_tier=action.risk_tier,
        status=action.status,
        action_version_hash=action.action_version_hash,
        approval_required=action.approval_required,
    )


__all__ = ["trusted_baseline", "verifier_node"]
