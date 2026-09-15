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
from asic.db.projections import append_incident_event, apply_transition
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    RemediationActionStatus,
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
from asic.remediation.trust import (
    baseline_json,
    baseline_provenance,
    observation_provenance,
    trusted_baseline_record,
)
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
                    provenance_hash="",  # filled from the typed row below
                )
                baseline_row.provenance_hash = baseline_provenance(baseline_row)
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
            post_execution_id: uuid.UUID | None = None
            post_observed_at: datetime | None = None
            post_observed_value: float | None = None
            post_source: str | None = None
            post_provenance: str | None = None
            if "observed_value" in observed and baseline_row is not None:
                post_execution_id = uuid.UUID(str(observed["tool_execution_id"]))
                post_observed_at = datetime.fromisoformat(str(observed["observed_at"]))
                post_observed_value = float(observed["observed_value"])
                post_source = str(observed["source"])
                post_provenance = observation_provenance(
                    tenant_id=deps.context.tenant_id,
                    incident_id=action.incident_id,
                    remediation_target_id=target.id,
                    remediation_action_id=action.id,
                    remediation_baseline_id=baseline_row.id,
                    service_id=target.service_id,
                    environment_id=target.environment_id,
                    profile_id=profile.profile_id,
                    profile_version=profile.profile_version,
                    criteria_hash=action.verification_criteria_hash,
                    metric=profile.metric,
                    source_capability=profile.source_capability,
                    source_provider=post_source,
                    read_execution_id=post_execution_id,
                    observed_at=post_observed_at,
                    observed_value=post_observed_value,
                )
            record = Verification(
                id=uuid.uuid4(),
                tenant_id=deps.context.tenant_id,
                remediation_action_id=action.id,
                remediation_baseline_id=baseline_row.id if post_execution_id else None,
                post_action_read_execution_id=post_execution_id,
                profile_id=profile.profile_id if post_execution_id else None,
                profile_version=profile.profile_version if post_execution_id else None,
                observed_metric=profile.metric if post_execution_id else None,
                observed_value=post_observed_value,
                observed_at=post_observed_at,
                observation_source_provider=post_source,
                observation_source_capability=(
                    profile.source_capability if post_execution_id else None
                ),
                observation_provenance_hash=post_provenance,
                attempt=attempt,
                callback_idempotency_key=verification_callback_key(
                    tenant_id=deps.context.tenant_id, action_id=action.id, attempt=attempt
                ),
                criteria_hash=criteria_hash,
                verdict=verdict,
                observed=observed,
                baseline=baseline_json(baseline_row) if baseline_row else {},
                margin=margin,
                observation_window_start=window_end - timedelta(seconds=window_seconds),
                observation_window_end=window_end,
                verified_at=window_end,
            )
            deps.session.add(record)
            action.status = {
                VerificationVerdict.VERIFIED: RemediationActionStatus.VERIFIED,
                VerificationVerdict.NOT_VERIFIED: RemediationActionStatus.NOT_VERIFIED,
                VerificationVerdict.INCONCLUSIVE: RemediationActionStatus.INCONCLUSIVE,
            }[verdict]
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
    return trusted_baseline_record(
        deps.session,
        tenant_id=deps.context.tenant_id,
        profile=profile,
        baseline=baseline,
        action=action,
        target=target,
        service_name=deps.objective.service_name,
        environment_name=deps.objective.environment_name,
        dispatch_at=dispatch_at,
        as_of=deps.clock.now(),
    )


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
