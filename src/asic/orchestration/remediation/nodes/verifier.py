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
from datetime import timedelta
from typing import Any

import sqlalchemy as sa

from asic.contracts.nodes import G10_VERIFIER
from asic.contracts.remediation_state import RemediationGraphState, VerificationRef
from asic.db.models.incident import Incident
from asic.db.models.remediation import RemediationAction, Verification
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
from asic.tools.broker import CapabilityRequest
from asic.tools.registry import ToolRegistry

_OPERATORS: dict[str, Any] = {
    "<": lambda observed, threshold: observed < threshold,
    "<=": lambda observed, threshold: observed <= threshold,
    ">": lambda observed, threshold: observed > threshold,
    ">=": lambda observed, threshold: observed >= threshold,
}


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

            assert action.executed_at is not None  # guarded by the graph's routing
            settled_at = action.executed_at + timedelta(seconds=descriptor.settling_seconds)
            if deps.clock.now() < settled_at:
                span.set_decision(settled=False, settled_at=settled_at.isoformat())
                update: dict[str, Any] = {"phase": "awaiting_settling", "terminated": False}
                contract.validate_update(update)
                return update

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
                verdict, observed, margin = _evaluate(deps, criteria)

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
                baseline=dict(action.baseline_snapshot or {}),
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
    deps: RemediationDependencies, criteria: dict[str, Any]
) -> tuple[VerificationVerdict, dict[str, Any], float | None]:
    """Independently observe the criteria's metric and judge it. Never trusts the executor."""
    metric = criteria.get("metric")
    operator = criteria.get("operator")
    threshold = criteria.get("threshold")
    window_seconds = int(criteria.get("window_seconds", 300))
    if not metric or operator not in _OPERATORS or threshold is None:
        return VerificationVerdict.INCONCLUSIVE, {"reason": "malformed verification criteria"}, None

    now = deps.clock.now()
    result = deps.broker.invoke(
        deps.session,
        request=CapabilityRequest(
            node_id=NodeId.G10_VERIFIER,
            capability="read.metrics",
            service_name=deps.context.scope.service_names[0],
            arguments={
                "window_start": now - timedelta(seconds=window_seconds),
                "window_end": now,
                "metric": metric,
            },
            incident_id=deps.context.incident_id,
            correlation_id=deps.context.correlation_id,
            purpose="independent post-remediation verification",
        ),
        contract=G10_VERIFIER,
    )
    if not result.succeeded:
        return (
            VerificationVerdict.INCONCLUSIVE,
            {"reason": result.failure.message if result.failure else "read failed"},
            None,
        )

    samples = result.payload.get("samples") or []
    if not samples:
        return (
            VerificationVerdict.INCONCLUSIVE,
            {"reason": "no samples in observation window"},
            None,
        )

    try:
        observed_value = float(str(samples[-1]).split("=")[-1])
    except (ValueError, IndexError):
        return VerificationVerdict.INCONCLUSIVE, {"reason": "could not parse observed sample"}, None

    passed = _OPERATORS[operator](observed_value, float(threshold))
    margin = round(observed_value - float(threshold), 6)
    verdict = VerificationVerdict.VERIFIED if passed else VerificationVerdict.NOT_VERIFIED
    return (
        verdict,
        {"metric": metric, "observed_value": observed_value, "threshold": threshold},
        margin,
    )


__all__ = ["verifier_node"]
