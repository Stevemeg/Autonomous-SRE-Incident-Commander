"""G8 Approval Service.

Deterministic, and the only node whose normal outcome can be "the run is not finished, and
nothing further happens until a human acts". That outcome is a **durable interrupt**, not a
crash: the run suspends with everything it has done so far committed, exactly as a crash
suspension does, and resumes by re-entering this same node and re-reading the durable
``approval`` row - never trusting anything held in memory across the wait.

The one property that makes SI-6/SI-7 real here: an ``approval`` row is only ever inserted
with a *final* decision (:mod:`asic.remediation.approval_service` is the only writer, and it
is never called from inside this graph - a human, or whatever surface eventually calls it on
a human's behalf, calls it). There is no "pending" row to race against; "pending" is the
*absence* of a row, and this node's only job while it is absent is to notice whether the
window has expired.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

import sqlalchemy as sa

from asic.contracts.nodes import G8_APPROVAL_SERVICE
from asic.contracts.remediation_state import ApprovalRef, RemediationGraphState
from asic.db.models.incident import Incident
from asic.db.models.remediation import Approval, PolicyDecision, RemediationAction
from asic.db.projections import append_incident_event, apply_transition
from asic.domain.enums import (
    ActorType,
    ApprovalDecision,
    AuditEventType,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    TerminationReason,
    TraceSpanKind,
)
from asic.domain.idempotency import approval_callback_key, incident_event_key
from asic.orchestration.remediation.context import RemediationDependencies
from asic.orchestration.remediation.nodes.planner import APPROVAL_WINDOW_SECONDS

#: The event naming this node's own incident-timeline entries; kept distinct from the
#: approval *decision* events, which are emitted by the approval service itself when a
#: human actually decides.
_REQUESTED_DISCRIMINATOR = "requested"


def approval_service_node(deps: RemediationDependencies) -> Any:
    """Build the approval node."""

    contract = G8_APPROVAL_SERVICE

    def run(state: RemediationGraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.approval_service",
            node_id=NodeId.G8_APPROVAL_SERVICE,
            node_version=contract.node_version,
        ) as span:
            action_ref = state.get("remediation_action")
            assert action_ref is not None
            action_id = uuid.UUID(action_ref.action_id)

            action = deps.session.execute(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == action_id,
                )
            ).scalar_one()

            existing = deps.session.execute(
                sa.select(Approval)
                .where(
                    Approval.tenant_id == deps.context.tenant_id,
                    Approval.remediation_action_id == action_id,
                    Approval.action_version_hash == action.action_version_hash,
                )
                .order_by(Approval.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()

            if existing is not None:
                span.set_decision(decided=True, decision=existing.decision.value)
                return _route_decided(deps, contract, action, existing)

            decision_deadline = _deadline(deps, action)
            if deps.clock.now() >= decision_deadline:
                expired = _record_system_decision(
                    deps,
                    action,
                    decision=ApprovalDecision.EXPIRED,
                    requested_at=decision_deadline
                    - timedelta(seconds=APPROVAL_WINDOW_SECONDS[action.risk_tier]),
                    expires_at=decision_deadline,
                )
                span.set_decision(decided=True, decision="expired")
                return _route_decided(deps, contract, action, expired)

            # Still within the window, and not yet decided: request, and suspend.
            incident = deps.session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == deps.context.tenant_id,
                    Incident.id == deps.context.incident_id,
                )
            ).scalar_one()

            deps.audit.record(
                deps.session,
                event_type=AuditEventType.APPROVAL_REQUESTED,
                outcome="requested",
                actor_type=ActorType.SYSTEM,
                actor_id=NodeId.G8_APPROVAL_SERVICE.value,
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                target_type="remediation_action",
                target_id=str(action.id),
                risk_tier=action.risk_tier,
                payload={"expires_at": decision_deadline.isoformat()},
            )
            append_incident_event(
                deps.session,
                incident=incident,
                event_type=IncidentEventType.APPROVAL_REQUESTED,
                source=NodeId.G8_APPROVAL_SERVICE.value,
                actor_type=ActorType.SYSTEM,
                correlation_id=deps.context.correlation_id,
                payload={"action_id": str(action.id), "expires_at": decision_deadline.isoformat()},
                idempotency_key=incident_event_key(
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    event_type=IncidentEventType.APPROVAL_REQUESTED.value,
                    subject_id=action.id,
                    occurrence_discriminator=_REQUESTED_DISCRIMINATOR,
                ),
            )

            span.set_decision(decided=False, expires_at=decision_deadline.isoformat())
            update: dict[str, Any] = {
                "phase": "awaiting_approval",
                "approval": None,
                # Deliberately NOT terminated: the kernel suspends a remediation run that
                # reaches the end of the graph without terminating, and resumes it later by
                # re-entering this exact node.
                "terminated": False,
            }
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _deadline(deps: RemediationDependencies, action: RemediationAction) -> datetime:
    decision = deps.session.execute(
        sa.select(PolicyDecision).where(
            PolicyDecision.tenant_id == deps.context.tenant_id,
            PolicyDecision.remediation_action_id == action.id,
        )
    ).scalar_one()
    window = APPROVAL_WINDOW_SECONDS[action.risk_tier]
    return decision.evaluated_at + timedelta(seconds=window)


def _record_system_decision(
    deps: RemediationDependencies,
    action: RemediationAction,
    *,
    decision: ApprovalDecision,
    requested_at: datetime,
    expires_at: datetime,
) -> Approval:
    """Record a decision the *system*, not a human, reached: only ever ``expired``.

    A system-authored row has no approver - the check constraints require exactly that
    (``human_decision_names_approver``) - so this is the one caller of
    :class:`~asic.db.models.remediation.Approval` outside
    :mod:`asic.remediation.approval_service`, and it is restricted to the one decision a
    human cannot be the author of.
    """
    row = Approval(
        id=uuid.uuid4(),
        tenant_id=deps.context.tenant_id,
        remediation_action_id=action.id,
        action_version_hash=action.action_version_hash,
        callback_idempotency_key=approval_callback_key(
            tenant_id=deps.context.tenant_id,
            action_id=action.id,
            action_version_hash_value=action.action_version_hash,
        )
        + ":system_expiry",
        required_role_key="remediation.approve",
        proposer_user_id=None,
        approver_user_id=None,
        decision=decision,
        justification="approval window elapsed with no human decision recorded",
        decision_channel="system",
        requested_at=requested_at,
        expires_at=expires_at,
        decided_at=deps.clock.now(),
    )
    deps.session.add(row)
    deps.session.flush()
    return row


def _route_decided(
    deps: RemediationDependencies,
    contract: Any,
    action: RemediationAction,
    approval: Approval,
) -> dict[str, Any]:
    incident = deps.session.execute(
        sa.select(Incident).where(
            Incident.tenant_id == deps.context.tenant_id,
            Incident.id == deps.context.incident_id,
        )
    ).scalar_one()

    ref = ApprovalRef(
        approval_id=str(approval.id),
        decision=approval.decision,
        expires_at=approval.expires_at.isoformat(),
    )

    # A resumed run re-enters this node every time it re-enters the graph at all (no
    # attached checkpointer - the kernel's own docstring), so ``_route_decided`` runs again
    # on every later pass for an action whose approval was already actioned. The incident's
    # own status is the durable record of whether this decision's consequence has already
    # been applied: once it has moved on, the transition and the events below are replayed
    # as a no-op rather than re-applied (a second APPROVED pass would otherwise fail closed
    # against ``AWAITING_APPROVAL -> REMEDIATING`` no longer being a legal edge from
    # wherever the run has since reached, exactly as intended by "must only be written when
    # it actually changes").
    first_pass = incident.status is IncidentStatus.AWAITING_APPROVAL
    if first_pass:
        deps.audit.record(
            deps.session,
            event_type=AuditEventType.APPROVAL_DECIDED,
            outcome={
                ApprovalDecision.APPROVED: "allowed",
                ApprovalDecision.REJECTED: "denied",
                ApprovalDecision.EXPIRED: "expired",
                ApprovalDecision.INVALIDATED: "invalidated",
            }[approval.decision],
            actor_type=ActorType.HUMAN if approval.approver_user_id else ActorType.SYSTEM,
            actor_id=str(approval.approver_user_id) if approval.approver_user_id else "system",
            incident_id=deps.context.incident_id,
            correlation_id=deps.context.correlation_id,
            target_type="remediation_action",
            target_id=str(action.id),
            risk_tier=action.risk_tier,
            payload={"decision": approval.decision.value, "approval_id": str(approval.id)},
        )

    if approval.decision is ApprovalDecision.APPROVED:
        if first_pass:
            # AWAITING_APPROVAL -> REMEDIATING is restricted to a human actor
            # (asic.domain.incident_state.TRANSITIONS): a system-authored decision is never
            # APPROVED (_record_system_decision only ever produces EXPIRED), so an approver
            # is always on record here.
            apply_transition(
                deps.session,
                incident=incident,
                target=IncidentStatus.REMEDIATING,
                actor_type=ActorType.HUMAN,
                actor_id=str(approval.approver_user_id),
                source=NodeId.G8_APPROVAL_SERVICE.value,
                correlation_id=deps.context.correlation_id,
            )
            append_incident_event(
                deps.session,
                incident=incident,
                event_type=IncidentEventType.APPROVAL_GRANTED,
                source=NodeId.G8_APPROVAL_SERVICE.value,
                actor_type=ActorType.HUMAN if approval.approver_user_id else ActorType.SYSTEM,
                correlation_id=deps.context.correlation_id,
                payload={"action_id": str(action.id)},
                idempotency_key=incident_event_key(
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    event_type=IncidentEventType.APPROVAL_GRANTED.value,
                    subject_id=action.id,
                ),
            )
        update: dict[str, Any] = {
            "phase": "executing",
            "approval": ref,
            "terminated": False,
        }
        contract.validate_update(update)
        return update

    event_type, reason = {
        ApprovalDecision.REJECTED: (IncidentEventType.APPROVAL_REJECTED, "approval was rejected"),
        ApprovalDecision.EXPIRED: (IncidentEventType.APPROVAL_EXPIRED, "approval window elapsed"),
        ApprovalDecision.INVALIDATED: (
            IncidentEventType.APPROVAL_INVALIDATED_STALE,
            "the action changed after approval was requested",
        ),
    }[approval.decision]

    apply_transition(
        deps.session,
        incident=incident,
        target=IncidentStatus.ESCALATED,
        actor_type=ActorType.SYSTEM,
        source=NodeId.G8_APPROVAL_SERVICE.value,
        correlation_id=deps.context.correlation_id,
        termination_reason=TerminationReason.APPROVAL_NOT_GRANTED,
    )
    append_incident_event(
        deps.session,
        incident=incident,
        event_type=event_type,
        source=NodeId.G8_APPROVAL_SERVICE.value,
        actor_type=ActorType.HUMAN if approval.approver_user_id else ActorType.SYSTEM,
        correlation_id=deps.context.correlation_id,
        payload={"action_id": str(action.id), "reason": reason},
        idempotency_key=incident_event_key(
            tenant_id=deps.context.tenant_id,
            incident_id=deps.context.incident_id,
            event_type=event_type.value,
            subject_id=action.id,
        ),
    )
    update = {
        "phase": "terminated",
        "approval": ref,
        "terminated": True,
        "termination_reason": reason,
        "target_incident_status": IncidentStatus.ESCALATED.value,
    }
    contract.validate_update(update)
    return update


__all__ = ["approval_service_node"]
