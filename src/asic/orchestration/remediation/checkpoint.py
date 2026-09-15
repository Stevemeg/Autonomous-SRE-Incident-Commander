"""Checkpointing for the remediation graph.

Reuses :class:`~asic.db.models.orchestration.WorkflowCheckpoint` - the table carries nothing
investigation-specific - and :func:`asic.orchestration.checkpoint.digest_state`, but not
:class:`~asic.orchestration.checkpoint.CheckpointStore` itself, whose ``serialise``/
``rehydrate`` pair is written against investigation's own key set. Remediation's state is
smaller and has no accumulating lists, so its own pair is a few lines rather than a
generalisation of investigation's.

The one property this module exists to provide: **a suspended remediation run - most often
one waiting on a human approval decision - resumes by re-reading durable rows, never by
trusting what a checkpoint said was true when it was written.** ``remediation_action``,
``policy_decision``, ``approval`` and ``verification`` are all re-read fresh from their own
tables on resume; only ``phase``, ``terminated``, ``termination_reason`` and
``target_incident_status`` come from the checkpoint itself.
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.remediation_state import (
    ApprovalRef,
    PolicyDecisionRef,
    RemediationActionRef,
    RemediationGraphState,
    RemediationObjective,
    VerificationRef,
)
from asic.contracts.state import BudgetSnapshot, RunIdentity, TraceContext
from asic.db.models.incident import WorkflowRun
from asic.db.models.orchestration import WorkflowCheckpoint
from asic.db.models.remediation import Approval, PolicyDecision, RemediationAction, Verification
from asic.domain.budget import BudgetState
from asic.domain.clock import Clock
from asic.orchestration.checkpoint import CHECKPOINT_REASONS, digest_state

_EPHEMERAL_KEYS: tuple[str, ...] = (
    "phase",
    "terminated",
    "termination_reason",
    "target_incident_status",
)


def serialise(state: RemediationGraphState) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in _EPHEMERAL_KEYS:
        if key in state:
            payload[key] = state[key]  # type: ignore[literal-required]
    return payload


def write(
    session: Session,
    *,
    state: RemediationGraphState,
    reason: str,
    after_node: str | None,
    budget: BudgetState,
    clock: Clock,
) -> WorkflowCheckpoint:
    if reason not in CHECKPOINT_REASONS:
        raise ValueError(f"checkpoint reason {reason!r} is not one of {sorted(CHECKPOINT_REASONS)}")
    identity = state["identity"]
    tenant_id = uuid.UUID(identity.tenant_id)
    run_id = uuid.UUID(identity.workflow_run_id)

    session.execute(
        sa.select(WorkflowRun.id)
        .where(WorkflowRun.tenant_id == tenant_id, WorkflowRun.id == run_id)
        .with_for_update()
    ).scalar_one()
    high_water = session.execute(
        sa.select(sa.func.coalesce(sa.func.max(WorkflowCheckpoint.sequence), 0)).where(
            WorkflowCheckpoint.tenant_id == tenant_id,
            WorkflowCheckpoint.workflow_run_id == run_id,
        )
    ).scalar_one()

    payload = serialise(state)
    checkpoint = WorkflowCheckpoint(
        tenant_id=tenant_id,
        workflow_run_id=run_id,
        incident_id=uuid.UUID(identity.incident_id),
        sequence=int(high_water) + 1,
        after_node=after_node,
        reason=reason,
        state=payload,
        state_digest=digest_state(payload),
        durable_counts={},
        budget_consumed=budget.to_dict(),
        behaviour_version_id=uuid.UUID(identity.behaviour_version_id),
        correlation_id=uuid.UUID(state["trace"].correlation_id),
        taken_at=clock.now(),
    )
    session.add(checkpoint)
    session.flush()
    return checkpoint


def latest(
    session: Session, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> WorkflowCheckpoint | None:
    return session.execute(
        sa.select(WorkflowCheckpoint)
        .where(
            WorkflowCheckpoint.tenant_id == tenant_id,
            WorkflowCheckpoint.workflow_run_id == run_id,
        )
        .order_by(WorkflowCheckpoint.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()


class CheckpointIntegrityError(RuntimeError):
    """A checkpoint could not be trusted enough to resume from."""


def rehydrate(
    session: Session,
    *,
    checkpoint: WorkflowCheckpoint,
    identity: RunIdentity,
    trace: TraceContext,
    objective: RemediationObjective,
) -> RemediationGraphState:
    """Rebuild working state: durable rows for the four references, the checkpoint for the rest.

    Raises:
        CheckpointIntegrityError: the stored digest does not match the stored state.
    """
    stored = dict(checkpoint.state or {})
    if digest_state(stored) != checkpoint.state_digest:
        raise CheckpointIntegrityError(
            f"checkpoint {checkpoint.id} fails its own digest; the stored state has been "
            "altered or truncated since it was written and will not be resumed from"
        )

    tenant_id = uuid.UUID(identity.tenant_id)
    run_id = uuid.UUID(identity.workflow_run_id)

    action = session.execute(
        sa.select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id, RemediationAction.workflow_run_id == run_id
        )
    ).scalar_one_or_none()

    policy_decision_ref: PolicyDecisionRef | None = None
    approval_ref: ApprovalRef | None = None
    verification_ref: VerificationRef | None = None
    action_ref: RemediationActionRef | None = None

    if action is not None:
        action_ref = RemediationActionRef(
            action_id=str(action.id),
            tool_name=action.tool_name,
            tool_version=action.tool_version,
            capability=action.tool_name,
            risk_tier=action.risk_tier,
            status=action.status,
            action_version_hash=action.action_version_hash,
            approval_required=action.approval_required,
        )
        decision = session.execute(
            sa.select(PolicyDecision).where(
                PolicyDecision.tenant_id == tenant_id,
                PolicyDecision.remediation_action_id == action.id,
            )
        ).scalar_one_or_none()
        if decision is not None:
            policy_decision_ref = PolicyDecisionRef(
                verdict=decision.verdict,
                rule_id=decision.rule_id,
                ambiguity_signals=tuple(decision.ambiguity_signals or ()),
            )
        approval = session.execute(
            sa.select(Approval)
            .where(
                Approval.tenant_id == tenant_id,
                Approval.remediation_action_id == action.id,
                Approval.action_version_hash == action.action_version_hash,
            )
            .order_by(Approval.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if approval is not None:
            approval_ref = ApprovalRef(
                approval_id=str(approval.id),
                decision=approval.decision,
                expires_at=approval.expires_at.isoformat(),
            )
        verification = session.execute(
            sa.select(Verification)
            .where(
                Verification.tenant_id == tenant_id,
                Verification.remediation_action_id == action.id,
            )
            .order_by(Verification.attempt.desc())
            .limit(1)
        ).scalar_one_or_none()
        if verification is not None:
            verification_ref = VerificationRef(
                verification_id=str(verification.id),
                attempt=verification.attempt,
                verdict=verification.verdict,
                margin=float(verification.margin) if verification.margin is not None else None,
            )

    state: RemediationGraphState = {
        "identity": identity,
        "trace": trace,
        "objective": objective,
        "phase": stored.get("phase", "planning"),
        "remediation_action": action_ref,
        "policy_decision": policy_decision_ref,
        "approval": approval_ref,
        "verification": verification_ref,
        "baseline_captured": bool(action and action.baseline_snapshot),
        "failures": [],
        "terminated": bool(stored.get("terminated", False)),
        "termination_reason": stored.get("termination_reason"),
        "target_incident_status": stored.get("target_incident_status"),
    }
    budget = BudgetState.from_dict(dict(checkpoint.budget_consumed))
    exhausted = budget.exhausted_kind()
    state["budget"] = BudgetSnapshot(
        consumed=budget.ledger.to_dict(),
        remaining=budget.remaining(),
        exhausted_kind=exhausted.value if exhausted else None,
    )
    return state


__all__ = [
    "CheckpointIntegrityError",
    "latest",
    "rehydrate",
    "serialise",
    "write",
]
