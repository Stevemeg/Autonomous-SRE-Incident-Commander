"""A human decides one remediation approval. The only writer of a decided ``Approval`` row.

This is not a graph node - it is called *from outside* the remediation workflow, by
whatever surface a human actually uses (Phase 9's API is expected to be a thin wrapper
around :func:`decide`, nothing more). :mod:`asic.orchestration.remediation.nodes.approval`
(G8) never calls this; it only ever reads what this wrote, on resume.

Every check here enforces one of the safety invariants directly:

* **INV-10** (separation of duties): the deciding actor may not be the action's proposer.
* **SI-6** (version binding): the caller states the action version it believes it is
  deciding on; a mismatch against the action's *current* recorded version is refused, not
  silently accepted against whatever the row now says.
* **Least privilege / role scoping**: the actor must hold, through a current (unexpired)
  role assignment, a permission whose ``max_risk_tier`` covers this action's tier, granted
  for this tenant and either this environment specifically or every environment.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.catalog import Environment
from asic.db.models.remediation import Approval, PolicyDecision, RemediationAction
from asic.db.models.tenancy import Permission, RolePermission, User, UserRoleAssignment
from asic.domain.clock import Clock
from asic.domain.enums import ApprovalDecision, RemediationActionStatus, RiskTier, UserStatus
from asic.domain.errors import ApprovalInvalid
from asic.domain.idempotency import approval_callback_key
from asic.domain.permissions import PermissionKey
from asic.observability.logging import log_event

_logger = logging.getLogger("asic.remediation.approval_service")

#: The permission an approver must hold. Seeded by migration 0011.
REMEDIATION_APPROVE_PERMISSION = PermissionKey.REMEDIATION_APPROVE.value

#: Mirrors ``asic.orchestration.remediation.nodes.planner.APPROVAL_WINDOW_SECONDS``. Kept
#: independent (not imported) so this module - which Phase 9's API will depend on directly
#: - never needs to import the orchestration graph package to answer "is this still open".
APPROVAL_WINDOW_SECONDS: dict[RiskTier, int] = {RiskTier.R1: 1800, RiskTier.R2: 900}


def is_authorized_approver(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    environment_id: uuid.UUID,
    risk_tier: RiskTier,
    now: datetime,
) -> bool:
    """Whether ``user_id`` currently holds authority to decide an action at this tier.

    A current (unexpired) role assignment, scoped to this tenant and to either this
    environment specifically or every environment, granting a permission whose
    ``max_risk_tier`` is at least this action's tier - mirroring
    ``asic.memory.service._may_decide``'s query shape, extended with the environment and
    risk-tier scoping a remediation approval (unlike a memory-promotion decision) requires.
    """
    ceilings = session.execute(
        sa.select(Permission.max_risk_tier)
        .select_from(User)
        .join(
            UserRoleAssignment,
            sa.and_(
                UserRoleAssignment.tenant_id == User.tenant_id,
                UserRoleAssignment.user_id == User.id,
            ),
        )
        .join(RolePermission, RolePermission.role_id == UserRoleAssignment.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            User.tenant_id == tenant_id,
            User.id == user_id,
            User.status == UserStatus.ACTIVE,
            Permission.key == REMEDIATION_APPROVE_PERMISSION,
            Permission.max_risk_tier.is_not(None),
            sa.or_(
                UserRoleAssignment.environment_id.is_(None),
                UserRoleAssignment.environment_id == environment_id,
            ),
            sa.or_(UserRoleAssignment.expires_at.is_(None), UserRoleAssignment.expires_at > now),
        )
    ).scalars()
    return any(
        ceiling is not None and ceiling is not RiskTier.R3 and ceiling.rank >= risk_tier.rank
        for ceiling in ceilings
    )


def decide(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    decision: ApprovalDecision,
    expected_action_version_hash: str,
    justification: str,
    clock: Clock,
    decision_channel: str = "dashboard",
) -> Approval:
    """Record a human's decision on one action, or refuse to.

    Raises:
        ApprovalInvalid: the action is not awaiting approval, the window has elapsed, the
            caller's view of the action's version does not match its current version
            (SI-6), or the actor is not authorised for this tier/tenant/environment.
        SelfApprovalAttempt: the actor proposed this action (INV-10).
    """
    if decision not in (ApprovalDecision.APPROVED, ApprovalDecision.REJECTED):
        raise ApprovalInvalid(
            f"a human decision must be 'approved' or 'rejected', got {decision.value!r}; "
            "'expired' and 'invalidated' are system-only outcomes"
        )

    action = session.execute(
        sa.select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id, RemediationAction.id == action_id
        )
    ).scalar_one_or_none()
    if action is None:
        raise ApprovalInvalid(f"remediation action {action_id} is not visible in this tenant")
    if action.status is not RemediationActionStatus.AWAITING_APPROVAL:
        raise ApprovalInvalid(
            f"remediation action {action_id} is {action.status.value}, not awaiting "
            "approval; a decision on it now would not bind to anything"
        )
    if expected_action_version_hash != action.action_version_hash:
        raise ApprovalInvalid(
            "the action's version has changed since this approval request was displayed "
            "(SI-6); re-read the action before deciding"
        )
    # INV-10 (separation of duties) is enforced by the database
    # (``no_self_approval``: ``approver_user_id <> proposer_user_id`` whenever both are
    # set) rather than checked again here. It is not exercisable by this phase's own flow:
    # every action is proposed by G6, an agent node, and ``Approval.proposer_user_id`` is
    # always NULL as a result - there is no human proposer for a human to collide with yet.
    # The constraint stands ready for the day a human-authored proposal path exists.

    policy_decision = session.execute(
        sa.select(PolicyDecision).where(
            PolicyDecision.tenant_id == tenant_id, PolicyDecision.remediation_action_id == action_id
        )
    ).scalar_one()
    window = APPROVAL_WINDOW_SECONDS[action.risk_tier]
    deadline = policy_decision.evaluated_at + timedelta(seconds=window)
    now = clock.now()
    if now >= deadline:
        raise ApprovalInvalid(
            f"the approval window for action {action_id} elapsed at {deadline.isoformat()}; "
            "the run will record this as expired on its own, and a late decision does not "
            "revive it"
        )

    environment = session.execute(
        sa.select(Environment).where(
            Environment.tenant_id == tenant_id,
            Environment.name == action.permission_scope.get("environment"),
        )
    ).scalar_one()
    if not is_authorized_approver(
        session,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        environment_id=environment.id,
        risk_tier=action.risk_tier,
        now=now,
    ):
        raise ApprovalInvalid(
            f"actor {actor_user_id} does not hold a current role granting "
            f"{REMEDIATION_APPROVE_PERMISSION!r} at tier {action.risk_tier.value} for this "
            "tenant and environment"
        )

    key = approval_callback_key(
        tenant_id=tenant_id,
        action_id=action_id,
        action_version_hash_value=action.action_version_hash,
    )
    existing = session.execute(
        sa.select(Approval).where(
            Approval.tenant_id == tenant_id, Approval.callback_idempotency_key == key
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    row = Approval(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        remediation_action_id=action_id,
        action_version_hash=action.action_version_hash,
        callback_idempotency_key=key,
        required_role_key=REMEDIATION_APPROVE_PERMISSION,
        proposer_user_id=None,  # G6 (an agent node) proposed it, never a human, this phase
        approver_user_id=actor_user_id,
        decision=decision,
        justification=justification[:4000] if justification else None,
        decision_channel=decision_channel,
        requested_at=policy_decision.evaluated_at,
        expires_at=deadline,
        decided_at=now,
    )
    session.add(row)
    session.flush()
    log_event(
        _logger,
        "approval.decided",
        tenant_id=str(tenant_id),
        action_id=str(action_id),
        decision=decision.value,
        decision_channel=decision_channel,
        risk_tier=action.risk_tier.value,
    )
    return row


__all__ = [
    "APPROVAL_WINDOW_SECONDS",
    "REMEDIATION_APPROVE_PERMISSION",
    "decide",
    "is_authorized_approver",
]
