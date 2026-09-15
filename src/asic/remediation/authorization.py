"""Dispatch-time authorization from durable policy and trusted human identity."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.remediation import (
    Approval,
    PolicyDecision,
    RemediationAction,
    RemediationTarget,
)
from asic.domain.enums import ApprovalDecision, PolicyVerdict, RemediationActionStatus
from asic.domain.errors import CapabilityNotGranted
from asic.domain.idempotency import action_version_hash
from asic.remediation.approval_service import is_authorized_approver
from asic.tools.descriptor import ToolDescriptor


def require_write_authority(
    session: Session,
    *,
    action: RemediationAction,
    descriptor: ToolDescriptor,
    arguments: Mapping[str, Any],
    environment_id: uuid.UUID,
    service_name: str,
    resolved_scope: Mapping[str, Any],
    now: datetime,
) -> None:
    """Refuse before dispatch if the approved effect or its authority has changed."""
    if (
        action.status is not RemediationActionStatus.EXECUTING
        or action.tool_name != descriptor.name
        or action.tool_version != descriptor.version
        or action.risk_tier is not descriptor.risk_tier
        or list(action.preconditions) != list(descriptor.preconditions)
        or dict(action.arguments) != dict(arguments)
    ):
        raise CapabilityNotGranted("write request does not match an executing registered action")
    current_hash = action_version_hash(
        action_id=action.id,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments=action.arguments,
        permission_scope=action.permission_scope,
        preconditions=action.preconditions,
        risk_tier=action.risk_tier.value,
    )
    if current_hash != action.action_version_hash:
        raise CapabilityNotGranted("action version changed before dispatch (SI-6)")
    target = session.execute(
        sa.select(RemediationTarget).where(
            RemediationTarget.tenant_id == action.tenant_id,
            RemediationTarget.id == action.remediation_target_id,
            RemediationTarget.workflow_run_id == action.workflow_run_id,
            RemediationTarget.incident_id == action.incident_id,
            RemediationTarget.hypothesis_id == action.hypothesis_id,
            RemediationTarget.environment_id == environment_id,
        )
    ).scalar_one_or_none()
    if target is None:
        raise CapabilityNotGranted("write action is not bound to its immutable remediation target")
    frozen = dict(target.resolved_permission_scope)
    if frozen.get("service") != service_name:
        raise CapabilityNotGranted("write service does not match immutable remediation target")
    normalized_scope = {
        key: str(value) if isinstance(value, uuid.UUID) else value
        for key, value in resolved_scope.items()
    }
    if any(frozen.get(key) != value for key, value in normalized_scope.items()):
        raise CapabilityNotGranted(
            "resolved broker scope differs from immutable remediation target"
        )
    if dict(action.permission_scope) != frozen:
        raise CapabilityNotGranted(
            "action permission scope differs from immutable remediation target"
        )
    policy = session.execute(
        sa.select(PolicyDecision).where(
            PolicyDecision.tenant_id == action.tenant_id,
            PolicyDecision.remediation_action_id == action.id,
        )
    ).scalar_one_or_none()
    if policy is None or policy.verdict is PolicyVerdict.DENY:
        raise CapabilityNotGranted("write requires a durable permitting policy decision")
    if policy.verdict is PolicyVerdict.ALLOW:
        return
    approval = session.execute(
        sa.select(Approval)
        .where(
            Approval.tenant_id == action.tenant_id,
            Approval.remediation_action_id == action.id,
            Approval.action_version_hash == current_hash,
        )
        .order_by(Approval.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if (
        approval is None
        or approval.decision is not ApprovalDecision.APPROVED
        or approval.approver_user_id is None
        or approval.expires_at <= now
        or approval.decided_at is None
        or approval.decided_at > now
        or approval.decision_channel == "system"
        or not is_authorized_approver(
            session,
            tenant_id=action.tenant_id,
            user_id=approval.approver_user_id,
            environment_id=environment_id,
            risk_tier=action.risk_tier,
            now=now,
        )
    ):
        raise CapabilityNotGranted("write requires a current, scoped human approval")
