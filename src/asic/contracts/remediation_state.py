"""Graph state for the remediation workflow (Phase 8).

A separate state shape from :mod:`asic.contracts.state`, for the reason ADR-0023 records:
remediation is a separate graph over the same four kinds of state
(``orchestration-kernel.md`` section 3) that investigation uses, not an extension of
investigation's own state. Reusing :class:`~asic.contracts.state.GraphState` would mean
every remediation-only key (an approval, a policy decision) permanently exists on every
investigation run too, and a node contract's ``permitted_state_keys`` would stop being a
precise description of what that node actually touches.

Remediation is linear, not a bounded loop: one action is proposed, evaluated, optionally
approved, executed and verified per run. There is no accumulating list of steps here the
way investigation accumulates evidence - each reference below is the *current* state of
one thing, replaced wholesale as the run advances through G6 -> G7 -> (G8) -> G9 -> G10.
"""

from __future__ import annotations

from typing import TypedDict

from pydantic import BaseModel, ConfigDict

from asic.contracts.state import BudgetSnapshot, NodeFailureRef, RunIdentity, TraceContext
from asic.domain.enums import (
    ApprovalDecision,
    PolicyVerdict,
    RemediationActionStatus,
    RiskTier,
    VerificationVerdict,
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class RemediationObjective(_Frozen):
    """What this remediation run is trying to fix, and within what bounds.

    Resolved from durable rows by the kernel, exactly as
    :class:`~asic.contracts.state.InvestigationObjective` is - never from model output, so
    a planner cannot widen which hypothesis or which service it is proposing an action
    against.
    """

    incident_reference: str
    hypothesis_id: str
    hypothesis_statement: str
    root_cause_class: str
    service_names: tuple[str, ...]
    environment_name: str
    is_production: bool


class RemediationActionRef(_Frozen):
    """A pointer to the one persisted :class:`~asic.db.models.remediation.RemediationAction`
    this run concerns."""

    action_id: str
    tool_name: str
    tool_version: str
    capability: str
    risk_tier: RiskTier
    status: RemediationActionStatus
    action_version_hash: str
    approval_required: bool


class PolicyDecisionRef(_Frozen):
    """A pointer to G7's persisted verdict."""

    verdict: PolicyVerdict
    rule_id: str
    ambiguity_signals: tuple[str, ...] = ()


class ApprovalRef(_Frozen):
    """A pointer to the current :class:`~asic.db.models.remediation.Approval` row, if any.

    ``decision`` is ``None`` while the request is outstanding - the state a durable
    interrupt suspends the run in.
    """

    approval_id: str
    decision: ApprovalDecision | None
    expires_at: str


class VerificationRef(_Frozen):
    """A pointer to G10's persisted verdict for one attempt."""

    verification_id: str
    attempt: int
    verdict: VerificationVerdict
    margin: float | None = None


class RemediationGraphState(TypedDict, total=False):
    """The state LangGraph threads between remediation nodes."""

    identity: RunIdentity
    trace: TraceContext
    objective: RemediationObjective

    phase: str
    remediation_action: RemediationActionRef | None
    policy_decision: PolicyDecisionRef | None
    approval: ApprovalRef | None
    verification: VerificationRef | None

    budget: BudgetSnapshot
    failures: list[NodeFailureRef]

    terminated: bool
    termination_reason: str | None
    #: The incident-status transition this run's outcome drives, applied by the kernel
    #: through the same :func:`asic.db.projections.apply_transition` investigation uses.
    target_incident_status: str | None


#: Every key the remediation graph state may contain.
REMEDIATION_STATE_KEYS: frozenset[str] = frozenset(RemediationGraphState.__annotations__)

#: Fixed for the lifetime of a remediation run, exactly as investigation's are.
REMEDIATION_IMMUTABLE_STATE_KEYS: frozenset[str] = frozenset({"identity", "trace", "objective"})


def remediation_state_summary(state: RemediationGraphState) -> dict[str, object]:
    """A compact, JSON-safe view for span attributes and log lines."""
    action = state.get("remediation_action")
    return {
        "phase": state.get("phase", "initialising"),
        "action_id": action.action_id if action else None,
        "action_status": action.status.value if action else None,
        "terminated": state.get("terminated", False),
        "termination_reason": state.get("termination_reason"),
        "target_incident_status": state.get("target_incident_status"),
    }


__all__ = [
    "REMEDIATION_IMMUTABLE_STATE_KEYS",
    "REMEDIATION_STATE_KEYS",
    "ApprovalRef",
    "PolicyDecisionRef",
    "RemediationActionRef",
    "RemediationGraphState",
    "RemediationObjective",
    "VerificationRef",
    "remediation_state_summary",
]
