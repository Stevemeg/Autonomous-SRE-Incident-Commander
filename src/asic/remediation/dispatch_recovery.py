"""Durable dispatch evidence: what a crashed execution left behind, and what it means.

The executor's own transaction commits at the node boundary, *after* the write. A process
that dies between the adapter's response and that commit therefore loses the execution
receipt and the in-session status update alike, and a later pass sees an action that still
looks un-dispatched while the external system has already changed. Reading "the deployment
is not on the revision we expected" as *precondition drift* - "nothing happened, try
something else" - is exactly the inversion SI-8 forbids.

Two durable facts exist outside that transaction and survive the crash:

* the **execution intent** (``executing``), committed by :func:`record_execution_intent`
  before dispatch - the checkpoint that `failure-and-recovery.md` §3.1 requires *before*
  any state-changing tool call;
* the **effect claim**, committed by the broker in its own transaction immediately before
  the adapter is invoked (:func:`asic.tools.broker.dispatch_claim_exists`).

Together they let recovery place an interrupted action in exactly one of three states, named
by :class:`DispatchState` and decided in one place, :attr:`DispatchEvidence.state`:

============================  ==========================================================
Durable evidence              Meaning
============================  ==========================================================
no claim                      ``NO_EFFECT_ATTEMPTED`` - nothing reached an adapter
claim, no conclusive receipt  ``EFFECT_MAY_HAVE_OCCURRED`` - reconcile, never assume
receipt                       the broker already classified it; replay that classification
============================  ==========================================================

``EFFECT_MAY_HAVE_OCCURRED`` never becomes ``failed_clean``. It is reconciled by an
independent read and, when that cannot confirm the effect, escalated as a partial effect
for a human - the conservative direction of §5.2's table.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.remediation import RemediationAction
from asic.db.models.tools import ToolExecution
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.enums import RemediationActionStatus, RiskTier, ToolExecutionOutcome
from asic.observability import lifecycle
from asic.tools.broker import dispatch_claim_exists

#: Statuses an action may hold when the executor is about to dispatch. Any other status is
#: terminal or awaiting a decision, and the executor routes it before recovery is reached.
_PRE_DISPATCH: frozenset[RemediationActionStatus] = frozenset(
    {
        RemediationActionStatus.AUTHORIZED,
        RemediationActionStatus.APPROVED,
        RemediationActionStatus.AWAITING_APPROVAL,
        RemediationActionStatus.EXECUTING,
    }
)


class DispatchState(StrEnum):
    """What the durable record says about an interrupted dispatch."""

    NO_EFFECT_ATTEMPTED = "no_effect_attempted"
    EFFECT_MAY_HAVE_OCCURRED = "effect_may_have_occurred"
    RECEIPT_RECORDED = "receipt_recorded"


@dataclass(frozen=True, slots=True)
class DispatchEvidence:
    """Everything durable about one action's dispatch, read inside the caller's session."""

    intent_recorded: bool
    claimed: bool
    receipt: ToolExecutionOutcome | None

    @property
    def state(self) -> DispatchState:
        if self.receipt is not None:
            return DispatchState.RECEIPT_RECORDED
        if self.claimed:
            return DispatchState.EFFECT_MAY_HAVE_OCCURRED
        return DispatchState.NO_EFFECT_ATTEMPTED

    @property
    def interrupted(self) -> bool:
        """True when a prior pass got far enough that this pass must not simply dispatch."""
        return self.intent_recorded or self.claimed or self.receipt is not None


def dispatch_evidence(
    session: Session, *, tenant_id: uuid.UUID, action: RemediationAction
) -> DispatchEvidence:
    """Read the durable dispatch evidence for one action.

    ``receipt`` is the outcome of the *write* execution only: precondition and
    reconciliation reads carry no ``remediation_action_id``, so they cannot be mistaken for
    evidence that the effect itself was recorded.
    """
    receipt = session.execute(
        sa.select(ToolExecution.outcome)
        .where(
            ToolExecution.tenant_id == tenant_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.risk_tier != RiskTier.RO,
        )
        .order_by(ToolExecution.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    return DispatchEvidence(
        intent_recorded=action.status is RemediationActionStatus.EXECUTING,
        claimed=dispatch_claim_exists(
            session, tenant_id=tenant_id, remediation_action_id=action.id
        ),
        receipt=receipt,
    )


def record_execution_intent(
    session_factory: Callable[[], Session],
    *,
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
) -> bool:
    """Commit ``executing`` in its own transaction, before anything can be dispatched.

    Committed outside the node's unit of work on purpose: the node's transaction is what a
    crash takes away, and an intent that disappears with it cannot tell recovery that a
    dispatch was ever begun. Guarded on the current status so a concurrent or resumed pass
    cannot move a terminal action back into ``executing``.

    Returns:
        Whether this call performed the transition.
    """
    session = session_factory()
    try:
        bind_tenant(session, tenant_id)
        apply_statement_timeouts(session)
        transitioned = lifecycle.core_update(
            session,
            sa.update(RemediationAction)
            .where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.id == action_id,
                RemediationAction.status.in_(sorted(_PRE_DISPATCH, key=lambda s: s.value)),
            )
            .values(status=RemediationActionStatus.EXECUTING),
        )
        session.commit()
        return bool(transitioned)
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


__all__ = [
    "DispatchEvidence",
    "DispatchState",
    "dispatch_evidence",
    "record_execution_intent",
]
