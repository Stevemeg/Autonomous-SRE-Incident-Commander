"""Audit writing.

Every authorization decision and every effect produces a row here (SI-10, SEC-I7). The
property that makes it an audit trail rather than an application log is that it is written
at the chokepoint: the tool broker emits unconditionally, on both the allow and the refuse
path, so "an action occurred with no audit record" is not a reachable state.

Recording only refusals is a common and useless choice: a log that cannot say what was
permitted cannot answer the question an auditor actually asks.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy.orm import Session

from asic.db.models.audit import AuditRecord
from asic.domain.clock import Clock
from asic.domain.enums import ActorType, AuditEventType, RiskTier
from asic.observability.redaction import redact_mapping

#: The outcome vocabulary the ``ck_audit_record_known_outcome`` constraint accepts. Named
#: here so a caller cannot invent one and discover the problem at INSERT time.
ALLOWED_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "allowed",
        "denied",
        "succeeded",
        "failed",
        "requested",
        "expired",
        "invalidated",
        "recorded",
    }
)


class AuditWriter:
    """Writes immutable audit records for one tenant."""

    __slots__ = ("_clock", "_tenant_id")

    def __init__(self, *, tenant_id: uuid.UUID, clock: Clock) -> None:
        self._tenant_id = tenant_id
        self._clock = clock

    def record(
        self,
        session: Session,
        *,
        event_type: AuditEventType,
        outcome: str,
        actor_type: ActorType,
        actor_id: str | None = None,
        incident_id: uuid.UUID | None = None,
        tool_execution_id: uuid.UUID | None = None,
        remediation_action_id: uuid.UUID | None = None,
        approval_id: uuid.UUID | None = None,
        correlation_id: uuid.UUID | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        policy_rule_id: str | None = None,
        risk_tier: RiskTier | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> AuditRecord:
        """Append one audit record.

        The payload is redacted here rather than by the caller, so a caller that forgets
        cannot leak. Redaction at emission is the only kind that works: filtering on read
        cannot un-write a secret.
        """
        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError(
                f"audit outcome {outcome!r} is not in the accepted vocabulary "
                f"{sorted(ALLOWED_OUTCOMES)}"
            )
        record = AuditRecord(
            tenant_id=self._tenant_id,
            event_type=event_type,
            occurred_at=self._clock.now(),
            actor_type=actor_type,
            actor_id=actor_id,
            incident_id=incident_id,
            remediation_action_id=remediation_action_id,
            tool_execution_id=tool_execution_id,
            approval_id=approval_id,
            correlation_id=correlation_id,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            policy_rule_id=policy_rule_id,
            risk_tier=risk_tier,
            payload_redacted=redact_mapping(dict(payload or {})),
        )
        session.add(record)
        session.flush()
        return record


__all__ = ["ALLOWED_OUTCOMES", "AuditWriter"]
