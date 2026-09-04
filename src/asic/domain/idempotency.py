"""Domain-level idempotency.

The Phase 3 brief is explicit that "use retries" is not an answer. This module defines
*what makes two submissions the same logical operation*, per operation class. The database
then enforces uniqueness on the resulting key, so a duplicate collides rather than being
applied twice.

Two rules govern every key here:

1. **Keys are derived from business identity, never from a random value.** A random
   idempotency token makes a retry safe but does nothing about two independent
   submissions of the same logical operation - which is the case that actually causes a
   double-applied remediation.
2. **Keys are stable across process restarts.** They are pure functions of their inputs,
   so a resumed workflow recomputes the same key and collides with its own earlier write.

Not everything should be de-duplicated. Retrying a *semantic* failure (an empty query
result, a policy denial) is a bug, not a duplicate; those operations have no key here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final
from uuid import UUID

#: Length of the hex digest stored in ``*_idempotency_key`` columns.
KEY_LENGTH: Final[int] = 64

_SEPARATOR: Final[str] = "\x1f"  # ASCII unit separator: cannot appear in our inputs


def _canonical(value: Any) -> str:
    """Render a value canonically so equal inputs always produce equal keys.

    Mappings are key-sorted and sequences keep their order, because argument order is
    semantically meaningful for some tools but mapping order never is.
    """
    if value is None:
        return "\x00null"
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError(
                "naive datetime in an idempotency key: timestamps must be timezone-aware, "
                "otherwise the same instant produces different keys in different processes"
            )
        return value.astimezone(tz=None).isoformat()
    if isinstance(value, Mapping):
        return json.dumps(
            {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))},
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=True,
        )
    if isinstance(value, Sequence):
        return json.dumps([_canonical(v) for v in value], separators=(",", ":"), ensure_ascii=True)
    raise TypeError(f"unsupported type in idempotency key: {type(value).__name__}")


def _digest(scope: str, *parts: Any) -> str:
    payload = _SEPARATOR.join([scope, *(_canonical(p) for p in parts)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- alerts


def alert_key(
    *,
    tenant_id: UUID,
    source: str,
    source_fingerprint: str,
    started_at: datetime,
) -> str:
    """Identity of an alert occurrence.

    Alertmanager and PagerDuty both re-deliver until acknowledged, so the same alert
    arrives many times. ``started_at`` is part of the key because the *same* fingerprint
    firing again after resolution is a genuinely new occurrence, not a duplicate.
    """
    return _digest("alert", tenant_id, source, source_fingerprint, started_at)


# --------------------------------------------------------------------------- events


def incident_event_key(
    *,
    tenant_id: UUID,
    incident_id: UUID,
    event_type: str,
    subject_id: UUID | str | None,
    occurrence_discriminator: str | None = None,
) -> str:
    """Identity of an incident event.

    ``subject_id`` is the entity the event is about (an action, an evidence record, an
    alert). ``occurrence_discriminator`` distinguishes legitimately repeated events about
    the same subject - a second checkpoint, a retry attempt number.
    """
    return _digest(
        "incident_event",
        tenant_id,
        incident_id,
        event_type,
        subject_id,
        occurrence_discriminator,
    )


# ---------------------------------------------------------------------- tool calls


def tool_execution_key(
    *,
    tenant_id: UUID,
    tool_name: str,
    tool_major_version: int,
    scope_arguments: Mapping[str, Any],
) -> str:
    """Identity of a tool *effect*.

    Deliberately composed from the arguments that determine the effect - the target
    cluster, namespace and workload - and **not** from the action id. Two different
    proposals asking for the same effect must collide; if the key included the action id
    they would not, and the effect would be applied twice.

    The major version participates because a major bump may change semantics; the minor
    and patch do not, because they must not.
    """
    return _digest(
        "tool_execution",
        tenant_id,
        tool_name,
        tool_major_version,
        scope_arguments,
    )


def action_version_hash(
    *,
    action_id: UUID,
    tool_name: str,
    tool_version: str,
    arguments: Mapping[str, Any],
    permission_scope: Mapping[str, Any],
    preconditions: Sequence[str],
    risk_tier: str,
) -> str:
    """Bind an approval to exactly one version of one action (SI-6).

    The broker recomputes this immediately before execution. Any divergence invalidates
    the approval and fails closed, which closes the "approve a small change, execute a
    large one" attack.
    """
    return _digest(
        "action_version",
        action_id,
        tool_name,
        tool_version,
        arguments,
        permission_scope,
        list(preconditions),
        risk_tier,
    )


# ------------------------------------------------------------------------ callbacks


def approval_callback_key(
    *,
    tenant_id: UUID,
    action_id: UUID,
    action_version_hash_value: str,
) -> str:
    """Identity of an approval decision.

    Keyed by the action *version*, not merely the action: a re-proposed action with
    changed parameters is a new decision and must not be satisfied by an earlier reply.
    An approval platform that delivers the same reply twice collides here.
    """
    return _digest("approval_callback", tenant_id, action_id, action_version_hash_value)


def verification_callback_key(
    *,
    tenant_id: UUID,
    action_id: UUID,
    attempt: int,
) -> str:
    """Identity of a verification result for one attempt against one action."""
    return _digest("verification_callback", tenant_id, action_id, attempt)


def remediation_request_key(
    *,
    tenant_id: UUID,
    incident_id: UUID,
    hypothesis_id: UUID,
    tool_name: str,
    scope_arguments: Mapping[str, Any],
) -> str:
    """Identity of a remediation *proposal*.

    Stops a replanning loop from proposing the same action against the same hypothesis
    repeatedly and consuming the per-incident write-action budget on duplicates.
    """
    return _digest(
        "remediation_request",
        tenant_id,
        incident_id,
        hypothesis_id,
        tool_name,
        scope_arguments,
    )


__all__ = [
    "KEY_LENGTH",
    "action_version_hash",
    "alert_key",
    "approval_callback_key",
    "incident_event_key",
    "remediation_request_key",
    "tool_execution_key",
    "verification_callback_key",
]
