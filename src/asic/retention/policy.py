"""Data-retention classification and policy (Phase 13, ADR-0030).

What this module is, and is not
===============================

The master specification requires *data-retention controls*. What is justified today - and
built - is the part that can be made enforceable now:

* a **complete classification** of every table into a retention class, checked mechanically
  against the model registry so a new table cannot ship unclassified;
* a **policy schema** for ``tenant.retention_policy`` with platform minimums that a tenant
  may lengthen but never shorten below, and a per-class legal/operational **hold**;
* a **dry-run planner** that reports, per tenant, what a lifecycle job *would* consider and
  why, bounded by a batch size, with the reason for every decision.

What is deliberately **not** built is a deletion engine. The application role holds no
``DELETE`` on any table (``tests/security/test_tenancy_and_grants.py``), so the runtime
cannot erase anything even if this module were wrong. Deleting aged rows without breaking
audit immutability, replay reproducibility, verification lineage or memory governance needs an
owner-role lifecycle job with its own change control; that belongs with the deployment
(Phase 14 owns scheduling and privileges, ``docs/security/DATA_RETENTION.md``). Shipping a
generic ``DELETE ... WHERE created_at < X`` now would have been the unsafe option.

No number here is a legal or regulatory obligation. They are platform defaults chosen to keep
evidence for at least as long as the investigations that need it; an operator with a real
obligation sets a longer tenant value. Nothing in this repository claims compliance with any
framework.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum, unique
from types import MappingProxyType
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ApiIdempotencyRecord


@unique
class RetentionClass(StrEnum):
    #: Immutable security and authority evidence: audit, approvals, policy decisions,
    #: verification and its lineage, effect executions and their reservations, connector
    #: authority history. Append-only in the database; never deleted by policy.
    PROTECTED_EVIDENCE = "protected_evidence"
    #: The incident's own history and the workflow state that produced it.
    INCIDENT_RECORD = "incident_record"
    #: Execution traces and spans (replay and analysis inputs).
    EXECUTION_TRACE = "execution_trace"
    #: Evaluation scenarios, runs, judge results and replay fixtures (gate history).
    EVALUATION_HISTORY = "evaluation_history"
    #: Ingested knowledge, its ingestion and retrieval history.
    KNOWLEDGE_CONTENT = "knowledge_content"
    #: Governed operational memory and its promotion decisions.
    OPERATIONAL_MEMORY = "operational_memory"
    #: Users, role assignments, environments, services, tool grants, connector configuration.
    IDENTITY_AND_CONFIG = "identity_and_config"
    #: Replay records that exist only to make a retried request idempotent.
    OPERATIONAL_CACHE = "operational_cache"
    #: Platform-owned catalogues shared by all tenants (no tenant boundary, no retention).
    GLOBAL_CATALOGUE = "global_catalogue"


_C = RetentionClass

#: Table -> retention class. Complete: ``tests/security/test_retention.py`` asserts the key
#: set equals every table in the schema.
TABLE_CLASSIFICATION: Final[Mapping[str, RetentionClass]] = MappingProxyType(
    {
        # ---- protected evidence
        "audit_record": _C.PROTECTED_EVIDENCE,
        "approval": _C.PROTECTED_EVIDENCE,
        "policy_decision": _C.PROTECTED_EVIDENCE,
        "verification": _C.PROTECTED_EVIDENCE,
        "remediation_action": _C.PROTECTED_EVIDENCE,
        "remediation_target": _C.PROTECTED_EVIDENCE,
        "remediation_baseline": _C.PROTECTED_EVIDENCE,
        "tool_execution": _C.PROTECTED_EVIDENCE,
        "model_call_reservation": _C.PROTECTED_EVIDENCE,
        "connector_scope_binding": _C.PROTECTED_EVIDENCE,
        # ---- incident record
        "incident": _C.INCIDENT_RECORD,
        "incident_event": _C.INCIDENT_RECORD,
        "incident_reopen_candidate": _C.INCIDENT_RECORD,
        "timeline_event": _C.INCIDENT_RECORD,
        "alert": _C.INCIDENT_RECORD,
        "signal_receipt": _C.INCIDENT_RECORD,
        "evidence": _C.INCIDENT_RECORD,
        "hypothesis": _C.INCIDENT_RECORD,
        "hypothesis_evidence": _C.INCIDENT_RECORD,
        "investigation_step": _C.INCIDENT_RECORD,
        "investigation_dispatch": _C.INCIDENT_RECORD,
        "postmortem": _C.INCIDENT_RECORD,
        "workflow_run": _C.INCIDENT_RECORD,
        "workflow_checkpoint": _C.INCIDENT_RECORD,
        # ---- execution traces
        "execution_trace": _C.EXECUTION_TRACE,
        "trace_span": _C.EXECUTION_TRACE,
        # ---- evaluation history
        "evaluation_scenario": _C.EVALUATION_HISTORY,
        "evaluation_run": _C.EVALUATION_HISTORY,
        "evaluation_suite_run": _C.EVALUATION_HISTORY,
        "evaluation_judge_result": _C.EVALUATION_HISTORY,
        "evaluation_replay_fixture": _C.EVALUATION_HISTORY,
        # ---- knowledge
        "knowledge_source": _C.KNOWLEDGE_CONTENT,
        "knowledge_document": _C.KNOWLEDGE_CONTENT,
        "knowledge_chunk": _C.KNOWLEDGE_CONTENT,
        "knowledge_ingestion": _C.KNOWLEDGE_CONTENT,
        "knowledge_retrieval": _C.KNOWLEDGE_CONTENT,
        "knowledge_retrieval_result": _C.KNOWLEDGE_CONTENT,
        # ---- operational memory
        "memory_entry": _C.OPERATIONAL_MEMORY,
        "memory_promotion": _C.OPERATIONAL_MEMORY,
        "memory_write_decision": _C.OPERATIONAL_MEMORY,
        # ---- identity and configuration
        "app_user": _C.IDENTITY_AND_CONFIG,
        "user_role_assignment": _C.IDENTITY_AND_CONFIG,
        "environment": _C.IDENTITY_AND_CONFIG,
        "service": _C.IDENTITY_AND_CONFIG,
        "service_dependency": _C.IDENTITY_AND_CONFIG,
        "tenant_tool_grant": _C.IDENTITY_AND_CONFIG,
        "integration_connector": _C.IDENTITY_AND_CONFIG,
        # ---- operational cache
        "api_idempotency_record": _C.OPERATIONAL_CACHE,
        # ---- global catalogues
        "tenant": _C.GLOBAL_CATALOGUE,
        "role": _C.GLOBAL_CATALOGUE,
        "permission": _C.GLOBAL_CATALOGUE,
        "role_permission": _C.GLOBAL_CATALOGUE,
        "tool_definition": _C.GLOBAL_CATALOGUE,
        "behaviour_version": _C.GLOBAL_CATALOGUE,
        "alembic_version": _C.GLOBAL_CATALOGUE,
    }
)


@dataclass(frozen=True, slots=True)
class ClassPolicy:
    """Platform bounds for one class. ``None`` means "no time-based retention"."""

    #: Applied when the tenant sets nothing. ``None`` = retained until an operator decides.
    default_days: int | None
    #: A tenant may lengthen but never shorten below this. ``None`` = no time-based limit.
    minimum_days: int | None
    maximum_days: int | None
    #: Whether time alone may ever make rows of this class eligible for removal.
    time_eligible: bool
    rationale: str


CLASS_POLICIES: Final[Mapping[RetentionClass, ClassPolicy]] = MappingProxyType(
    {
        _C.PROTECTED_EVIDENCE: ClassPolicy(
            None,
            2555,
            None,
            False,
            "immutable evidence; ages out only through an owner-run, audited lifecycle "
            "decision, never by a time predicate",
        ),
        _C.INCIDENT_RECORD: ClassPolicy(
            None, 365, None, True, "must outlive the investigations, replays and reviews using it"
        ),
        _C.EXECUTION_TRACE: ClassPolicy(
            None, 90, None, True, "replay and analysis input; shorter than the incident record"
        ),
        _C.EVALUATION_HISTORY: ClassPolicy(
            None, 365, None, True, "gate history must remain comparable across versions"
        ),
        _C.KNOWLEDGE_CONTENT: ClassPolicy(
            None, None, None, False, "governed by source lifecycle (revoke/delete), not by age"
        ),
        _C.OPERATIONAL_MEMORY: ClassPolicy(
            None, None, None, False, "governed by memory promotion and revocation, not by age"
        ),
        _C.IDENTITY_AND_CONFIG: ClassPolicy(
            None, None, None, False, "current configuration; changes are audited, not aged out"
        ),
        _C.OPERATIONAL_CACHE: ClassPolicy(
            30, 1, 365, True, "an idempotency replay window; meaningless after retries stop"
        ),
        _C.GLOBAL_CATALOGUE: ClassPolicy(
            None, None, None, False, "platform-owned; outside any tenant's retention"
        ),
    }
)

#: A tenant policy may name only these classes (the rest have no time-based semantics).
POLICY_CLASSES: Final[frozenset[RetentionClass]] = frozenset(
    c for c, p in CLASS_POLICIES.items() if p.time_eligible or p.minimum_days is not None
)
_MAX_DAYS: Final[int] = 36_500


class RetentionPolicyError(ValueError):
    """The tenant retention policy is malformed or weaker than a platform minimum."""


@dataclass(frozen=True, slots=True)
class ClassRetention:
    days: int | None
    hold: bool


def validate_retention_policy(
    policy: Mapping[str, Any] | None,
) -> dict[RetentionClass, ClassRetention]:
    """Validate a ``tenant.retention_policy`` document and resolve it against the defaults.

    Shape: ``{"<class>": {"days": <int>, "hold": <bool>}}``. Unknown classes and keys are
    refused (a typo must not silently mean "no policy"), booleans are not integers, a value
    below the platform minimum is refused, and a hold suspends any time-based eligibility.

    Raises:
        RetentionPolicyError: with a message that never echoes a caller-supplied value.
    """
    document = dict(policy or {})
    known = {c.value: c for c in RetentionClass}
    resolved: dict[RetentionClass, ClassRetention] = {
        c: ClassRetention(days=CLASS_POLICIES[c].default_days, hold=False) for c in RetentionClass
    }
    for key, entry in document.items():
        klass = known.get(key) if isinstance(key, str) else None
        if klass is None or klass not in POLICY_CLASSES:
            raise RetentionPolicyError(
                "retention policy names an unknown or non-configurable class"
            )
        if not isinstance(entry, Mapping) or set(entry) - {"days", "hold"}:
            raise RetentionPolicyError(f"retention entry for {klass.value} has unexpected fields")
        days: Any = entry.get("days", resolved[klass].days)
        hold: Any = entry.get("hold", False)
        if not isinstance(hold, bool):
            raise RetentionPolicyError(f"hold for {klass.value} must be a boolean")
        limits = CLASS_POLICIES[klass]
        if days is not None:
            if isinstance(days, bool) or not isinstance(days, int):
                raise RetentionPolicyError(f"days for {klass.value} must be an integer")
            floor = limits.minimum_days or 1
            ceiling = limits.maximum_days or _MAX_DAYS
            if not floor <= days <= ceiling:
                raise RetentionPolicyError(
                    f"days for {klass.value} must be between {floor} and {ceiling}"
                )
        resolved[klass] = ClassRetention(days=days, hold=hold)
    return resolved


@unique
class RetentionAction(StrEnum):
    #: Never removed by policy (protected, or not time-based).
    RETAIN = "retain"
    #: A hold suspends time-based eligibility.
    HELD = "held"
    #: Time-based eligibility would apply, but only an owner-run lifecycle job may act.
    OWNER_LIFECYCLE = "owner_lifecycle"
    #: Counted in this dry run; still not deleted by this module.
    PREVIEW_ELIGIBLE = "preview_eligible"


@dataclass(frozen=True, slots=True)
class RetentionRow:
    table: str
    retention_class: RetentionClass
    action: RetentionAction
    reason: str
    cutoff: datetime | None = None
    eligible_rows: int = 0
    #: True when ``eligible_rows`` was capped at the batch bound.
    truncated_to_batch: bool = False


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    tenant_id: uuid.UUID
    as_of: datetime
    batch_limit: int
    rows: tuple[RetentionRow, ...]
    #: Always ``True``: this module never deletes anything.
    dry_run: bool = True

    def eligible(self) -> tuple[RetentionRow, ...]:
        return tuple(r for r in self.rows if r.action is RetentionAction.PREVIEW_ELIGIBLE)


def plan_retention(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    policy: Mapping[str, Any] | None,
    now: datetime,
    batch_limit: int = 1000,
) -> RetentionPlan:
    """A deterministic, tenant-bound, read-only retention preview.

    The session must already be bound to ``tenant_id`` (row-level security then makes a
    foreign tenant's rows invisible whatever the query says). Every table gets exactly one
    row with the reason for its decision; only the operational cache is ever counted as
    eligible, because it is the only class whose rows have no meaning after a fixed period.
    """
    if batch_limit < 1 or batch_limit > 100_000:
        raise ValueError("batch_limit must be between 1 and 100000")
    resolved = validate_retention_policy(policy)
    rows: list[RetentionRow] = []
    for table in sorted(TABLE_CLASSIFICATION):
        klass = TABLE_CLASSIFICATION[table]
        limits = CLASS_POLICIES[klass]
        setting = resolved[klass]
        if klass is RetentionClass.GLOBAL_CATALOGUE:
            rows.append(
                RetentionRow(table, klass, RetentionAction.RETAIN, "platform-owned catalogue")
            )
        elif klass is RetentionClass.PROTECTED_EVIDENCE:
            rows.append(
                RetentionRow(table, klass, RetentionAction.RETAIN, "protected immutable evidence")
            )
        elif setting.hold:
            rows.append(RetentionRow(table, klass, RetentionAction.HELD, "retention hold is set"))
        elif not limits.time_eligible or setting.days is None:
            rows.append(
                RetentionRow(
                    table, klass, RetentionAction.RETAIN, "no time-based retention applies"
                )
            )
        elif klass is RetentionClass.OPERATIONAL_CACHE:
            cutoff = now - timedelta(days=setting.days)
            count = session.scalar(
                sa.select(sa.func.count()).select_from(
                    sa.select(ApiIdempotencyRecord.id)
                    .where(
                        ApiIdempotencyRecord.tenant_id == tenant_id,
                        ApiIdempotencyRecord.created_at < cutoff,
                    )
                    .order_by(ApiIdempotencyRecord.created_at, ApiIdempotencyRecord.id)
                    .limit(batch_limit + 1)
                    .subquery()
                )
            )
            counted = int(count or 0)
            rows.append(
                RetentionRow(
                    table,
                    klass,
                    RetentionAction.PREVIEW_ELIGIBLE if counted else RetentionAction.RETAIN,
                    f"older than {setting.days} days" if counted else "nothing older than cutoff",
                    cutoff=cutoff,
                    eligible_rows=min(counted, batch_limit),
                    truncated_to_batch=counted > batch_limit,
                )
            )
        else:
            rows.append(
                RetentionRow(
                    table,
                    klass,
                    RetentionAction.OWNER_LIFECYCLE,
                    f"eligible after {setting.days} days through an owner-run lifecycle job only",
                    cutoff=now - timedelta(days=setting.days),
                )
            )
    return RetentionPlan(tenant_id=tenant_id, as_of=now, batch_limit=batch_limit, rows=tuple(rows))


__all__ = [
    "CLASS_POLICIES",
    "POLICY_CLASSES",
    "TABLE_CLASSIFICATION",
    "ClassPolicy",
    "ClassRetention",
    "RetentionAction",
    "RetentionClass",
    "RetentionPlan",
    "RetentionPolicyError",
    "RetentionRow",
    "plan_retention",
    "validate_retention_policy",
]
