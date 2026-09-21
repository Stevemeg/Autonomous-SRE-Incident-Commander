"""Proposals, human decisions and governed reads of durable memory.

Write path, and the guarantee each step provides:

1. **propose** - references are resolved in the proposer's tenant, the deterministic policy
   is applied, and every outcome - including refusals - is recorded in the append-only
   ``memory_write_decision`` table. A passing request becomes a ``proposed`` promotion;
   identical open proposals collapse to one under a per-proposal advisory lock backed by a
   partial unique index. Nothing durable is written.
2. **decide** - a human with the ``memory.promotion.decide`` permission, who is not the
   proposer, approves or declines. Approval re-resolves and re-evaluates the references at
   decision time (a verification that has since changed does not slip through), then writes
   exactly one ``memory_entry`` whose provenance and verification status were derived from
   records. The database refuses a verified fact without a verification record, and any
   memory carrying SYSTEM or HUMAN provenance.

Concurrent decisions on one promotion serialize on its row lock; the unique
``(tenant_id, promotion_id)`` constraint on ``memory_entry`` is the backstop, so a promotion
can never produce two entries.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Evidence,
    Incident,
    MemoryEntry,
    MemoryPromotion,
    MemoryWriteDecision,
    Permission,
    RemediationAction,
    RolePermission,
    User,
    UserRoleAssignment,
    Verification,
)
from asic.db.session import apply_statement_timeouts, bind_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    MemoryCategory,
    MemoryDecisionOutcome,
    MemoryKind,
    MemoryPromotionStatus,
    MemoryVerificationStatus,
    ProvenanceLabel,
    UserStatus,
    VerificationVerdict,
)
from asic.domain.errors import DomainError
from asic.domain.incident_state import is_terminal
from asic.domain.permissions import PermissionKey
from asic.domain.untrusted import UntrustedBlock
from asic.knowledge import telemetry
from asic.knowledge.citations import citation_reference_exists
from asic.knowledge.errors import CitationInvalid
from asic.memory.policy import (
    POLICY_VERSION,
    MemoryActor,
    MemoryWriteRequest,
    ResolvedReferences,
    VerificationFact,
    evaluate,
    proposal_key,
    references_digest,
    support_count,
)
from asic.observability.audit import AuditWriter
from asic.remediation.trust import trusted_verified_outcome

#: The permission a human needs to decide a promotion. Seeded by migration 0008.
DECIDE_PERMISSION: Final[str] = PermissionKey.MEMORY_PROMOTION_DECIDE.value
PROPOSAL_LOCK_NAMESPACE: Final[str] = "asic.memory.proposal.v1"


class MemoryGovernanceError(DomainError):
    """A decision could not be made. Carries a safe reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MemoryWriteOutcome:
    outcome: MemoryDecisionOutcome
    reason: str
    decision_id: uuid.UUID
    promotion_id: uuid.UUID | None = None
    memory_entry_id: uuid.UUID | None = None


class MemoryGovernanceService:
    __slots__ = ("_clock", "_factory")

    def __init__(
        self, session_factory: Callable[[], Session], *, clock: Clock | None = None
    ) -> None:
        self._factory = session_factory
        self._clock = clock or SystemClock()

    # --------------------------------------------------------------------- propose

    def propose(
        self,
        tenant_id: uuid.UUID,
        request: MemoryWriteRequest,
        actor: MemoryActor,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> MemoryWriteOutcome:
        with (
            telemetry.stage(
                "memory.propose", tenant_id=str(tenant_id), category=request.category.value
            ),
            self._factory() as session,
            session.begin(),
        ):
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            refs = _resolve(session, tenant_id, request)
            decision = evaluate(request, actor, refs)
            incident_id = request.incident_ids[0] if request.incident_ids else None
            if not decision.allowed:
                return self._decision(
                    session,
                    tenant_id,
                    request.category,
                    MemoryDecisionOutcome.REJECTED,
                    decision.reason,
                    actor,
                    references=references_digest(request),
                    incident_id=incident_id if incident_id in refs.incidents else None,
                    correlation_id=correlation_id,
                )

            key = proposal_key(request)
            session.execute(
                sa.text("SELECT pg_advisory_xact_lock(:namespace, :key)"),
                {
                    "namespace": _lock_int(PROPOSAL_LOCK_NAMESPACE),
                    "key": _lock_int(f"{tenant_id}:{key}"),
                },
            )
            existing = session.scalars(
                sa.select(MemoryPromotion).where(
                    MemoryPromotion.tenant_id == tenant_id,
                    MemoryPromotion.proposal_key == key,
                    MemoryPromotion.status == MemoryPromotionStatus.PROPOSED,
                )
            ).one_or_none()
            if existing is not None:
                return self._decision(
                    session,
                    tenant_id,
                    request.category,
                    MemoryDecisionOutcome.PROPOSED,
                    "existing_open_proposal",
                    actor,
                    references=references_digest(request),
                    promotion_id=existing.id,
                    incident_id=incident_id,
                    correlation_id=correlation_id,
                )

            assert decision.target_kind is not None and decision.origin_provenance is not None
            promotion = MemoryPromotion(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                incident_id=incident_id,
                target_kind=decision.target_kind,
                proposed_payload={
                    "statement": request.statement,
                    "root_cause_class": request.root_cause_class,
                    "context_signature": dict(request.context_signature),
                },
                rationale=request.rationale,
                supporting_incident_ids=list(request.incident_ids),
                status=MemoryPromotionStatus.PROPOSED,
                category=request.category,
                origin_provenance=decision.origin_provenance,
                proposal_key=key,
                proposed_by_type=actor.actor_type,
                proposed_by_id=str(actor.user_id) if actor.user_id else actor.actor_id,
                verification_ids=list(request.verification_ids),
                evidence_ids=list(request.evidence_ids),
                knowledge_citations=list(request.knowledge_citations),
                policy_version=POLICY_VERSION,
            )
            session.add(promotion)
            session.flush()
            return self._decision(
                session,
                tenant_id,
                request.category,
                MemoryDecisionOutcome.PROPOSED,
                decision.reason,
                actor,
                references=references_digest(request),
                promotion_id=promotion.id,
                incident_id=incident_id,
                correlation_id=correlation_id,
            )

    # ---------------------------------------------------------------------- decide

    def decide(
        self,
        tenant_id: uuid.UUID,
        promotion_id: uuid.UUID,
        approver: MemoryActor,
        *,
        approve: bool,
        note: str | None = None,
    ) -> MemoryWriteOutcome:
        """A human decision on one proposal.

        Raises:
            MemoryGovernanceError: ``approver_not_human``, ``approver_not_authorized``,
                ``approver_is_proposer``, ``unknown_promotion``,
                ``promotion_already_decided``, or a policy reason when the proposal no
                longer satisfies the policy at decision time.
        """
        with (
            telemetry.stage("memory.decide", tenant_id=str(tenant_id)),
            self._factory() as session,
            session.begin(),
        ):
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            if approver.actor_type is not ActorType.HUMAN or approver.user_id is None:
                self._deny(session, tenant_id, promotion_id, approver, "approver_not_human")
                raise MemoryGovernanceError("approver_not_human")
            promotion = session.scalars(
                sa.select(MemoryPromotion)
                .where(MemoryPromotion.tenant_id == tenant_id, MemoryPromotion.id == promotion_id)
                .with_for_update()
            ).one_or_none()
            if promotion is None or promotion.category is None:
                raise MemoryGovernanceError("unknown_promotion")
            if promotion.status is not MemoryPromotionStatus.PROPOSED:
                raise MemoryGovernanceError("promotion_already_decided")
            if not _may_decide(session, tenant_id, approver.user_id, self._clock.now()):
                self._deny(session, tenant_id, promotion_id, approver, "approver_not_authorized")
                raise MemoryGovernanceError("approver_not_authorized")
            if promotion.proposed_by_id == str(approver.user_id):
                self._deny(session, tenant_id, promotion_id, approver, "approver_is_proposer")
                raise MemoryGovernanceError("approver_is_proposer")

            request = _request_from(promotion)
            now = self._clock.now()
            if not approve:
                promotion.status = MemoryPromotionStatus.REJECTED
                promotion.approver_user_id = approver.user_id
                promotion.decided_at = now
                promotion.decision_note = note
                session.flush()
                return self._decision(
                    session,
                    tenant_id,
                    promotion.category,
                    MemoryDecisionOutcome.DECLINED,
                    "declined_by_human",
                    approver,
                    references=references_digest(request),
                    promotion_id=promotion.id,
                    incident_id=promotion.incident_id,
                )

            proposer = MemoryActor(
                actor_type=promotion.proposed_by_type or ActorType.SYSTEM,
                actor_id=promotion.proposed_by_id,
            )
            refs = _resolve(session, tenant_id, request)
            decision = evaluate(request, proposer, refs)
            if not decision.allowed:
                self._deny(
                    session,
                    tenant_id,
                    promotion_id,
                    approver,
                    decision.reason,
                )
                raise MemoryGovernanceError(decision.reason)
            if decision.origin_provenance is not promotion.origin_provenance:
                raise MemoryGovernanceError("provenance_changed_since_proposal")

            entry = _entry(session, tenant_id, promotion, request, refs, now)
            session.add(entry)
            session.flush()
            promotion.status = MemoryPromotionStatus.APPROVED
            promotion.approver_user_id = approver.user_id
            promotion.decided_at = now
            promotion.decision_note = note
            promotion.memory_entry_id = entry.id
            session.flush()
            return self._decision(
                session,
                tenant_id,
                promotion.category,
                MemoryDecisionOutcome.APPROVED,
                "approved_by_human",
                approver,
                references=references_digest(request),
                promotion_id=promotion.id,
                memory_entry_id=entry.id,
                incident_id=promotion.incident_id,
            )

    # ----------------------------------------------------------------- recording

    def _decision(
        self,
        session: Session,
        tenant_id: uuid.UUID,
        category: MemoryCategory,
        outcome: MemoryDecisionOutcome,
        reason: str,
        actor: MemoryActor,
        *,
        references: str,
        promotion_id: uuid.UUID | None = None,
        memory_entry_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
        correlation_id: uuid.UUID | None = None,
    ) -> MemoryWriteOutcome:
        record = MemoryWriteDecision(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            category=category,
            outcome=outcome,
            reason=reason,
            policy_version=POLICY_VERSION,
            actor_type=actor.actor_type,
            actor_id=str(actor.user_id) if actor.user_id else actor.actor_id,
            promotion_id=promotion_id,
            memory_entry_id=memory_entry_id,
            incident_id=incident_id,
            references_digest=references,
            correlation_id=correlation_id,
        )
        session.add(record)
        session.flush()
        telemetry.memory_decisions.add(
            1, {"category": category.value, "outcome": outcome.value, "reason": reason}
        )
        return MemoryWriteOutcome(
            outcome=outcome,
            reason=reason,
            decision_id=record.id,
            promotion_id=promotion_id,
            memory_entry_id=memory_entry_id,
        )

    def _deny(
        self,
        session: Session,
        tenant_id: uuid.UUID,
        promotion_id: uuid.UUID,
        actor: MemoryActor,
        reason: str,
    ) -> None:
        AuditWriter(tenant_id=tenant_id, clock=self._clock).record(
            session,
            event_type=AuditEventType.AUTHORIZATION_DENIED,
            outcome="denied",
            actor_type=actor.actor_type,
            actor_id=str(actor.user_id) if actor.user_id else actor.actor_id,
            target_type="memory_promotion",
            target_id=str(promotion_id),
            payload={"reason": reason},
        )
        session.commit()
        telemetry.memory_decisions.add(
            1, {"category": "decision", "outcome": "denied", "reason": reason}
        )


# ------------------------------------------------------------------------- reads


def memory_blocks(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    root_cause_class: str | None = None,
    limit: int = 5,
    now: datetime | None = None,
) -> tuple[UntrustedBlock, ...]:
    """Active, unexpired memory as untrusted prompt data, verified outcomes first.

    Memory informs; it never overrides current evidence, and it is never SYSTEM context.
    """
    moment = now or SystemClock().now()
    query = sa.select(MemoryEntry).where(
        MemoryEntry.tenant_id == tenant_id,
        MemoryEntry.is_active.is_(True),
        MemoryEntry.provenance.is_not(None),
        sa.or_(MemoryEntry.expires_at.is_(None), MemoryEntry.expires_at > moment),
    )
    if root_cause_class is not None:
        query = query.where(MemoryEntry.root_cause_class == root_cause_class)
    entries = session.scalars(
        query.order_by(
            (MemoryEntry.provenance == ProvenanceLabel.VERIFIED_FACT).desc(),
            MemoryEntry.support_count.desc(),
            MemoryEntry.id,
        ).limit(max(1, min(limit, 20)))
    ).all()
    return tuple(
        UntrustedBlock(
            source=f"memory:{entry.id}",
            provenance=entry.provenance or ProvenanceLabel.MODEL_CLAIM,
            content=(
                f"[{entry.kind.value}; verification="
                f"{(entry.verification_status or MemoryVerificationStatus.UNVERIFIED).value}; "
                f"support={entry.support_count}] {entry.statement}"
            )[:2000],
        )
        for entry in entries
    )


# ------------------------------------------------------------------------ helpers


def _lock_int(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:4], "big", signed=True)


def _request_from(promotion: MemoryPromotion) -> MemoryWriteRequest:
    payload = dict(promotion.proposed_payload)
    assert promotion.category is not None
    return MemoryWriteRequest(
        category=promotion.category,
        statement=str(payload.get("statement", "")) or "-",
        rationale=promotion.rationale,
        root_cause_class=str(payload.get("root_cause_class", "")),
        context_signature=dict(payload.get("context_signature") or {}),
        incident_ids=tuple(promotion.supporting_incident_ids),
        evidence_ids=tuple(promotion.evidence_ids),
        verification_ids=tuple(promotion.verification_ids),
        knowledge_citations=tuple(str(c) for c in promotion.knowledge_citations),
    )


def _resolve(
    session: Session, tenant_id: uuid.UUID, request: MemoryWriteRequest
) -> ResolvedReferences:
    """Resolve every reference in the caller's tenant. RLS makes other tenants invisible."""
    missing: list[str] = []
    incidents: dict[uuid.UUID, bool] = {}
    if request.incident_ids:
        for incident_id, status in session.execute(
            sa.select(Incident.id, Incident.status).where(
                Incident.tenant_id == tenant_id, Incident.id.in_(request.incident_ids)
            )
        ).all():
            incidents[incident_id] = is_terminal(status)
        if set(incidents) != set(request.incident_ids):
            missing.append("incident")

    evidence: set[uuid.UUID] = set()
    if request.evidence_ids:
        evidence = set(
            session.scalars(
                sa.select(Evidence.id).where(
                    Evidence.tenant_id == tenant_id, Evidence.id.in_(request.evidence_ids)
                )
            )
        )
        if evidence != set(request.evidence_ids):
            missing.append("evidence")

    verifications: list[VerificationFact] = []
    if request.verification_ids:
        for (
            verification,
            incident_id,
            action_criteria_hash,
            action_status,
        ) in session.execute(
            sa.select(
                Verification,
                RemediationAction.incident_id,
                RemediationAction.verification_criteria_hash,
                RemediationAction.status,
            )
            .join(
                RemediationAction,
                sa.and_(
                    RemediationAction.tenant_id == Verification.tenant_id,
                    RemediationAction.id == Verification.remediation_action_id,
                ),
            )
            .where(
                Verification.tenant_id == tenant_id,
                Verification.id.in_(request.verification_ids),
            )
        ).all():
            verifications.append(
                VerificationFact(
                    verification_id=verification.id,
                    verdict=verification.verdict,
                    incident_id=incident_id,
                    remediation_action_id=verification.remediation_action_id,
                    criteria_hash=verification.criteria_hash,
                    action_criteria_hash=action_criteria_hash,
                    baseline=dict(verification.baseline or {}),
                    observed=dict(verification.observed or {}),
                    provenance_valid=trusted_verified_outcome(
                        session, tenant_id=tenant_id, verification=verification
                    ),
                    action_status=action_status,
                )
            )
        if {v.verification_id for v in verifications} != set(request.verification_ids):
            missing.append("verification")

    resolved_citations = 0
    for token in request.knowledge_citations:
        try:
            citation_reference_exists(session, token)
            resolved_citations += 1
        except CitationInvalid:
            missing.append("knowledge_citation")
            break

    return ResolvedReferences(
        incidents=incidents,
        evidence_ids=frozenset(evidence),
        verifications=tuple(sorted(verifications, key=lambda v: str(v.verification_id))),
        citations_resolved=resolved_citations,
        missing=tuple(missing),
    )


def _may_decide(session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID, now: datetime) -> bool:
    """Active user in this tenant holding the decide permission through a current role."""
    return (
        session.scalar(
            sa.select(sa.literal(1))
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
                Permission.key == DECIDE_PERMISSION,
                sa.or_(
                    UserRoleAssignment.expires_at.is_(None), UserRoleAssignment.expires_at > now
                ),
            )
            .limit(1)
        )
        is not None
    )


def _entry(
    session: Session,
    tenant_id: uuid.UUID,
    promotion: MemoryPromotion,
    request: MemoryWriteRequest,
    refs: ResolvedReferences,
    now: datetime,
) -> MemoryEntry:
    """Build the entry from records. Verified outcomes get a mechanical statement."""
    verified = promotion.target_kind is MemoryKind.VERIFIED_OUTCOME
    action_reference: dict[str, Any] = {}
    observed_effect: dict[str, Any] = {}
    statement = request.statement
    verification_id: uuid.UUID | None = None
    if verified:
        first = refs.verifications[0]
        verification_id = first.verification_id
        action = session.scalars(
            sa.select(RemediationAction).where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.id == first.remediation_action_id,
            )
        ).one()
        action_reference = {
            "remediation_action_id": str(action.id),
            "tool_name": action.tool_name,
            "tool_version": action.tool_version,
            "incident_id": str(action.incident_id),
        }
        observed_effect = {
            "verifications": [
                {"verification_id": str(v.verification_id), "verdict": v.verdict.value}
                for v in refs.verifications
            ]
        }
        # The durable statement is generated from the records, not taken from the
        # proposer. The proposer's words stay on the promotion as untrusted rationale.
        statement = (
            f"Remediation {action.tool_name}@{action.tool_version} (action {action.id}) was "
            f"verified: {len(refs.verifications)} verification record(s) with verdict "
            f"{VerificationVerdict.VERIFIED.value}."
        )
    seen = sorted(
        session.scalars(
            sa.select(Incident.opened_at).where(
                Incident.tenant_id == tenant_id, Incident.id.in_(request.incident_ids or [])
            )
        )
    )
    return MemoryEntry(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        kind=promotion.target_kind,
        root_cause_class=request.root_cause_class,
        context_signature=dict(request.context_signature),
        statement=statement,
        action_reference=action_reference,
        observed_effect=observed_effect,
        support_count=support_count(request, refs.verifications),
        first_seen_at=seen[0] if seen else now,
        last_seen_at=max(seen[-1], now) if seen else now,
        provenance=promotion.origin_provenance,
        verification_status=MemoryVerificationStatus.VERIFIED
        if verified
        else MemoryVerificationStatus.UNVERIFIED,
        promotion_id=promotion.id,
        verification_id=verification_id,
        source_refs={
            "incident_ids": sorted(map(str, request.incident_ids)),
            "evidence_ids": sorted(map(str, request.evidence_ids)),
            "verification_ids": sorted(map(str, request.verification_ids)),
            "knowledge_citations": sorted(request.knowledge_citations),
        },
        policy_version=POLICY_VERSION,
        effective_at=now,
    )


__all__ = [
    "DECIDE_PERMISSION",
    "MemoryGovernanceError",
    "MemoryGovernanceService",
    "MemoryWriteOutcome",
    "memory_blocks",
]
