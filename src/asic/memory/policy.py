"""The deterministic memory-write policy.

A pure function of a request, the proposer and the references resolved from the database.
No model is consulted, and nothing in the request's text can change the outcome: the text is
carried as data and never parsed for instructions or claims.

The five categories and what the policy does with each:

========================  =====================================================
``working_state``         Refused. It already lives in the workflow state.
``incident_history``      Refused. It is derived from the append-only event log.
``model_inference``       Refused. Hypotheses stay incident-scoped MODEL_CLAIMs.
``operational_knowledge`` May become a proposal for an ``operational_fact``.
``verified_outcome``      May become a proposal only with a verified verification.
========================  =====================================================

**Provenance is derived, never declared.** A proposal from an agent node carries
``model_claim`` provenance; a proposal from a human or an external source carries
``retrieved`` (human-authored text of unknown accuracy). ``verified_fact`` is assigned only
for a verified outcome whose every cited verification record has verdict ``verified`` - the
evidence, not the proposer, confers it. Human approval later decides whether a proposal is
written; it does not upgrade provenance, because approval is not verification.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field

from asic.domain.enums import (
    ActorType,
    MemoryCategory,
    MemoryKind,
    ProvenanceLabel,
    VerificationVerdict,
)

POLICY_VERSION: Final[str] = "memory-write/1"

_ROOT_CAUSE_PATTERN: Final[str] = r"^[a-z][a-z0-9_]{1,63}$"
_KEY_PATTERN: Final[str] = r"^[a-z][a-z0-9_]{0,63}$"


class MemoryWriteRequest(BaseModel):
    """A request to remember something. Every field is data.

    There is deliberately no ``provenance``, ``verified`` or ``confidence`` field: a caller
    cannot claim any of them. A statement that says "this is verified" is a statement.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: MemoryCategory
    statement: Annotated[str, Field(min_length=1, max_length=2000)]
    rationale: Annotated[str, Field(min_length=1, max_length=2000)]
    root_cause_class: Annotated[str, Field(pattern=_ROOT_CAUSE_PATTERN)]
    context_signature: dict[
        Annotated[str, Field(pattern=_KEY_PATTERN)], Annotated[str, Field(max_length=200)]
    ] = Field(default_factory=dict, max_length=16)
    incident_ids: tuple[uuid.UUID, ...] = Field(default=(), max_length=16)
    evidence_ids: tuple[uuid.UUID, ...] = Field(default=(), max_length=64)
    verification_ids: tuple[uuid.UUID, ...] = Field(default=(), max_length=32)
    knowledge_citations: tuple[Annotated[str, Field(max_length=160)], ...] = Field(
        default=(), max_length=32
    )


@dataclass(frozen=True, slots=True)
class MemoryActor:
    """Who is proposing or deciding. Established by trusted wiring."""

    actor_type: ActorType
    actor_id: str | None = None
    #: Set for a human; the approver check resolves permissions from it.
    user_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class VerificationFact:
    verification_id: uuid.UUID
    verdict: VerificationVerdict
    incident_id: uuid.UUID
    remediation_action_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class ResolvedReferences:
    """What the request's references resolved to, in the proposer's own tenant."""

    #: incident id -> whether the incident is terminal.
    incidents: Mapping[uuid.UUID, bool] = field(default_factory=dict)
    evidence_ids: frozenset[uuid.UUID] = frozenset()
    verifications: tuple[VerificationFact, ...] = ()
    citations_resolved: int = 0
    #: Reference kinds that did not resolve.
    missing: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    target_kind: MemoryKind | None = None
    origin_provenance: ProvenanceLabel | None = None


def evaluate(
    request: MemoryWriteRequest, actor: MemoryActor, refs: ResolvedReferences
) -> PolicyDecision:
    """Decide whether a request may become a proposal. Deterministic; no side effects."""
    if request.category is MemoryCategory.WORKING_STATE:
        return PolicyDecision(False, "working_state_is_not_durable_memory")
    if request.category is MemoryCategory.INCIDENT_HISTORY:
        return PolicyDecision(False, "incident_history_is_derived_not_written")
    if request.category is MemoryCategory.MODEL_INFERENCE:
        return PolicyDecision(False, "model_inferences_are_not_retained")
    if refs.missing:
        return PolicyDecision(False, "unresolved_reference")

    if request.category is MemoryCategory.VERIFIED_OUTCOME:
        if not request.verification_ids:
            return PolicyDecision(False, "verification_evidence_required")
        if any(v.verdict is not VerificationVerdict.VERIFIED for v in refs.verifications):
            return PolicyDecision(False, "verification_not_verified")
        verified_incidents = {v.incident_id for v in refs.verifications}
        if not request.incident_ids or not verified_incidents <= set(request.incident_ids):
            return PolicyDecision(False, "verification_not_linked_to_incident")
        return PolicyDecision(
            True,
            "proposal_accepted",
            target_kind=MemoryKind.VERIFIED_OUTCOME,
            origin_provenance=ProvenanceLabel.VERIFIED_FACT,
        )

    # Operational knowledge promoted from incident experience (T3 -> T4).
    if request.verification_ids:
        return PolicyDecision(False, "verification_only_for_verified_outcomes")
    if not (request.incident_ids or request.evidence_ids or request.knowledge_citations):
        return PolicyDecision(False, "source_reference_required")
    if any(not terminal for terminal in refs.incidents.values()):
        return PolicyDecision(False, "incident_not_closed")
    origin = (
        ProvenanceLabel.MODEL_CLAIM
        if actor.actor_type is ActorType.AGENT_NODE
        else ProvenanceLabel.RETRIEVED
    )
    return PolicyDecision(
        True, "proposal_accepted", target_kind=MemoryKind.OPERATIONAL_FACT, origin_provenance=origin
    )


def references_digest(request: MemoryWriteRequest) -> str:
    return _digest(
        {
            "incidents": sorted(map(str, request.incident_ids)),
            "evidence": sorted(map(str, request.evidence_ids)),
            "verifications": sorted(map(str, request.verification_ids)),
            "citations": sorted(request.knowledge_citations),
        }
    )


def proposal_key(request: MemoryWriteRequest) -> str:
    """Identical proposals collapse to one open proposal."""
    return _digest(
        {
            "category": request.category.value,
            "root_cause_class": request.root_cause_class,
            "references": references_digest(request),
            "statement": hashlib.sha256(request.statement.encode("utf-8")).hexdigest(),
        }
    )


def support_count(request: MemoryWriteRequest, verifications: Sequence[VerificationFact]) -> int:
    """Independent incidents supporting the entry. Never less than one."""
    if request.category is MemoryCategory.VERIFIED_OUTCOME:
        incidents = {
            v.incident_id for v in verifications if v.verdict is VerificationVerdict.VERIFIED
        }
    else:
        incidents = set(request.incident_ids)
    return max(1, len(incidents))


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "POLICY_VERSION",
    "MemoryActor",
    "MemoryWriteRequest",
    "PolicyDecision",
    "ResolvedReferences",
    "VerificationFact",
    "evaluate",
    "proposal_key",
    "references_digest",
    "support_count",
]
