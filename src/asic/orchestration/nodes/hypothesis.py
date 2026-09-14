"""G5 Hypothesis Engine.

Reasons over evidence already gathered. It has no capabilities and calls no tools, which is
what makes it safe to feed it the untrusted content of every log line and runbook the
investigation collected: it cannot act on anything it reads.

Three mechanisms distinguish a fact from a claim, and all three are code rather than prompt
instructions.

**Citation integrity.** Every evidence id a hypothesis cites is checked against the
persisted evidence set for this run. A hypothesis citing an id that does not exist is
dropped before ranking and recorded as ``hypothesis.rejected_unsupported``. That converts a
hallucinated citation from a scoring problem into an unreachable state (FR-RCA-02, INV-5),
and the foreign key on ``hypothesis_evidence`` makes it unreachable a second time at the
database.

**A confidence ceiling.** The model states a confidence; the node computes a maximum from
the evidence actually available - how many records support it, their quality, and whether
anything contradicts it - and stores the lower of the two. Both numbers and the derivation
go into ``confidence_basis``, so calibration is measurable later rather than being a number
the model chose. This is the mechanism against failure mode F4, a confident wrong answer
that nothing crashes on.

**Provenance stays where it was.** Evidence content enters the prompt as fenced untrusted
data. A hypothesis is a ``MODEL_CLAIM`` no matter how it is phrased, and the only thing
that makes it citable is the evidence it is linked to.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Final

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asic.contracts.nodes import G5_HYPOTHESIS_ENGINE
from asic.contracts.state import (
    BudgetSnapshot,
    EvidenceRef,
    GraphState,
    HypothesisRef,
    NodeFailureRef,
    ReflectionDecisionRef,
)
from asic.db.models.investigation import Evidence, Hypothesis, HypothesisEvidence
from asic.domain.budget import BudgetState
from asic.domain.enums import (
    EvidenceFailureCategory,
    EvidenceRelation,
    HypothesisStatus,
    InvestigationPhase,
    NodeId,
    ReflectionAction,
    TraceSpanKind,
)
from asic.domain.errors import ModelProviderError, SchemaViolation
from asic.domain.untrusted import UntrustedBlock
from asic.knowledge.errors import RetrievalRefused
from asic.llm.port import ModelRequest
from asic.llm.prompts import HYPOTHESIS_PROMPT
from asic.observability import metrics
from asic.orchestration.alert_context import incident_alert_blocks
from asic.orchestration.context import NodeDependencies
from asic.orchestration.knowledge_context import (
    knowledge_evidence_blocks,
    recompute_investigation_context,
)
from asic.orchestration.reflection import ReflectionInputs, ReflectionProposal, decide_reflection

SCHEMA_REPAIR_ATTEMPTS: Final[int] = 1

#: Ceiling applied when a single evidence record supports a hypothesis. One observation is
#: a coincidence until something corroborates it.
_SINGLE_SUPPORT_CEILING: Final[float] = 0.4

#: Ceiling applied when any evidence contradicts the hypothesis. Deliberately below the
#: actionable threshold, so a contradicted hypothesis cannot be escalated as a cause.
_CONTRADICTED_CEILING: Final[float] = 0.35

#: Ceiling with no supporting evidence at all.
_UNSUPPORTED_CEILING: Final[float] = 0.1

#: Sentinel citations the scripted provider uses to mean "everything" and "nothing". A real
#: provider emits explicit ids; these keep the fixtures readable without teaching the parser
#: to accept anything else.
_ALL: Final[str] = "ALL"
_NONE: Final[str] = "NONE"


class HypothesisDraft(BaseModel):
    """One hypothesis as the model proposed it, before any of it is believed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    statement: str = Field(min_length=1, max_length=2000)
    root_cause_class: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    remaining_gaps: list[str] = Field(default_factory=list)


class ReflectionProposalModel(BaseModel):
    """The model's proposed bounded-reflection decision, before any of it is believed.

    Optional on the wire (``HypothesisOutput.reflection`` defaults to ``None``) so every
    scripted response predating Phase 7 remains valid: an absent proposal is handled the
    same way :func:`asic.orchestration.reflection.decide_reflection` handles any other
    proposal it does not trust, by falling back to a deterministic default.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: ReflectionAction
    rationale: str = Field(min_length=1, max_length=1000)
    target_hypothesis_id: str | None = None
    gap: str | None = Field(default=None, max_length=500)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class HypothesisOutput(BaseModel):
    """The model's whole response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypotheses: list[HypothesisDraft] = Field(default_factory=list)
    insufficient_evidence_reason: str | None = None
    reflection: ReflectionProposalModel | None = None


def hypothesis_node(deps: NodeDependencies) -> Any:
    """Build the hypothesis node."""

    contract = G5_HYPOTHESIS_ENGINE

    def run(state: GraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.hypothesis_engine",
            node_id=NodeId.G5_HYPOTHESIS_ENGINE,
            node_version=contract.node_version,
            input_refs={"evidence_count": len(state.get("evidence", []))},
        ) as span:
            budget = _budget_state(state, deps)
            span.budget_snapshot = dict(budget.remaining())

            evidence = list(state.get("evidence", []))
            if not evidence:
                span.set_decision(skipped=True, reason="no evidence has been gathered")
                update: dict[str, Any] = {
                    "phase": InvestigationPhase.PLANNING,
                    "budget": _snapshot(budget),
                }
                contract.validate_update(update)
                return update

            try:
                output, tokens, cost = _ask_model(deps, state, evidence, span)
            except (SchemaViolation, ModelProviderError) as exc:
                metrics.schema_violations_total.add(1, {"node": NodeId.G5_HYPOTHESIS_ENGINE.value})
                span.fail(str(exc))
                update = {
                    "phase": InvestigationPhase.PLANNING,
                    "budget": _snapshot(budget.charge(iterations=0)),
                    "failures": [
                        _failure(deps, contract, type(exc).__name__, str(exc), recoverable=True)
                    ],
                }
                contract.validate_update(update)
                return update

            charged = budget.charge(tokens=tokens, cost_usd=cost)
            known = {ref.evidence_id: ref for ref in evidence}
            persisted = _persisted_ids(deps, known)

            accepted: list[HypothesisRef] = []
            rejected: list[dict[str, Any]] = []
            rank = len(state.get("hypotheses", []))

            for draft in output.hypotheses:
                supporting, contradicting = _partition_citations(draft, known, persisted)
                unknown = _unknown_citations(draft, persisted)
                if unknown:
                    # Dropped in code, not scored down in a prompt.
                    rejected.append({"statement": draft.statement[:120], "unknown": unknown})
                    continue
                rank += 1
                accepted.append(_persist(deps, draft, supporting, contradicting, rank=rank))

            span.set_decision(
                proposed=len(output.hypotheses),
                accepted=len(accepted),
                rejected_unsupported=rejected,
                insufficient_evidence_reason=output.insufficient_evidence_reason,
                model_confidences=[d.confidence for d in output.hypotheses],
                final_confidences=[h.confidence for h in accepted],
            )
            span.confidence = max((h.confidence for h in accepted), default=None)
            span.evidence_refs.extend(uuid.UUID(ref.evidence_id) for ref in evidence)

            merged_gaps = sorted(
                {
                    *state.get("open_gaps", []),
                    *(gap for h in accepted for gap in h.remaining_gaps),
                }
            )

            reflection_ref, hypotheses_update = _reflect(
                deps,
                state,
                output=output,
                accepted=accepted,
                open_gaps=merged_gaps,
            )
            span.set_decision(
                reflection_action=reflection_ref.action.value,
                reflection_rule_id=reflection_ref.rule_id,
                reflection_overridden_reason=reflection_ref.overridden_reason,
                reflection_target=reflection_ref.target_hypothesis_id,
            )

            update = {
                "phase": InvestigationPhase.PLANNING,
                "hypotheses": hypotheses_update,
                "reflection_decision": reflection_ref,
                "budget": _snapshot(charged),
                "open_gaps": sorted(
                    {*merged_gaps, *([reflection_ref.gap] if reflection_ref.gap else [])}
                ),
            }
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _ask_model(
    deps: NodeDependencies,
    state: GraphState,
    evidence: list[EvidenceRef],
    span: Any,
) -> tuple[HypothesisOutput, int, float]:
    objective = deps.objective
    context = {
        "objective": objective.statement,
        "services": list(objective.service_names),
        "environment": objective.environment_name,
        "evidence_index": [
            {
                "evidence_id": ref.evidence_id,
                "domain": ref.domain.value,
                "provenance": ref.provenance.value,
                "quality": ref.quality_score,
                "injection_flagged": ref.injection_flagged,
            }
            for ref in evidence
        ],
        "open_gaps": list(state.get("open_gaps", [])),
        "degraded_domains": sorted(state.get("degraded_domains", [])),
    }
    # Retrieved knowledge is operational data like any other: fenced, labelled RETRIEVED,
    # bounded, and withheld if access was withdrawn after it was retrieved - re-checked
    # against the *current* principal and scope (P6-03), recomputed here rather than
    # trusted from whenever the evidence was originally gathered.
    try:
        principal, scope = recompute_investigation_context(
            deps.session,
            tenant_id=deps.context.tenant_id,
            environment_id=deps.context.scope.environment_id,
            service_ids=tuple(s.service_id for s in deps.context.scope.services),
            correlation_id=deps.context.correlation_id,
        )
        knowledge_blocks: tuple[UntrustedBlock, ...] = knowledge_evidence_blocks(
            deps.session,
            tenant_id=deps.context.tenant_id,
            evidence=evidence,
            principal=principal,
            scope=scope,
        )
    except RetrievalRefused:
        # An unresolvable principal (malformed grant configuration) withholds knowledge
        # content rather than surfacing it unauthorized or crashing the hypothesis step;
        # every other evidence domain is unaffected.
        knowledge_blocks = ()
    untrusted = (
        incident_alert_blocks(
            deps.session,
            tenant_id=deps.context.tenant_id,
            incident_id=deps.context.incident_id,
        )
        + knowledge_blocks
    ) + tuple(
        UntrustedBlock(
            source=f"{ref.domain.value}:{ref.evidence_id}",
            provenance=ref.provenance,
            content=ref.headline,
        )
        for ref in evidence
    )

    tokens = 0
    cost = 0.0
    last_error = ""
    for attempt in range(SCHEMA_REPAIR_ATTEMPTS + 1):
        request = ModelRequest(
            node_id=NodeId.G5_HYPOTHESIS_ENGINE,
            prompt_id=HYPOTHESIS_PROMPT.prompt_id,
            prompt_version=HYPOTHESIS_PROMPT.version,
            prompt_hash=HYPOTHESIS_PROMPT.content_hash,
            prompt_text=HYPOTHESIS_PROMPT.render(context=context, untrusted=untrusted),
            metadata={
                "workflow_run_id": deps.context.identity.workflow_run_id,
                "attempt": str(attempt + 1),
            },
        )
        response = deps.model.complete(request)
        tokens += response.total_tokens
        cost += response.cost_usd
        span.set_model_call(
            provider=response.provider,
            model_id=response.model_id,
            prompt_version=HYPOTHESIS_PROMPT.version,
            prompt_hash=HYPOTHESIS_PROMPT.content_hash,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=response.cost_usd,
            finish_reason=response.finish_reason,
        )
        metrics.llm_calls_total.add(
            1, {"provider": response.provider, "model": response.model_id, "outcome": "ok"}
        )
        try:
            return HypothesisOutput.model_validate(json.loads(response.text)), tokens, cost
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    raise SchemaViolation(
        f"hypothesis output failed validation after {SCHEMA_REPAIR_ATTEMPTS + 1} "
        f"attempt(s): {last_error}"
    )


def _persisted_ids(deps: NodeDependencies, known: dict[str, EvidenceRef]) -> set[str]:
    """Evidence ids that genuinely exist in this tenant.

    Checked against the database rather than against graph state: state is what we believe,
    and the point of this check is to catch a citation that does not correspond to
    something actually recorded.
    """
    if not known:
        return set()
    rows = deps.session.execute(
        sa.select(Evidence.id).where(
            Evidence.tenant_id == deps.context.tenant_id,
            Evidence.incident_id == deps.context.incident_id,
        )
    ).scalars()
    return {str(value) for value in rows}


def _partition_citations(
    draft: HypothesisDraft,
    known: dict[str, EvidenceRef],
    persisted: set[str],
) -> tuple[list[str], list[str]]:
    """Split citations into support and counter-evidence, with contradiction winning.

    A record named in both lists is counted only as counter-evidence. This is not merely
    tidying up an ambiguous output: counting it as support too would inflate the support
    count, which is one of the inputs to the deterministic confidence ceiling. A model - or
    an attacker shaping one - could otherwise buy confidence by citing the same record
    twice.
    """
    contradicting = _resolve(draft.contradicting_evidence, known, persisted)
    contradicted = set(contradicting)
    supporting = [
        evidence_id
        for evidence_id in _resolve(draft.supporting_evidence, known, persisted)
        if evidence_id not in contradicted
    ]
    return supporting, contradicting


def _resolve(cited: list[str], known: dict[str, EvidenceRef], persisted: set[str]) -> list[str]:
    """Expand the fixture sentinels and drop anything not persisted."""
    if cited in ([_ALL], [_ALL.lower()]):
        return [eid for eid in known if eid in persisted]
    if cited in ([_NONE], [_NONE.lower()], []):
        return []
    expanded: list[str] = []
    for entry in cited:
        if entry.upper() in {domain_hint.upper() for domain_hint in _DOMAIN_SENTINELS}:
            expanded.extend(
                eid
                for eid, ref in known.items()
                if ref.domain.value.upper() == entry.upper() and eid in persisted
            )
        elif entry in persisted:
            expanded.append(entry)
    return expanded


#: Domain-name sentinels the fixtures use in place of concrete ids.
_DOMAIN_SENTINELS: Final[tuple[str, ...]] = (
    "METRICS",
    "LOGS",
    "TRACES",
    "DEPLOYMENTS",
    "KUBERNETES_STATE",
    "KNOWLEDGE",
)


def _unknown_citations(draft: HypothesisDraft, persisted: set[str]) -> list[str]:
    """Citations that are neither a sentinel nor a real evidence id."""
    sentinels = {_ALL, _NONE, *_DOMAIN_SENTINELS}
    unknown: list[str] = []
    for entry in [*draft.supporting_evidence, *draft.contradicting_evidence]:
        if entry.upper() in sentinels or entry in persisted:
            continue
        unknown.append(entry)
    return unknown


def confidence_ceiling(*, supporting: int, contradicting: int, mean_quality: float) -> float:
    """The most confidence the evidence can justify, independent of what was claimed.

    Deterministic and deliberately conservative. The inputs are counts and measured
    quality, none of which the model controls.
    """
    if supporting == 0:
        return _UNSUPPORTED_CEILING
    if contradicting > 0:
        return _CONTRADICTED_CEILING
    if supporting == 1:
        return min(_SINGLE_SUPPORT_CEILING, 0.2 + mean_quality * 0.4)
    # Two or more corroborating records with no contradiction: the ceiling scales with
    # both how much agrees and how complete each answer was.
    return round(min(0.95, 0.45 + 0.1 * min(supporting, 4) + 0.2 * mean_quality), 3)


def _persist(
    deps: NodeDependencies,
    draft: HypothesisDraft,
    supporting: list[str],
    contradicting: list[str],
    *,
    rank: int,
) -> HypothesisRef:
    qualities = _qualities(deps, [*supporting, *contradicting])
    mean_quality = sum(qualities) / len(qualities) if qualities else 0.0
    ceiling = confidence_ceiling(
        supporting=len(supporting),
        contradicting=len(contradicting),
        mean_quality=mean_quality,
    )
    final = round(min(draft.confidence, ceiling), 3)

    hypothesis = Hypothesis(
        id=uuid.uuid4(),
        tenant_id=deps.context.tenant_id,
        incident_id=deps.context.incident_id,
        workflow_run_id=deps.context.workflow_run_id,
        rank=rank,
        root_cause_class=draft.root_cause_class,
        statement=draft.statement,
        confidence=final,
        confidence_basis={
            "model_stated_confidence": draft.confidence,
            "deterministic_ceiling": ceiling,
            "applied": final,
            "supporting_count": len(supporting),
            "contradicting_count": len(contradicting),
            "mean_evidence_quality": round(mean_quality, 3),
            "ceiling_rule": _ceiling_rule(len(supporting), len(contradicting)),
        },
        status=HypothesisStatus.PROPOSED,
        remaining_gaps=list(draft.remaining_gaps),
        produced_by_node=NodeId.G5_HYPOTHESIS_ENGINE,
    )
    deps.session.add(hypothesis)
    deps.session.flush()

    for evidence_id in supporting:
        _link(deps, hypothesis.id, evidence_id, EvidenceRelation.SUPPORTS)
    for evidence_id in contradicting:
        _link(deps, hypothesis.id, evidence_id, EvidenceRelation.CONTRADICTS)
    deps.session.flush()

    return HypothesisRef(
        hypothesis_id=str(hypothesis.id),
        rank=rank,
        root_cause_class=draft.root_cause_class,
        confidence=final,
        status=HypothesisStatus.PROPOSED,
        supporting_evidence_count=len(supporting),
        contradicting_evidence_count=len(contradicting),
        remaining_gaps=tuple(draft.remaining_gaps),
    )


_RANK_SENTINEL: Final = re.compile(r"^RANK:(\d+)$", re.IGNORECASE)


def _resolve_target(
    raw: str | None,
    prior: list[HypothesisRef],
    accepted: list[HypothesisRef],
) -> str | None:
    """Expand a fixture sentinel for ``target_hypothesis_id`` into a real, persisted id.

    A scripted response is written before a run exists, so it cannot know a hypothesis's
    generated UUID in advance - the same problem evidence-citation sentinels solve in
    :func:`_resolve`. ``rank`` is assigned deterministically (sequentially, as hypotheses
    are formed across the run), so ``"RANK:<n>"`` is stable to script against; ``"LATEST"``
    means the strongest hypothesis accepted this same step, for a proposal that refers to
    what it just proposed. Anything else - including a real-looking but wrong id - is left
    unresolved and is then rejected by ``reflection.py`` exactly as an unknown target is.
    """
    if raw is None:
        return None
    if raw.strip().upper() == "LATEST":
        if not accepted:
            return raw
        return max(accepted, key=lambda h: h.confidence).hypothesis_id
    match = _RANK_SENTINEL.match(raw.strip())
    if match:
        rank = int(match.group(1))
        for ref in (*prior, *accepted):
            if ref.rank == rank:
                return ref.hypothesis_id
    return raw


def _reflect(
    deps: NodeDependencies,
    state: GraphState,
    *,
    output: HypothesisOutput,
    accepted: list[HypothesisRef],
    open_gaps: list[str],
) -> tuple[ReflectionDecisionRef, list[HypothesisRef]]:
    """Validate the model's reflection proposal and apply any hypothesis revision it wins.

    Returns the validated decision alongside the ``hypotheses`` update this step should
    return: normally just ``accepted``, plus a corrected reference for a superseded target
    when the decision is ``revise_hypothesis`` - graph state accumulates append-only, so the
    corrected status has to be re-asserted rather than edited in place (see
    :func:`asic.orchestration.termination.best_hypothesis_of`).
    """
    prior = list(state.get("hypotheses", []))
    proposal = (
        ReflectionProposal(
            action=output.reflection.action,
            rationale=output.reflection.rationale,
            target_hypothesis_id=_resolve_target(
                output.reflection.target_hypothesis_id, prior, accepted
            ),
            gap=output.reflection.gap,
            confidence=output.reflection.confidence,
        )
        if output.reflection is not None
        else ReflectionProposal(action=None, rationale="no reflection was proposed")
    )
    inputs = ReflectionInputs(
        proposal=proposal,
        hypotheses=[*prior, *accepted],
        new_hypothesis_ids=frozenset(h.hypothesis_id for h in accepted),
        open_gaps=open_gaps,
        degraded_domains=list(state.get("degraded_domains", [])),
        attempted_domains=[
            *state.get("covered_domains", []),
            *state.get("degraded_domains", []),
        ],
    )
    verdict = decide_reflection(inputs)

    hypotheses_update = list(accepted)
    if verdict.action is ReflectionAction.REVISE_HYPOTHESIS:
        assert verdict.target_hypothesis_id is not None  # guaranteed by the guard
        superseding = max(accepted, key=lambda h: h.confidence)
        deps.session.execute(
            sa.update(Hypothesis)
            .where(
                Hypothesis.tenant_id == deps.context.tenant_id,
                Hypothesis.id == uuid.UUID(verdict.target_hypothesis_id),
            )
            .values(
                status=HypothesisStatus.SUPERSEDED,
                superseded_by_id=uuid.UUID(superseding.hypothesis_id),
            )
        )
        deps.session.flush()
        target_ref = next(h for h in prior if h.hypothesis_id == verdict.target_hypothesis_id)
        hypotheses_update.append(
            target_ref.model_copy(update={"status": HypothesisStatus.SUPERSEDED})
        )
        metrics.hypothesis_revisions_total.add(1)

    metrics.reflection_decisions_total.add(
        1, {"action": verdict.action.value, "rule_id": verdict.rule_id}
    )

    reflection_ref = ReflectionDecisionRef(
        action=verdict.action,
        rationale=verdict.rationale[:1000],
        target_hypothesis_id=verdict.target_hypothesis_id,
        gap=verdict.gap,
        confidence=verdict.confidence,
        overridden_reason=verdict.overridden_reason,
        rule_id=verdict.rule_id,
    )
    return reflection_ref, hypotheses_update


def _ceiling_rule(supporting: int, contradicting: int) -> str:
    if supporting == 0:
        return "unsupported"
    if contradicting > 0:
        return "contradicted"
    if supporting == 1:
        return "single_support"
    return "corroborated"


def _link(
    deps: NodeDependencies,
    hypothesis_id: uuid.UUID,
    evidence_id: str,
    relation: EvidenceRelation,
) -> None:
    deps.session.add(
        HypothesisEvidence(
            id=uuid.uuid4(),
            tenant_id=deps.context.tenant_id,
            hypothesis_id=hypothesis_id,
            evidence_id=uuid.UUID(evidence_id),
            relation=relation,
        )
    )


def _qualities(deps: NodeDependencies, evidence_ids: list[str]) -> list[float]:
    if not evidence_ids:
        return []
    rows = deps.session.execute(
        sa.select(Evidence.quality_score).where(
            Evidence.tenant_id == deps.context.tenant_id,
            Evidence.id.in_([uuid.UUID(eid) for eid in evidence_ids]),
        )
    ).scalars()
    return [float(value) for value in rows if value is not None]


def _failure(
    deps: NodeDependencies,
    contract: Any,
    error_type: str,
    message: str,
    *,
    recoverable: bool,
    category: EvidenceFailureCategory = EvidenceFailureCategory.MODEL_FAILURE,
) -> NodeFailureRef:
    return NodeFailureRef(
        node_id=NodeId.G5_HYPOTHESIS_ENGINE,
        node_version=contract.node_version,
        error_type=error_type,
        message=message[:1000],
        recoverable=recoverable,
        occurred_at=deps.clock.now().isoformat(),
        category=category,
    )


def _budget_state(state: GraphState, deps: NodeDependencies) -> BudgetState:
    """The run's budget, with the wall clock read at the moment of the call.

    Delegated so every node observes elapsed time the same way. Reading the snapshot alone
    would give a figure that was correct when the last checkpoint was written and stale by
    the time this node checks whether it may take another step.
    """
    return deps.budget_from(state.get("budget"))


def _snapshot(budget: BudgetState) -> BudgetSnapshot:
    kind = budget.exhausted_kind()
    return BudgetSnapshot(
        consumed=budget.ledger.to_dict(),
        remaining=budget.remaining(),
        exhausted_kind=kind.value if kind else None,
    )


__all__ = [
    "SCHEMA_REPAIR_ATTEMPTS",
    "HypothesisDraft",
    "HypothesisOutput",
    "confidence_ceiling",
    "hypothesis_node",
]
