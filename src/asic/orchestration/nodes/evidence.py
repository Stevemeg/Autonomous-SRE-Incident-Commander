"""G4 Evidence Collector.

The only node with capabilities, and therefore the only node that can reach anything
outside this process - and it reaches it through the broker, which authorizes, bounds,
audits and traces every call.

**Narrowed for this phase, deliberately.** The approved topology gives G4 six
model-assisted strategies. This implementation has six strategies and no model: collection
and normalisation are deterministic, so the first vertical slice has no model in the
evidence path at all. Interpretation per domain is Phase 7 work, needs the evaluation
harness to be worth doing, and adding it now would put a model between a tool result and
the evidence record derived from it - which is exactly where a fabricated observation would
be hardest to detect. The narrowing is recorded on the node contract and in
``docs/architecture/orchestration-kernel.md``.

**Provenance is assigned by the broker, not here.** A node cannot label its own output a
verified fact. This node copies what the broker gave it onto the evidence row and the
database refuses anything authority-bearing (``ck_evidence_evidence_provenance_is_not_
authoritative``).

**Partial failure degrades; it does not abort.** A domain that errors or times out is
recorded on the step as degraded with its reason, added to ``degraded_domains``, and the
investigation continues. The terminator later decides whether the remaining coverage is
enough - which is the right place for that judgement, because only it can see all of it.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from typing import Any, Final

import sqlalchemy as sa

from asic.contracts.nodes import G4_EVIDENCE_COLLECTOR
from asic.contracts.state import (
    BudgetSnapshot,
    EvidenceRef,
    GraphState,
    NodeFailureRef,
    StepRef,
)
from asic.db.models.investigation import Evidence, InvestigationStep
from asic.domain.budget import BudgetState
from asic.domain.enums import (
    BudgetKind,
    EvidenceDomain,
    InvestigationPhase,
    InvestigationStepStatus,
    NodeId,
    TraceSpanKind,
)
from asic.domain.errors import BudgetExhausted, DomainError
from asic.domain.untrusted import scan_structure
from asic.knowledge.errors import RetrievalRefused
from asic.observability import metrics
from asic.orchestration import knowledge_context
from asic.orchestration.context import NodeDependencies
from asic.tools.broker import CapabilityRequest, ToolResult
from asic.tools.catalogue import capability_for_domain

#: Result keys that hold the collection a domain actually returned. Used to build the
#: headline and to score coverage. A domain whose key is absent returned nothing.
_COLLECTION_KEY: Final[dict[EvidenceDomain, str]] = {
    EvidenceDomain.METRICS: "samples",
    EvidenceDomain.LOGS: "lines",
    EvidenceDomain.TRACES: "operations",
    EvidenceDomain.DEPLOYMENTS: "deployments",
    EvidenceDomain.KUBERNETES_STATE: "workloads",
    EvidenceDomain.KNOWLEDGE: "documents",
}

#: How many items a domain must return before its evidence is treated as fully covering the
#: gap it was collected for. Below this the quality score is scaled down rather than the
#: evidence being discarded: a thin answer is still an answer, and pretending otherwise
#: would hide a real finding.
_FULL_COVERAGE_ITEMS: Final[int] = 3


def evidence_node(deps: NodeDependencies) -> Any:
    """Build the evidence-collection node."""

    contract = G4_EVIDENCE_COLLECTOR

    def run(state: GraphState) -> dict[str, Any]:
        decision = state.get("last_decision")
        if decision is None or decision.domain is None:
            # Reached only if routing changed without this node changing. Returning a
            # typed no-op beats guessing which domain was meant.
            return _no_op(contract, state, deps)

        domain = decision.domain
        step_ref = _current_step(state)

        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name=f"node.evidence_collector[{domain.value}]",
            node_id=NodeId.G4_EVIDENCE_COLLECTOR,
            node_version=contract.node_version,
            input_refs={"domain": domain.value, "gap": decision.gap},
        ) as span:
            budget = _budget_state(state, deps)
            span.budget_snapshot = dict(budget.remaining())

            try:
                budget.require_headroom(tool_calls=1)
            except BudgetExhausted as exc:
                span.set_decision(skipped=True, overridden_reason=str(exc))
                return _degrade(
                    contract,
                    state,
                    deps,
                    domain,
                    step_ref,
                    budget,
                    reason=str(exc),
                    budget_refusal=exc.kind,
                )

            request = CapabilityRequest(
                node_id=NodeId.G4_EVIDENCE_COLLECTOR,
                capability=capability_for_domain(domain),
                service_name=_service_for(deps, domain),
                arguments=_arguments_for(domain, deps, decision.gap),
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                investigation_step_id=uuid.UUID(step_ref.step_id) if step_ref else None,
                purpose=decision.gap,
            )

            try:
                result = deps.broker.invoke(deps.session, request=request, contract=contract)
            except DomainError as exc:
                # A refusal the broker chose to raise rather than return. Degrade, record,
                # continue: an investigation survives a source it cannot reach.
                span.fail(str(exc))
                return _degrade(contract, state, deps, domain, step_ref, budget, reason=str(exc))

            charged = budget.charge(tool_calls=0 if result.deduplicated else 1)
            span.set_decision(
                capability=request.capability,
                service=request.service_name,
                outcome=result.outcome.value,
                deduplicated=result.deduplicated,
                injection_flags=list(result.injection_flags),
            )
            if result.tool_execution_id is not None:
                span.tool_execution_id = result.tool_execution_id

            if not result.succeeded:
                reason = result.failure.message if result.failure else "the source did not answer"
                span.fail(reason)
                metrics.node_failures_total.add(
                    1,
                    {
                        "node": NodeId.G4_EVIDENCE_COLLECTOR.value,
                        "reason": result.failure.error_type if result.failure else "unknown",
                    },
                )
                return _degrade(contract, state, deps, domain, step_ref, charged, reason=reason)

            # Knowledge results arrive with a provider manifest, and providing one is
            # mandatory (P6-02): it is untrusted input, re-checked against the database and
            # against principal/policy/query facts this node recomputes itself - never
            # taken from the provider on trust - before anything is recorded. Any claim
            # that does not hold, or a missing manifest, refuses and degrades the domain.
            verified: knowledge_context.VerifiedRetrieval | None = None
            if domain is EvidenceDomain.KNOWLEDGE:
                try:
                    principal, scope = knowledge_context.recompute_investigation_context(
                        deps.session,
                        tenant_id=deps.context.tenant_id,
                        environment_id=deps.context.scope.environment_id,
                        service_ids=(deps.context.scope.service(request.service_name).service_id,),
                        correlation_id=deps.context.correlation_id,
                    )
                    verified = knowledge_context.validate_manifest(
                        deps.session,
                        tenant_id=deps.context.tenant_id,
                        correlation_id=deps.context.correlation_id,
                        principal=principal,
                        scope=scope,
                        query_text=str(request.arguments["topic"]),
                        result=result,
                    )
                except (knowledge_context.KnowledgeManifestInvalid, RetrievalRefused) as exc:
                    span.fail(exc.code)
                    return _degrade(
                        contract,
                        state,
                        deps,
                        domain,
                        step_ref,
                        charged,
                        reason=f"knowledge retrieval could not be verified: {exc.code}",
                    )

            evidence_ref = _persist_evidence(deps, domain, decision.gap, result, step_ref, verified)
            if verified is not None:
                knowledge_context.record_manifest(
                    deps.session,
                    verified,
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    workflow_run_id=deps.context.workflow_run_id,
                    tool_execution_id=result.tool_execution_id,
                    evidence_id=uuid.UUID(evidence_ref.evidence_id),
                )
                span.set_decision(
                    retrieval_id=str(verified.retrieval_id),
                    retrieved_citations=list(verified.citations),
                    retrieval_replayed=verified.replayed,
                )
            span.evidence_refs.append(uuid.UUID(evidence_ref.evidence_id))
            span.confidence = evidence_ref.quality_score

            _complete_step(deps, step_ref, charged, status=InvestigationStepStatus.COMPLETED)

            update: dict[str, Any] = {
                "phase": InvestigationPhase.PLANNING,
                "evidence": [evidence_ref],
                "steps": [],
                "covered_domains": sorted({*state.get("covered_domains", []), domain.value}),
                "budget": _snapshot(charged),
            }
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _service_for(deps: NodeDependencies, domain: EvidenceDomain) -> str:
    """Which of the incident's services to ask about.

    The first service in scope. Selecting *within* an already-bounded set is a narrowing
    choice, not a widening one - the broker still refuses any name that is not in scope.
    Multi-service investigation strategy arrives with the analyser strategies in Phase 7.
    """
    del domain
    names = deps.context.scope.service_names
    if not names:
        raise DomainError(
            "the incident has no service in scope; evidence cannot be collected for "
            "nothing, and inventing a target would be worse than failing"
        )
    return names[0]


def _arguments_for(domain: EvidenceDomain, deps: NodeDependencies, gap: str) -> dict[str, Any]:
    """Non-scope arguments for one domain.

    Scope arguments are deliberately absent: supplying one is rejected by the descriptor,
    and the broker fills them from the incident.
    """
    objective = deps.objective
    window = {
        "window_start": objective.window_start,
        "window_end": objective.window_end,
    }
    if domain is EvidenceDomain.METRICS:
        return {**window, "metric": "http_request_duration_p95_seconds", "step_seconds": 60}
    if domain is EvidenceDomain.LOGS:
        return {**window, "min_level": "warn", "limit": 100}
    if domain is EvidenceDomain.TRACES:
        return {**window, "min_duration_ms": 250}
    if domain is EvidenceDomain.DEPLOYMENTS:
        return dict(window)
    if domain is EvidenceDomain.KUBERNETES_STATE:
        return {"include_events": True}
    return {"topic": _knowledge_topic(gap, objective.statement), "limit": 5}


_CONTROL_CHARACTERS: Final = re.compile(r"[\x00-\x1f\x7f]+")


def _knowledge_topic(gap: str, fallback: str) -> str:
    """The planner's declared information need is the retrieval query.

    It may be model-authored text, and that is acceptable here: a query is not authority.
    What is retrieved is decided by the tenant, scope and clearances the broker and the
    knowledge provider resolve - never by the words of the query.
    """
    topic = " ".join(_CONTROL_CHARACTERS.sub(" ", gap).split())[:200].strip()
    return topic or fallback[:200]


def _persist_evidence(
    deps: NodeDependencies,
    domain: EvidenceDomain,
    gap: str,
    result: ToolResult,
    step_ref: StepRef | None,
    verified: knowledge_context.VerifiedRetrieval | None = None,
) -> EvidenceRef:
    """Write the evidence row and return the reference the graph state carries."""
    payload = dict(result.payload)
    items = _items(domain, payload)
    flags = result.injection_flags or scan_structure(payload)
    if verified is not None:
        flags = tuple(sorted({*flags, *verified.injection_flags}))
    digest = _digest(payload)
    quality = _quality(items, degraded=False)

    content: dict[str, Any] = {
        "headline": _headline(domain, items),
        "items": items,
        # The retrieval manifest is recorded in its own tables; it is not copied here.
        "envelope": {
            key: value
            for key, value in payload.items()
            if key not in _COLLECTION_KEY.values() and key != "retrieval"
        },
    }
    citation = {**dict(result.citation), "content_digest": digest, "gap": gap}
    if verified is not None:
        citation["retrieval_id"] = str(verified.retrieval_id)
        citation["citations"] = list(verified.citations)

    if result.tool_execution_id is None:  # pragma: no cover - broker always sets it
        raise DomainError(
            "a successful tool result carried no execution id; evidence must reference the "
            "recorded query that produced it (INV-4)"
        )

    evidence = Evidence(
        id=uuid.uuid4(),
        tenant_id=deps.context.tenant_id,
        incident_id=deps.context.incident_id,
        investigation_step_id=uuid.UUID(step_ref.step_id) if step_ref else None,
        tool_execution_id=result.tool_execution_id,
        domain=domain,
        provenance=result.provenance,
        content=content,
        citation=citation,
        quality_score=quality,
        gathered_at=deps.clock.now(),
        injection_flagged=bool(flags),
    )
    deps.session.add(evidence)
    deps.session.flush()

    for flag in flags:
        metrics.injection_flags_total.add(1, {"source": domain.value, "pattern": flag})

    return EvidenceRef(
        evidence_id=str(evidence.id),
        tool_execution_id=str(result.tool_execution_id),
        domain=domain,
        provenance=result.provenance,
        headline=str(content["headline"])[:240],
        content_digest=digest,
        quality_score=quality,
        injection_flagged=bool(flags),
    )


def _items(domain: EvidenceDomain, payload: Mapping[str, Any]) -> list[str]:
    key = _COLLECTION_KEY.get(domain)
    if key is None:
        return []
    raw = payload.get(key) or []
    return [str(item) for item in raw] if isinstance(raw, (list, tuple)) else []


def _headline(domain: EvidenceDomain, items: list[str]) -> str:
    """A deterministic one-line summary. Mechanical on purpose.

    A model-authored headline would put generated prose into the reference that every
    downstream component reads, which is precisely where an unsupported claim would spread
    fastest.
    """
    if not items:
        return f"{domain.value}: no matching records in the requested window"
    return f"{domain.value}: {len(items)} record(s); first = {items[0][:160]}"


def _digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _quality(items: list[str], *, degraded: bool) -> float:
    """Coverage of the declared gap: how much the answer actually contains.

    Deliberately crude and deliberately not a model's opinion of its own evidence. It
    scales with how much came back, and a degraded source scores zero because a partial
    answer from a broken source is not the same as a complete answer that happens to be
    short.
    """
    if degraded:
        return 0.0
    if not items:
        return 0.1
    return round(min(1.0, len(items) / _FULL_COVERAGE_ITEMS), 3)


def _current_step(state: GraphState) -> StepRef | None:
    steps = state.get("steps", [])
    return steps[-1] if steps else None


def _complete_step(
    deps: NodeDependencies,
    step_ref: StepRef | None,
    budget: BudgetState,
    *,
    status: InvestigationStepStatus,
    degradation_reason: str | None = None,
) -> None:
    if step_ref is None:
        return
    deps.session.execute(
        sa.update(InvestigationStep)
        .where(
            InvestigationStep.tenant_id == deps.context.tenant_id,
            InvestigationStep.id == uuid.UUID(step_ref.step_id),
        )
        .values(
            status=status,
            degradation_reason=degradation_reason,
            budget_after=budget.to_dict(),
            completed_at=deps.clock.now(),
        )
    )
    deps.session.flush()


def _degrade(
    contract: Any,
    state: GraphState,
    deps: NodeDependencies,
    domain: EvidenceDomain,
    step_ref: StepRef | None,
    budget: BudgetState,
    *,
    reason: str,
    budget_refusal: BudgetKind | None = None,
) -> dict[str, Any]:
    """Record a domain as unusable and continue with reduced coverage."""
    _complete_step(
        deps,
        step_ref,
        budget,
        status=InvestigationStepStatus.DEGRADED,
        degradation_reason=reason[:1000],
    )
    update: dict[str, Any] = {
        "phase": InvestigationPhase.PLANNING,
        "degraded_domains": sorted({*state.get("degraded_domains", []), domain.value}),
        "budget": _snapshot(budget),
        "failures": [
            NodeFailureRef(
                node_id=NodeId.G4_EVIDENCE_COLLECTOR,
                node_version=contract.node_version,
                error_type="EvidenceUnavailable",
                message=reason[:1000],
                # Recoverable: the investigation continues without this domain. Whether
                # the remaining coverage suffices is the terminator's judgement, not this
                # node's.
                recoverable=True,
                occurred_at=deps.clock.now().isoformat(),
                stage="adapter_invocation",
            )
        ],
    }
    if budget_refusal is not None:
        update["budget_refusal"] = budget_refusal.value
    contract.validate_update(update)
    return update


def _no_op(contract: Any, state: GraphState, deps: NodeDependencies) -> dict[str, Any]:
    update: dict[str, Any] = {
        "phase": InvestigationPhase.PLANNING,
        "budget": _snapshot(_budget_state(state, deps)),
    }
    contract.validate_update(update)
    return update


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


__all__ = ["evidence_node"]
