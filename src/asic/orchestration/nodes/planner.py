"""G3 Investigation Planner.

The planner is the loop, and therefore the most important place to be strict. Its job is to
name the largest open information gap and select one step to close it. It has no
capabilities, calls no tools, and cannot execute anything: the evidence collector does that,
under a separate contract.

The order of operations in :func:`planner_node` is the design:

1. **Budget first, before the model.** If a limit is reached or would be reached, the node
   terminates without spending a token. Checking afterwards would pay for the step that
   broke the limit.
2. **Model second**, with a rendered prompt whose untrusted regions are fenced.
3. **Deterministic guards third**, applied to whatever came back. The model's choice is a
   *proposal*; four rules can override it, and every override is recorded with a reason:

   - output that will not parse gets one repair attempt, then the node terminates;
   - a domain outside the resolved capability menu is **rejected, never repaired** - a
     repair loop teaches a planner to negotiate for capability it was not granted;
   - a domain already covered with no new gap declared is redundant and is converted into
     a hypothesis step;
   - the hard iteration cap terminates the run regardless of what the model asked for.

That third group is the answer to "do not rely on the model to stop". Nothing here trusts
the model to respect a bound; the bounds are applied to its output.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asic.contracts.nodes import G3_INVESTIGATION_PLANNER
from asic.contracts.state import (
    BudgetSnapshot,
    CandidateTask,
    GraphState,
    NodeFailureRef,
    PlannerDecisionRef,
    StepRef,
)
from asic.db.models.investigation import InvestigationStep
from asic.domain.budget import BudgetState
from asic.domain.enums import (
    BudgetKind,
    EvidenceDomain,
    InvestigationPhase,
    InvestigationStepStatus,
    NodeId,
    PlannerAction,
    TerminationReason,
    TraceSpanKind,
)
from asic.domain.errors import BudgetExhausted, ModelProviderError, SchemaViolation
from asic.llm.budgeted import complete_with_budget
from asic.llm.port import ModelRequest
from asic.llm.prompts import PLANNER_PROMPT
from asic.observability import metrics
from asic.orchestration.alert_context import incident_alert_blocks
from asic.orchestration.context import NodeDependencies
from asic.tools.catalogue import DOMAIN_CAPABILITY

#: Repair attempts permitted for unparseable model output. One, and the repair is a fresh
#: request rather than the same one resent.
SCHEMA_REPAIR_ATTEMPTS: Final[int] = 1


class PlannerDecision(BaseModel):
    """The planner's structured output. Anything else is a schema violation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: PlannerAction
    gap: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=1000)
    domain: EvidenceDomain | None = None
    expected_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    candidates: tuple[CandidateTask, ...] = ()


def planner_node(deps: NodeDependencies) -> Any:
    """Build the planning node."""

    contract = G3_INVESTIGATION_PLANNER

    def run(state: GraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.PLANNER_STEP,
            name="node.planner",
            node_id=NodeId.G3_INVESTIGATION_PLANNER,
            node_version=contract.node_version,
        ) as span:
            budget = _budget_state(state, deps)
            span.budget_snapshot = dict(budget.remaining())

            # 1. Budget before the model. Exhaustion here costs nothing.
            try:
                budget.require_headroom(iterations=1)
            except BudgetExhausted as exc:
                span.set_decision(
                    action=PlannerAction.TERMINATE.value,
                    overridden_reason=str(exc),
                    budget_kind=exc.kind.value,
                )
                span.termination_reason = TerminationReason.BUDGET_EXHAUSTED
                return _terminate(
                    contract,
                    budget,
                    gap="budget exhausted before a further step could be taken",
                    reason=str(exc),
                    budget_refusal=exc.kind,
                )

            charged = budget.charge(iterations=1)
            menu = list(state.get("capability_menu", []))
            available = _available_domains(menu)

            # 2. The model proposes.
            try:
                decision, tokens, cost = _ask_model(deps, state, available, span, charged)
            except SchemaViolation as exc:
                metrics.schema_violations_total.add(
                    1, {"node": NodeId.G3_INVESTIGATION_PLANNER.value}
                )
                span.set_decision(action=PlannerAction.TERMINATE.value, overridden_reason=str(exc))
                return _terminate(
                    contract,
                    charged,
                    gap="the planner could not produce a valid step",
                    reason=str(exc),
                    failure=NodeFailureRef(
                        node_id=NodeId.G3_INVESTIGATION_PLANNER,
                        node_version=contract.node_version,
                        error_type="SchemaViolation",
                        message=str(exc),
                        recoverable=True,
                        occurred_at=deps.clock.now().isoformat(),
                    ),
                )
            except ModelProviderError as exc:
                span.fail(str(exc))
                return _terminate(
                    contract,
                    charged,
                    gap="the model provider was unavailable",
                    reason=str(exc),
                    failure=NodeFailureRef(
                        node_id=NodeId.G3_INVESTIGATION_PLANNER,
                        node_version=contract.node_version,
                        error_type="ModelProviderError",
                        message=str(exc),
                        recoverable=exc.transient,
                        occurred_at=deps.clock.now().isoformat(),
                    ),
                )

            charged = charged.charge(tokens=tokens, cost_usd=cost)

            # 3. Deterministic guards over the proposal.
            decision, override = _apply_guards(decision, state, available)
            span.set_decision(
                action=decision.action.value,
                domain=decision.domain.value if decision.domain else None,
                gap=decision.gap,
                rationale=decision.rationale,
                expected_gain=decision.expected_gain,
                candidates=[c.model_dump(mode="json") for c in decision.candidates],
                overridden_reason=override,
                available_domains=sorted(d.value for d in available),
            )
            span.confidence = decision.expected_gain

            reference = PlannerDecisionRef(
                action=decision.action,
                gap=decision.gap,
                rationale=decision.rationale,
                domain=decision.domain,
                expected_gain=decision.expected_gain,
                candidates=decision.candidates,
                overridden_reason=override,
            )

            update: dict[str, Any] = {
                "last_decision": reference,
                "iteration": int(state.get("iteration", 0)) + 1,
                "budget": _snapshot(charged),
                "phase": _phase_for(decision.action),
            }

            if decision.action is PlannerAction.COLLECT_EVIDENCE and decision.domain:
                step = _persist_step(deps, state, decision, charged)
                update["steps"] = [step]
                update["open_gaps"] = _remaining_gaps(state, decision.gap)
            elif decision.action is PlannerAction.TERMINATE:
                update["terminated"] = False  # the terminator decides; the planner proposes
                update["open_gaps"] = list(state.get("open_gaps", []))
            else:
                update["open_gaps"] = list(state.get("open_gaps", []))

            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _available_domains(menu: list[str]) -> frozenset[EvidenceDomain]:
    """Domains reachable through the capabilities actually on this run's menu.

    The menu is the resolved set of granted capabilities, so a domain absent from it was
    never offered - the planner is not told it exists.
    """
    granted = set(menu)
    return frozenset(
        domain for domain, capability in DOMAIN_CAPABILITY.items() if capability in granted
    )


def _ask_model(
    deps: NodeDependencies,
    state: GraphState,
    available: frozenset[EvidenceDomain],
    span: Any,
    budget: BudgetState,
) -> tuple[PlannerDecision, int, float]:
    """One model call, with a single repair attempt on unparseable output."""
    objective = deps.objective
    context = {
        "objective": objective.statement,
        "services": list(objective.service_names),
        "environment": objective.environment_name,
        "window": {"start": objective.window_start, "end": objective.window_end},
        "available_domains": sorted(d.value for d in available),
        "covered_domains": sorted(state.get("covered_domains", [])),
        "degraded_domains": sorted(state.get("degraded_domains", [])),
        "open_gaps": list(state.get("open_gaps", [])),
        "evidence_count": len(state.get("evidence", [])),
        "hypothesis_count": len(state.get("hypotheses", [])),
        "budget_remaining": (
            state.get("budget") or BudgetSnapshot(consumed={}, remaining={})
        ).remaining,
        "iteration": int(state.get("iteration", 0)),
    }

    tokens = 0
    cost = 0.0
    last_error = ""
    for attempt in range(SCHEMA_REPAIR_ATTEMPTS + 1):
        request = ModelRequest(
            node_id=NodeId.G3_INVESTIGATION_PLANNER,
            prompt_id=PLANNER_PROMPT.prompt_id,
            prompt_version=PLANNER_PROMPT.version,
            prompt_hash=PLANNER_PROMPT.content_hash,
            prompt_text=PLANNER_PROMPT.render(
                context=context,
                untrusted=incident_alert_blocks(
                    deps.session,
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                ),
            ),
            metadata={
                "workflow_run_id": deps.context.identity.workflow_run_id,
                "attempt": str(attempt + 1),
            },
        )
        response, _ = complete_with_budget(
            deps.model,
            request,
            budget.charge(tokens=tokens, cost_usd=cost),
        )
        tokens += response.total_tokens
        cost += response.cost_usd
        span.set_model_call(
            provider=response.provider,
            model_id=response.model_id,
            prompt_version=PLANNER_PROMPT.version,
            prompt_hash=PLANNER_PROMPT.content_hash,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=response.cost_usd,
            finish_reason=response.finish_reason,
        )
        metrics.llm_calls_total.add(
            1, {"provider": response.provider, "model": response.model_id, "outcome": "ok"}
        )
        metrics.llm_tokens_total.add(response.input_tokens, {"direction": "input"})
        metrics.llm_tokens_total.add(response.output_tokens, {"direction": "output"})

        try:
            return PlannerDecision.model_validate(json.loads(response.text)), tokens, cost
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    raise SchemaViolation(
        f"planner output failed validation after {SCHEMA_REPAIR_ATTEMPTS + 1} attempt(s): "
        f"{last_error}. Unparseable output is a typed failure, never a guess at what the "
        "model meant."
    )


def _apply_guards(
    decision: PlannerDecision,
    state: GraphState,
    available: frozenset[EvidenceDomain],
) -> tuple[PlannerDecision, str | None]:
    """Deterministic overrides of the model's proposal."""
    if decision.action is not PlannerAction.COLLECT_EVIDENCE:
        return decision, None

    if decision.domain is None:
        return (
            decision.model_copy(update={"action": PlannerAction.FORM_HYPOTHESIS}),
            "collect_evidence was proposed with no domain; converted to hypothesis formation",
        )

    if decision.domain not in available:
        # Rejected, never repaired. Offering a repair would teach the loop that asking for
        # an ungranted capability is a negotiation rather than a refusal.
        return (
            decision.model_copy(update={"action": PlannerAction.FORM_HYPOTHESIS}),
            (
                f"domain {decision.domain.value!r} maps to a capability that is not on this "
                f"run's menu ({sorted(d.value for d in available)}); the selection is "
                "rejected rather than repaired"
            ),
        )

    covered = set(state.get("covered_domains", []))
    degraded = set(state.get("degraded_domains", []))
    if decision.domain.value in covered or decision.domain.value in degraded:
        seen_gaps = {step.gap for step in state.get("steps", [])}
        if decision.gap in seen_gaps:
            return (
                decision.model_copy(update={"action": PlannerAction.FORM_HYPOTHESIS}),
                (
                    f"domain {decision.domain.value!r} was already collected for the same "
                    "gap; a repeated collection would spend budget without closing anything"
                ),
            )
    return decision, None


def _persist_step(
    deps: NodeDependencies,
    state: GraphState,
    decision: PlannerDecision,
    budget: BudgetState,
) -> StepRef:
    """Record the planner's decision durably, before anything is collected.

    Persisting the *decision* rather than only its result is what makes a redundant or
    misdirected step diagnosable later, and what lets a resumed run recompute the same
    sequence number instead of appending a duplicate.
    """
    assert decision.domain is not None
    sequence = len(state.get("steps", [])) + 1
    step = InvestigationStep(
        id=uuid.uuid4(),
        tenant_id=deps.context.tenant_id,
        incident_id=deps.context.incident_id,
        workflow_run_id=deps.context.workflow_run_id,
        sequence=sequence,
        gap_declared=decision.gap,
        domain=decision.domain,
        rationale=decision.rationale,
        status=InvestigationStepStatus.PLANNED,
        budget_before=budget.to_dict(),
        budget_after={},
        started_at=deps.clock.now(),
    )
    deps.session.add(step)
    deps.session.flush()
    return StepRef(
        step_id=str(step.id),
        sequence=sequence,
        domain=decision.domain,
        gap=decision.gap,
        status=InvestigationStepStatus.PLANNED,
        evidence_count=0,
    )


def _remaining_gaps(state: GraphState, closed: str) -> list[str]:
    return [gap for gap in state.get("open_gaps", []) if gap != closed]


def _phase_for(action: PlannerAction) -> InvestigationPhase:
    if action is PlannerAction.COLLECT_EVIDENCE:
        return InvestigationPhase.COLLECTING
    if action is PlannerAction.FORM_HYPOTHESIS:
        return InvestigationPhase.ANALYSING
    return InvestigationPhase.TERMINATING


def _terminate(
    contract: Any,
    budget: BudgetState,
    *,
    gap: str,
    reason: str,
    failure: NodeFailureRef | None = None,
    budget_refusal: BudgetKind | None = None,
) -> dict[str, Any]:
    """Produce the update that stops the loop, without deciding the outcome.

    The planner never sets ``terminated``: it proposes ``TERMINATE`` and the deterministic
    terminator decides the category. Letting the planner name its own outcome would put the
    choice between "uncertain" and "failed" inside the component least able to judge it.
    """
    update: dict[str, Any] = {
        "last_decision": PlannerDecisionRef(
            action=PlannerAction.TERMINATE,
            gap=gap,
            rationale=reason,
            overridden_reason=reason,
        ),
        "phase": InvestigationPhase.TERMINATING,
        "budget": _snapshot(budget),
    }
    if failure is not None:
        update["failures"] = [failure]
    if budget_refusal is not None:
        # The ledger still shows headroom, because the step was refused before its cost was
        # paid. Recording the dimension is what lets the terminator report "budget
        # exhausted" rather than "insufficient evidence".
        update["budget_refusal"] = budget_refusal.value
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


__all__ = ["SCHEMA_REPAIR_ATTEMPTS", "PlannerDecision", "planner_node"]
