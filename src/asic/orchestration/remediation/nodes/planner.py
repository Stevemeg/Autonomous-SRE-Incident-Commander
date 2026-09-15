"""G6 Remediation Planner.

Proposes exactly one remediation action, or proposes nothing. It has no capabilities and
calls no tools - it selects from a menu resolved for the *executor*
(:data:`asic.contracts.nodes.G9_REMEDIATION_EXECUTOR`), never for itself, on the same
"the model sees a pre-resolved menu, never a request-and-verdict exchange" principle the
investigation planner already uses.

Master specification section 6 requires twelve fields on every action proposal; this node
authors exactly four of them - reason, evidence, expected effect, verification criteria -
plus the choice of registered tool and its typed arguments. Risk tier, permission scope,
preconditions, rollback, approval requirement and timeout are resolved from the registry and
the incident by :func:`_persist_action`, never taken from the model. That split is what
makes "the model cannot escalate its own privileges" structural rather than a hope.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Final

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asic.contracts.nodes import G6_REMEDIATION_PLANNER, G9_REMEDIATION_EXECUTOR
from asic.contracts.remediation_state import RemediationActionRef, RemediationGraphState
from asic.contracts.state import BudgetSnapshot, NodeFailureRef
from asic.db.models.incident import Incident
from asic.db.models.investigation import Evidence, HypothesisEvidence
from asic.db.models.remediation import RemediationAction
from asic.db.projections import apply_transition
from asic.domain.budget import BudgetState
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    IncidentStatus,
    NodeId,
    ProvenanceLabel,
    RemediationActionStatus,
    RiskTier,
    TerminationReason,
    TraceSpanKind,
)
from asic.domain.errors import BudgetExhausted, ModelProviderError, SchemaViolation
from asic.domain.idempotency import action_version_hash, remediation_request_key
from asic.domain.untrusted import UntrustedBlock
from asic.llm.budgeted import complete_with_budget
from asic.llm.port import ModelRequest
from asic.llm.prompts import REMEDIATION_PLANNER_PROMPT
from asic.observability import metrics
from asic.orchestration.remediation.context import RemediationDependencies
from asic.remediation.verification import require_permitted_proposal

SCHEMA_REPAIR_ATTEMPTS: Final[int] = 1

#: How long an approval request from this proposal is valid for, keyed by risk tier. R2 is
#: never autonomous and is the more consequential decision, so it gets less time to sit
#: unanswered while state can still be drifting underneath it.
APPROVAL_WINDOW_SECONDS: Final[dict[RiskTier, int]] = {RiskTier.R1: 1800, RiskTier.R2: 900}


class RemediationProposal(BaseModel):
    """The model's proposal, exactly as it proposed it - not yet believed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list)
    expected_effect: dict[str, Any] = Field(default_factory=dict)
    verification_criteria: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


def remediation_planner_node(deps: RemediationDependencies) -> Any:
    """Build the remediation planning node."""

    contract = G6_REMEDIATION_PLANNER

    def run(state: RemediationGraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.remediation_planner",
            node_id=NodeId.G6_REMEDIATION_PLANNER,
            node_version=contract.node_version,
        ) as span:
            budget = deps.budget_from(state.get("budget"))
            span.budget_snapshot = dict(budget.remaining())

            # Resume the persisted proposal. A fresh model call could select a different
            # effect or consume another allowance while an approval is already pending.
            if state.get("remediation_action") is not None:
                replay_update = {"phase": "policy_evaluation", "budget": _snapshot(budget)}
                contract.validate_update(replay_update)
                return replay_update

            menu = deps.broker.menu_for(deps.session, G9_REMEDIATION_EXECUTOR)
            evidence_index = _evidence_index(deps)

            try:
                proposal, tokens, cost = _ask_model(
                    deps, menu.tool_names(), evidence_index, span, budget
                )
            except (BudgetExhausted, SchemaViolation, ModelProviderError) as exc:
                budget = deps.durable_budget(budget)
                span.fail(str(exc))
                metrics.schema_violations_total.add(
                    1, {"node": NodeId.G6_REMEDIATION_PLANNER.value}
                )
                return _terminate(
                    contract,
                    deps,
                    budget,
                    reason=str(exc),
                    error_type=type(exc).__name__,
                    recoverable=True,
                )

            charged = budget.charge(tokens=tokens, cost_usd=cost)

            if proposal.tool_name is None:
                span.set_decision(proposed=False)
                return _terminate(
                    contract,
                    deps,
                    charged,
                    reason="the planner proposed no action for this hypothesis",
                    target_incident_status=None,
                    error_type="NoActionProposed",
                    recoverable=True,
                )

            granted = menu.get_by_tool_name(proposal.tool_name)
            if granted is None:
                # Rejected, never repaired - selecting an ungranted tool is not a
                # negotiation.
                span.set_decision(
                    proposed=True,
                    rejected_reason=f"{proposal.tool_name!r} is not on the executor's menu",
                )
                return _terminate(
                    contract,
                    deps,
                    charged,
                    reason=f"proposed tool {proposal.tool_name!r} is not a granted capability",
                    error_type="CapabilityNotGranted",
                    recoverable=True,
                )

            valid_evidence = set(evidence_index)
            cited, unknown = _resolve_citations(proposal.evidence_ids, valid_evidence)
            if unknown or not cited:
                span.set_decision(
                    proposed=True,
                    rejected_reason=f"unsupported evidence citation(s): {unknown or 'none cited'}",
                )
                return _terminate(
                    contract,
                    deps,
                    charged,
                    reason="the proposal cited evidence this incident does not hold",
                    error_type="UnsupportedCitation",
                    recoverable=True,
                )

            try:
                action_ref = _persist_action(deps, proposal, granted, cited_evidence=cited)
            except SchemaViolation as exc:
                span.set_decision(proposed=True, rejected_reason=str(exc))
                return _terminate(
                    contract,
                    deps,
                    charged,
                    reason=str(exc),
                    error_type="VerificationProfileRejected",
                    recoverable=False,
                )

            span.set_decision(
                proposed=True,
                tool_name=proposal.tool_name,
                risk_tier=action_ref.risk_tier.value,
                evidence_refs=cited,
                confidence=proposal.confidence,
            )
            span.confidence = proposal.confidence

            update: dict[str, Any] = {
                "phase": "policy_evaluation",
                "remediation_action": action_ref,
                "budget": _snapshot(charged),
            }
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


#: Fixture sentinels, mirroring the hypothesis engine's ``ALL``/``NONE`` citation
#: resolution: a scripted test response is written before a run exists and cannot know a
#: generated evidence id in advance.
_ALL: Final[str] = "ALL"
_NONE: Final[str] = "NONE"


def _resolve_citations(cited: list[str], valid_evidence: set[str]) -> tuple[list[str], list[str]]:
    if cited in ([_ALL], [_ALL.lower()]):
        return sorted(valid_evidence), []
    if cited in ([_NONE], [_NONE.lower()], []):
        return [], []
    resolved = [eid for eid in cited if eid in valid_evidence]
    unknown = [eid for eid in cited if eid not in valid_evidence]
    return resolved, unknown


def _evidence_index(deps: RemediationDependencies) -> dict[str, dict[str, Any]]:
    """This hypothesis's supporting/contradicting evidence, keyed by persisted id.

    Read from durable rows, exactly as the hypothesis engine's own citation check is -
    never from the model, never from graph state alone.
    """
    hypothesis_id = uuid.UUID(deps.objective.hypothesis_id)
    rows = deps.session.execute(
        sa.select(Evidence, HypothesisEvidence.relation)
        .join(HypothesisEvidence, HypothesisEvidence.evidence_id == Evidence.id)
        .where(
            Evidence.tenant_id == deps.context.tenant_id,
            HypothesisEvidence.hypothesis_id == hypothesis_id,
        )
    ).all()
    return {
        str(evidence.id): {
            "domain": evidence.domain.value,
            "relation": relation.value,
            "headline": str((evidence.content or {}).get("headline", ""))[:240],
        }
        for evidence, relation in rows
    }


def _ask_model(
    deps: RemediationDependencies,
    menu_names: tuple[str, ...],
    evidence_index: dict[str, dict[str, Any]],
    span: Any,
    budget: BudgetState,
) -> tuple[RemediationProposal, int, float]:
    objective = deps.objective
    context = {
        "objective": (
            f"Determine whether a registered action safely addresses: "
            f"{objective.hypothesis_statement}"
        ),
        "root_cause_class": objective.root_cause_class,
        "services": [objective.service_name],
        "environment": objective.environment_name,
        "is_production": objective.is_production,
        "write_capability_menu": sorted(menu_names),
        "evidence_index": evidence_index,
    }
    untrusted = tuple(
        UntrustedBlock(
            source=f"evidence:{eid}",
            provenance=ProvenanceLabel.VERIFIED_FACT,
            content=info["headline"],
        )
        for eid, info in evidence_index.items()
    )

    tokens = 0
    cost = 0.0
    last_error = ""
    for attempt in range(SCHEMA_REPAIR_ATTEMPTS + 1):
        request = ModelRequest(
            node_id=NodeId.G6_REMEDIATION_PLANNER,
            prompt_id=REMEDIATION_PLANNER_PROMPT.prompt_id,
            prompt_version=REMEDIATION_PLANNER_PROMPT.version,
            prompt_hash=REMEDIATION_PLANNER_PROMPT.content_hash,
            prompt_text=REMEDIATION_PLANNER_PROMPT.render(context=context, untrusted=untrusted),
            metadata={
                "workflow_run_id": deps.context.identity.workflow_run_id,
                "attempt": str(attempt + 1),
            },
        )
        response, _ = complete_with_budget(
            deps.model,
            request,
            budget.charge(tokens=tokens, cost_usd=cost),
            durable=deps.model_budget,
            invocation_key=f"{NodeId.G6_REMEDIATION_PLANNER.value}:0:{attempt + 1}",
        )
        tokens += response.total_tokens
        cost += response.cost_usd
        span.set_model_call(
            provider=response.provider,
            model_id=response.model_id,
            prompt_version=REMEDIATION_PLANNER_PROMPT.version,
            prompt_hash=REMEDIATION_PLANNER_PROMPT.content_hash,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=response.cost_usd,
            finish_reason=response.finish_reason,
        )
        metrics.llm_calls_total.add(
            1, {"provider": response.provider, "model": response.model_id, "outcome": "ok"}
        )
        try:
            return RemediationProposal.model_validate(json.loads(response.text)), tokens, cost
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    raise SchemaViolation(
        f"remediation planner output failed validation after "
        f"{SCHEMA_REPAIR_ATTEMPTS + 1} attempt(s): {last_error}"
    )


def _persist_action(
    deps: RemediationDependencies,
    proposal: RemediationProposal,
    granted: Any,
    *,
    cited_evidence: list[str],
) -> RemediationActionRef:
    assert proposal.tool_name is not None
    descriptor = granted.descriptor
    verification_profile = require_permitted_proposal(
        descriptor.name, proposal.verification_criteria
    ).to_dict()
    incident_id = deps.context.incident_id
    hypothesis_id = uuid.UUID(deps.objective.hypothesis_id)
    # Generated once, up front: both hashes below bind to this exact id, and the
    # RemediationAction row is created with it, so the executor's SI-6 recomputation
    # (from the row's own id) reproduces the identical value rather than one over a
    # different, discarded id nothing else ever sees.
    action_id = uuid.uuid4()

    scope = deps.context.scope
    resolved_scope = scope.resolve_arguments(descriptor, service_name=deps.objective.service_name)
    # The durable action carries the complete frozen objective scope, even when a specific
    # descriptor needs only a subset (for example a node operation has no service argument).
    # The broker resolves that subset independently and dispatch authorization checks it is
    # contained in this exact target rather than allowing omission to erase target identity.
    permission_scope = dict(deps.objective.permission_scope)

    version_hash = action_version_hash(
        action_id=action_id,
        tool_name=descriptor.name,
        tool_version=descriptor.version,
        arguments=proposal.arguments,
        permission_scope=permission_scope,
        preconditions=descriptor.preconditions,
        risk_tier=descriptor.risk_tier.value,
    )
    request_key = remediation_request_key(
        tenant_id=deps.context.tenant_id,
        incident_id=incident_id,
        hypothesis_id=hypothesis_id,
        tool_name=descriptor.name,
        scope_arguments=resolved_scope,
    )

    verification_criteria_hash = action_version_hash(
        action_id=action_id,
        tool_name="verification_criteria",
        tool_version="1",
        arguments=verification_profile,
        permission_scope={},
        preconditions=(),
        risk_tier=descriptor.risk_tier.value,
    )

    existing = deps.session.execute(
        sa.select(RemediationAction).where(
            RemediationAction.tenant_id == deps.context.tenant_id,
            RemediationAction.request_idempotency_key == request_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _ref(existing, capability=descriptor.capability)

    action = RemediationAction(
        id=action_id,
        tenant_id=deps.context.tenant_id,
        incident_id=incident_id,
        workflow_run_id=deps.context.workflow_run_id,
        hypothesis_id=hypothesis_id,
        tool_definition_id=granted.tool_definition_id,
        remediation_target_id=_target_id(deps),
        reason=proposal.reason[:4000],
        expected_effect=proposal.expected_effect,
        risk_tier=descriptor.risk_tier,
        permission_scope=permission_scope,
        preconditions=list(descriptor.preconditions),
        rollback_tool_name=descriptor.rollback_tool_name,
        rollback_arguments={},
        approval_required=descriptor.risk_tier is not RiskTier.RO,
        timeout_seconds=descriptor.timeout_seconds,
        verification_criteria=verification_profile,
        verification_criteria_hash=verification_criteria_hash,
        baseline_snapshot={},
        tool_name=descriptor.name,
        tool_version=descriptor.version,
        arguments=proposal.arguments,
        action_version_hash=version_hash,
        request_idempotency_key=request_key,
        status=RemediationActionStatus.PROPOSED,
        proposed_by_node=NodeId.G6_REMEDIATION_PLANNER,
    )
    deps.session.add(action)
    deps.session.flush()

    deps.audit.record(
        deps.session,
        event_type=AuditEventType.REMEDIATION_PLANNED,
        outcome="recorded",
        actor_type=ActorType.AGENT_NODE,
        actor_id=NodeId.G6_REMEDIATION_PLANNER.value,
        incident_id=incident_id,
        correlation_id=deps.context.correlation_id,
        target_type="remediation_action",
        target_id=str(action.id),
        risk_tier=descriptor.risk_tier,
        payload={
            "tool_name": descriptor.name,
            "hypothesis_id": str(hypothesis_id),
            "evidence_ids": cited_evidence,
        },
    )

    return _ref(action, capability=descriptor.capability)


def _target_id(deps: RemediationDependencies) -> uuid.UUID:
    from asic.db.models.remediation import RemediationTarget

    target = deps.session.execute(
        sa.select(RemediationTarget).where(
            RemediationTarget.tenant_id == deps.context.tenant_id,
            RemediationTarget.workflow_run_id == deps.context.workflow_run_id,
            RemediationTarget.hypothesis_id == uuid.UUID(deps.objective.hypothesis_id),
            RemediationTarget.service_id == uuid.UUID(deps.objective.service_id),
            RemediationTarget.environment_id == uuid.UUID(deps.objective.environment_id),
        )
    ).scalar_one_or_none()
    if target is None:
        raise SchemaViolation("immutable remediation target is missing or mismatched")
    return target.id


def _ref(action: RemediationAction, *, capability: str) -> RemediationActionRef:
    return RemediationActionRef(
        action_id=str(action.id),
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        capability=capability,
        risk_tier=action.risk_tier,
        status=action.status,
        action_version_hash=action.action_version_hash,
        approval_required=action.approval_required,
    )


def _terminate(
    contract: Any,
    deps: RemediationDependencies,
    budget: BudgetState,
    *,
    reason: str,
    error_type: str,
    recoverable: bool,
    target_incident_status: str | None = "escalated",
) -> dict[str, Any]:
    """Stop the run with no action ever reaching a durable, authorised state.

    ``target_incident_status`` defaults to ``escalated``: a planner that could not produce
    a safe, well-cited proposal is exactly the case a human should look at. ``None`` means
    the planner explicitly proposed nothing (a legitimate "no safe action exists" verdict,
    not a failure) and the incident is left investigating for a human to review normally.
    """
    if target_incident_status == IncidentStatus.ESCALATED.value:
        incident = deps.session.execute(
            sa.select(Incident).where(
                Incident.tenant_id == deps.context.tenant_id,
                Incident.id == deps.context.incident_id,
            )
        ).scalar_one()
        if incident.status is not IncidentStatus.ESCALATED:
            apply_transition(
                deps.session,
                incident=incident,
                target=IncidentStatus.ESCALATED,
                actor_type=ActorType.SYSTEM,
                source=NodeId.G6_REMEDIATION_PLANNER.value,
                correlation_id=deps.context.correlation_id,
                termination_reason=TerminationReason.INSUFFICIENT_EVIDENCE,
            )

    update: dict[str, Any] = {
        "phase": "terminated",
        "terminated": True,
        "termination_reason": reason[:1000],
        "target_incident_status": target_incident_status,
        "budget": _snapshot(budget),
        "failures": [
            NodeFailureRef(
                node_id=NodeId.G6_REMEDIATION_PLANNER,
                node_version=contract.node_version,
                error_type=error_type,
                message=reason[:1000],
                recoverable=recoverable,
                occurred_at=deps.clock.now().isoformat(),
            )
        ],
    }
    contract.validate_update(update)
    return update


def _snapshot(budget: BudgetState) -> BudgetSnapshot:
    kind = budget.exhausted_kind()
    return BudgetSnapshot(
        consumed=budget.ledger.to_dict(),
        remaining=budget.remaining(),
        exhausted_kind=kind.value if kind else None,
    )


__all__ = ["APPROVAL_WINDOW_SECONDS", "RemediationProposal", "remediation_planner_node"]
