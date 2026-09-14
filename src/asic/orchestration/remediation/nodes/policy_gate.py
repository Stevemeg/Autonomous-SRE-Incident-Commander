"""G7 Policy Gate.

Deterministic. Reads the proposed action and the hypothesis it is justified by from durable
rows - never a model, never retrieved content (SI-3: authority flows only from ``SYSTEM``
and ``HUMAN`` provenance) - and applies ``asic.domain.policy.evaluate_policy`` exactly as
specified.

Writes exactly one :class:`~asic.db.models.remediation.PolicyDecision` row per action
(INV-6), on every path including allow, and is the point at which the incident first moves
out of ``investigating`` - into ``remediating`` on an outright allow, or ``awaiting_approval``
when a human must decide.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import sqlalchemy as sa

from asic.contracts.nodes import G7_POLICY_GATE
from asic.contracts.remediation_state import PolicyDecisionRef, RemediationGraphState
from asic.db.models.catalog import Environment
from asic.db.models.incident import Incident
from asic.db.models.investigation import Evidence, Hypothesis, HypothesisEvidence
from asic.db.models.remediation import PolicyDecision, RemediationAction
from asic.db.projections import append_incident_event, apply_transition
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    HypothesisStatus,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    PolicyVerdict,
    RemediationActionStatus,
    TerminationReason,
    TraceSpanKind,
)
from asic.domain.idempotency import incident_event_key
from asic.domain.policy import PolicyInputs, evaluate_policy
from asic.orchestration.remediation.context import RemediationDependencies

#: Evidence older than this, relative to now, counts as stale support for an action.
#: Deliberately shorter than the investigation window: a remediation is a claim about
#: *current* state, and telemetry a policy gate is willing to act on autonomously should be
#: fresher than telemetry a human investigator is willing to reason over.
STALENESS_WINDOW: timedelta = timedelta(minutes=30)

#: Confidence margin within which two hypotheses proposing different root causes are
#: treated as competing rather than one simply outranking the other.
COMPETING_MARGIN: float = 0.15

_CONCURRENT_STATUSES: tuple[IncidentStatus, ...] = (
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.REMEDIATING,
)


def policy_gate_node(deps: RemediationDependencies) -> Any:
    """Build the policy gate node."""

    contract = G7_POLICY_GATE

    def run(state: RemediationGraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.policy_gate",
            node_id=NodeId.G7_POLICY_GATE,
            node_version=contract.node_version,
        ) as span:
            action_ref = state.get("remediation_action")
            assert action_ref is not None  # guarded by the graph's routing
            action = deps.session.execute(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == uuid.UUID(action_ref.action_id),
                )
            ).scalar_one()

            # INV-6: exactly one policy decision per action. A resumed run re-enters this
            # node - the graph always starts at G6 and re-derives where it had got to
            # (§0 of this module's docstring) - and must reuse the recorded verdict rather
            # than evaluating (and trying to insert) a second one.
            existing = deps.session.execute(
                sa.select(PolicyDecision).where(
                    PolicyDecision.tenant_id == deps.context.tenant_id,
                    PolicyDecision.remediation_action_id == action.id,
                )
            ).scalar_one_or_none()
            if existing is not None:
                span.set_decision(
                    verdict=existing.verdict.value, rule_id=existing.rule_id, replayed=True
                )
                update: dict[str, Any] = {
                    "phase": "policy_evaluation",
                    "policy_decision": PolicyDecisionRef(
                        verdict=existing.verdict,
                        rule_id=existing.rule_id,
                        ambiguity_signals=tuple(existing.ambiguity_signals or ()),
                    ),
                    "remediation_action": action_ref,
                }
                if existing.verdict is PolicyVerdict.DENY:
                    update["terminated"] = True
                    update["termination_reason"] = existing.rationale[:1000]
                    update["target_incident_status"] = IncidentStatus.ESCALATED.value
                contract.validate_update(update)
                return update

            inputs = _policy_inputs(deps, action)
            result = evaluate_policy(inputs)

            decision = PolicyDecision(
                id=uuid.uuid4(),
                tenant_id=deps.context.tenant_id,
                remediation_action_id=action.id,
                verdict=result.verdict,
                rule_id=result.rule_id,
                policy_version="2026.09.14-1",
                rationale=result.rationale,
                ambiguity_signals=list(result.ambiguity_signals),
            )
            deps.session.add(decision)

            new_status = {
                PolicyVerdict.ALLOW: RemediationActionStatus.AUTHORIZED,
                PolicyVerdict.DENY: RemediationActionStatus.DENIED,
                PolicyVerdict.REQUIRE_APPROVAL: RemediationActionStatus.AWAITING_APPROVAL,
            }[result.verdict]
            deps.session.execute(
                sa.update(RemediationAction)
                .where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == action.id,
                )
                .values(status=new_status)
            )

            incident = deps.session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == deps.context.tenant_id,
                    Incident.id == deps.context.incident_id,
                )
            ).scalar_one()

            target_status: IncidentStatus | None = None
            if result.verdict is PolicyVerdict.ALLOW:
                target_status = IncidentStatus.REMEDIATING
            elif result.verdict is PolicyVerdict.REQUIRE_APPROVAL:
                target_status = IncidentStatus.AWAITING_APPROVAL
            else:
                target_status = IncidentStatus.ESCALATED

            if target_status is not None and target_status is not incident.status:
                apply_transition(
                    deps.session,
                    incident=incident,
                    target=target_status,
                    actor_type=ActorType.SYSTEM,
                    source=NodeId.G7_POLICY_GATE.value,
                    correlation_id=deps.context.correlation_id,
                    termination_reason=(
                        TerminationReason.POLICY_DENIED
                        if target_status is IncidentStatus.ESCALATED
                        else None
                    ),
                )

            append_incident_event(
                deps.session,
                incident=incident,
                event_type=IncidentEventType.POLICY_EVALUATED,
                source=NodeId.G7_POLICY_GATE.value,
                actor_type=ActorType.SYSTEM,
                correlation_id=deps.context.correlation_id,
                payload={
                    "action_id": str(action.id),
                    "verdict": result.verdict.value,
                    "rule_id": result.rule_id,
                },
                idempotency_key=incident_event_key(
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    event_type=IncidentEventType.POLICY_EVALUATED.value,
                    subject_id=action.id,
                ),
            )

            deps.audit.record(
                deps.session,
                event_type=AuditEventType.POLICY_DECIDED,
                # AuditWriter's outcome vocabulary is deliberately generic across every
                # audited event type; the actual verdict is already the payload's own
                # "verdict" field and the span's decision, both recorded verbatim below.
                outcome={
                    PolicyVerdict.ALLOW: "allowed",
                    PolicyVerdict.DENY: "denied",
                    PolicyVerdict.REQUIRE_APPROVAL: "recorded",
                }[result.verdict],
                actor_type=ActorType.SYSTEM,
                actor_id=NodeId.G7_POLICY_GATE.value,
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                target_type="remediation_action",
                target_id=str(action.id),
                policy_rule_id=result.rule_id,
                risk_tier=action.risk_tier,
                payload={
                    "verdict": result.verdict.value,
                    "ambiguity_signals": list(result.ambiguity_signals),
                    "rationale": result.rationale,
                },
            )

            span.set_decision(
                verdict=result.verdict.value,
                rule_id=result.rule_id,
                ambiguity_signals=list(result.ambiguity_signals),
            )

            update = {
                "phase": "policy_evaluation",
                "policy_decision": PolicyDecisionRef(
                    verdict=result.verdict,
                    rule_id=result.rule_id,
                    ambiguity_signals=result.ambiguity_signals,
                ),
                "remediation_action": action_ref.model_copy(update={"status": new_status}),
            }
            if result.verdict is PolicyVerdict.DENY:
                update["terminated"] = True
                update["termination_reason"] = result.rationale[:1000]
                update["target_incident_status"] = IncidentStatus.ESCALATED.value
            contract.validate_update(update)
            return update

    return run


# ------------------------------------------------------------------------------ helpers


def _policy_inputs(deps: RemediationDependencies, action: RemediationAction) -> PolicyInputs:
    hypothesis = deps.session.execute(
        sa.select(Hypothesis).where(
            Hypothesis.tenant_id == deps.context.tenant_id,
            Hypothesis.id == action.hypothesis_id,
        )
    ).scalar_one()

    environment = deps.session.execute(
        sa.select(Environment).where(
            Environment.tenant_id == deps.context.tenant_id,
            Environment.name == deps.objective.environment_name,
        )
    ).scalar_one()

    links = deps.session.execute(
        sa.select(Evidence.gathered_at, HypothesisEvidence.relation)
        .join(HypothesisEvidence, HypothesisEvidence.evidence_id == Evidence.id)
        .where(
            Evidence.tenant_id == deps.context.tenant_id,
            HypothesisEvidence.hypothesis_id == hypothesis.id,
        )
    ).all()
    supporting = sum(1 for _, relation in links if relation.value == "supports")
    contradicting = sum(1 for _, relation in links if relation.value == "contradicts")
    newest = max((ts for ts, _ in links), default=None)
    stale = newest is None or (deps.clock.now() - newest) > STALENESS_WINDOW

    others = deps.session.execute(
        sa.select(Hypothesis.confidence, Hypothesis.root_cause_class).where(
            Hypothesis.tenant_id == deps.context.tenant_id,
            Hypothesis.incident_id == deps.context.incident_id,
            Hypothesis.id != hypothesis.id,
            Hypothesis.status.in_((HypothesisStatus.PROPOSED, HypothesisStatus.ACCEPTED)),
        )
    ).all()
    competing = any(
        other_class != hypothesis.root_cause_class
        and abs(float(other_confidence) - float(hypothesis.confidence)) <= COMPETING_MARGIN
        for other_confidence, other_class in others
    )

    concurrent = _concurrent_incident_same_scope(deps)

    approval_policy = dict(environment.approval_policy or {})

    return PolicyInputs(
        risk_tier=action.risk_tier,
        is_production=environment.is_production,
        hypothesis_confidence=float(hypothesis.confidence),
        supporting_evidence_count=supporting,
        contradicting_evidence_count=contradicting,
        competing_hypotheses_conflict=competing,
        unexplained_counter_evidence=False,  # captured via contradicting_evidence_count
        evidence_stale=stale,
        concurrent_incident_same_scope=concurrent,
        tenant_requires_approval_override=approval_policy.get("require_approval_override"),
    )


def _concurrent_incident_same_scope(deps: RemediationDependencies) -> bool:
    """Another incident already holds a live write action against a service in scope.

    A blunt but honest proxy for "overlapping blast radius": any other incident in this
    tenant and environment currently ``awaiting_approval`` or ``remediating`` is treated as
    overlapping, rather than attempting fine-grained namespace/service intersection this
    phase has not built a reliable source for.
    """
    other = deps.session.execute(
        sa.select(sa.func.count())
        .select_from(Incident)
        .where(
            Incident.tenant_id == deps.context.tenant_id,
            Incident.environment_id == deps.context.scope.environment_id,
            Incident.id != deps.context.incident_id,
            Incident.status.in_(_CONCURRENT_STATUSES),
        )
    ).scalar_one()
    return bool(other)


__all__ = ["COMPETING_MARGIN", "STALENESS_WINDOW", "policy_gate_node"]
