"""Observations: what a run actually did, read back from the records production writes.

Evaluators never inspect in-memory kernel state or the scenario script. They read the same
durable rows an operator would - incident, workflow run, evidence, hypotheses and their
citations, tool executions, trace spans, remediation action, policy decision, approval,
verification and audit - under the application role and the tenant's row-level security.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Approval,
    AuditRecord,
    Evidence,
    ExecutionTrace,
    Hypothesis,
    HypothesisEvidence,
    Incident,
    KnowledgeRetrieval,
    PolicyDecision,
    RemediationAction,
    ToolExecution,
    TraceSpan,
    Verification,
    WorkflowRun,
)
from asic.db.session import bind_tenant
from asic.domain.enums import AuditEventType, HypothesisStatus
from asic.remediation.trust import trusted_verified_outcome


@dataclass(frozen=True, slots=True)
class ToolCallObservation:
    tool_name: str
    capability: str
    outcome: str
    effect_class: str
    requested_by_node: str | None
    remediation_action_id: uuid.UUID | None
    tenant_id: uuid.UUID
    risk_tier: str
    attempts: int


@dataclass(frozen=True, slots=True)
class HypothesisObservation:
    id: uuid.UUID
    rank: int
    root_cause_class: str
    confidence: float
    status: str
    supporting_ids: tuple[uuid.UUID, ...]
    contradicting_ids: tuple[uuid.UUID, ...]


@dataclass
class RunObservation:
    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    workflow_run_ids: list[uuid.UUID] = field(default_factory=list)
    incident_status: str | None = None
    termination_reason: str | None = None
    evidence_domains: list[str] = field(default_factory=list)
    evidence_ids: set[uuid.UUID] = field(default_factory=set)
    injection_flagged_evidence: int = 0
    knowledge_retrievals: int = 0
    knowledge_results: int = 0
    hypotheses: list[HypothesisObservation] = field(default_factory=list)
    rejected_citation_events: int = 0
    tool_calls: list[ToolCallObservation] = field(default_factory=list)
    tokens: int = 0
    cost_usd: float = 0.0
    budget: dict[str, Any] = field(default_factory=dict)
    trace_span_count: int = 0
    trace_error_spans: int = 0
    trace_duration_ms: int | None = None
    model_calls: int = 0
    authorization_denials: int = 0
    remediation_actions: list[dict[str, Any]] = field(default_factory=list)
    policy_decisions: list[dict[str, Any]] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    verifications: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


def observe(session: Session, *, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> RunObservation:
    bind_tenant(session, tenant_id)
    observation = RunObservation(tenant_id=tenant_id, incident_id=incident_id)

    incident = session.execute(
        sa.select(Incident).where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
    ).scalar_one()
    observation.incident_status = incident.status.value
    observation.termination_reason = (
        incident.termination_reason.value if incident.termination_reason else None
    )

    runs = list(
        session.scalars(
            sa.select(WorkflowRun)
            .where(WorkflowRun.tenant_id == tenant_id, WorkflowRun.incident_id == incident_id)
            .order_by(WorkflowRun.started_at, WorkflowRun.id)
        )
    )
    observation.workflow_run_ids = [run.id for run in runs]
    for run in runs:
        ledger = dict(run.budget_consumed or {}).get("ledger", {})
        observation.tokens += int(ledger.get("tokens", 0) or 0)
        observation.cost_usd += float(ledger.get("cost_usd", 0.0) or 0.0)
        observation.budget[str(run.id)] = dict(run.budget_consumed or {})

    for evidence in session.scalars(
        sa.select(Evidence)
        .where(Evidence.tenant_id == tenant_id, Evidence.incident_id == incident_id)
        .order_by(Evidence.gathered_at, Evidence.id)
    ):
        observation.evidence_ids.add(evidence.id)
        observation.evidence_domains.append(evidence.domain.value)
        if evidence.injection_flagged:
            observation.injection_flagged_evidence += 1

    for retrieval in session.scalars(
        sa.select(KnowledgeRetrieval).where(
            KnowledgeRetrieval.tenant_id == tenant_id, KnowledgeRetrieval.incident_id == incident_id
        )
    ):
        observation.knowledge_retrievals += 1
        observation.knowledge_results += retrieval.result_count

    hypotheses = list(
        session.scalars(
            sa.select(Hypothesis)
            .where(Hypothesis.tenant_id == tenant_id, Hypothesis.incident_id == incident_id)
            .order_by(Hypothesis.rank, Hypothesis.id)
        )
    )
    links: dict[uuid.UUID, list[HypothesisEvidence]] = {}
    if hypotheses:
        for link in session.scalars(
            sa.select(HypothesisEvidence).where(
                HypothesisEvidence.tenant_id == tenant_id,
                HypothesisEvidence.hypothesis_id.in_([h.id for h in hypotheses]),
            )
        ):
            links.setdefault(link.hypothesis_id, []).append(link)
    for hypothesis in hypotheses:
        related = links.get(hypothesis.id, [])
        observation.hypotheses.append(
            HypothesisObservation(
                id=hypothesis.id,
                rank=hypothesis.rank,
                root_cause_class=hypothesis.root_cause_class,
                confidence=float(hypothesis.confidence),
                status=hypothesis.status.value,
                supporting_ids=tuple(
                    link.evidence_id for link in related if link.relation.value == "supports"
                ),
                contradicting_ids=tuple(
                    link.evidence_id for link in related if link.relation.value == "contradicts"
                ),
            )
        )

    executions = list(
        session.scalars(
            sa.select(ToolExecution)
            .where(ToolExecution.tenant_id == tenant_id, ToolExecution.incident_id == incident_id)
            .order_by(ToolExecution.started_at, ToolExecution.created_at, ToolExecution.id)
        )
    )
    observation.tool_calls = [
        ToolCallObservation(
            tool_name=e.tool_name,
            capability=e.capability,
            outcome=e.outcome.value if e.outcome else "none",
            effect_class=e.effect_class.value if e.effect_class else "read",
            requested_by_node=e.requested_by_node.value if e.requested_by_node else None,
            remediation_action_id=e.remediation_action_id,
            tenant_id=e.tenant_id,
            risk_tier=e.risk_tier.value,
            attempts=e.attempt,
        )
        for e in executions
    ]

    traces = list(
        session.scalars(
            sa.select(ExecutionTrace).where(
                ExecutionTrace.tenant_id == tenant_id, ExecutionTrace.incident_id == incident_id
            )
        )
    )
    starts: list[datetime] = []
    ends: list[datetime] = []
    for trace in traces:
        for span in session.scalars(
            sa.select(TraceSpan).where(
                TraceSpan.tenant_id == tenant_id, TraceSpan.execution_trace_id == trace.id
            )
        ):
            observation.trace_span_count += 1
            if span.status.value == "error":
                observation.trace_error_spans += 1
            if span.kind.value == "llm.call":
                observation.model_calls += 1
            rejected = dict(span.decision or {}).get("rejected_unsupported")
            if isinstance(rejected, list) and rejected:
                observation.rejected_citation_events += len(rejected)
            starts.append(span.started_at)
            if span.ended_at is not None:
                ends.append(span.ended_at)
    if starts and ends:
        observation.trace_duration_ms = int((max(ends) - min(starts)).total_seconds() * 1000)

    observation.authorization_denials = int(
        session.scalar(
            sa.select(sa.func.count())
            .select_from(AuditRecord)
            .where(
                AuditRecord.tenant_id == tenant_id,
                AuditRecord.incident_id == incident_id,
                AuditRecord.event_type == AuditEventType.TOOL_AUTHORIZATION_EVALUATED,
                AuditRecord.outcome == "denied",
            )
        )
        or 0
    )

    actions = list(
        session.scalars(
            sa.select(RemediationAction).where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.incident_id == incident_id,
            )
        )
    )
    for action in actions:
        observation.remediation_actions.append(
            {
                "id": action.id,
                "tool_name": action.tool_name,
                "status": action.status.value,
                "risk_tier": action.risk_tier.value,
                "approval_required": action.approval_required,
            }
        )
        for decision in session.scalars(
            sa.select(PolicyDecision).where(
                PolicyDecision.tenant_id == tenant_id,
                PolicyDecision.remediation_action_id == action.id,
            )
        ):
            observation.policy_decisions.append(
                {
                    "action_id": action.id,
                    "verdict": decision.verdict.value,
                    "rule_id": decision.rule_id,
                }
            )
        for approval in session.scalars(
            sa.select(Approval).where(
                Approval.tenant_id == tenant_id, Approval.remediation_action_id == action.id
            )
        ):
            observation.approvals.append(
                {"action_id": action.id, "decision": approval.decision.value}
            )
        for verification in session.scalars(
            sa.select(Verification).where(
                Verification.tenant_id == tenant_id,
                Verification.remediation_action_id == action.id,
            )
        ):
            observation.verifications.append(
                {
                    "action_id": action.id,
                    "verdict": verification.verdict.value,
                    "trusted_lineage": (
                        verification.verdict.value == "verified"
                        and trusted_verified_outcome(
                            session, tenant_id=tenant_id, verification=verification
                        )
                    ),
                }
            )
    return observation


def active_hypotheses(observation: RunObservation) -> list[HypothesisObservation]:
    excluded = {HypothesisStatus.SUPERSEDED.value, HypothesisStatus.REJECTED_UNSUPPORTED.value}
    return sorted(
        (h for h in observation.hypotheses if h.status not in excluded), key=lambda h: h.rank
    )


def summary(observation: RunObservation) -> Mapping[str, Any]:
    """A deterministic, identifier-free signature of what happened, for replay comparison."""
    return {
        "incident_status": observation.incident_status,
        "termination_reason": observation.termination_reason,
        "evidence_domains": sorted(observation.evidence_domains),
        "knowledge_results": observation.knowledge_results,
        "hypotheses": [
            (h.rank, h.root_cause_class, round(h.confidence, 3), h.status)
            for h in observation.hypotheses
        ],
        # A multiset, not a sequence: under a logical clock several executions share a
        # timestamp and rows carry no sequence number. Call *order* is enforced where it is
        # knowable - strict replay raises ReplayDivergence on any out-of-order request.
        "tool_calls": sorted((t.tool_name, t.outcome) for t in observation.tool_calls),
        "tokens": observation.tokens,
        "remediation": [(a["tool_name"], a["status"]) for a in observation.remediation_actions],
        "verifications": sorted(v["verdict"] for v in observation.verifications),
    }


__all__ = [
    "HypothesisObservation",
    "RunObservation",
    "ToolCallObservation",
    "active_hypotheses",
    "observe",
    "summary",
]
