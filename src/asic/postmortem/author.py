"""G11 Postmortem Author: an evidence-grounded, draft-only postmortem for a resolved incident.

Responsibility, stated as a contract (master specification section 4):

=====================  =======================================================================
Trigger                an incident whose status is ``resolved``; nothing else is eligible
Input                  persisted records only (:mod:`asic.postmortem.sources`)
Output                 one ``postmortem`` row per (incident, source fingerprint), ``draft``,
                       ``review_required``; one ``postmortem.drafted`` incident event
Tool permissions       none. The author has no broker and cannot reach any adapter
Model use              one bounded call, for prose only (summary, went well / poorly,
                       follow-ups); facts are assembled from typed columns, never from prose
Confidence             not a number: every claim carries citations, and ungrounded claims move
                       to the uncertainty list (:mod:`asic.postmortem.grounding`)
Timeout / budget       the model port's own timeout, and :data:`POSTMORTEM_BUDGET`
Retry                  idempotent by fingerprint; the worker re-invokes after any failure
Failure path           model failure or unusable output degrades to a records-only draft;
                       a database failure writes nothing and is retried
Audit                  the ``postmortem.drafted`` event and the draft's ``generation`` and
                       ``validation`` columns
=====================  =======================================================================

Why a stage and not a graph node: the investigation and remediation graphs end when their run
ends, and an incident can also be resolved by a person with no run at all. Drafting a
postmortem is a separate unit of work over the incident's *final* record set, re-runnable and
idempotent on its own, so the worker invokes it directly rather than growing either graph.

The draft is never published. The database refuses any row that is not an unreviewed draft,
the runtime role cannot update a draft, and nothing a model or a retrieved document says can
change either fact.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import sqlalchemy as sa
from opentelemetry import trace
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import Incident, Postmortem
from asic.db.projections import append_incident_event, project_timeline
from asic.domain.budget import BudgetPolicy, BudgetState
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    PostmortemStatus,
    ProvenanceLabel,
)
from asic.domain.idempotency import incident_event_key
from asic.domain.untrusted import UntrustedBlock
from asic.llm.budgeted import complete_with_budget
from asic.llm.port import ModelProvider, ModelRequest
from asic.llm.prompts import POSTMORTEM_PROMPT, PROMPT_SET_VERSION
from asic.observability import metrics
from asic.observability.logging import log_event
from asic.orchestration.context import UnitOfWork
from asic.postmortem.grounding import (
    MODEL_SECTIONS,
    Claim,
    GroundingReport,
    Uncertainty,
    check_record_claims,
    clean_text,
    validate_model_output,
)
from asic.postmortem.sources import PostmortemSources, SourceRecord, load_sources

_logger = logging.getLogger("asic.postmortem")

#: Version of the assembly and validation rules. Recorded on every draft.
GENERATOR_VERSION: Final[str] = "g11-1.0.0"

#: Section order of a draft. Model sections are a subset (grounding.MODEL_SECTIONS).
SECTIONS: Final[tuple[str, ...]] = (
    "summary",
    "impact",
    "timeline",
    "root_cause",
    "contributing_factors",
    "detection",
    "response",
    "verification",
    "what_went_well",
    "what_went_poorly",
    "follow_up_actions",
)

#: One drafting call. Generous for prose, tiny beside an investigation budget.
POSTMORTEM_BUDGET: Final[BudgetPolicy] = BudgetPolicy(
    max_iterations=1,
    max_tool_calls=1,
    max_wall_clock_seconds=120,
    max_tokens=24_000,
    max_cost_usd=0.5,
)

MAX_TIMELINE_CLAIMS: Final[int] = 60
REVIEW_REQUIRED_TEXT: Final[str] = (
    "A human must review this draft before it is shared or published; it was generated from "
    "the incident records and has not been reviewed."
)
IMPACT_UNKNOWN_TEXT: Final[str] = (
    "No record measures customer or business impact. A reviewer must supply it before "
    "publication; the draft does not estimate it."
)


@dataclass(frozen=True, slots=True)
class PostmortemOutcome:
    """What one invocation did. ``outcome`` is a closed vocabulary (the metric label)."""

    outcome: str
    postmortem_id: uuid.UUID | None = None
    version: int | None = None


class PostmortemAuthor:
    """Drafts a postmortem for one resolved incident. Idempotent per source fingerprint."""

    __slots__ = ("_clock", "_model", "_session_factory")

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        model: ModelProvider,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._model = model
        self._clock = clock or SystemClock()

    def draft(self, *, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> PostmortemOutcome:
        tracer = trace.get_tracer("asic.postmortem")
        with tracer.start_as_current_span("postmortem.author") as span:
            span.set_attribute("asic.node", NodeId.G11_POSTMORTEM_AUTHOR.value)
            span.set_attribute("incident_id", str(incident_id))
            outcome = self._draft(tenant_id, incident_id)
            span.set_attribute("postmortem.outcome", outcome.outcome)
            metrics.postmortem_drafts_total.add(1, {"outcome": outcome.outcome})
            return outcome

    # ------------------------------------------------------------------ steps

    def _draft(self, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> PostmortemOutcome:
        with UnitOfWork(self._session_factory, tenant_id=tenant_id) as session:
            sources = load_sources(session, tenant_id=tenant_id, incident_id=incident_id)
            if sources is None:
                return PostmortemOutcome("not_visible")
            if sources.status is not IncidentStatus.RESOLVED:
                return PostmortemOutcome("not_eligible")
            existing = _existing(session, sources)
            if existing is not None:
                return PostmortemOutcome("existing", existing.id, existing.version)

        record_sections, uncertainties = assemble(sources)
        check_record_claims(
            [claim for claims in record_sections.values() for claim in claims], sources
        )
        # The model call runs outside any transaction: no lock is held while it thinks.
        report, generation = self._generate(sources, record_sections)
        sections = merge(record_sections, report)
        uncertainties.extend(report.removed)
        for item in report.removed:
            metrics.postmortem_claims_removed_total.add(1, {"reason": item.reason})
        return self._persist(
            tenant_id, incident_id, sources, sections, uncertainties, report, generation
        )

    def _generate(
        self, sources: PostmortemSources, record_sections: Mapping[str, list[Claim]]
    ) -> tuple[GroundingReport, dict[str, Any]]:
        generation: dict[str, Any] = {
            "generator_version": GENERATOR_VERSION,
            "node": NodeId.G11_POSTMORTEM_AUTHOR.value,
            "prompt_id": POSTMORTEM_PROMPT.prompt_id,
            "prompt_version": POSTMORTEM_PROMPT.version,
            "prompt_hash": POSTMORTEM_PROMPT.content_hash,
            "prompt_set_version": PROMPT_SET_VERSION,
            "provider": self._model.provider_name,
            "model_id": self._model.model_id,
            "generated_at": self._clock.now().isoformat(),
        }
        request = ModelRequest(
            node_id=NodeId.G11_POSTMORTEM_AUTHOR,
            prompt_id=POSTMORTEM_PROMPT.prompt_id,
            prompt_version=POSTMORTEM_PROMPT.version,
            prompt_hash=POSTMORTEM_PROMPT.content_hash,
            prompt_text=POSTMORTEM_PROMPT.render(
                context=_prompt_context(sources, record_sections),
                untrusted=_untrusted_blocks(sources),
            ),
            metadata={"incident_id": str(sources.incident_id)},
        )
        try:
            response, _ = complete_with_budget(
                self._model, request, BudgetState.initial(POSTMORTEM_BUDGET)
            )
        except Exception as exc:  # a failing model degrades the draft; it never fails it
            log_event(
                _logger,
                "postmortem.model_unavailable",
                level=logging.WARNING,
                error=exc,
                incident_id=str(sources.incident_id),
            )
            generation["model_outcome"] = f"unavailable:{type(exc).__name__}"
            return GroundingReport(output_error="model_unavailable"), generation
        generation.update(
            {
                "model_outcome": "completed",
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cost_usd": response.cost_usd,
            }
        )
        return validate_model_output(response.text, sources), generation

    def _persist(
        self,
        tenant_id: uuid.UUID,
        incident_id: uuid.UUID,
        drafted_from: PostmortemSources,
        sections: Mapping[str, list[Claim]],
        uncertainties: Sequence[Uncertainty],
        report: GroundingReport,
        generation: dict[str, Any],
    ) -> PostmortemOutcome:
        try:
            with UnitOfWork(self._session_factory, tenant_id=tenant_id) as session:
                incident = session.scalar(
                    sa.select(Incident)
                    .where(Incident.tenant_id == tenant_id, Incident.id == incident_id)
                    .with_for_update()
                )
                if incident is None:
                    return PostmortemOutcome("not_visible")
                current = load_sources(session, tenant_id=tenant_id, incident_id=incident_id)
                if current is None or current.status is not IncidentStatus.RESOLVED:
                    return PostmortemOutcome("not_eligible")
                if current.fingerprint != drafted_from.fingerprint:
                    # The records moved while the model was drafting. Writing now would
                    # attach this draft to a record set it was not built from.
                    return PostmortemOutcome("sources_changed")
                existing = _existing(session, current)
                if existing is not None:
                    return PostmortemOutcome("existing", existing.id, existing.version)
                version = 1 + int(
                    session.scalar(
                        sa.select(sa.func.coalesce(sa.func.max(Postmortem.version), 0)).where(
                            Postmortem.tenant_id == tenant_id,
                            Postmortem.incident_id == incident_id,
                        )
                    )
                    or 0
                )
                cited = sorted(
                    {h for claims in sections.values() for c in claims for h in c.citations}
                    | {h for item in uncertainties for h in item.citations if h in current.records}
                    | {current.incident.handle}
                )
                row = Postmortem(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    version=version,
                    source_fingerprint=current.fingerprint,
                    title=clean_text(f"Postmortem draft: {current.reference} {current.title}"),
                    content=render(current, sections, uncertainties, version),
                    sections={
                        name: [c.to_json() for c in sections.get(name, [])] for name in SECTIONS
                    },
                    uncertainties=[item.to_json() for item in uncertainties],
                    citations=[current.records[h].citation() for h in cited],
                    resolution_basis=current.resolution_basis,
                    generation=generation,
                    validation={
                        **report.to_json(),
                        "record_claims": sum(1 for c in _all(sections) if c.origin == "record"),
                        "system_claims": sum(1 for c in _all(sections) if c.origin == "system"),
                    },
                    review_required=True,
                    status=PostmortemStatus.DRAFT,
                )
                session.add(row)
                session.flush()
                append_incident_event(
                    session,
                    incident=incident,
                    event_type=IncidentEventType.POSTMORTEM_DRAFTED,
                    source=NodeId.G11_POSTMORTEM_AUTHOR.value,
                    actor_type=ActorType.AGENT_NODE,
                    actor_id=NodeId.G11_POSTMORTEM_AUTHOR.value,
                    correlation_id=uuid.uuid4(),
                    payload={
                        "postmortem_id": str(row.id),
                        "version": version,
                        "status": PostmortemStatus.DRAFT.value,
                        "review_required": True,
                        "source_fingerprint": current.fingerprint,
                        "model_claims_removed": len(report.removed),
                    },
                    idempotency_key=incident_event_key(
                        tenant_id=tenant_id,
                        incident_id=incident_id,
                        event_type=IncidentEventType.POSTMORTEM_DRAFTED.value,
                        subject_id=incident_id,
                        occurrence_discriminator=current.fingerprint,
                    ),
                )
                project_timeline(session, tenant_id=tenant_id, incident_id=incident_id)
                return PostmortemOutcome("created", row.id, version)
        except IntegrityError:
            # A concurrent author won the unique (incident, fingerprint) race: use its draft.
            with UnitOfWork(self._session_factory, tenant_id=tenant_id) as session:
                winner = session.scalar(
                    sa.select(Postmortem).where(
                        Postmortem.tenant_id == tenant_id,
                        Postmortem.incident_id == incident_id,
                        Postmortem.source_fingerprint == drafted_from.fingerprint,
                    )
                )
                if winner is None:
                    raise
                return PostmortemOutcome("existing", winner.id, winner.version)


# ------------------------------------------------------------------------ assembly


def assemble(sources: PostmortemSources) -> tuple[dict[str, list[Claim]], list[Uncertainty]]:
    """Every factual section, built mechanically from typed record columns."""
    sections: dict[str, list[Claim]] = {name: [] for name in SECTIONS}
    uncertain: list[Uncertainty] = []

    def record(section: str, text: str, *handles: str | None) -> None:
        cited = tuple(h for h in handles if h)
        sections[section].append(Claim(clean_text(text), cited, "record"))

    def system(section: str, text: str) -> None:
        sections[section].append(Claim(text, (), "system"))

    closing = sources.resolution_event.handle if sources.resolution_event else None
    record(
        "summary",
        f"Incident {sources.reference} ('{sources.title}', severity {sources.severity}) in "
        f"environment {sources.environment} was opened at {sources.opened_at.isoformat()} "
        f"and resolved at "
        f"{sources.terminated_at.isoformat() if sources.terminated_at else 'an unrecorded time'}.",
        sources.incident.handle,
        closing,
    )

    if sources.alerts:
        services = ", ".join(sources.services) or "an unrecorded service"
        record(
            "impact",
            f"{len(sources.alerts)} alert(s) were correlated into this incident for {services}.",
            *(a.handle for a in sources.alerts[:10]),
        )
    system("impact", IMPACT_UNKNOWN_TEXT)
    uncertain.append(Uncertainty("impact", IMPACT_UNKNOWN_TEXT, "not_recorded"))

    for entry in sources.timeline[:MAX_TIMELINE_CLAIMS]:
        record(
            "timeline",
            f"{entry.occurred_at.isoformat()} {entry.summary}",
            entry.event_handle,
            entry.evidence_handle,
        )
    if len(sources.timeline) > MAX_TIMELINE_CLAIMS:
        system(
            "timeline",
            f"{len(sources.timeline) - MAX_TIMELINE_CLAIMS} further entries are in the "
            "incident timeline.",
        )

    root = sources.root_cause
    if root is not None:
        record(
            "root_cause",
            f"Leading hypothesis ({sources.root_cause_class}, confidence "
            f"{sources.root_cause_confidence:.2f}): {sources.root_cause_statement}",
            root.handle,
            *sources.supporting,
        )
        verified = [
            p
            for p in sources.remediation
            if p.verification_verdict == "verified" and p.hypothesis_id == root.record_id
        ]
        if verified:
            path = verified[-1]
            record(
                "root_cause",
                "A remediation action taken against this hypothesis was executed and "
                "independently verified. That supports the hypothesis; it does not prove it.",
                root.handle,
                path.action.handle,
                path.verification.handle if path.verification else None,
            )
        else:
            uncertain.append(
                Uncertainty(
                    "root_cause",
                    "No remediation of the leading hypothesis was independently verified; it "
                    "remains a hypothesis.",
                    "not_verified",
                    (root.handle,),
                )
            )
    else:
        system("root_cause", "No evidence-supported root-cause hypothesis was recorded.")
        uncertain.append(
            Uncertainty("root_cause", "The records establish no root cause.", "not_recorded")
        )

    if sources.contradicting and root is not None:
        record(
            "contributing_factors",
            "Evidence was recorded against the leading hypothesis.",
            root.handle,
            *sources.contradicting,
        )
    for alternative, cause_class, status in sources.alternatives:
        record(
            "contributing_factors",
            f"Alternative hypothesis considered ({cause_class}), status {status}.",
            alternative.handle,
        )
    if not sections["contributing_factors"]:
        system(
            "contributing_factors",
            "No alternative hypothesis or counter-evidence was recorded.",
        )

    if sources.alerts:
        first = sources.alerts[0]
        record("detection", f"First signal: {first.description}.", first.handle)
    else:
        system("detection", "No alert is recorded for this incident.")

    if sources.evidence:
        domains = sorted({e.label or "unknown" for e in sources.evidence})
        record(
            "response",
            f"The investigation gathered {len(sources.evidence)} evidence record(s) from: "
            f"{', '.join(domains)}.",
            *(e.handle for e in sources.evidence[:10]),
        )
    for path in sources.remediation:
        record(
            "response",
            f"Remediation {path.tool_name} (risk tier {path.risk_tier}) was proposed; the "
            f"policy gate returned {path.policy_verdict or 'no decision'}.",
            path.action.handle,
            path.policy.handle if path.policy else None,
        )
        if path.approval is not None:
            record(
                "response",
                f"The action approval was recorded as {path.approval_decision}, bound to the "
                "exact proposed action version.",
                path.approval.handle,
                path.action.handle,
            )
        elif path.policy_verdict == "allow":
            record(
                "response",
                "The policy gate allowed the action without human approval.",
                path.policy.handle if path.policy else None,
                path.action.handle,
            )
        if path.execution is not None:
            record(
                "response",
                f"The action was executed: {path.execution.description}.",
                path.execution.handle,
            )
        if path.verification is not None:
            record(
                "verification",
                f"Independent verification: {path.verification.description}.",
                path.verification.handle,
                path.action.handle,
            )
    if not sections["response"]:
        system("response", "No investigation evidence or remediation action is recorded.")
    if sources.resolution_basis == "human_declared":
        text = "The resolution was declared by a responder and was not independently verified."
        if closing:
            record("verification", text, closing)
        else:
            system("verification", text)
        uncertain.append(
            Uncertainty("verification", text, "human_declared", (closing,) if closing else ())
        )

    for evidence in sources.evidence:
        if evidence.injection_flagged:
            uncertain.append(
                Uncertainty(
                    "response",
                    f"Evidence {evidence.handle} was flagged as a possible prompt injection; "
                    "its content was not used as fact.",
                    "injection_flagged",
                    (evidence.handle,),
                )
            )
    system("follow_up_actions", REVIEW_REQUIRED_TEXT)
    return sections, uncertain


def merge(
    record_sections: Mapping[str, list[Claim]], report: GroundingReport
) -> dict[str, list[Claim]]:
    merged = {name: list(record_sections.get(name, [])) for name in SECTIONS}
    for name in MODEL_SECTIONS:
        merged[name].extend(report.kept.get(name, []))
    return merged


def render(
    sources: PostmortemSources,
    sections: Mapping[str, list[Claim]],
    uncertainties: Sequence[Uncertainty],
    version: int,
) -> str:
    """Plain-text rendering for a reader. Every factual line carries its record handles."""
    lines = [
        f"POSTMORTEM DRAFT v{version} - {sources.reference} - HUMAN REVIEW REQUIRED",
        f"Resolution basis: {sources.resolution_basis}",
        "",
    ]
    for name in SECTIONS:
        lines.append(name.replace("_", " ").upper())
        for claim in sections.get(name, []):
            cites = f" [{', '.join(claim.citations)}]" if claim.citations else ""
            lines.append(f"- {claim.text}{cites}")
        lines.append("")
    lines.append("UNCERTAINTIES")
    for item in uncertainties:
        cites = f" [{', '.join(item.citations)}]" if item.citations else ""
        lines.append(f"- ({item.reason}) {item.text}{cites}")
    return "\n".join(lines)


def _all(sections: Mapping[str, list[Claim]]) -> list[Claim]:
    return [claim for claims in sections.values() for claim in claims]


def _existing(session: Session, sources: PostmortemSources) -> Postmortem | None:
    return session.scalar(
        sa.select(Postmortem).where(
            Postmortem.tenant_id == sources.tenant_id,
            Postmortem.incident_id == sources.incident_id,
            Postmortem.source_fingerprint == sources.fingerprint,
        )
    )


def _prompt_context(
    sources: PostmortemSources, record_sections: Mapping[str, list[Claim]]
) -> dict[str, Any]:
    return {
        "incident": {
            "reference": sources.reference,
            "severity": sources.severity,
            "environment": sources.environment,
            "status": sources.status.value,
            "resolution_basis": sources.resolution_basis,
        },
        "citation_index": {h: r.description for h, r in sorted(sources.records.items())},
        "root_cause_handle": sources.root_cause.handle if sources.root_cause else None,
        "assembled_sections": {
            name: [f"{c.text} [{', '.join(c.citations)}]" for c in claims]
            for name, claims in record_sections.items()
            if claims
        },
    }


def _untrusted_blocks(sources: PostmortemSources) -> list[UntrustedBlock]:
    """Content that arrived from outside, fenced. Human notes are not sent to the model."""
    blocks: list[UntrustedBlock] = []
    provenance_of: dict[str, ProvenanceLabel] = {
        "alert": ProvenanceLabel.RETRIEVED,
        "evidence": ProvenanceLabel.VERIFIED_FACT,
        "hypothesis": ProvenanceLabel.MODEL_CLAIM,
    }
    records: Sequence[SourceRecord] = (*sources.alerts, *sources.evidence, *sources.hypotheses)
    for item in records:
        if item.untrusted_text:
            blocks.append(
                UntrustedBlock(
                    source=f"{item.kind}:{item.handle}",
                    provenance=provenance_of[item.kind],
                    content=item.untrusted_text[:2000],
                )
            )
    return blocks


__all__ = [
    "GENERATOR_VERSION",
    "POSTMORTEM_BUDGET",
    "SECTIONS",
    "PostmortemAuthor",
    "PostmortemOutcome",
    "assemble",
]
