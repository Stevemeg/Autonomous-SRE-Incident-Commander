"""Lifecycle metrics counted from committed records, not from call sites.

An incident transition, a policy verdict, an approval, a verification, a model call's cost
or an evaluation result is a fact only once its row commits. Counting at the call site
would count work a rolled-back transaction undid - a remediation "verified" in a metric but
absent from the database is exactly the false success this system exists to prevent.

So facts are collected from the unit of work as it flushes, attached to the (sub)transaction
that wrote them, merged upward when a savepoint is released, discarded when any enclosing
transaction rolls back, and emitted only when the outermost transaction commits. Every
label comes from a closed enumeration on the row; no identifier is ever read into a label.

The listeners are registered on :class:`sqlalchemy.orm.Session` itself, so every write path
- kernels, API, ingestion, harness - is covered without instrumenting each one.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Final

import sqlalchemy as sa
from opentelemetry import metrics as otel_metrics
from sqlalchemy import event
from sqlalchemy.orm import Session, SessionTransaction

from asic.db.models import (
    Approval,
    AuditRecord,
    EvaluationJudgeResult,
    EvaluationRun,
    EvaluationSuiteRun,
    Incident,
    PolicyDecision,
    RemediationAction,
    TraceSpan,
    Verification,
    WorkflowRun,
)
from asic.domain.enums import (
    WorkflowRunStatus,
)

_meter = otel_metrics.get_meter("asic.lifecycle")

incidents_opened = _meter.create_counter(
    "asic.incidents.opened", description="Incidents committed, by severity."
)
incident_transitions = _meter.create_counter(
    "asic.incident.transitions", description="Committed incident status changes, by new status."
)
incidents_terminated = _meter.create_counter(
    "asic.incidents.terminated", description="Incidents committed to a terminal state, by reason."
)
workflow_runs_started = _meter.create_counter(
    "asic.workflow.runs.started", description="Workflow runs committed."
)
workflow_runs_finished = _meter.create_counter(
    "asic.workflow.runs.finished",
    description="Workflow runs committed to completed, failed or dead-lettered.",
)
policy_decisions = _meter.create_counter(
    "asic.remediation.policy_decisions", description="Committed policy verdicts."
)
approvals = _meter.create_counter(
    "asic.remediation.approvals", description="Committed approval decisions (human or system)."
)
approval_wait = _meter.create_histogram(
    "asic.remediation.approval.wait",
    unit="s",
    description="Seconds from approval request to a committed decision.",
)
action_transitions = _meter.create_counter(
    "asic.remediation.action.transitions",
    description="Committed remediation action statuses, by status and risk tier.",
)
verifications = _meter.create_counter(
    "asic.remediation.verifications", description="Committed verification verdicts."
)
authorization_denials = _meter.create_counter(
    "asic.authorization.denials", description="Committed audit records with a denied outcome."
)
llm_tokens = _meter.create_counter(
    "asic.llm.usage.tokens",
    description=(
        "Model tokens from committed spans carrying model-call metadata, by provider, model "
        "and direction."
    ),
)
llm_cost = _meter.create_counter(
    "asic.llm.usage.cost_usd",
    description=(
        "Model cost in US dollars from committed spans carrying model-call metadata, by "
        "provider and model."
    ),
)
evaluation_suite_runs = _meter.create_counter(
    "asic.evaluation.suite_runs", description="Committed evaluation suite runs, by gate status."
)
evaluation_results = _meter.create_counter(
    "asic.evaluation.results", description="Committed per-scenario evaluation verdicts."
)
evaluation_judge_results = _meter.create_counter(
    "asic.evaluation.judge_results", description="Committed judge results, by outcome."
)

_FINISHED: Final[frozenset[WorkflowRunStatus]] = frozenset(
    {WorkflowRunStatus.COMPLETED, WorkflowRunStatus.FAILED, WorkflowRunStatus.DEAD_LETTERED}
)
_KEY: Final[str] = "asic.lifecycle.facts"
_OUTCOME: Final[str] = "asic.lifecycle.outcome"


@dataclass(frozen=True, slots=True)
class _Fact:
    instrument: Any
    value: float
    attributes: dict[str, str]

    def emit(self) -> None:
        if isinstance(self.instrument, otel_metrics.Histogram):
            self.instrument.record(self.value, self.attributes)
        else:
            self.instrument.add(self.value, self.attributes)


def _enum(value: Any, default: str = "unknown") -> str:
    return str(getattr(value, "value", value)) if value is not None else default


def _changed(obj: Any, attribute: str) -> bool:
    return bool(sa.inspect(obj).attrs[attribute].history.added)


def facts_for_new(obj: Any) -> list[_Fact]:
    facts: list[_Fact] = []
    if isinstance(obj, Incident):
        facts.append(_Fact(incidents_opened, 1, {"severity": _enum(obj.severity)}))
    elif isinstance(obj, WorkflowRun):
        facts.append(_Fact(workflow_runs_started, 1, {}))
        if obj.status in _FINISHED:
            facts.append(_Fact(workflow_runs_finished, 1, {"status": _enum(obj.status)}))
    elif isinstance(obj, PolicyDecision):
        facts.append(_Fact(policy_decisions, 1, {"verdict": _enum(obj.verdict)}))
    elif isinstance(obj, Approval):
        facts.extend(_approval_facts(obj))
    elif isinstance(obj, RemediationAction):
        facts.append(_action_fact(obj))
    elif isinstance(obj, Verification):
        facts.append(_Fact(verifications, 1, {"verdict": _enum(obj.verdict)}))
    elif isinstance(obj, AuditRecord):
        if obj.outcome == "denied":
            facts.append(_Fact(authorization_denials, 1, {"event_type": _enum(obj.event_type)}))
    elif isinstance(obj, TraceSpan):
        facts.extend(_model_usage(obj))
    elif isinstance(obj, EvaluationSuiteRun):
        facts.append(
            _Fact(
                evaluation_suite_runs,
                1,
                {
                    "suite": obj.suite_key if obj.suite_key in ("golden", "smoke") else "other",
                    "mode": _enum(obj.execution_mode),
                    "gate_status": _enum(obj.gate_status),
                },
            )
        )
    elif isinstance(obj, EvaluationRun):
        facts.append(
            _Fact(
                evaluation_results,
                1,
                {"mode": _enum(obj.execution_mode, "legacy"), "verdict": _enum(obj.verdict)},
            )
        )
    elif isinstance(obj, EvaluationJudgeResult):
        facts.append(_Fact(evaluation_judge_results, 1, {"outcome": _enum(obj.outcome)}))
    return facts


def facts_for_dirty(obj: Any) -> list[_Fact]:
    facts: list[_Fact] = []
    if isinstance(obj, Incident) and _changed(obj, "status"):
        facts.append(_Fact(incident_transitions, 1, {"to_status": _enum(obj.status)}))
        if obj.terminated_at is not None and obj.termination_reason is not None:
            facts.append(
                _Fact(
                    incidents_terminated, 1, {"termination_reason": _enum(obj.termination_reason)}
                )
            )
    elif isinstance(obj, WorkflowRun) and _changed(obj, "status") and obj.status in _FINISHED:
        facts.append(_Fact(workflow_runs_finished, 1, {"status": _enum(obj.status)}))
    elif isinstance(obj, RemediationAction) and _changed(obj, "status"):
        facts.append(_action_fact(obj))
    return facts


def _action_fact(action: RemediationAction) -> _Fact:
    return _Fact(
        action_transitions,
        1,
        {"status": _enum(action.status), "risk_tier": _enum(action.risk_tier)},
    )


def _approval_facts(approval: Approval) -> list[_Fact]:
    facts = [_Fact(approvals, 1, {"decision": _enum(approval.decision)})]
    if approval.decided_at is not None and approval.requested_at is not None:
        waited = (approval.decided_at - approval.requested_at).total_seconds()
        facts.append(_Fact(approval_wait, max(0.0, waited), {"decision": _enum(approval.decision)}))
    return facts


def _model_usage(span: TraceSpan) -> list[_Fact]:
    # A model call is recorded on the span that made it (``SpanHandle.set_model_call``), so
    # usage is read from any committed span carrying model-call metadata, whatever its kind.
    metadata = dict(span.model_metadata or {})
    if not metadata.get("provider") or (span.input_tokens is None and span.cost_usd is None):
        return []
    labels = {
        "provider": str(metadata.get("provider") or "unknown")[:64],
        "model": str(metadata.get("model_id") or "unknown")[:64],
    }
    facts: list[_Fact] = []
    for direction, tokens in (("input", span.input_tokens), ("output", span.output_tokens)):
        if tokens:
            facts.append(_Fact(llm_tokens, float(tokens), {**labels, "direction": direction}))
    if span.cost_usd:
        facts.append(_Fact(llm_cost, float(span.cost_usd), labels))
    return facts


# ------------------------------------------------------------------ transaction plumbing


def _store(session: Session) -> dict[int, list[_Fact]]:
    store: dict[int, list[_Fact]] = session.info.setdefault(_KEY, {})
    return store


def _current(session: Session) -> SessionTransaction | None:
    return session.get_nested_transaction() or session.get_transaction()


def _after_flush(session: Session, _context: Any) -> None:
    transaction = _current(session)
    if transaction is None:
        return
    collected: list[_Fact] = []
    for obj in session.new:
        collected.extend(facts_for_new(obj))
    for obj in session.dirty:
        collected.extend(facts_for_dirty(obj))
    if collected:
        _store(session).setdefault(id(transaction), []).extend(collected)


def _after_commit(session: Session) -> None:
    session.info[_OUTCOME] = "commit"


def _after_rollback(session: Session) -> None:
    session.info[_OUTCOME] = "rollback"


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    # SQLAlchemy fires after_commit / after_rollback immediately before after_transaction_end
    # for the same (sub)transaction, savepoints included. An end with no recorded outcome is
    # treated as a rollback: a fact is emitted only when a commit is confirmed.
    outcome = session.info.pop(_OUTCOME, "rollback")
    store = session.info.get(_KEY)
    facts = store.pop(id(transaction), []) if store else []
    if outcome != "commit" or not facts:
        return
    parent = transaction.parent
    if parent is not None:
        _store(session).setdefault(id(parent), []).extend(facts)
        return
    for fact in facts:
        fact.emit()


_installed = False
_lock = threading.Lock()


def install() -> None:
    """Register the listeners once per process. Safe to call repeatedly."""
    global _installed
    with _lock:
        if _installed:
            return
        event.listen(Session, "after_flush", _after_flush)
        event.listen(Session, "after_commit", _after_commit)
        event.listen(Session, "after_rollback", _after_rollback)
        event.listen(Session, "after_transaction_end", _after_transaction_end)
        _installed = True


__all__ = ["facts_for_dirty", "facts_for_new", "install"]
