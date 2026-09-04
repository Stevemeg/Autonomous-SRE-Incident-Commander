"""Canonical incident state machine.

The Phase 3 brief requires that arbitrary state transitions be impossible and that every
transition record *who or what* is allowed to cause it. This module is the single source
of truth for both, and it is deterministic: no model output participates in a transition
decision.

Two levels of state exist in this system, and keeping them apart matters:

* :class:`~asic.domain.enums.IncidentStatus` - coarse incident lifecycle, defined here.
* :class:`~asic.domain.enums.RemediationActionStatus` - fine-grained per-action execution
  state (proposed, authorized, executing, reconciling, compensating, ...).

Folding action-level execution edge cases into the incident status would give the incident
a state per failure mode. An incident is ``REMEDIATING`` whether the action underneath it
is executing, reconciling or compensating.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Final

from asic.domain.enums import ActorType, IncidentStatus, TerminationReason
from asic.domain.errors import IllegalStateTransition

# States from which no further automated progress is possible.
CLOSED_STATES: Final[frozenset[IncidentStatus]] = frozenset(
    {IncidentStatus.RESOLVED, IncidentStatus.FAILED}
)

# States that satisfy master specification section 5's requirement that every run
# terminate through success, uncertainty, timeout, failure or human escalation.
TERMINAL_STATES: Final[frozenset[IncidentStatus]] = frozenset(
    {
        IncidentStatus.RESOLVED,
        IncidentStatus.FAILED,
        IncidentStatus.ESCALATED,
        IncidentStatus.UNCERTAIN,
    }
)

#: ``FAILED`` is absolutely final: an incident that failed unrecoverably is not reopened,
#: a new incident is opened instead. This keeps the audit history of a failure intact.
IRREVERSIBLE_STATES: Final[frozenset[IncidentStatus]] = frozenset({IncidentStatus.FAILED})


@dataclass(frozen=True, slots=True)
class Transition:
    """One permitted edge of the incident state machine."""

    source: IncidentStatus
    target: IncidentStatus
    #: Which actor kinds may cause this transition. A transition an agent node may not
    #: cause is one where a human or a deterministic system component must act.
    allowed_actors: frozenset[ActorType]
    #: Human-readable trigger, used in documentation and audit records.
    trigger: str
    #: Transitions into a terminal state must record why the run stopped.
    requires_termination_reason: bool = False
    #: Transitions a human must justify in writing (audit obligation).
    requires_justification: bool = False

    def permits(self, actor: ActorType) -> bool:
        return actor in self.allowed_actors


_SYSTEM: Final = frozenset({ActorType.SYSTEM, ActorType.AGENT_NODE})
_HUMAN: Final = frozenset({ActorType.HUMAN})
_SYSTEM_OR_HUMAN: Final = _SYSTEM | _HUMAN


def _t(
    source: IncidentStatus,
    target: IncidentStatus,
    actors: frozenset[ActorType],
    trigger: str,
    *,
    reason: bool = False,
    justify: bool = False,
) -> Transition:
    return Transition(
        source=source,
        target=target,
        allowed_actors=actors,
        trigger=trigger,
        requires_termination_reason=reason,
        requires_justification=justify,
    )


#: The complete transition table. Any (source, target) pair absent from this table is
#: rejected by :func:`assert_transition_allowed`.
TRANSITIONS: Final[tuple[Transition, ...]] = (
    # --- detected -------------------------------------------------------------
    _t(
        IncidentStatus.DETECTED,
        IncidentStatus.ACKNOWLEDGED,
        _SYSTEM_OR_HUMAN,
        "responder acknowledged, or auto-acknowledged by policy",
    ),
    _t(
        IncidentStatus.DETECTED,
        IncidentStatus.INVESTIGATING,
        _SYSTEM,
        "orchestrator began the bounded investigation loop",
    ),
    _t(
        IncidentStatus.DETECTED,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "escalated before investigation began",
        reason=True,
    ),
    _t(
        IncidentStatus.DETECTED,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure before investigation began",
        reason=True,
    ),
    # --- acknowledged ---------------------------------------------------------
    _t(
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.INVESTIGATING,
        _SYSTEM,
        "orchestrator began the bounded investigation loop",
    ),
    _t(
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "escalated by responder or policy",
        reason=True,
    ),
    _t(
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.RESOLVED,
        _HUMAN,
        "responder resolved without automated investigation",
        reason=True,
        justify=True,
    ),
    _t(
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure",
        reason=True,
    ),
    # --- investigating --------------------------------------------------------
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.AWAITING_APPROVAL,
        _SYSTEM,
        "policy gate returned require_approval for a proposed action",
    ),
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.REMEDIATING,
        _SYSTEM,
        "policy gate allowed an action without human approval",
    ),
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.UNCERTAIN,
        _SYSTEM,
        "investigation completed without sufficient evidence, or a budget was exhausted",
        reason=True,
    ),
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "escalated to a human",
        reason=True,
    ),
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        _HUMAN,
        "responder resolved during investigation",
        reason=True,
        justify=True,
    ),
    _t(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure during investigation",
        reason=True,
    ),
    # --- awaiting approval ----------------------------------------------------
    _t(
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.REMEDIATING,
        _HUMAN,
        "an authorised approver granted approval",
    ),
    _t(
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.INVESTIGATING,
        _SYSTEM,
        "approval was refused or invalidated; investigation resumes",
    ),
    _t(
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "approval rejected, expired or invalidated by state drift",
        reason=True,
    ),
    _t(
        IncidentStatus.AWAITING_APPROVAL,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure while awaiting approval",
        reason=True,
    ),
    # --- remediating ----------------------------------------------------------
    _t(
        IncidentStatus.REMEDIATING,
        IncidentStatus.VERIFYING,
        _SYSTEM,
        "execution reported an outcome; independent verification begins",
    ),
    _t(
        IncidentStatus.REMEDIATING,
        IncidentStatus.INVESTIGATING,
        _SYSTEM,
        "execution failed cleanly with no effect; investigation resumes",
    ),
    _t(
        IncidentStatus.REMEDIATING,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "execution failed partially, compensation failed, or reconciliation was impossible",
        reason=True,
    ),
    _t(
        IncidentStatus.REMEDIATING,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure during remediation",
        reason=True,
    ),
    # --- verifying ------------------------------------------------------------
    _t(
        IncidentStatus.VERIFYING,
        IncidentStatus.RESOLVED,
        _SYSTEM,
        "verification confirmed the symptoms resolved",
        reason=True,
    ),
    _t(
        IncidentStatus.VERIFYING,
        IncidentStatus.INVESTIGATING,
        _SYSTEM,
        "verification failed; investigation resumes with the new evidence",
    ),
    _t(
        IncidentStatus.VERIFYING,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "verification was inconclusive, or failed with no safe next action",
        reason=True,
    ),
    _t(
        IncidentStatus.VERIFYING,
        IncidentStatus.FAILED,
        _SYSTEM,
        "unrecoverable failure during verification",
        reason=True,
    ),
    # --- uncertain ------------------------------------------------------------
    # Terminating in uncertainty is a correct outcome, not a failure. A human may pick it
    # up, reopen it with new information, or close it.
    _t(
        IncidentStatus.UNCERTAIN,
        IncidentStatus.ESCALATED,
        _SYSTEM_OR_HUMAN,
        "uncertain outcome handed to a human",
        reason=True,
    ),
    _t(
        IncidentStatus.UNCERTAIN,
        IncidentStatus.INVESTIGATING,
        _HUMAN,
        "reopened with new information",
        justify=True,
    ),
    _t(
        IncidentStatus.UNCERTAIN,
        IncidentStatus.RESOLVED,
        _HUMAN,
        "responder resolved after an uncertain outcome",
        reason=True,
        justify=True,
    ),
    # --- escalated ------------------------------------------------------------
    _t(
        IncidentStatus.ESCALATED,
        IncidentStatus.INVESTIGATING,
        _HUMAN,
        "human returned the incident to automated investigation",
        justify=True,
    ),
    _t(
        IncidentStatus.ESCALATED,
        IncidentStatus.RESOLVED,
        _HUMAN,
        "human resolved the escalated incident",
        reason=True,
        justify=True,
    ),
    _t(
        IncidentStatus.ESCALATED,
        IncidentStatus.FAILED,
        _HUMAN,
        "human recorded the incident as failed",
        reason=True,
        justify=True,
    ),
    # --- resolved -------------------------------------------------------------
    # Reopening is human-only and must be justified: it reverses a recorded outcome.
    _t(
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
        _HUMAN,
        "incident reopened because symptoms recurred",
        justify=True,
    ),
    # --- failed ---------------------------------------------------------------
    # No outbound transitions. A failed incident is history; recurrence opens a new one.
)


def _build_index() -> dict[tuple[IncidentStatus, IncidentStatus], Transition]:
    index: dict[tuple[IncidentStatus, IncidentStatus], Transition] = {}
    for transition in TRANSITIONS:
        key = (transition.source, transition.target)
        if key in index:  # pragma: no cover - guards against a duplicated table entry
            raise ValueError(f"duplicate transition defined: {key}")
        index[key] = transition
    return index


_TRANSITION_INDEX: Final[dict[tuple[IncidentStatus, IncidentStatus], Transition]] = _build_index()


@dataclass(frozen=True, slots=True)
class TransitionRequest:
    """A proposed state change, carrying everything the machine needs to judge it."""

    source: IncidentStatus
    target: IncidentStatus
    actor_type: ActorType
    termination_reason: TerminationReason | None = None
    justification: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def find_transition(source: IncidentStatus, target: IncidentStatus) -> Transition | None:
    return _TRANSITION_INDEX.get((source, target))


def allowed_targets(source: IncidentStatus) -> frozenset[IncidentStatus]:
    """Every state reachable from ``source`` in one step."""
    return frozenset(t.target for t in TRANSITIONS if t.source is source)


def allowed_transitions_for(
    source: IncidentStatus, actor_type: ActorType
) -> frozenset[IncidentStatus]:
    """Every state ``actor_type`` may move this incident to in one step."""
    return frozenset(t.target for t in TRANSITIONS if t.source is source and t.permits(actor_type))


def is_terminal(status: IncidentStatus) -> bool:
    return status in TERMINAL_STATES


def is_closed(status: IncidentStatus) -> bool:
    return status in CLOSED_STATES


def assert_transition_allowed(request: TransitionRequest) -> Transition:
    """Validate a proposed transition, or raise.

    Raises:
        IllegalStateTransition: if the edge does not exist, the actor may not cause it,
            or a required termination reason or justification is missing.
    """
    if request.source is request.target:
        raise IllegalStateTransition(
            f"no-op transition {request.source.value} -> {request.target.value} is not a "
            "state change; incident status must only be written when it actually changes"
        )

    transition = find_transition(request.source, request.target)
    if transition is None:
        permitted = sorted(s.value for s in allowed_targets(request.source))
        raise IllegalStateTransition(
            f"{request.source.value} -> {request.target.value} is not a permitted "
            f"transition; from {request.source.value} the incident may only move to: "
            f"{permitted or ['(none - terminal)']}"
        )

    if not transition.permits(request.actor_type):
        allowed = sorted(a.value for a in transition.allowed_actors)
        raise IllegalStateTransition(
            f"actor type {request.actor_type.value!r} may not cause "
            f"{request.source.value} -> {request.target.value}; allowed: {allowed}"
        )

    if transition.requires_termination_reason and request.termination_reason is None:
        raise IllegalStateTransition(
            f"{request.source.value} -> {request.target.value} requires a termination "
            "reason; a run may not stop without recording why"
        )

    if transition.requires_justification and not (request.justification or "").strip():
        raise IllegalStateTransition(
            f"{request.source.value} -> {request.target.value} requires a written "
            "justification from the acting human"
        )

    return transition


def iter_transitions() -> Iterator[Transition]:
    yield from TRANSITIONS


def reachable_from(source: IncidentStatus) -> frozenset[IncidentStatus]:
    """Transitive closure of states reachable from ``source``."""
    seen: set[IncidentStatus] = set()
    frontier = [source]
    while frontier:
        current = frontier.pop()
        for target in allowed_targets(current):
            if target not in seen:
                seen.add(target)
                frontier.append(target)
    return frozenset(seen)


def states_without_path_to_closure() -> frozenset[IncidentStatus]:
    """States from which no closed state is reachable.

    Master specification section 5 requires every run to terminate. A non-empty result
    here is a defect in the transition table, and the test suite asserts it is empty.
    """
    stuck: set[IncidentStatus] = set()
    for status in IncidentStatus:
        if status in CLOSED_STATES:
            continue
        if not (reachable_from(status) & CLOSED_STATES):
            stuck.add(status)
    return frozenset(stuck)
