"""G9 Remediation Executor.

The only node in either graph with both read and write capabilities: read, to re-validate
preconditions against live state immediately before dispatch (SI-7) and to reconcile an
unknown outcome by query; write, to actually invoke the one authorised action.

Two checks happen here and nowhere else, immediately before anything is dispatched:

**SI-6, recomputed, not trusted.** The action's version hash is recomputed from the row's
*current* tool, arguments, permission scope, preconditions and risk tier and compared
against the hash the approval (or the policy allow) was granted against. Any divergence
fails closed - the action is not executed, regardless of how it diverged.

**SI-7, re-checked, not assumed.** Every precondition the action declared is re-evaluated
against a fresh read, not against whatever was true when the action was proposed. A
precondition that no longer holds fails closed before the write is ever attempted.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import sqlalchemy as sa

from asic.contracts.nodes import G9_REMEDIATION_EXECUTOR
from asic.contracts.remediation_state import RemediationActionRef, RemediationGraphState
from asic.db.models.incident import Incident
from asic.db.models.remediation import RemediationAction
from asic.db.projections import append_incident_event, apply_transition
from asic.domain.enums import (
    ActorType,
    IncidentEventType,
    IncidentStatus,
    NodeId,
    RemediationActionStatus,
    TerminationReason,
    ToolExecutionOutcome,
    TraceSpanKind,
)
from asic.domain.idempotency import action_version_hash, incident_event_key
from asic.orchestration.remediation.context import RemediationDependencies
from asic.remediation.observations import effect_observed, precondition_holds
from asic.tools.broker import CapabilityRequest
from asic.tools.descriptor import ToolDescriptor
from asic.tools.registry import ToolRegistry
from asic.tools.remediation_catalogue import PRECONDITION_CAPABILITY


def remediation_executor_node(deps: RemediationDependencies) -> Any:
    """Build the executor node."""

    contract = G9_REMEDIATION_EXECUTOR

    def run(state: RemediationGraphState) -> dict[str, Any]:
        with deps.tracer.span(
            kind=TraceSpanKind.NODE_EXECUTE,
            name="node.remediation_executor",
            node_id=NodeId.G9_REMEDIATION_EXECUTOR,
            node_version=contract.node_version,
        ) as span:
            action_ref = state.get("remediation_action")
            assert action_ref is not None
            action = deps.session.execute(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == uuid.UUID(action_ref.action_id),
                )
            ).scalar_one()

            # A stateless lookup against the same code catalogue the broker's own resolver
            # was built from - not a second broker pathway, just reading what "the current
            # descriptor for this tool" means in order to recompute SI-6's hash below.
            descriptor = ToolRegistry.remediation_full().by_name(action.tool_name)

            # A resumed run always re-enters the graph from START (no attached checkpointer -
            # see the kernel's own docstring), so this node runs again for an action a prior
            # pass of *this same run* already dispatched - most often because G10 suspended
            # for the tool's settling window, not because anything about the action needs
            # re-deciding. SI-5 (never execute twice) and SI-7's own read-dedup (a replayed
            # precondition read answers "{}", not "still holds" - see ``_drifted_precondition``)
            # both make re-running SI-6/SI-7/dispatch on that second pass unsafe, not merely
            # redundant, so a terminal action status is replayed rather than re-decided.
            if action.status is RemediationActionStatus.SUCCEEDED:
                span.set_decision(replayed=True, outcome="succeeded")
                update = {
                    "phase": "verifying",
                    "remediation_action": action_ref.model_copy(
                        update={"status": RemediationActionStatus.SUCCEEDED}
                    ),
                    "terminated": False,
                }
                contract.validate_update(update)
                return update
            if action.status in (
                RemediationActionStatus.FAILED_CLEAN,
                RemediationActionStatus.FAILED_PARTIAL,
            ):
                span.set_decision(replayed=True, outcome=action.status.value)
                update = {
                    "phase": "terminated",
                    "remediation_action": action_ref.model_copy(update={"status": action.status}),
                    "terminated": True,
                    "termination_reason": "replayed from a prior pass of this run",
                }
                contract.validate_update(update)
                return update
            if action.status is RemediationActionStatus.EXECUTING:
                # The status update that precedes dispatch (below) committed, but this run
                # crashed - or is being resumed concurrently - before the outcome was
                # recorded. SI-5 forbids a blind second dispatch: ask the target directly.
                span.fail(
                    "resuming after an interrupted execution; reconciling, not re-dispatching"
                )
                confirmed = _reconcile(deps, action, descriptor)
                incident = deps.session.execute(
                    sa.select(Incident).where(
                        Incident.tenant_id == deps.context.tenant_id,
                        Incident.id == deps.context.incident_id,
                    )
                ).scalar_one()
                if confirmed:
                    return _route_success(deps, contract, incident, action, action_ref)
                return _fail_closed(
                    deps,
                    contract,
                    action,
                    reason="execution status was left 'executing' by an interrupted prior "
                    "pass, and reconciliation could not confirm the effect took hold",
                    target_status=IncidentStatus.ESCALATED,
                    new_action_status=RemediationActionStatus.FAILED_PARTIAL,
                    emit_compensation_event=True,
                )

            recomputed = action_version_hash(
                action_id=action.id,
                tool_name=action.tool_name,
                tool_version=action.tool_version,
                arguments=action.arguments,
                permission_scope=action.permission_scope,
                preconditions=action.preconditions,
                risk_tier=action.risk_tier.value,
            )
            if recomputed != action.action_version_hash:
                span.fail("action_version_hash mismatch at dispatch")
                return _fail_closed(
                    deps,
                    contract,
                    action,
                    reason="the action's recorded version no longer matches its own row; "
                    "refusing to execute against a version that has drifted (SI-6)",
                    target_status=IncidentStatus.ESCALATED,
                )

            drifted = _drifted_precondition(deps, action, descriptor)
            if drifted is not None:
                span.fail(f"precondition drift: {drifted}")
                return _fail_closed(
                    deps,
                    contract,
                    action,
                    reason=f"precondition {drifted!r} no longer holds (SI-7)",
                    target_status=IncidentStatus.INVESTIGATING,
                )

            deps.session.execute(
                sa.update(RemediationAction)
                .where(
                    RemediationAction.tenant_id == deps.context.tenant_id,
                    RemediationAction.id == action.id,
                )
                .values(status=RemediationActionStatus.EXECUTING)
            )
            incident = deps.session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == deps.context.tenant_id,
                    Incident.id == deps.context.incident_id,
                )
            ).scalar_one()
            append_incident_event(
                deps.session,
                incident=incident,
                event_type=IncidentEventType.EXECUTION_STARTED,
                source=NodeId.G9_REMEDIATION_EXECUTOR.value,
                actor_type=ActorType.SYSTEM,
                correlation_id=deps.context.correlation_id,
                payload={"action_id": str(action.id), "tool_name": action.tool_name},
                idempotency_key=incident_event_key(
                    tenant_id=deps.context.tenant_id,
                    incident_id=deps.context.incident_id,
                    event_type=IncidentEventType.EXECUTION_STARTED.value,
                    subject_id=action.id,
                ),
            )

            result = deps.broker.invoke(
                deps.session,
                request=CapabilityRequest(
                    node_id=NodeId.G9_REMEDIATION_EXECUTOR,
                    capability=descriptor.capability,
                    service_name=deps.context.scope.service_names[0],
                    arguments=dict(action.arguments),
                    incident_id=deps.context.incident_id,
                    correlation_id=deps.context.correlation_id,
                    remediation_action_id=action.id,
                    purpose=action.reason[:200],
                ),
                contract=contract,
            )

            if result.outcome is ToolExecutionOutcome.UNKNOWN:
                confirmed = _reconcile(deps, action, descriptor)
                final_outcome = (
                    ToolExecutionOutcome.SUCCEEDED
                    if confirmed
                    else ToolExecutionOutcome.FAILED_PARTIAL
                )
            else:
                final_outcome = result.outcome

            span.set_decision(
                outcome=final_outcome.value,
                broker_outcome=result.outcome.value,
                tool_execution_id=(
                    str(result.tool_execution_id) if result.tool_execution_id else None
                ),
            )
            if result.tool_execution_id is not None:
                span.tool_execution_id = result.tool_execution_id

            if final_outcome is ToolExecutionOutcome.SUCCEEDED:
                return _route_success(deps, contract, incident, action, action_ref)

            # Clean failure (no effect applied, per the broker) resumes investigation;
            # everything else - a confirmed partial effect - escalates for a human, because
            # this phase executes at most one action and does not automate compensation.
            no_effect = result.outcome is ToolExecutionOutcome.FAILED_CLEAN
            return _fail_closed(
                deps,
                contract,
                action,
                reason=(
                    result.failure.message
                    if result.failure
                    else f"execution outcome {final_outcome.value}"
                ),
                target_status=(
                    IncidentStatus.INVESTIGATING if no_effect else IncidentStatus.ESCALATED
                ),
                new_action_status=(
                    RemediationActionStatus.FAILED_CLEAN
                    if no_effect
                    else RemediationActionStatus.FAILED_PARTIAL
                ),
                emit_compensation_event=not no_effect,
            )

    return run


# ------------------------------------------------------------------------------ helpers


def _route_success(
    deps: RemediationDependencies,
    contract: Any,
    incident: Incident,
    action: RemediationAction,
    action_ref: RemediationActionRef,
) -> dict[str, Any]:
    deps.session.execute(
        sa.update(RemediationAction)
        .where(
            RemediationAction.tenant_id == deps.context.tenant_id,
            RemediationAction.id == action.id,
        )
        .values(
            status=RemediationActionStatus.SUCCEEDED,
            executed_at=action.executed_at or deps.clock.now(),
        )
    )
    if incident.status is not IncidentStatus.VERIFYING:
        apply_transition(
            deps.session,
            incident=incident,
            target=IncidentStatus.VERIFYING,
            actor_type=ActorType.SYSTEM,
            source=NodeId.G9_REMEDIATION_EXECUTOR.value,
            correlation_id=deps.context.correlation_id,
        )
        append_incident_event(
            deps.session,
            incident=incident,
            event_type=IncidentEventType.EXECUTION_COMPLETED,
            source=NodeId.G9_REMEDIATION_EXECUTOR.value,
            actor_type=ActorType.SYSTEM,
            correlation_id=deps.context.correlation_id,
            payload={"action_id": str(action.id)},
            idempotency_key=incident_event_key(
                tenant_id=deps.context.tenant_id,
                incident_id=deps.context.incident_id,
                event_type=IncidentEventType.EXECUTION_COMPLETED.value,
                subject_id=action.id,
            ),
        )
    update: dict[str, Any] = {
        "phase": "verifying",
        "remediation_action": action_ref.model_copy(
            update={"status": RemediationActionStatus.SUCCEEDED}
        ),
        "terminated": False,
    }
    contract.validate_update(update)
    return update


def _drifted_precondition(
    deps: RemediationDependencies, action: RemediationAction, descriptor: ToolDescriptor
) -> str | None:
    """The first precondition, if any, that a fresh read no longer supports."""
    for name in action.preconditions:
        capability = PRECONDITION_CAPABILITY.get(name)
        if capability is None:
            return name
        result = deps.broker.invoke(
            deps.session,
            request=CapabilityRequest(
                node_id=NodeId.G9_REMEDIATION_EXECUTOR,
                capability=capability,
                service_name=deps.context.scope.service_names[0],
                arguments=_read_arguments(capability, deps),
                incident_id=deps.context.incident_id,
                correlation_id=deps.context.correlation_id,
                purpose=f"precondition check: {name}",
            ),
            contract=G9_REMEDIATION_EXECUTOR,
        )
        if not result.succeeded or result.deduplicated:
            return name
        if not precondition_holds(name, action.arguments, result.payload):
            return name
    return None


def _reconcile(
    deps: RemediationDependencies, action: RemediationAction, descriptor: ToolDescriptor
) -> bool:
    """After an unknown outcome, ask the target directly rather than guessing.

    A deliberately narrow check: did the read-back for this write's own rollback
    capability confirm the change is now in effect. Returning ``False`` is the safe
    default - it routes to escalation, never to a second attempt at the write.
    """
    capability = (
        PRECONDITION_CAPABILITY.get(action.preconditions[0]) if action.preconditions else None
    )
    if capability is None:
        return False
    result = deps.broker.invoke(
        deps.session,
        request=CapabilityRequest(
            node_id=NodeId.G9_REMEDIATION_EXECUTOR,
            capability=capability,
            service_name=deps.context.scope.service_names[0],
            arguments=_read_arguments(capability, deps),
            incident_id=deps.context.incident_id,
            correlation_id=deps.context.correlation_id,
            purpose="reconcile unknown outcome",
        ),
        contract=G9_REMEDIATION_EXECUTOR,
    )
    return (
        result.succeeded
        and not result.deduplicated
        and effect_observed(action.tool_name, action.arguments, result.payload)
    )


def _read_arguments(capability: str, deps: RemediationDependencies) -> dict[str, Any]:
    if capability == "read.deploy":
        # deploy.list's window arguments are required (no default): a wide-enough lookback
        # to see the deployment this action targets, not a claim about its actual history.
        now = deps.clock.now()
        return {"window_start": now - timedelta(hours=24), "window_end": now}
    return {"include_events": False}


def _fail_closed(
    deps: RemediationDependencies,
    contract: Any,
    action: RemediationAction,
    *,
    reason: str,
    target_status: IncidentStatus,
    new_action_status: RemediationActionStatus = RemediationActionStatus.FAILED_CLEAN,
    emit_compensation_event: bool = False,
) -> dict[str, Any]:
    deps.session.execute(
        sa.update(RemediationAction)
        .where(
            RemediationAction.tenant_id == deps.context.tenant_id, RemediationAction.id == action.id
        )
        .values(status=new_action_status)
    )
    incident = deps.session.execute(
        sa.select(Incident).where(
            Incident.tenant_id == deps.context.tenant_id,
            Incident.id == deps.context.incident_id,
        )
    ).scalar_one()
    if target_status is not incident.status:
        apply_transition(
            deps.session,
            incident=incident,
            target=target_status,
            actor_type=ActorType.SYSTEM,
            source=NodeId.G9_REMEDIATION_EXECUTOR.value,
            correlation_id=deps.context.correlation_id,
            termination_reason=(
                TerminationReason.UNRECOVERABLE_FAILURE
                if target_status is IncidentStatus.ESCALATED
                else None
            ),
        )
    append_incident_event(
        deps.session,
        incident=incident,
        event_type=IncidentEventType.EXECUTION_FAILED,
        source=NodeId.G9_REMEDIATION_EXECUTOR.value,
        actor_type=ActorType.SYSTEM,
        correlation_id=deps.context.correlation_id,
        payload={"action_id": str(action.id), "reason": reason[:1000]},
        idempotency_key=incident_event_key(
            tenant_id=deps.context.tenant_id,
            incident_id=deps.context.incident_id,
            event_type=IncidentEventType.EXECUTION_FAILED.value,
            subject_id=action.id,
        ),
    )
    if emit_compensation_event:
        append_incident_event(
            deps.session,
            incident=incident,
            event_type=IncidentEventType.COMPENSATION_STARTED,
            source=NodeId.G9_REMEDIATION_EXECUTOR.value,
            actor_type=ActorType.SYSTEM,
            correlation_id=deps.context.correlation_id,
            payload={
                "action_id": str(action.id),
                "note": (
                    "a partial or unknown-then-unconfirmed effect was recorded; automated "
                    "compensation execution is not implemented in this phase, so this is "
                    "recorded as a signal for a human, not as a retried write"
                ),
            },
            idempotency_key=incident_event_key(
                tenant_id=deps.context.tenant_id,
                incident_id=deps.context.incident_id,
                event_type=IncidentEventType.COMPENSATION_STARTED.value,
                subject_id=action.id,
            ),
        )

    update: dict[str, Any] = {
        "phase": "terminated",
        "terminated": True,
        "termination_reason": reason[:1000],
        "target_incident_status": target_status.value,
    }
    contract.validate_update(update)
    return update


__all__ = ["remediation_executor_node"]
