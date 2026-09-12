"""Explicit application boundary from durable eligibility to the read-only kernel."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Alert, Incident, InvestigationDispatch, WorkflowRun
from asic.db.session import TenantContext, apply_statement_timeouts, bind_tenant
from asic.domain.enums import WorkflowRunStatus
from asic.domain.errors import DomainError, LeaseNotHeld
from asic.domain.incident_state import is_terminal
from asic.ingestion.telemetry import stage
from asic.orchestration.kernel import DispatchAlreadyLinked
from asic.orchestration.service import InvestigationRequest, InvestigationService


@dataclass(frozen=True)
class DispatchResult:
    request_id: UUID
    run_id: UUID | None
    status: str


class InvestigationDispatcher:
    """Caller supplies trusted behaviour configuration, never values from an alert.

    Invoke dispatch again after transient failure or lease expiry. This is a bounded
    worker entry point, not an in-process scheduler or an automatic retry loop.
    """

    def __init__(self, factory: Callable[[], Session], service: InvestigationService) -> None:
        self.factory, self.service = factory, service

    def dispatch(
        self, context: TenantContext, request_id: UUID, behaviour_version_id: UUID
    ) -> DispatchResult:
        with stage(
            "investigation_trigger", tenant_id=str(context.tenant_id), request_id=str(request_id)
        ) as trigger_span:
            with self.factory() as session, session.begin():
                bind_tenant(session, context.tenant_id)
                apply_statement_timeouts(session)
                request = session.scalar(
                    sa.select(InvestigationDispatch)
                    .where(
                        InvestigationDispatch.tenant_id == context.tenant_id,
                        InvestigationDispatch.id == request_id,
                    )
                    .with_for_update()
                )
                if request is None:
                    raise DomainError("investigation request not visible")
                if request.status == "terminal":
                    return DispatchResult(request_id, request.workflow_run_id, "terminal")
                run_id = request.workflow_run_id
                if run_id is None:
                    incident_status = session.scalar(
                        sa.select(Incident.status).where(
                            Incident.tenant_id == context.tenant_id,
                            Incident.id == request.incident_id,
                        )
                    )
                    if incident_status is None:
                        raise DomainError("dispatch incident not visible")
                    if is_terminal(incident_status):
                        request.attempts += 1
                        request.status = "terminal"
                        request.last_error = "terminal_incident"
                        trigger_span.set_attribute("dispatch.outcome", "terminal")
                        return DispatchResult(request_id, None, "terminal")
                    request.attempts += 1
                else:
                    # A linked workflow is the committed dispatch outcome. Later incident
                    # termination must not rewrite that success as an error.
                    request.status = "completed"
                    request.last_error = None
                incident_id = request.incident_id
                trigger_span.set_attribute("incident_id", str(incident_id))
                trigger_span.set_attribute("correlation_id", str(request.correlation_id))
                service_ids = (
                    tuple(
                        session.scalars(
                            sa.select(Alert.service_id)
                            .where(
                                Alert.tenant_id == context.tenant_id,
                                Alert.incident_id == incident_id,
                                Alert.service_id.is_not(None),
                            )
                            .distinct()
                        )
                    )
                    if run_id is None
                    else ()
                )
            try:
                if run_id is None:
                    try:
                        outcome = self.service.start(
                            InvestigationRequest(
                                tenant_id=context.tenant_id,
                                incident_id=incident_id,
                                behaviour_version_id=behaviour_version_id,
                                service_ids=tuple(s for s in service_ids if s is not None),
                                dispatch_id=request_id,
                            )
                        )
                        trigger_span.set_attribute("workflow_run_id", str(outcome.workflow_run_id))
                        self._mark_completed(context.tenant_id, request_id)
                        return DispatchResult(
                            request_id,
                            outcome.workflow_run_id,
                            "completed" if outcome.terminated else "suspended",
                        )
                    except DispatchAlreadyLinked:
                        pass
                with self.factory() as session, session.begin():
                    bind_tenant(session, context.tenant_id)
                    request = session.scalars(
                        sa.select(InvestigationDispatch)
                        .where(
                            InvestigationDispatch.tenant_id == context.tenant_id,
                            InvestigationDispatch.id == request_id,
                        )
                        .with_for_update()
                    ).one()
                    run_id = request.workflow_run_id
                    if run_id is None:
                        raise DomainError("dispatch has no linked run")
                    request.status = "completed"
                    request.last_error = None
                    run = session.scalars(
                        sa.select(WorkflowRun).where(
                            WorkflowRun.tenant_id == context.tenant_id, WorkflowRun.id == run_id
                        )
                    ).one()
                    if run.status in (WorkflowRunStatus.COMPLETED, WorkflowRunStatus.FAILED):
                        return DispatchResult(request_id, run_id, run.status.value)
                outcome = self.service.resume(tenant_id=context.tenant_id, workflow_run_id=run_id)
                return DispatchResult(
                    request_id, run_id, "completed" if outcome.terminated else "suspended"
                )
            except LeaseNotHeld:
                return DispatchResult(request_id, run_id, "busy")
            except Exception:
                # Store a safe code, never an exception message containing SQL or source data.
                linked_success = False
                with self.factory() as session, session.begin():
                    bind_tenant(session, context.tenant_id)
                    request = session.scalars(
                        sa.select(InvestigationDispatch)
                        .where(
                            InvestigationDispatch.tenant_id == context.tenant_id,
                            InvestigationDispatch.id == request_id,
                        )
                        .with_for_update()
                    ).one()
                    if request.workflow_run_id is not None:
                        request.status = "completed"
                        request.last_error = None
                        linked_success = True
                    else:
                        incident_status = session.scalar(
                            sa.select(Incident.status).where(
                                Incident.tenant_id == context.tenant_id,
                                Incident.id == request.incident_id,
                            )
                        )
                        if incident_status is not None and is_terminal(incident_status):
                            request.status = "terminal"
                            request.last_error = "terminal_incident"
                            return DispatchResult(request_id, None, "terminal")
                        request.last_error = "trigger_failed"
                if linked_success:
                    trigger_span.set_attribute("dispatch.outcome", "linked_run_failed_to_drive")
                raise

    def _mark_completed(self, tenant_id: UUID, request_id: UUID) -> None:
        """Persist successful run linkage without conflating it with workflow completion."""
        with self.factory() as session, session.begin():
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            request = session.scalars(
                sa.select(InvestigationDispatch)
                .where(
                    InvestigationDispatch.tenant_id == tenant_id,
                    InvestigationDispatch.id == request_id,
                )
                .with_for_update()
            ).one()
            if request.workflow_run_id is None:
                raise DomainError("dispatch has no linked run")
            request.status = "completed"
            request.last_error = None
