"""Versioned FastAPI edge for the five independently authorized Phase 9 surfaces."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import uuid
from collections.abc import Iterator, MutableMapping
from contextlib import asynccontextmanager
from datetime import datetime
from time import perf_counter
from typing import Annotated, Any, cast

import sqlalchemy as sa
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import metrics as otel_metrics
from opentelemetry import trace
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from asic.api.auth import (
    ApiSettings,
    CurrentPrincipal,
    PermissionDenied,
    Principal,
    build_token_verifier,
    require_any_environment,
    require_environment,
    require_tenant_wide,
)
from asic.api.limits import RequestBoundsMiddleware
from asic.api.rate_limit import RateLimiter
from asic.db.models import (
    ApiIdempotencyRecord,
    Approval,
    AuditRecord,
    ConnectorScopeBinding,
    Environment,
    EvaluationRun,
    EvaluationScenario,
    EvaluationSuiteRun,
    Evidence,
    ExecutionTrace,
    Hypothesis,
    Incident,
    KnowledgeSource,
    PolicyDecision,
    RemediationAction,
    RemediationTarget,
    Service,
    Tenant,
    TimelineEvent,
    ToolDefinition,
    Verification,
)
from asic.db.projections import append_incident_event, apply_transition
from asic.db.session import (
    apply_statement_timeouts,
    bind_tenant,
    create_app_engine,
    session_factory,
)
from asic.domain.clock import SystemClock
from asic.domain.enums import (
    ActorType,
    ApprovalDecision,
    AuditEventType,
    IncidentEventType,
    IncidentStatus,
    TerminationReason,
)
from asic.domain.errors import ApprovalInvalid, IllegalStateTransition
from asic.domain.idempotency import incident_event_key
from asic.domain.permissions import PermissionKey
from asic.evaluation.versioning import digest
from asic.ingestion.contracts import ConnectorContext, IngestionRejected
from asic.ingestion.service import IngestionService
from asic.observability.audit import AuditWriter
from asic.observability.health import ReadinessCache, check_database, evaluate_readiness
from asic.observability.logging import log_event
from asic.observability.setup import render_prometheus
from asic.remediation.approval_service import decide

_logger = logging.getLogger("asic.api")
_meter = otel_metrics.get_meter("asic.api")
api_requests = _meter.create_counter(
    "asic.api.requests", description="API requests, by method, route template and status class."
)
api_request_duration = _meter.create_histogram(
    "asic.api.request.duration",
    unit="s",
    description="API request duration, by method and route template.",
)

INCIDENT_READ = PermissionKey.INCIDENT_READ.value
INCIDENT_CONTROL = PermissionKey.INCIDENT_CONTROL.value
INGEST_WRITE = PermissionKey.INGESTION_WRITE.value
APPROVAL_DECIDE = PermissionKey.REMEDIATION_APPROVE.value
EVALUATION_READ = PermissionKey.EVALUATION_READ.value
ADMIN_READ = PermissionKey.ADMINISTRATION_READ.value
AUDIT_READ = PermissionKey.AUDIT_READ.value
MAX_PAGE_SIZE = 100


#: Characters a human-authored field may not carry: C0 controls other than tab, newline and
#: carriage return; DEL and C1 controls; zero-width, bidi-override and BOM characters. A NUL
#: byte in particular cannot be stored in PostgreSQL text and used to surface as a 500.
_FORBIDDEN_TEXT = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)


def _human_text(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    if _FORBIDDEN_TEXT.search(value):
        raise ValueError("must not contain control or invisible formatting characters")
    return value


#: A justification: bounded, non-blank and free of control characters (newlines are allowed).
Justification = Annotated[str, Field(min_length=1, max_length=4000), AfterValidator(_human_text)]


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: ApprovalDecision
    justification: Justification
    action_version_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ControlBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    justification: Justification


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    return value


def _row(**values: Any) -> dict[str, Any]:
    return {key: _json(value) for key, value in values.items()}


def _request_digest(operation: str, body: BaseModel) -> str:
    value = {"operation": operation, "body": body.model_dump(mode="json")}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _replay(
    session: Session,
    principal: Principal,
    idempotency_key: str,
    operation: str,
    body: BaseModel,
) -> dict[str, Any] | None:
    lock_key = f"{principal.tenant_id}:{principal.user_id}:{idempotency_key}"
    session.execute(
        sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": lock_key}
    )
    existing = session.scalar(
        sa.select(ApiIdempotencyRecord).where(
            ApiIdempotencyRecord.tenant_id == principal.tenant_id,
            ApiIdempotencyRecord.principal_id == principal.user_id,
            ApiIdempotencyRecord.idempotency_key == idempotency_key,
        )
    )
    if existing is None:
        return None
    if existing.operation != operation or existing.request_digest != _request_digest(
        operation, body
    ):
        raise HTTPException(
            409,
            detail={
                "code": "idempotency_conflict",
                "message": "idempotency key was already used for a different request",
            },
        )
    return existing.response_body


def _remember(
    session: Session,
    principal: Principal,
    idempotency_key: str,
    operation: str,
    body: BaseModel,
    response: dict[str, Any],
) -> dict[str, Any]:
    session.add(
        ApiIdempotencyRecord(
            id=uuid.uuid4(),
            tenant_id=principal.tenant_id,
            principal_id=principal.user_id,
            idempotency_key=idempotency_key,
            operation=operation,
            request_digest=_request_digest(operation, body),
            response_body=response,
        )
    )
    session.flush()
    return response


def _cursor(value: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(str(value).encode()).decode().rstrip("=")


MAX_CURSOR_CHARS = 64


def _decode_cursor(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    if len(value) > MAX_CURSOR_CHARS:
        raise HTTPException(400, detail={"code": "invalid_cursor", "message": "invalid cursor"})
    try:
        return uuid.UUID(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode())
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(
            400, detail={"code": "invalid_cursor", "message": "invalid cursor"}
        ) from exc


def _page(items: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    more = len(items) > limit
    shown = items[:limit]
    return {"items": shown, "next_cursor": _cursor(uuid.UUID(shown[-1]["id"])) if more else None}


def _session(request: Request, principal: CurrentPrincipal) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        try:
            bind_tenant(session, principal.tenant_id)
            apply_statement_timeouts(session)
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


DbSession = Annotated[Session, Depends(_session)]


def _visible_incident(session: Session, principal: Principal, incident_id: uuid.UUID) -> Incident:
    incident = session.scalar(
        sa.select(Incident).where(
            Incident.tenant_id == principal.tenant_id, Incident.id == incident_id
        )
    )
    if incident is None or not principal.allows_environment(INCIDENT_READ, incident.environment_id):
        raise HTTPException(404, detail={"code": "not_found", "message": "incident not found"})
    return incident


def _incident_json(item: Incident) -> dict[str, Any]:
    return _row(
        id=item.id,
        reference=item.reference,
        title=item.title,
        environment_id=item.environment_id,
        status=item.status,
        severity=item.severity,
        opened_at=item.opened_at,
        acknowledged_at=item.acknowledged_at,
        terminated_at=item.terminated_at,
        termination_reason=item.termination_reason,
    )


incidents = APIRouter(prefix="/incidents", tags=["incidents"])
approvals = APIRouter(prefix="/approvals", tags=["approvals"])
ingestion = APIRouter(prefix="/ingest", tags=["ingestion"])
evaluation = APIRouter(prefix="/evaluation", tags=["evaluation"])
admin = APIRouter(prefix="/admin", tags=["administration"])


@incidents.get("")
def list_incidents(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_any_environment(principal, INCIDENT_READ)
    statement = sa.select(Incident).where(Incident.tenant_id == principal.tenant_id)
    environments = principal.visible_environments(INCIDENT_READ)
    if environments is not None:
        statement = statement.where(Incident.environment_id.in_(environments))
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(Incident.id > after)
    rows = list(session.scalars(statement.order_by(Incident.id).limit(limit + 1)))
    return _page([_incident_json(item) for item in rows], limit)


@incidents.get("/{incident_id}")
def get_incident(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    return _incident_json(_visible_incident(session, principal, incident_id))


@incidents.get("/{incident_id}/timeline")
def get_timeline(
    incident_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    statement = sa.select(TimelineEvent).where(TimelineEvent.incident_id == incident_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(TimelineEvent.id > after)
    rows = list(session.scalars(statement.order_by(TimelineEvent.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                sequence=x.sequence,
                occurred_at=x.occurred_at,
                category=x.category,
                summary=x.summary,
                source_event_id=x.source_event_id,
                source_evidence_id=x.source_evidence_id,
            )
            for x in rows
        ],
        limit,
    )


@incidents.get("/{incident_id}/evidence")
def get_evidence(
    incident_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    statement = sa.select(Evidence).where(Evidence.incident_id == incident_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(Evidence.id > after)
    rows = list(session.scalars(statement.order_by(Evidence.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                domain=x.domain,
                provenance=x.provenance,
                content=x.content,
                citation=x.citation,
                quality_score=float(x.quality_score) if x.quality_score is not None else None,
                gathered_at=x.gathered_at,
                injection_flagged=x.injection_flagged,
            )
            for x in rows
        ],
        limit,
    )


@incidents.get("/{incident_id}/hypotheses")
def get_hypotheses(
    incident_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    statement = sa.select(Hypothesis).where(Hypothesis.incident_id == incident_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(Hypothesis.id > after)
    rows = list(session.scalars(statement.order_by(Hypothesis.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                rank=x.rank,
                root_cause_class=x.root_cause_class,
                root_cause_ref=x.root_cause_ref,
                statement=x.statement,
                confidence=float(x.confidence),
                confidence_basis=x.confidence_basis,
                status=x.status,
                remaining_gaps=x.remaining_gaps,
            )
            for x in rows
        ],
        limit,
    )


@incidents.get("/{incident_id}/actions")
def get_actions(
    incident_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    statement = sa.select(RemediationAction).where(RemediationAction.incident_id == incident_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(RemediationAction.id > after)
    rows = list(session.scalars(statement.order_by(RemediationAction.id).limit(limit + 1)))
    return _page(_actions_json(session, rows), limit)


@incidents.get("/{incident_id}/trace")
def get_trace(
    incident_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    statement = sa.select(ExecutionTrace).where(ExecutionTrace.incident_id == incident_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(ExecutionTrace.id > after)
    rows = list(session.scalars(statement.order_by(ExecutionTrace.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                trace_id=x.trace_id,
                correlation_id=x.correlation_id,
                started_at=x.started_at,
                completed_at=x.completed_at,
                termination_reason=x.termination_reason,
                total_tokens=x.total_tokens,
                total_cost_usd=float(x.total_cost_usd) if x.total_cost_usd is not None else None,
                total_tool_calls=x.total_tool_calls,
            )
            for x in rows
        ],
        limit,
    )


def _control(
    session: Session,
    principal: Principal,
    incident_id: uuid.UUID,
    body: ControlBody,
    target: IncidentStatus,
    reason: TerminationReason,
    idempotency_key: str,
) -> dict[str, Any]:
    operation = f"incident.{target.value}:{incident_id}"
    incident = _visible_incident(session, principal, incident_id)
    require_environment(principal, INCIDENT_CONTROL, incident.environment_id)
    replay = _replay(session, principal, idempotency_key, operation, body)
    if replay is not None:
        return replay
    try:
        apply_transition(
            session,
            incident=incident,
            target=target,
            actor_type=ActorType.HUMAN,
            source="phase9_api",
            correlation_id=uuid.uuid4(),
            actor_id=str(principal.user_id),
            termination_reason=reason,
            justification=body.justification,
        )
    except IllegalStateTransition as exc:
        raise HTTPException(
            409, detail={"code": "invalid_transition", "message": str(exc)}
        ) from exc
    return _remember(session, principal, idempotency_key, operation, body, _incident_json(incident))


@incidents.post("/{incident_id}/escalate")
def escalate(
    incident_id: uuid.UUID,
    body: ControlBody,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> dict[str, Any]:
    return _control(
        session,
        principal,
        incident_id,
        body,
        IncidentStatus.ESCALATED,
        TerminationReason.HUMAN_ESCALATION,
        idempotency_key,
    )


@incidents.post("/{incident_id}/cancel")
def cancel(
    incident_id: uuid.UUID,
    body: ControlBody,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> dict[str, Any]:
    return _control(
        session,
        principal,
        incident_id,
        body,
        IncidentStatus.ESCALATED,
        TerminationReason.CANCELLED,
        idempotency_key,
    )


@incidents.post("/{incident_id}/annotate")
def annotate(
    incident_id: uuid.UUID,
    body: ControlBody,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> dict[str, Any]:
    incident = _visible_incident(session, principal, incident_id)
    require_environment(principal, INCIDENT_CONTROL, incident.environment_id)
    operation = f"incident.annotate:{incident_id}"
    replay = _replay(session, principal, idempotency_key, operation, body)
    if replay is not None:
        return replay
    result = append_incident_event(
        session,
        incident=incident,
        event_type=IncidentEventType.INCIDENT_ANNOTATED,
        source="phase9_api",
        actor_type=ActorType.HUMAN,
        actor_id=str(principal.user_id),
        correlation_id=uuid.uuid4(),
        payload={"annotation": body.justification},
        idempotency_key=incident_event_key(
            tenant_id=principal.tenant_id,
            incident_id=incident.id,
            event_type=IncidentEventType.INCIDENT_ANNOTATED.value,
            subject_id=principal.user_id,
            occurrence_discriminator=idempotency_key,
        ),
    )
    response = _row(
        id=result.event.id,
        incident_id=incident.id,
        sequence=result.event.sequence,
        annotation=body.justification,
        actor_id=principal.user_id,
        occurred_at=result.event.occurred_at,
    )
    return _remember(session, principal, idempotency_key, operation, body, response)


def _action_json(session: Session, action: RemediationAction) -> dict[str, Any]:
    return _actions_json(session, [action])[0]


def _actions_json(session: Session, actions: list[RemediationAction]) -> list[dict[str, Any]]:
    """Serialize a bounded action page with three batched relation reads."""
    if not actions:
        return []
    action_ids = [action.id for action in actions]
    approvals: dict[uuid.UUID, Approval] = {}
    for approval in session.scalars(
        sa.select(Approval)
        .where(Approval.remediation_action_id.in_(action_ids))
        .order_by(Approval.remediation_action_id, Approval.created_at.desc())
    ):
        approvals.setdefault(approval.remediation_action_id, approval)
    verifications: dict[uuid.UUID, Verification] = {}
    for verification in session.scalars(
        sa.select(Verification)
        .where(Verification.remediation_action_id.in_(action_ids))
        .order_by(Verification.remediation_action_id, Verification.attempt.desc())
    ):
        verifications.setdefault(verification.remediation_action_id, verification)
    policies = {
        policy.remediation_action_id: policy
        for policy in session.scalars(
            sa.select(PolicyDecision).where(PolicyDecision.remediation_action_id.in_(action_ids))
        )
    }
    return [
        _action_row(
            action,
            approval=approvals.get(action.id),
            verification=verifications.get(action.id),
            policy=policies.get(action.id),
        )
        for action in actions
    ]


def _action_row(
    action: RemediationAction,
    *,
    approval: Approval | None,
    verification: Verification | None,
    policy: PolicyDecision | None,
) -> dict[str, Any]:
    return _row(
        id=action.id,
        incident_id=action.incident_id,
        reason=action.reason,
        expected_effect=action.expected_effect,
        risk_tier=action.risk_tier,
        permission_scope=action.permission_scope,
        preconditions=action.preconditions,
        approval_required=action.approval_required,
        timeout_seconds=action.timeout_seconds,
        verification_criteria=action.verification_criteria,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments=action.arguments,
        action_version_hash=action.action_version_hash,
        status=action.status,
        proposed_at=action.proposed_at,
        executed_at=action.executed_at,
        policy_verdict=policy.verdict if policy else None,
        approval=approval.decision.value if approval else None,
        verification=verification.verdict.value if verification else None,
    )


@approvals.get("/pending")
def pending_approvals(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_any_environment(principal, APPROVAL_DECIDE)
    statement = (
        sa.select(RemediationAction)
        .join(
            RemediationTarget,
            sa.and_(
                RemediationTarget.tenant_id == RemediationAction.tenant_id,
                RemediationTarget.id == RemediationAction.remediation_target_id,
            ),
        )
        .where(
            RemediationAction.approval_required.is_(True),
            RemediationAction.status == "awaiting_approval",
        )
        .order_by(RemediationAction.id)
    )
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(RemediationAction.id > after)
    visible_environments = principal.visible_environments(APPROVAL_DECIDE)
    if visible_environments is not None:
        statement = statement.where(RemediationTarget.environment_id.in_(visible_environments))
    rows = list(session.scalars(statement.limit(limit + 1)))
    return _page(_actions_json(session, rows), limit)


def _action_environment(
    session: Session, principal: Principal, action: RemediationAction
) -> uuid.UUID:
    environment = session.scalar(
        sa.select(Environment).where(
            Environment.tenant_id == principal.tenant_id,
            Environment.name == action.permission_scope.get("environment"),
        )
    )
    if environment is None:
        raise HTTPException(
            409,
            detail={
                "code": "invalid_action_scope",
                "message": "action environment is not registered",
            },
        )
    return environment.id


@approvals.get("/{action_id}")
def get_approval(
    action_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    require_any_environment(principal, APPROVAL_DECIDE)
    action = session.scalar(sa.select(RemediationAction).where(RemediationAction.id == action_id))
    if action is None or not principal.allows_environment(
        APPROVAL_DECIDE, _action_environment(session, principal, action)
    ):
        raise HTTPException(404, detail={"code": "not_found", "message": "approval not found"})
    return _action_json(session, action)


@approvals.post("/{action_id}/decide")
def decide_approval(
    action_id: uuid.UUID,
    body: DecisionBody,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> dict[str, Any]:
    operation = f"approval.decide:{action_id}"
    action = session.scalar(sa.select(RemediationAction).where(RemediationAction.id == action_id))
    if action is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "approval not found"})
    require_environment(principal, APPROVAL_DECIDE, _action_environment(session, principal, action))
    replay = _replay(session, principal, idempotency_key, operation, body)
    if replay is not None:
        return replay
    try:
        row = decide(
            session,
            tenant_id=principal.tenant_id,
            action_id=action_id,
            actor_user_id=principal.user_id,
            decision=body.decision,
            expected_action_version_hash=body.action_version_hash,
            justification=body.justification,
            clock=SystemClock(),
        )
    except ApprovalInvalid as exc:
        raise HTTPException(409, detail={"code": "approval_invalid", "message": str(exc)}) from exc
    response = _row(
        id=row.id,
        remediation_action_id=row.remediation_action_id,
        action_version_hash=row.action_version_hash,
        decision=row.decision,
        justification=row.justification,
        approver_user_id=row.approver_user_id,
        decided_at=row.decided_at,
        expires_at=row.expires_at,
    )
    return _remember(session, principal, idempotency_key, operation, body, response)


@ingestion.post("/alerts")
async def ingest_alert(
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    require_any_environment(principal, INGEST_WRITE)
    if idempotency_key is None or not 16 <= len(idempotency_key) <= 128:
        raise HTTPException(
            400,
            detail={"code": "missing_idempotency_key", "message": "Idempotency-Key is required"},
        )
    if not all(
        value is not None
        for value in (
            principal.connector_id,
            principal.source,
            principal.service_id,
            principal.environment_id,
        )
    ):
        raise HTTPException(
            400,
            detail={
                "code": "connector_scope_missing",
                "message": "the signed connector identity must bind source, service and environment",
            },
        )
    environment_id = cast(uuid.UUID, principal.environment_id)
    service_id = cast(uuid.UUID, principal.service_id)
    require_environment(principal, INGEST_WRITE, environment_id)
    environment = session.scalar(
        sa.select(Environment).where(
            Environment.tenant_id == principal.tenant_id,
            Environment.id == environment_id,
        )
    )
    service = session.scalar(
        sa.select(Service).where(
            Service.tenant_id == principal.tenant_id,
            Service.id == service_id,
        )
    )
    if environment is None or service is None or not service.is_active:
        raise HTTPException(
            404, detail={"code": "not_found", "message": "connector target not found"}
        )
    binding_id = session.scalar(
        sa.select(ConnectorScopeBinding.id).where(
            ConnectorScopeBinding.tenant_id == principal.tenant_id,
            ConnectorScopeBinding.connector_id == principal.connector_id,
            ConnectorScopeBinding.source == principal.source,
            ConnectorScopeBinding.service_id == service_id,
            ConnectorScopeBinding.environment_id == environment_id,
            ConnectorScopeBinding.is_enabled.is_(True),
            ConnectorScopeBinding.revoked_at.is_(None),
        )
    )
    if binding_id is None:
        raise HTTPException(
            403,
            detail={
                "code": "connector_scope_denied",
                "message": "connector is not authorized for the requested service/environment",
            },
        )
    raw = await request.body()
    try:
        result = await run_in_threadpool(
            IngestionService(request.app.state.session_factory).ingest,
            ConnectorContext(
                tenant_id=principal.tenant_id,
                connector_id=cast(str, principal.connector_id),
                source=cast(str, principal.source),
                service_id=cast(uuid.UUID, principal.service_id),
                environment_id=cast(uuid.UUID, principal.environment_id),
            ),
            raw,
        )
    except IngestionRejected as exc:
        raise HTTPException(
            400, detail={"code": exc.code, "message": "invalid alert envelope"}
        ) from exc
    return _row(
        receipt_id=result.receipt_id,
        incident_id=result.incident_id,
        alert_id=result.alert_id,
        outcome=result.outcome,
        reason=result.reason,
        duplicate=result.duplicate,
        correlation_id=result.correlation_id,
    )


@ingestion.post("/webhooks/{source}")
async def ingest_webhook(
    source: str,
    request: Request,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    if principal.source != source:
        raise HTTPException(
            404, detail={"code": "not_found", "message": "webhook source not found"}
        )
    return await ingest_alert(request, principal, session, idempotency_key)


def _suite_run_json(item: EvaluationSuiteRun) -> dict[str, Any]:
    return _row(
        id=item.id,
        suite_key=item.suite_key,
        suite_version=item.suite_version,
        execution_mode=item.execution_mode,
        evaluator_version=item.evaluator_version,
        gate_status=item.gate_status,
        scenario_count=item.scenario_count,
        corpus_digest=item.corpus_digest,
        report_digest=item.report_digest,
        baseline_suite_run_id=item.baseline_suite_run_id,
        started_at=item.started_at,
        completed_at=item.completed_at,
    )


# Evaluation results are read-only over the API. Suites are executed by the evaluation gate
# (``python -m asic.evaluation.gate``), never triggered by an API caller. Results span the
# tenant's evaluation environments, so reading them needs tenant-wide authority.


@evaluation.get("/suite-runs")
def list_suite_runs(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, EVALUATION_READ)
    statement = sa.select(EvaluationSuiteRun).where(
        EvaluationSuiteRun.tenant_id == principal.tenant_id
    )
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(EvaluationSuiteRun.id > after)
    rows = list(session.scalars(statement.order_by(EvaluationSuiteRun.id).limit(limit + 1)))
    return _page([_suite_run_json(item) for item in rows], limit)


@evaluation.get("/suite-runs/{suite_run_id}")
def get_suite_run(
    suite_run_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    require_tenant_wide(principal, EVALUATION_READ)
    item = session.scalar(
        sa.select(EvaluationSuiteRun).where(
            EvaluationSuiteRun.tenant_id == principal.tenant_id,
            EvaluationSuiteRun.id == suite_run_id,
        )
    )
    if item is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "suite run not found"})
    # The stored digest is re-checked on read: a report altered after sealing is reported as
    # unverified rather than served as if it were the gate's result.
    return {
        **_suite_run_json(item),
        "report_verified": digest(dict(item.report)) == item.report_digest,
        "report": item.report,
    }


@evaluation.get("/runs")
def list_evaluation_runs(
    principal: CurrentPrincipal,
    session: DbSession,
    suite_run_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, EVALUATION_READ)
    evaluated_trace = (
        sa.select(ExecutionTrace.trace_id)
        .where(
            ExecutionTrace.tenant_id == EvaluationRun.tenant_id,
            ExecutionTrace.workflow_run_id == EvaluationRun.workflow_run_id,
        )
        .order_by(ExecutionTrace.started_at, ExecutionTrace.id)
        .limit(1)
        .correlate(EvaluationRun)
        .scalar_subquery()
    )
    statement = (
        sa.select(EvaluationRun, EvaluationScenario.key, evaluated_trace)
        .join(
            EvaluationScenario,
            sa.and_(
                EvaluationScenario.tenant_id == EvaluationRun.tenant_id,
                EvaluationScenario.id == EvaluationRun.evaluation_scenario_id,
            ),
        )
        .where(EvaluationRun.tenant_id == principal.tenant_id)
    )
    if suite_run_id is not None:
        statement = statement.where(EvaluationRun.suite_run_id == suite_run_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(EvaluationRun.id > after)
    rows = session.execute(statement.order_by(EvaluationRun.id).limit(limit + 1)).all()
    return _page(
        [
            _row(
                id=run.id,
                suite_run_id=run.suite_run_id,
                scenario_key=key,
                scenario_version=run.scenario_version,
                scenario_digest=run.scenario_digest,
                execution_mode=run.execution_mode,
                evaluator_version=run.evaluator_version,
                verdict=run.verdict,
                failure_classes=run.failure_classes,
                metrics=run.metrics,
                workflow_run_id=run.workflow_run_id,
                # Joins this result to the product trace it scored.
                trace_id=trace_id,
            )
            for run, key, trace_id in rows
        ],
        limit,
    )


@admin.get("/tools")
def admin_tools(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, ADMIN_READ)
    statement = sa.select(ToolDefinition)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(ToolDefinition.id > after)
    rows = list(session.scalars(statement.order_by(ToolDefinition.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                name=x.name,
                version=x.version,
                capability=x.capability,
                risk_tier=x.risk_tier,
                enabled=x.is_enabled,
            )
            for x in rows
        ],
        limit,
    )


@admin.get("/policies")
def admin_policies(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, ADMIN_READ)
    statement = sa.select(Environment).where(Environment.tenant_id == principal.tenant_id)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(Environment.id > after)
    rows = list(session.scalars(statement.order_by(Environment.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                environment_id=x.id,
                environment=x.name,
                is_production=x.is_production,
                approval_policy=x.approval_policy,
            )
            for x in rows
        ],
        limit,
    )


@admin.get("/tenants")
def admin_tenants(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, ADMIN_READ)
    tenant = session.scalar(sa.select(Tenant).where(Tenant.id == principal.tenant_id))
    if tenant is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "tenant not found"})
    items = [_row(id=tenant.id, slug=tenant.slug, display_name=tenant.display_name)]
    after = _decode_cursor(cursor)
    if after is not None and tenant.id <= after:
        items = []
    return _page(items, limit)


@admin.get("/services")
def admin_services(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, ADMIN_READ)
    statement = sa.select(Service)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(Service.id > after)
    rows = list(session.scalars(statement.order_by(Service.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                name=x.name,
                display_name=x.display_name,
                owner_team=x.owner_team,
                criticality=x.criticality,
                is_active=x.is_active,
            )
            for x in rows
        ],
        limit,
    )


@admin.get("/knowledge-sources")
def admin_knowledge(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, ADMIN_READ)
    statement = sa.select(KnowledgeSource)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(KnowledgeSource.id > after)
    rows = list(session.scalars(statement.order_by(KnowledgeSource.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                provider=x.provider,
                source_ref=x.source_ref,
                document_type=x.document_type,
                status=x.status,
            )
            for x in rows
        ],
        limit,
    )


@admin.get("/audit")
def admin_audit(
    principal: CurrentPrincipal,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    require_tenant_wide(principal, AUDIT_READ)
    statement = sa.select(AuditRecord)
    after = _decode_cursor(cursor)
    if after is not None:
        statement = statement.where(AuditRecord.id > after)
    rows = list(session.scalars(statement.order_by(AuditRecord.id).limit(limit + 1)))
    return _page(
        [
            _row(
                id=x.id,
                event_type=x.event_type,
                occurred_at=x.occurred_at,
                actor_type=x.actor_type,
                actor_id=x.actor_id,
                incident_id=x.incident_id,
                outcome=x.outcome,
                policy_rule_id=x.policy_rule_id,
                correlation_id=x.correlation_id,
            )
            for x in rows
        ],
        limit,
    )


#: Denials worth a durable audit record. Every denial of a state-changing request, and of the
#: tenant-wide reads that expose configuration, evaluation history or the audit stream itself.
#: Ordinary denied reads (a viewer probing an incident list) are logged, not audited: a
#: durable row per failed GET would turn the audit trail into noise an attacker could fill.
#: Volume is bounded regardless by the per-principal request limiter.
_AUDITED_READ_PERMISSIONS = frozenset(
    {
        PermissionKey.ADMINISTRATION_READ.value,
        PermissionKey.AUDIT_READ.value,
        PermissionKey.EVALUATION_READ.value,
        PermissionKey.REMEDIATION_APPROVE.value,
    }
)


def _record_denial(factory: sessionmaker[Session], request: Request, exc: PermissionDenied) -> None:
    if request.method == "GET" and exc.permission not in _AUDITED_READ_PERMISSIONS:
        return
    principal = exc.principal
    correlation = getattr(request.state, "correlation_id", None)
    try:
        with factory() as session, session.begin():
            bind_tenant(session, principal.tenant_id)
            AuditWriter(tenant_id=principal.tenant_id, clock=SystemClock()).record(
                session,
                event_type=AuditEventType.AUTHORIZATION_DENIED,
                outcome="denied",
                actor_type=ActorType.HUMAN,
                actor_id=str(principal.user_id),
                correlation_id=uuid.UUID(correlation) if correlation else None,
                target_type="permission",
                target_id=exc.permission,
                payload={
                    "method": _method_label(request.method),
                    "route": _route_template(request.scope),
                    # Which authority source was consulted: current database role grants.
                    "authority_source": "rbac",
                },
            )
    except Exception as error:  # an audit failure must never turn a denial into an allow
        log_event(_logger, "audit.denial_write_failed", level=logging.ERROR, error=error)


def create_app(
    *, settings: ApiSettings | None = None, factory: sessionmaker[Session] | None = None
) -> FastAPI:
    resolved_settings = settings or ApiSettings.from_environment()
    resolved_factory = factory or session_factory(create_app_engine())
    # Composition refuses an unsafe production auth configuration here, at startup.
    verifier = build_token_verifier(resolved_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        yield
        if factory is None:
            resolved_factory.kw["bind"].dispose()

    app = FastAPI(title="Autonomous SRE Incident Commander", version="0.13.0", lifespan=lifespan)
    app.state.api_settings = resolved_settings
    app.state.session_factory = resolved_factory
    app.state.token_verifier = verifier
    app.state.rate_limiter = RateLimiter(resolved_settings.rate_limit_per_minute)
    #: Failed-authentication attempts per peer address; deliberately small.
    app.state.auth_failure_limiter = RateLimiter(30)
    readiness = ReadinessCache(lambda: evaluate_readiness([check_database(resolved_factory)]))
    app.add_middleware(RequestBoundsMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=[],
        allow_headers=[],
    )

    @app.middleware("http")
    async def correlation(request: Request, call_next: Any) -> Response:
        supplied = request.headers.get("X-Correlation-ID")
        try:
            correlation_id = str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
        except ValueError:
            return Response(
                content=json.dumps(
                    {
                        "detail": {
                            "code": "invalid_correlation_id",
                            "message": "X-Correlation-ID must be a UUID",
                        }
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        request.state.correlation_id = correlation_id
        tracer = trace.get_tracer("asic.api")
        started = perf_counter()
        status = 500
        method = _method_label(request.method)
        with tracer.start_as_current_span("api.request") as span:
            span.set_attribute("http.request.method", method)
            span.set_attribute("asic.correlation_id", correlation_id)
            try:
                response: Response = await call_next(request)
                status = response.status_code
                response.headers["X-Correlation-ID"] = correlation_id
                return response
            finally:
                # The route *template* (``/api/v1/incidents/{incident_id}``), never the
                # concrete path: identifiers stay out of span names and metric labels.
                route = _route_template(request.scope)
                elapsed = perf_counter() - started
                span.set_attribute("http.route", route)
                span.set_attribute("http.response.status_code", status)
                labels = {"method": method, "route": route}
                api_requests.add(1, {**labels, "status_class": f"{status // 100}xx"})
                api_request_duration.record(elapsed, labels)
                if route not in _PROBE_ROUTES:
                    log_event(
                        _logger,
                        "api.request",
                        level=logging.WARNING if status >= 500 else logging.INFO,
                        method=method,
                        route=route,
                        status=status,
                        duration_ms=round(elapsed * 1000, 3),
                        correlation_id=correlation_id,
                    )

    @app.exception_handler(PermissionDenied)
    async def permission_denied(request: Request, exc: PermissionDenied) -> Response:
        await run_in_threadpool(_record_denial, resolved_factory, request, exc)
        return Response(
            content=json.dumps({"detail": exc.detail}),
            status_code=403,
            media_type="application/json",
        )

    root = APIRouter(prefix="/api/v1")
    for router in (ingestion, incidents, approvals, evaluation, admin):
        root.include_router(router)
    app.include_router(root)

    @app.get("/livez", include_in_schema=False)
    @app.get("/healthz", include_in_schema=False)
    def livez() -> dict[str, str]:
        # Liveness touches nothing external (asic.observability.health).
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> Response:
        result = readiness.get()
        return Response(
            content=json.dumps(result.as_dict()),
            status_code=200 if result.ready else 503,
            media_type="application/json",
        )

    if resolved_settings.metrics_enabled:

        @app.get("/metrics", include_in_schema=False)
        def prometheus_metrics() -> Response:
            body, content_type = render_prometheus()
            return Response(content=body, media_type=content_type)

    return app


_PROBE_ROUTES = frozenset({"/livez", "/healthz", "/readyz", "/metrics"})

#: The request method is caller-supplied: HTTP permits any token, so an unknown method is
#: reported as ``OTHER`` rather than becoming a new label value per request.
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def _method_label(method: str) -> str:
    return method if method in _METHODS else "OTHER"


def _route_template(scope: MutableMapping[str, Any]) -> str:
    """The matched route's full template, e.g. ``/api/v1/incidents/{incident_id}``.

    Rebuilt from the concrete path by replacing whole path-parameter segments with their
    names: nested routers expose only their own relative path. Only a *matched* route has a
    template, so every remaining segment is static text from a route definition, never a
    caller-supplied value. Anything unmatched is reported as ``unmatched``.
    """
    if scope.get("route") is None:
        return "unmatched"
    names = {str(value): name for name, value in (scope.get("path_params") or {}).items()}
    path = str(scope.get("path", ""))
    return "/".join(f"{{{names[part]}}}" if part in names else part for part in path.split("/"))


__all__ = ["ApiSettings", "create_app"]
