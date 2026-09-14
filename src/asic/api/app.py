"""Versioned FastAPI edge for the five independently authorized Phase 9 surfaces."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, cast

import sqlalchemy as sa
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from asic.api.auth import ApiSettings, CurrentPrincipal, Principal, require
from asic.api.rate_limit import RateLimiter
from asic.db.models import (
    ApiIdempotencyRecord,
    Approval,
    AuditRecord,
    Environment,
    Evidence,
    ExecutionTrace,
    Hypothesis,
    Incident,
    KnowledgeSource,
    PolicyDecision,
    RemediationAction,
    Service,
    TimelineEvent,
    ToolDefinition,
    Verification,
)
from asic.db.projections import apply_transition
from asic.db.session import (
    apply_statement_timeouts,
    bind_tenant,
    create_app_engine,
    session_factory,
)
from asic.domain.clock import SystemClock
from asic.domain.enums import ActorType, ApprovalDecision, IncidentStatus, TerminationReason
from asic.domain.errors import ApprovalInvalid, IllegalStateTransition
from asic.ingestion.contracts import ConnectorContext, IngestionRejected
from asic.ingestion.service import IngestionService
from asic.remediation.approval_service import decide

INCIDENT_READ = "incident.read"
INCIDENT_CONTROL = "incident.control"
INGEST_WRITE = "ingestion.write"
APPROVAL_DECIDE = "remediation.approve"
EVALUATION_READ = "evaluation.read"
ADMIN_READ = "administration.read"
AUDIT_READ = "audit.read"
MAX_PAGE_SIZE = 100


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: ApprovalDecision
    justification: str = Field(min_length=1, max_length=4000)
    action_version_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ControlBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    justification: str = Field(min_length=1, max_length=4000)


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


def _decode_cursor(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
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
    if incident is None or not principal.allows(INCIDENT_READ, incident.environment_id):
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
    require(principal, INCIDENT_READ)
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
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    rows = session.scalars(
        sa.select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.sequence)
    )
    return {
        "items": [
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
        ]
    }


@incidents.get("/{incident_id}/evidence")
def get_evidence(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    rows = session.scalars(
        sa.select(Evidence)
        .where(Evidence.incident_id == incident_id)
        .order_by(Evidence.gathered_at, Evidence.id)
    )
    return {
        "items": [
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
        ]
    }


@incidents.get("/{incident_id}/hypotheses")
def get_hypotheses(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    rows = session.scalars(
        sa.select(Hypothesis)
        .where(Hypothesis.incident_id == incident_id)
        .order_by(Hypothesis.rank, Hypothesis.id)
    )
    return {
        "items": [
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
        ]
    }


@incidents.get("/{incident_id}/actions")
def get_actions(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    rows = session.scalars(
        sa.select(RemediationAction)
        .where(RemediationAction.incident_id == incident_id)
        .order_by(RemediationAction.proposed_at, RemediationAction.id)
    )
    return {"items": [_action_json(session, x) for x in rows]}


@incidents.get("/{incident_id}/trace")
def get_trace(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict[str, Any]:
    _visible_incident(session, principal, incident_id)
    rows = session.scalars(
        sa.select(ExecutionTrace)
        .where(ExecutionTrace.incident_id == incident_id)
        .order_by(ExecutionTrace.started_at, ExecutionTrace.id)
    )
    return {
        "items": [
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
        ]
    }


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
    replay = _replay(session, principal, idempotency_key, operation, body)
    if replay is not None:
        return replay
    incident = _visible_incident(session, principal, incident_id)
    require(principal, INCIDENT_CONTROL, incident.environment_id)
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


@incidents.post("/{incident_id}/annotate", status_code=501)
def annotate(
    incident_id: uuid.UUID,
    body: ControlBody,
    principal: CurrentPrincipal,
    session: DbSession,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)],
) -> None:
    del body, idempotency_key
    incident = _visible_incident(session, principal, incident_id)
    require(principal, INCIDENT_CONTROL, incident.environment_id)
    raise HTTPException(
        501,
        detail={
            "code": "deferred",
            "message": "operator annotations require a canonical event type deferred beyond Phase 9",
        },
    )


def _action_json(session: Session, action: RemediationAction) -> dict[str, Any]:
    approval = session.scalar(
        sa.select(Approval)
        .where(Approval.remediation_action_id == action.id)
        .order_by(Approval.created_at.desc())
        .limit(1)
    )
    verification = session.scalar(
        sa.select(Verification)
        .where(Verification.remediation_action_id == action.id)
        .order_by(Verification.attempt.desc())
        .limit(1)
    )
    policy = session.scalar(
        sa.select(PolicyDecision).where(PolicyDecision.remediation_action_id == action.id)
    )
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
def pending_approvals(principal: CurrentPrincipal, session: DbSession) -> dict[str, Any]:
    require(principal, APPROVAL_DECIDE)
    rows = session.scalars(
        sa.select(RemediationAction)
        .where(
            RemediationAction.approval_required.is_(True),
            RemediationAction.status == "awaiting_approval",
        )
        .order_by(RemediationAction.proposed_at, RemediationAction.id)
    )
    return {
        "items": [
            _action_json(session, x)
            for x in rows
            if principal.allows(APPROVAL_DECIDE, _action_environment(session, principal, x))
        ]
    }


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
    require(principal, APPROVAL_DECIDE)
    action = session.scalar(sa.select(RemediationAction).where(RemediationAction.id == action_id))
    if action is None or not principal.allows(
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
    require(principal, APPROVAL_DECIDE)
    operation = f"approval.decide:{action_id}"
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
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    require(principal, INGEST_WRITE)
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
    try:
        result = IngestionService(request.app.state.session_factory).ingest(
            ConnectorContext(
                tenant_id=principal.tenant_id,
                connector_id=cast(str, principal.connector_id),
                source=cast(str, principal.source),
                service_id=cast(uuid.UUID, principal.service_id),
                environment_id=cast(uuid.UUID, principal.environment_id),
            ),
            await request.body(),
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
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    require(principal, INGEST_WRITE)
    if principal.source != source:
        raise HTTPException(
            404, detail={"code": "not_found", "message": "webhook source not found"}
        )
    return await ingest_alert(request, principal, idempotency_key)


@evaluation.api_route("/{path:path}", methods=["GET", "POST"], status_code=501)
def evaluation_deferred(path: str, principal: CurrentPrincipal) -> None:
    del path
    require(principal, EVALUATION_READ)
    raise HTTPException(
        501, detail={"code": "deferred", "message": "evaluation and replay execution are Phase 11"}
    )


@admin.get("/tools")
def admin_tools(principal: CurrentPrincipal, session: DbSession) -> dict[str, Any]:
    require(principal, ADMIN_READ)
    rows = session.scalars(
        sa.select(ToolDefinition).order_by(ToolDefinition.name, ToolDefinition.version)
    )
    return {
        "items": [
            _row(
                id=x.id,
                name=x.name,
                version=x.version,
                capability=x.capability,
                risk_tier=x.risk_tier,
                enabled=x.is_enabled,
            )
            for x in rows
        ]
    }


@admin.get("/services")
def admin_services(principal: CurrentPrincipal, session: DbSession) -> dict[str, Any]:
    require(principal, ADMIN_READ)
    rows = session.scalars(sa.select(Service).order_by(Service.name))
    return {
        "items": [
            _row(
                id=x.id,
                name=x.name,
                display_name=x.display_name,
                owner_team=x.owner_team,
                criticality=x.criticality,
                is_active=x.is_active,
            )
            for x in rows
        ]
    }


@admin.get("/knowledge-sources")
def admin_knowledge(principal: CurrentPrincipal, session: DbSession) -> dict[str, Any]:
    require(principal, ADMIN_READ)
    rows = session.scalars(
        sa.select(KnowledgeSource).order_by(KnowledgeSource.provider, KnowledgeSource.source_ref)
    )
    return {
        "items": [
            _row(
                id=x.id,
                provider=x.provider,
                source_ref=x.source_ref,
                document_type=x.document_type,
                status=x.status,
            )
            for x in rows
        ]
    }


@admin.get("/audit")
def admin_audit(principal: CurrentPrincipal, session: DbSession) -> dict[str, Any]:
    require(principal, AUDIT_READ)
    rows = session.scalars(
        sa.select(AuditRecord).order_by(AuditRecord.occurred_at.desc()).limit(MAX_PAGE_SIZE)
    )
    return {
        "items": [
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
        ]
    }


def create_app(
    *, settings: ApiSettings | None = None, factory: sessionmaker[Session] | None = None
) -> FastAPI:
    resolved_settings = settings or ApiSettings.from_environment()
    resolved_factory = factory or session_factory(create_app_engine())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        yield
        if factory is None:
            resolved_factory.kw["bind"].dispose()

    app = FastAPI(title="Autonomous SRE Incident Commander", version="0.9.0", lifespan=lifespan)
    app.state.api_settings = resolved_settings
    app.state.session_factory = resolved_factory
    app.state.rate_limiter = RateLimiter(resolved_settings.rate_limit_per_minute)
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
        tracer = trace.get_tracer("asic.api")
        with tracer.start_as_current_span("api.request") as span:
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("http.request.path", request.url.path)
            span.set_attribute("asic.correlation_id", correlation_id)
            response: Response = await call_next(request)
            span.set_attribute("http.response.status_code", response.status_code)
            response.headers["X-Correlation-ID"] = correlation_id
            return response

    root = APIRouter(prefix="/api/v1")
    for router in (ingestion, incidents, approvals, evaluation, admin):
        root.include_router(router)
    app.include_router(root)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


__all__ = ["ApiSettings", "create_app"]
