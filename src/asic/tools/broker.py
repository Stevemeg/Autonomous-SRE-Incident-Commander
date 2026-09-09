"""The tool broker: the single controlled boundary between orchestration and the world.

Every capability request passes through the same ordered pipeline, and each stage can only
refuse - never widen, never repair, never substitute:

.. code-block:: text

    node
      -> request validation      is the caller a node whose contract declares this?
      -> tenant context          does the bound tenant match the request?
      -> capability resolution   is it registered, granted, and on this run's menu?
      -> risk boundary           is the tier within this deployment's ceiling?
      -> argument validation     typed; scope resolved, never supplied
      -> idempotency             has this exact effect already been recorded?
      -> adapter invocation      with a deadline, and retry classified per operation
      -> result validation       typed; a malformed result is a failure, not a default
      -> audit                   emitted on every path, including refusal
      -> trace                   span with tool, version, scope, outcome, duration

Three properties are load-bearing and are asserted by the test suite rather than assumed.

**It fails closed.** Every stage's error path leads to a refusal. There is no branch that
defaults to allow, and no ``except: pass``.

**A node cannot bypass it.** Nodes receive a broker, never a provider. The registry, the
resolver and the providers are all reachable only from here, and an import-graph test
asserts that no node module imports a provider or a simulator.

**A failure is never a success.** A refused, failed or timed-out call returns a typed
failure carrying the stage that produced it. Nothing in this module can return a
plausible-looking payload in place of one that did not arrive.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from asic.contracts.nodes import NodeContract
from asic.db.models.tools import ToolExecution
from asic.db.session import require_tenant
from asic.domain.clock import Clock
from asic.domain.enums import (
    ActorType,
    AuditEventType,
    BrokerStage,
    NodeId,
    OperationClass,
    ProvenanceLabel,
    RiskTier,
    ToolExecutionOutcome,
    TraceSpanKind,
)
from asic.domain.errors import (
    CapabilityNotGranted,
    DomainError,
    RiskTierNotPermitted,
    SchemaViolation,
    ToolAdapterError,
    ToolFailure,
    ToolTimeout,
    UnregisteredCapability,
)
from asic.domain.idempotency import tool_execution_key
from asic.domain.untrusted import scan_structure
from asic.observability import metrics
from asic.observability.audit import AuditWriter
from asic.observability.redaction import redact_arguments, redact_mapping
from asic.observability.tracing import SpanHandle, TraceRecorder
from asic.tools.capability import (
    CapabilityMenu,
    CapabilityResolver,
    GrantedCapability,
    IncidentScope,
    assert_tenant_matches,
)
from asic.tools.catalogue import RETRIEVED_DOMAINS, capability_for_domain
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ToolProvider


class CapabilityRequest(BaseModel):
    """What a node asks the broker for.

    Note what this type *cannot* carry: no tool name, no credential, no query string, no
    tenant override, no scope override, and no free text destined for an authorization
    decision. A node names a capability and a service already in the incident's scope, and
    supplies the non-scope arguments the descriptor declares. Everything else is resolved.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    node_id: NodeId
    capability: str
    #: Must be one of the incident's own services. Narrowing within an existing bound.
    service_name: str
    arguments: Mapping[str, Any] = Field(default_factory=dict)
    incident_id: uuid.UUID
    correlation_id: uuid.UUID
    investigation_step_id: uuid.UUID | None = None
    #: Why the call is being made. Recorded for audit; never consulted for authorization.
    purpose: str = ""


@dataclass(frozen=True, slots=True)
class BrokerFailure:
    """A refusal or failure, with the stage that produced it."""

    stage: BrokerStage
    error_type: str
    message: str
    operation_class: OperationClass
    retryable: bool


class ToolResult(BaseModel):
    """The outcome of one capability request. Success and failure share one type."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    request: CapabilityRequest
    tool_name: str
    tool_version: str
    capability: str
    risk_tier: RiskTier
    outcome: ToolExecutionOutcome
    #: Only the broker assigns provenance. A node cannot label its own output a verified
    #: fact (cross-cutting node contract, docs/architecture/agent-topology.md section 6).
    provenance: ProvenanceLabel
    payload: Mapping[str, Any] = Field(default_factory=dict)
    citation: Mapping[str, Any] = Field(default_factory=dict)
    resolved_scope: Mapping[str, Any] = Field(default_factory=dict)
    tool_execution_id: uuid.UUID | None = None
    duration_ms: int = 0
    attempts: int = 0
    #: True when an identical effect was already recorded and no adapter call was made.
    deduplicated: bool = False
    injection_flags: tuple[str, ...] = ()
    failure: BrokerFailure | None = None

    @property
    def succeeded(self) -> bool:
        return self.outcome is ToolExecutionOutcome.SUCCEEDED and self.failure is None


class ToolBroker:
    """The sole egress point. Constructed once per run, per tenant."""

    __slots__ = (
        "_audit",
        "_clock",
        "_executor",
        "_menus",
        "_providers",
        "_resolver",
        "_scope",
        "_sleep",
        "_tracer",
    )

    def __init__(
        self,
        *,
        resolver: CapabilityResolver,
        providers: Sequence[ToolProvider],
        scope: IncidentScope,
        audit: AuditWriter,
        tracer: TraceRecorder,
        clock: Clock,
        sleep: Any = time.sleep,
    ) -> None:
        if not providers:
            raise ValueError("a broker with no provider can refuse but never answer")
        self._resolver = resolver
        self._providers = tuple(providers)
        self._scope = scope
        self._audit = audit
        self._tracer = tracer
        self._clock = clock
        self._sleep = sleep
        self._menus: dict[NodeId, CapabilityMenu] = {}
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="asic-tool")

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ capability menu

    def menu_for(
        self, session: Session, contract: NodeContract, *, refresh: bool = False
    ) -> CapabilityMenu:
        """Resolve (and cache for this run) the menu offered to one node.

        Cached per node because it is stable for the run: the grants and the catalogue do
        not change mid-incident, and re-resolving on every call would make an already
        chatty path chattier. ``refresh`` exists for the tests that revoke a grant and
        assert the revocation takes effect.
        """
        if refresh or contract.node_id not in self._menus:
            self._menus[contract.node_id] = self._resolver.resolve(
                session, scope=self._scope, contract=contract
            )
        return self._menus[contract.node_id]

    # ------------------------------------------------------------------------- invoke

    def invoke(
        self,
        session: Session,
        *,
        request: CapabilityRequest,
        contract: NodeContract,
    ) -> ToolResult:
        """Run one capability request through the full pipeline.

        Never raises for a refusal or a tool failure - those are outcomes and are returned
        as a typed :class:`ToolResult`, because a node must be able to degrade rather than
        abort. Programming errors still raise.
        """
        started = self._clock.now()
        with self._tracer.span(
            kind=TraceSpanKind.TOOL_INVOKE,
            name=f"tool.invoke {request.capability}",
            node_id=request.node_id,
            node_version=contract.node_version,
            input_refs={
                "capability": request.capability,
                "service": request.service_name,
                "incident_id": str(request.incident_id),
            },
        ) as span:
            try:
                granted = self._authorize(session, request, contract)
            except DomainError as exc:
                failure = _classify_refusal(stage_of(exc), exc)
                span.fail(failure.message)
                span.set_attributes(refused_at=failure.stage.value, error=failure.error_type)
                self._audit_refusal(session, request, failure)
                metrics.tool_refusals_total.add(1, {"stage": failure.stage.value})
                return self._refused(request, failure)

            descriptor = granted.descriptor
            resolved_scope = self._scope.resolve_arguments(
                descriptor, service_name=request.service_name
            )
            try:
                bound = descriptor.bind_arguments(request.arguments, resolved_scope)
            except SchemaViolation as exc:
                failure = BrokerFailure(
                    stage=BrokerStage.ARGUMENT_VALIDATION,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
                    retryable=False,
                )
                span.fail(failure.message)
                self._audit_refusal(session, request, failure)
                metrics.tool_refusals_total.add(1, {"stage": failure.stage.value})
                metrics.schema_violations_total.add(1, {"node": request.node_id.value})
                return self._refused(request, failure)

            key = tool_execution_key(
                tenant_id=self._scope.tenant_id,
                tool_name=descriptor.name,
                tool_major_version=descriptor.major_version,
                scope_arguments={
                    name: _key_safe(value)
                    for name, value in sorted(bound.items())
                    if name in descriptor.idempotency_key_fields
                },
            )

            recorded = self._recorded_execution(session, key)
            if recorded is not None:
                span.set_attributes(deduplicated=True, idempotency_key=key)
                span.tool_execution_id = recorded.id
                return self._from_recorded(request, descriptor, recorded, resolved_scope)

            return self._dispatch(
                session,
                request=request,
                contract=contract,
                descriptor=descriptor,
                granted_credential_ref=granted.credential_ref,
                bound=bound,
                resolved_scope=resolved_scope,
                idempotency_key=key,
                started=started,
                span=span,
            )

    # --------------------------------------------------------------------- pipeline

    def _authorize(
        self,
        session: Session,
        request: CapabilityRequest,
        contract: NodeContract,
    ) -> GrantedCapability:
        """Stages 1-4. Returns the granted capability, or raises the refusal."""
        # 1. Request validation: does the calling node's contract declare this capability?
        if not contract.permits_capability(request.capability):
            raise CapabilityNotGranted(
                f"node {request.node_id.value} requested {request.capability!r}, which its "
                f"contract {contract.contract_version} does not declare. A node's reach is "
                "fixed by its contract, not by what it asks for."
            )

        # 2. Tenant context: taken from the bound session, then compared with the scope.
        bound_tenant = require_tenant(session)
        assert_tenant_matches(bound_tenant, self._scope.tenant_id)
        if request.incident_id != self._scope.incident_id:
            raise CapabilityNotGranted(
                f"request names incident {request.incident_id} but this broker is scoped to "
                f"{self._scope.incident_id}; a broker serves exactly one incident"
            )

        # 3. Capability resolution against tenant, environment and grant.
        menu = self.menu_for(session, contract)
        granted = menu.get(request.capability)
        descriptor = granted.descriptor
        if not descriptor.is_enabled:
            raise CapabilityNotGranted(f"{descriptor.name} is disabled in the registry")

        # 4. Risk boundary, re-checked immediately before dispatch rather than trusted
        #    from menu-resolution time.
        self._resolver.assert_tier_permitted(descriptor)
        return granted

    def _recorded_execution(self, session: Session, key: str) -> ToolExecution | None:
        return session.execute(
            sa.select(ToolExecution).where(
                ToolExecution.tenant_id == self._scope.tenant_id,
                ToolExecution.idempotency_key == key,
            )
        ).scalar_one_or_none()

    def _provider_for(self, descriptor: ToolDescriptor) -> ToolProvider:
        for provider in self._providers:
            if provider.supports(descriptor):
                return provider
        raise UnregisteredCapability(
            f"no provider implements {descriptor.name}; the registry describes it but "
            "nothing can execute it"
        )

    def _dispatch(
        self,
        session: Session,
        *,
        request: CapabilityRequest,
        contract: NodeContract,
        descriptor: ToolDescriptor,
        granted_credential_ref: str | None,
        bound: Mapping[str, Any],
        resolved_scope: Mapping[str, Any],
        idempotency_key: str,
        started: datetime,
        span: SpanHandle,
    ) -> ToolResult:
        """Stages 7-10: invoke, validate, persist, audit."""
        provider = self._provider_for(descriptor)
        attempts = 0
        failure: BrokerFailure | None = None
        payload: Mapping[str, Any] = {}
        began = time.perf_counter()

        while attempts < descriptor.max_attempts:
            attempts += 1
            context = InvocationContext(
                tenant_id=self._scope.tenant_id,
                correlation_id=request.correlation_id,
                idempotency_key=idempotency_key,
                credential_ref=granted_credential_ref,
                timeout_seconds=descriptor.timeout_seconds,
                attempt=attempts,
            )
            try:
                raw = self._invoke_with_deadline(provider, descriptor, bound, context)
                payload = descriptor.validate_result(raw)
                failure = None
                break
            except ToolTimeout as exc:
                failure = BrokerFailure(
                    stage=BrokerStage.ADAPTER_INVOCATION,
                    error_type="ToolTimeout",
                    message=str(exc),
                    # A read has no effect, so a read timeout is known-clean rather than
                    # unknown. Only a write timeout needs reconciliation.
                    operation_class=OperationClass.C1_PURE_READ,
                    retryable=True,
                )
            except ToolAdapterError as exc:
                failure = BrokerFailure(
                    stage=BrokerStage.ADAPTER_INVOCATION,
                    error_type="ToolAdapterError",
                    message=str(exc),
                    operation_class=(
                        OperationClass.C1_PURE_READ
                        if exc.transient
                        else OperationClass.C5_SEMANTIC_FAILURE
                    ),
                    retryable=exc.transient,
                )
            except SchemaViolation as exc:
                # A malformed result is never retried: the adapter will produce the same
                # shape again, and a "repaired" result would be data we invented.
                failure = BrokerFailure(
                    stage=BrokerStage.RESULT_VALIDATION,
                    error_type="SchemaViolation",
                    message=str(exc),
                    operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
                    retryable=False,
                )
                metrics.schema_violations_total.add(1, {"tool": descriptor.name})
                break
            except ToolFailure as exc:  # pragma: no cover - defensive; subclasses above
                failure = BrokerFailure(
                    stage=BrokerStage.ADAPTER_INVOCATION,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    operation_class=OperationClass.C5_SEMANTIC_FAILURE,
                    retryable=False,
                )
                break

            if not (failure and failure.retryable and attempts < descriptor.max_attempts):
                break
            self._sleep(descriptor.retry_backoff_seconds * attempts)

        duration_ms = max(0, int((time.perf_counter() - began) * 1000))
        outcome = (
            ToolExecutionOutcome.SUCCEEDED if failure is None else ToolExecutionOutcome.FAILED_CLEAN
        )
        injection_flags = scan_structure(payload) if failure is None else ()

        execution = ToolExecution(
            tenant_id=self._scope.tenant_id,
            incident_id=request.incident_id,
            investigation_step_id=request.investigation_step_id,
            remediation_action_id=None,
            tool_definition_id=self._tool_definition_id(session, descriptor),
            tool_name=descriptor.name,
            tool_version=descriptor.version,
            capability=descriptor.capability,
            risk_tier=descriptor.risk_tier,
            resolved_scope=redact_mapping(dict(resolved_scope)),
            arguments_redacted=redact_arguments(bound),
            idempotency_key=idempotency_key,
            actor_type=ActorType.AGENT_NODE,
            requested_by_node=request.node_id,
            attempt=attempts,
            outcome=outcome,
            observed_effect=_result_summary(payload) if failure is None else {},
            failure_reason=failure.message if failure else None,
            started_at=started,
            completed_at=self._clock.now(),
            duration_ms=duration_ms,
            correlation_id=request.correlation_id,
        )
        session.add(execution)
        session.flush()

        span.tool_execution_id = execution.id
        span.set_attributes(
            tool_name=descriptor.name,
            tool_version=descriptor.version,
            capability=descriptor.capability,
            risk_tier=descriptor.risk_tier.value,
            idempotency_key=idempotency_key,
            attempts=attempts,
            outcome=outcome.value,
            injection_flags=list(injection_flags),
        )
        if failure is not None:
            span.fail(failure.message)

        self._audit.record(
            session,
            event_type=AuditEventType.TOOL_EXECUTED,
            outcome="succeeded" if failure is None else "failed",
            actor_type=ActorType.AGENT_NODE,
            actor_id=request.node_id.value,
            incident_id=request.incident_id,
            tool_execution_id=execution.id,
            correlation_id=request.correlation_id,
            target_type="tool_definition",
            target_id=f"{descriptor.name}@{descriptor.version}",
            risk_tier=descriptor.risk_tier,
            payload={
                "capability": descriptor.capability,
                "resolved_scope": dict(resolved_scope),
                "arguments": dict(bound),
                "attempts": attempts,
                "duration_ms": duration_ms,
                "failure": failure.message if failure else None,
                "purpose": request.purpose,
                "node_contract_version": contract.contract_version,
            },
        )

        metrics.tool_invocations_total.add(1, {"tool": descriptor.name, "outcome": outcome.value})
        metrics.tool_latency_seconds.record(duration_ms / 1000.0, {"tool": descriptor.name})
        if failure is not None:
            metrics.tool_failures_total.add(
                1, {"tool": descriptor.name, "reason": failure.error_type}
            )
        for flag in injection_flags:
            metrics.injection_flags_total.add(1, {"source": descriptor.capability, "pattern": flag})

        return ToolResult(
            request=request,
            tool_name=descriptor.name,
            tool_version=descriptor.version,
            capability=descriptor.capability,
            risk_tier=descriptor.risk_tier,
            outcome=outcome,
            provenance=self._provenance_for(descriptor),
            payload=payload if failure is None else {},
            citation=self._citation(descriptor, bound, resolved_scope, payload),
            resolved_scope=dict(resolved_scope),
            tool_execution_id=execution.id,
            duration_ms=duration_ms,
            attempts=attempts,
            injection_flags=injection_flags,
            failure=failure,
        )

    def _invoke_with_deadline(
        self,
        provider: ToolProvider,
        descriptor: ToolDescriptor,
        bound: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        """Call the adapter, giving up at the declared deadline.

        The call runs on a worker thread so that the deadline is enforced *for the caller*
        even when an adapter blocks. The abandoned thread may still complete - which is
        exactly why a write timeout is an unknown outcome to be reconciled rather than a
        failure to be retried. Every tool here is read-only, so an abandoned read has no
        effect to reconcile.
        """
        future = self._executor.submit(provider.invoke, descriptor, bound, context)
        try:
            return future.result(timeout=descriptor.timeout_seconds)
        except FutureTimeout as exc:
            future.cancel()
            raise ToolTimeout(
                f"{descriptor.name} did not answer within {descriptor.timeout_seconds}s"
            ) from exc

    def _tool_definition_id(self, session: Session, descriptor: ToolDescriptor) -> uuid.UUID:
        # Joined through the resolver's registry so there is one source of the
        # code-to-database mapping rather than a second copy that could drift.
        joined = self._resolver.registry.assert_matches_database(session)
        return joined[descriptor.name].tool_definition_id

    @staticmethod
    def _provenance_for(descriptor: ToolDescriptor) -> ProvenanceLabel:
        """Assign provenance. Only the broker may hand out ``VERIFIED_FACT``.

        A telemetry query result is a verified fact: we issued the query and recorded the
        answer. A knowledge-base document is ``RETRIEVED``: it is someone's prose, citable
        but never authoritative, and never able to influence an authorization decision.
        """
        domains = {capability_for_domain(d): d for d in RETRIEVED_DOMAINS}
        if descriptor.capability in domains:
            return ProvenanceLabel.RETRIEVED
        return ProvenanceLabel.VERIFIED_FACT

    def _citation(
        self,
        descriptor: ToolDescriptor,
        bound: Mapping[str, Any],
        resolved_scope: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Everything a human needs to re-derive this result independently (FR-EVD-02)."""
        return {
            "tool": descriptor.name,
            "tool_version": descriptor.version,
            "capability": descriptor.capability,
            "source": str(payload.get("source", "unknown")),
            "schema_version": payload.get("schema_version"),
            "scope": redact_mapping(dict(resolved_scope)),
            "arguments": redact_arguments(bound),
            "queried_at": self._clock.now().isoformat(),
        }

    def _from_recorded(
        self,
        request: CapabilityRequest,
        descriptor: ToolDescriptor,
        recorded: ToolExecution,
        resolved_scope: Mapping[str, Any],
    ) -> ToolResult:
        """Return a previously recorded effect instead of invoking again.

        The honest limitation, stated plainly: ``observed_effect`` is a *summary* of the
        original result, not the result itself, because storing full payloads twice would
        duplicate evidence content into the execution log. A resumed run therefore learns
        that the call already happened and which evidence it produced, and reads the
        evidence rows rather than re-deriving them from this record.
        """
        return ToolResult(
            request=request,
            tool_name=recorded.tool_name,
            tool_version=recorded.tool_version,
            capability=recorded.capability,
            risk_tier=recorded.risk_tier,
            outcome=recorded.outcome or ToolExecutionOutcome.SUCCEEDED,
            provenance=self._provenance_for(descriptor),
            payload={},
            citation={"tool": recorded.tool_name, "replayed_from": str(recorded.id)},
            resolved_scope=dict(resolved_scope),
            tool_execution_id=recorded.id,
            duration_ms=recorded.duration_ms or 0,
            attempts=recorded.attempt,
            deduplicated=True,
            failure=None,
        )

    def _audit_refusal(
        self, session: Session, request: CapabilityRequest, failure: BrokerFailure
    ) -> None:
        self._audit.record(
            session,
            event_type=AuditEventType.TOOL_AUTHORIZATION_EVALUATED,
            outcome="denied",
            actor_type=ActorType.AGENT_NODE,
            actor_id=request.node_id.value,
            incident_id=request.incident_id,
            correlation_id=request.correlation_id,
            target_type="capability",
            target_id=request.capability,
            policy_rule_id=failure.stage.value,
            payload={
                "stage": failure.stage.value,
                "error_type": failure.error_type,
                "message": failure.message,
                "service": request.service_name,
                "purpose": request.purpose,
            },
        )

    @staticmethod
    def _refused(request: CapabilityRequest, failure: BrokerFailure) -> ToolResult:
        return ToolResult(
            request=request,
            tool_name="",
            tool_version="",
            capability=request.capability,
            risk_tier=RiskTier.RO,
            outcome=ToolExecutionOutcome.PRECONDITION_FAILED,
            provenance=ProvenanceLabel.SYSTEM,
            payload={},
            failure=failure,
        )


def stage_of(exc: DomainError) -> BrokerStage:
    """Which pipeline stage a refusal came from."""
    if isinstance(exc, RiskTierNotPermitted):
        return BrokerStage.RISK_BOUNDARY
    if isinstance(exc, UnregisteredCapability):
        return BrokerStage.CAPABILITY_RESOLUTION
    if isinstance(exc, CapabilityNotGranted):
        return BrokerStage.CAPABILITY_RESOLUTION
    if isinstance(exc, SchemaViolation):
        return BrokerStage.ARGUMENT_VALIDATION
    return BrokerStage.TENANT_CONTEXT


def _classify_refusal(stage: BrokerStage, exc: DomainError) -> BrokerFailure:
    return BrokerFailure(
        stage=stage,
        error_type=type(exc).__name__,
        message=str(exc),
        operation_class=OperationClass.C6_DETERMINISTIC_REJECTION,
        retryable=False,
    )


def _key_safe(value: Any) -> Any:
    """Render a bound argument into something the idempotency digest accepts."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _result_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    """A bounded summary of a result for ``tool_execution.observed_effect``.

    Counts and provenance, not content: the content belongs on the evidence row, once,
    where retention and tenancy already apply to it.
    """
    summary: dict[str, Any] = {
        "source": str(payload.get("source", "unknown")),
        "schema_version": payload.get("schema_version"),
    }
    for key, value in payload.items():
        if isinstance(value, (list, tuple)):
            summary[f"{key}_count"] = len(value)
    return summary


__all__ = [
    "BrokerFailure",
    "CapabilityRequest",
    "ToolBroker",
    "ToolResult",
]
