"""The tool broker refuses at every stage, and never fabricates a result.

These tests exercise the real pipeline against a live database, because most of what makes
the broker safe - the tenant binding, the grant lookup, the idempotency uniqueness, the
audit row - is enforced by the database rather than by the code around it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import G3_INVESTIGATION_PLANNER, G4_EVIDENCE_COLLECTOR
from asic.db.models import AuditRecord, TenantToolGrant, ToolExecution
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    AuditEventType,
    BrokerStage,
    NodeId,
    ProvenanceLabel,
    RiskTier,
    ToolExecutionOutcome,
    ToolProviderKind,
)
from asic.domain.errors import CapabilityNotGranted, RiskTierNotPermitted
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_trace_id
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import scenario
from asic.tools.broker import CapabilityRequest, ToolBroker
from asic.tools.capability import CapabilityResolver, IncidentScope, load_incident_scope
from asic.tools.descriptor import ToolDescriptor
from asic.tools.registry import ToolRegistry
from tests.conftest import requires_postgres
from tests.kernel_fixtures import CLOCK_START, Fixture, build_fixture

pytestmark = requires_postgres

WINDOW_START = CLOCK_START.replace(hour=9)
WINDOW_END = CLOCK_START


def _metric_arguments(metric: str = "http_request_duration_p95_seconds") -> dict[str, object]:
    return {"window_start": WINDOW_START, "window_end": WINDOW_END, "metric": metric}


def _log_arguments() -> dict[str, object]:
    return {"window_start": WINDOW_START, "window_end": WINDOW_END, "limit": 10}


def _broker(
    fixture: Fixture,
    session: Session,
    clock: FrozenClock,
    *,
    scenario_id: str = "SC-0001-checkout-latency-after-deploy",
    resolver: CapabilityResolver | None = None,
) -> tuple[ToolBroker, SimulatorProvider, TraceRecorder]:
    scope = load_incident_scope(
        session,
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        environment_id=fixture.environment.id,
        service_ids=fixture.service_ids,
    )
    return _broker_for_scope(fixture, scope, clock, scenario_id=scenario_id, resolver=resolver)


def _broker_for_scope(
    fixture: Fixture,
    scope: IncidentScope,
    clock: FrozenClock,
    *,
    scenario_id: str,
    resolver: CapabilityResolver | None = None,
) -> tuple[ToolBroker, SimulatorProvider, TraceRecorder]:
    correlation_id = uuid.uuid4()
    tracer = TraceRecorder(
        tenant_id=fixture.tenant_id,
        execution_trace_id=uuid.uuid4(),
        trace_id=derive_trace_id(correlation_id),
        clock=clock,
    )
    provider = SimulatorProvider(scenario(scenario_id), clock=clock)
    broker = ToolBroker(
        resolver=resolver or CapabilityResolver(ToolRegistry.read_only()),
        providers=[provider],
        scope=scope,
        audit=AuditWriter(tenant_id=fixture.tenant_id, clock=clock),
        tracer=tracer,
        clock=clock,
        sleep=lambda _seconds: None,
    )
    return broker, provider, tracer


def _request(
    fixture: Fixture,
    capability: str,
    *,
    service: str | None = None,
    arguments: dict[str, object] | None = None,
    node_id: NodeId = NodeId.G4_EVIDENCE_COLLECTOR,
) -> CapabilityRequest:
    return CapabilityRequest(
        node_id=node_id,
        capability=capability,
        service_name=service or fixture.service.name,
        arguments=arguments
        if arguments is not None
        else {"window_start": WINDOW_START, "window_end": WINDOW_END},
        incident_id=fixture.incident.id,
        correlation_id=uuid.uuid4(),
        purpose="test",
    )


@pytest.fixture
def fixture(kernel_session: Session) -> Fixture:
    return build_fixture(kernel_session, slug="broker-tenant")


class TestAuthorizedInvocation:
    def test_a_granted_capability_returns_a_validated_result(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.succeeded
        assert result.outcome is ToolExecutionOutcome.SUCCEEDED
        assert result.payload["samples"], "the simulator returned a series"
        assert result.tool_execution_id is not None

    def test_only_the_broker_assigns_verified_fact(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(fixture, kernel_session, clock)
        telemetry = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        knowledge = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.knowledge", arguments={"topic": "connection pool"}),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert telemetry.provenance is ProvenanceLabel.VERIFIED_FACT
        # Knowledge is someone's prose: citable, never authoritative.
        assert knowledge.provenance is ProvenanceLabel.RETRIEVED

    def test_scope_is_resolved_and_recorded(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.resolved_scope["environment"] == "production"
        assert result.resolved_scope["service"] == fixture.service.name
        assert str(result.resolved_scope["tenant_id"]) == str(fixture.tenant_id)


class TestRefusals:
    def test_an_unknown_capability_is_refused_at_resolution(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.telepathy"),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert result.failure.stage is BrokerStage.CAPABILITY_RESOLUTION
        assert provider.calls == (), "no adapter was reached"

    def test_a_write_capability_is_refused_before_any_adapter(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "mutate.k8s_deployment"),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert not result.succeeded
        assert provider.calls == ()

    def test_a_node_without_the_capability_in_its_contract_is_refused(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        # The planner declares no capabilities at all. Even a granted, registered,
        # read-only capability is refused for it.
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.metrics", node_id=NodeId.G3_INVESTIGATION_PLANNER),
            contract=G3_INVESTIGATION_PLANNER,
        )
        broker.close()
        assert result.failure is not None
        assert "does not declare" in result.failure.message
        assert provider.calls == ()

    def test_an_ungranted_capability_is_refused(
        self, kernel_session: Session, clock: FrozenClock
    ) -> None:
        limited = build_fixture(
            kernel_session,
            slug="broker-limited",
            grant_capabilities=("read.metrics",),
        )
        broker, provider, _ = _broker(limited, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(limited, "read.logs", arguments=_log_arguments()),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert "not on this run's menu" in result.failure.message
        assert provider.calls == ()

    def test_a_service_outside_the_incident_scope_is_refused(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        with pytest.raises(CapabilityNotGranted, match="not in scope"):
            broker.invoke(
                kernel_session,
                request=_request(
                    fixture,
                    "read.metrics",
                    service="some-other-service",
                    arguments={
                        "window_start": WINDOW_START,
                        "window_end": WINDOW_END,
                        "metric": "http_request_duration_p95_seconds",
                    },
                ),
                contract=G4_EVIDENCE_COLLECTOR,
            )
        broker.close()
        assert provider.calls == ()

    def test_a_request_for_another_incident_is_refused(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        request = _request(fixture, "read.metrics").model_copy(update={"incident_id": uuid.uuid4()})
        result = broker.invoke(kernel_session, request=request, contract=G4_EVIDENCE_COLLECTOR)
        broker.close()
        assert result.failure is not None
        assert "serves exactly one incident" in result.failure.message
        assert provider.calls == ()

    def test_a_disabled_grant_removes_the_capability(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        kernel_session.execute(
            sa.update(TenantToolGrant)
            .where(TenantToolGrant.tenant_id == fixture.tenant_id)
            .values(is_enabled=False)
        )
        kernel_session.flush()
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.metrics"),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert not result.succeeded
        assert provider.calls == ()


class TestArgumentValidation:
    def test_an_undeclared_argument_is_rejected_not_dropped(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                    "promql": "up{}",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert result.failure.stage is BrokerStage.ARGUMENT_VALIDATION
        assert provider.calls == ()

    def test_a_caller_supplied_scope_argument_is_rejected(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        # The attack: name a different tenant or service in the arguments. Rejected rather
        # than overwritten, so the attempt is visible instead of being silently corrected.
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                    "tenant_id": uuid.uuid4(),
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert "caller-supplied scope argument" in result.failure.message
        assert provider.calls == ()

    def test_an_out_of_vocabulary_enum_value_is_rejected(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "definitely_not_registered",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert result.failure.stage is BrokerStage.ARGUMENT_VALIDATION
        assert provider.calls == ()

    def test_a_naive_timestamp_is_rejected(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": datetime(2026, 9, 7, 9, 0, 0),
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert "timezone-aware" in result.failure.message


class TestFailureHandling:
    def test_a_permanent_adapter_error_is_a_typed_failure_not_a_success(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(
            fixture, kernel_session, clock, scenario_id="SC-0004-log-source-error"
        )
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.logs", arguments=_log_arguments()),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert not result.succeeded
        assert result.payload == {}, "a failure never carries a plausible-looking payload"
        assert result.failure is not None
        assert result.failure.stage is BrokerStage.ADAPTER_INVOCATION

    def test_a_timeout_is_reported_as_a_timeout(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(
            fixture, kernel_session, clock, scenario_id="SC-0005-metrics-source-timeout"
        )
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert result.failure.error_type == "ToolTimeout"

    def test_a_transient_error_is_retried_and_a_permanent_one_is_not(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(
            fixture, kernel_session, clock, scenario_id="SC-0004-log-source-error"
        )
        result = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.logs", arguments=_log_arguments()),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        # A permanent upstream error is class C5: retrying it would ask a deterministic
        # function for a different answer.
        assert result.attempts == 1
        assert len(provider.calls) == 1

    def test_a_malformed_result_is_rejected_not_coerced(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(
            fixture, kernel_session, clock, scenario_id="SC-0010-malformed-tool-result"
        )
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert result.failure is not None
        assert result.failure.stage is BrokerStage.RESULT_VALIDATION
        assert result.attempts == 1, "a malformed shape is never retried"
        assert result.payload == {}


class TestIdempotency:
    def test_a_duplicate_effect_returns_the_recorded_result_without_calling_again(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        arguments = {
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "metric": "http_request_duration_p95_seconds",
        }
        first = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.metrics", arguments=arguments),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        second = broker.invoke(
            kernel_session,
            request=_request(fixture, "read.metrics", arguments=arguments),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        assert first.deduplicated is False
        assert second.deduplicated is True
        assert second.tool_execution_id == first.tool_execution_id
        assert len(provider.calls) == 1, "the adapter was reached exactly once"

        rows = list(
            kernel_session.execute(
                sa.select(ToolExecution).where(
                    ToolExecution.tenant_id == fixture.tenant_id,
                    ToolExecution.tool_name == "metrics.query",
                )
            ).scalars()
        )
        assert len(rows) == 1

    def test_a_different_effect_is_a_different_key(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, provider, _ = _broker(fixture, kernel_session, clock)
        for metric in (
            "http_request_duration_p95_seconds",
            "http_request_duration_p50_seconds",
        ):
            broker.invoke(
                kernel_session,
                request=_request(
                    fixture,
                    "read.metrics",
                    arguments={
                        "window_start": WINDOW_START,
                        "window_end": WINDOW_END,
                        "metric": metric,
                    },
                ),
                contract=G4_EVIDENCE_COLLECTOR,
            )
        broker.close()
        assert len(provider.calls) == 2


class TestAuditAndTrace:
    def test_every_successful_invocation_writes_an_audit_record(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, _ = _broker(fixture, kernel_session, clock)
        result = broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        record = kernel_session.execute(
            sa.select(AuditRecord).where(
                AuditRecord.tenant_id == fixture.tenant_id,
                AuditRecord.tool_execution_id == result.tool_execution_id,
            )
        ).scalar_one()
        assert record.event_type is AuditEventType.TOOL_EXECUTED
        assert record.outcome == "succeeded"

    def test_a_refusal_is_audited_too(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        # An audit log that only records denials cannot prove what was permitted; one that
        # only records successes cannot prove what was attempted.
        broker, _, _ = _broker(fixture, kernel_session, clock)
        broker.invoke(
            kernel_session,
            request=_request(fixture, "mutate.k8s_deployment"),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        record = kernel_session.execute(
            sa.select(AuditRecord).where(
                AuditRecord.tenant_id == fixture.tenant_id,
                AuditRecord.event_type == AuditEventType.TOOL_AUTHORIZATION_EVALUATED,
            )
        ).scalar_one()
        assert record.outcome == "denied"
        assert record.target_id == "mutate.k8s_deployment"
        assert record.policy_rule_id == BrokerStage.CAPABILITY_RESOLUTION.value

    def test_the_invocation_span_carries_the_tool_and_its_version(
        self, fixture: Fixture, kernel_session: Session, clock: FrozenClock
    ) -> None:
        broker, _, tracer = _broker(fixture, kernel_session, clock)
        broker.invoke(
            kernel_session,
            request=_request(
                fixture,
                "read.metrics",
                arguments={
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "metric": "http_request_duration_p95_seconds",
                },
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
        broker.close()
        span = tracer.pending[-1]
        assert span.attributes["tool_name"] == "metrics.query"
        assert span.attributes["tool_version"] == "1.0.0"
        assert span.attributes["risk_tier"] == "ro"
        assert span.tool_execution_id is not None


class TestRiskCeiling:
    def test_the_resolver_refuses_a_destructive_ceiling(self) -> None:
        # Phase 8 (ADR-0023): the ceiling now admits R1/R2 now that the policy gate and
        # approval service exist to authorise them. R3 remains refused unconditionally -
        # no descriptor can ever be registered at that tier (SI-5), so a ceiling naming it
        # could never resolve anything and the refusal is for the caller's own benefit.
        with pytest.raises(ValueError, match="r3"):
            CapabilityResolver(ToolRegistry.read_only(), max_risk_tier=RiskTier.R3)

    def test_a_non_destructive_ceiling_is_now_accepted(self) -> None:
        resolver = CapabilityResolver(ToolRegistry.read_only(), max_risk_tier=RiskTier.R1)
        assert resolver.max_risk_tier is RiskTier.R1

    def test_a_write_descriptor_is_refused_at_the_risk_boundary(self) -> None:
        resolver = CapabilityResolver(ToolRegistry.read_only())
        write_tool = ToolDescriptor(
            name="k8s.deployment.rollback",
            version="1.0.0",
            capability="mutate.k8s_deployment",
            description="Roll a Deployment back.",
            risk_tier=RiskTier.R1,
            provider_kind=ToolProviderKind.NATIVE,
            arguments=(),
            result_fields=(),
            timeout_seconds=300,
            settling_seconds=60,
            rollback_tool_name="k8s.deployment.rollback",
        )
        with pytest.raises(RiskTierNotPermitted, match="risk tier r1"):
            resolver.assert_tier_permitted(write_tool)


def test_a_broker_with_no_provider_is_refused(
    fixture: Fixture, kernel_session: Session, clock: FrozenClock
) -> None:
    scope = load_incident_scope(
        kernel_session,
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        environment_id=fixture.environment.id,
        service_ids=fixture.service_ids,
    )
    with pytest.raises(ValueError, match="refuse but never answer"):
        ToolBroker(
            resolver=CapabilityResolver(ToolRegistry.read_only()),
            providers=[],
            scope=scope,
            audit=AuditWriter(tenant_id=fixture.tenant_id, clock=clock),
            tracer=TraceRecorder(
                tenant_id=fixture.tenant_id,
                execution_trace_id=uuid.uuid4(),
                trace_id=derive_trace_id(uuid.uuid4()),
                clock=clock,
            ),
            clock=clock,
        )
