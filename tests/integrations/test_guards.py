"""Versioned verification policy, descriptor invariants and non-vacuity of Phase 10 guards."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import (
    G4_EVIDENCE_COLLECTOR,
    NOTIFICATION_CAPABILITIES,
    S2_NOTIFICATION_SERVICE,
)
from asic.domain.enums import IntegrationKind, RiskTier, ToolEffectClass, ToolProviderKind
from asic.domain.errors import SchemaViolation
from asic.domain.safety import check_field_names
from asic.remediation.verification import (
    profile_for,
    profile_for_criteria,
    require_permitted_proposal,
)
from asic.tools import broker as broker_module
from asic.tools.descriptor import ArgumentKind, ResultField, ToolDescriptor
from asic.tools.integration_catalogue import INTEGRATION_CATALOGUE
from asic.tools.provider import ConnectorGrant
from asic.tools.registry import ToolRegistry
from tests.conftest import requires_postgres
from tests.integrations.conftest import NOW
from tests.integrations.local_http import LocalHttpServer, Scripted
from tests.integrations.world import broker_for, make_world, request


class TestVersionedVerificationPolicy:
    def test_new_proposals_select_the_current_profile_only(self) -> None:
        current = profile_for("k8s.deployment.rollback")
        assert current.profile_version == 2
        assert "prometheus" in current.approved_sources
        assert (
            require_permitted_proposal(
                "k8s.deployment.rollback", {"profile_id": current.profile_id}
            )
            == current
        )
        with pytest.raises(SchemaViolation):
            require_permitted_proposal(
                "k8s.deployment.rollback", {"profile_id": "latency-p95-recovery-v1"}
            )

    def test_frozen_criteria_resolve_to_exactly_the_version_they_froze(self) -> None:
        v1 = profile_for_criteria(
            "k8s.deployment.rollback",
            {
                **profile_for("k8s.deployment.rollback").to_dict(),
                "profile_id": "latency-p95-recovery-v1",
                "profile_version": 1,
                "approved_sources": ["prometheus-simulator"],
            },
        )
        assert v1.profile_version == 1
        assert "prometheus" not in v1.approved_sources
        tampered = {**profile_for("k8s.deployment.rollback").to_dict(), "threshold": 10.0}
        with pytest.raises(SchemaViolation):
            profile_for_criteria("k8s.deployment.rollback", tampered)
        # A v1 action cannot be upgraded to trust a live source by relabelling its version.
        mixed = {**v1.to_dict(), "approved_sources": ["prometheus", "prometheus-simulator"]}
        with pytest.raises(SchemaViolation):
            profile_for_criteria("k8s.deployment.rollback", mixed)


class TestDescriptorInvariants:
    def _record(self, **overrides: object) -> ToolDescriptor:
        base = INTEGRATION_CATALOGUE[0].model_dump()
        base.update(overrides)
        return ToolDescriptor(**base)

    def test_external_records_cannot_retry_roll_back_or_be_high_risk(self) -> None:
        for overrides in (
            {"max_attempts": 2},
            {"rollback_tool_name": "slack.post"},
            {"risk_tier": RiskTier.R2},
            {"settling_seconds": 30},
        ):
            with pytest.raises(ValueError):
                self._record(**overrides)

    def test_a_read_tier_cannot_claim_an_effect_class_or_vice_versa(self) -> None:
        with pytest.raises(ValueError):
            self._record(risk_tier=RiskTier.RO)
        with pytest.raises(ValueError):
            ToolDescriptor(
                name="metrics.fake",
                version="1.0.0",
                capability="read.metrics",
                description="x",
                risk_tier=RiskTier.RO,
                effect_class=ToolEffectClass.EXTERNAL_RECORD,
                provider_kind=ToolProviderKind.NATIVE,
                arguments=(),
                result_fields=(ResultField(name="source", kind=ArgumentKind.BOUNDED_STRING),),
                timeout_seconds=5,
            )

    def test_no_external_record_accepts_a_destination_url_query_or_command(self) -> None:
        for descriptor in INTEGRATION_CATALOGUE:
            names = [a.name for a in descriptor.arguments]
            assert check_field_names(names) == []
            assert not {
                "url",
                "channel",
                "channel_id",
                "project_key",
                "jql",
                "query",
                "issue_key",
                "routing_key",
                "webhook",
            } & set(names)
            assert descriptor.capability in NOTIFICATION_CAPABILITIES
        assert S2_NOTIFICATION_SERVICE.capabilities == NOTIFICATION_CAPABILITIES
        assert not NOTIFICATION_CAPABILITIES & G4_EVIDENCE_COLLECTOR.capabilities

    def test_the_integration_registry_is_separate_from_the_investigation_registry(self) -> None:
        assert not ToolRegistry.integrations().capabilities & ToolRegistry.read_only().capabilities
        assert (
            not ToolRegistry.integrations().capabilities
            & ToolRegistry.remediation_full().capabilities
        )


@requires_postgres
class TestNonVacuity:
    def test_the_connector_check_is_load_bearing(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        server.route(
            "GET",
            "/api/v1/query_range",
            Scripted(body={"status": "success", "data": {"resultType": "matrix", "result": []}}),
        )
        world = make_world(owner_engine, endpoint=server.url, kinds=())
        arguments = {
            "window_start": NOW - timedelta(minutes=5),
            "window_end": NOW,
            "metric": "http_requests_total",
        }

        def bypass(
            session: Session, *, scope: object, service_name: str, kind: IntegrationKind
        ) -> ConnectorGrant:
            return ConnectorGrant(
                connector_id="forged",
                kind=kind,
                endpoint_url=server.url,
                credential_ref="asic/test/read",
                write_credential_ref=None,
                service_name=service_name,
                environment_name="production",
            )

        with Session(bind=app_engine, expire_on_commit=False) as session:
            broker = broker_for(app_engine, session, world, registry=ToolRegistry.read_only())
            refused = broker.invoke(
                session,
                request=request(world, "read.metrics", arguments),
                contract=G4_EVIDENCE_COLLECTOR,
            )
            assert not refused.succeeded and server.requests == []
            monkeypatch.setattr(broker_module, "resolve_connector", bypass)
            bypassed = broker.invoke(
                session,
                request=request(
                    world, "read.metrics", {**arguments, "metric": "http_request_errors_total"}
                ),
                contract=G4_EVIDENCE_COLLECTOR,
            )
            session.rollback()
        assert bypassed.succeeded and len(server.requests) == 1

    def test_the_notification_node_restriction_is_load_bearing(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        # With the node restriction intact, the S2 contract but a different node id is refused
        # before any connector lookup or request.
        world = make_world(
            owner_engine,
            endpoint=server.url,
            kinds=(IntegrationKind.SLACK,),
            settings={IntegrationKind.SLACK: {"channel_id": "C0123456789"}},
        )
        server.route("POST", "/api/chat.postMessage", Scripted(body={"ok": True, "ts": "1.1"}))
        from asic.domain.enums import NodeId

        with Session(bind=app_engine, expire_on_commit=False) as session:
            broker = broker_for(
                app_engine,
                session,
                world,
                registry=ToolRegistry.integrations(),
                max_risk_tier=RiskTier.R1,
            )
            result = broker.invoke(
                session,
                request=request(
                    world,
                    "notify.slack_channel",
                    {
                        "event_id": uuid.uuid4().hex * 2,
                        "event_type": "incident_opened",
                        "incident_reference": "INC-1",
                        "severity": "sev3",
                        "status": "detected",
                        "summary": "x",
                    },
                    node_id=NodeId.G4_EVIDENCE_COLLECTOR,
                ),
                contract=S2_NOTIFICATION_SERVICE,
            )
            session.rollback()
        assert result.failure is not None and server.requests == []


def test_display_text_is_single_line_and_bounded() -> None:
    from asic.integrations.base import display_text

    hostile = "a" + chr(0x2028) + "b" + chr(0x2029) + "c\nd\re\tf" + chr(0) + "g" + "x" * 50
    cleaned = display_text(hostile, limit=20)
    assert all(ord(ch) >= 0x20 and ch not in (chr(0x2028), chr(0x2029)) for ch in cleaned)
    assert cleaned.startswith("a b c d e f g") and len(cleaned) == 20
    # Digits that appear in the escape sequences are ordinary text, not stripped.
    assert display_text("2028 2029 x1f", limit=50) == "2028 2029 x1f"
