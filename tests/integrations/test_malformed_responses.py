"""Vendor responses that break the parser, not the contract.

INTEGRATION + LOCAL SERVICE. A response body is untrusted input: its nesting depth, its
numeric magnitudes and its types are chosen by whatever answered the socket. Processing one
must therefore fail the way every other integration failure fails - a normalised class, a
persisted ``tool_execution`` row and an audit record - and never as an exception unwinding
into the kernel, where a write would lose its receipt and the run would dead-letter.

The asymmetry these tests pin down: a read that cannot be parsed applied nothing, so it is
``failed_clean``; anything effectful whose response cannot be parsed may already have been
applied, so it is ``unknown`` (SI-8).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.nodes import G4_EVIDENCE_COLLECTOR, S2_NOTIFICATION_SERVICE
from asic.db.models import AuditRecord, ToolExecution
from asic.db.session import bind_tenant
from asic.domain.enums import (
    AuditEventType,
    IntegrationFailureClass,
    IntegrationKind,
    NodeId,
    RiskTier,
    ToolExecutionOutcome,
)
from asic.tools.registry import ToolRegistry
from tests.conftest import requires_postgres
from tests.integrations.conftest import NOW, SECRETS
from tests.integrations.local_http import LocalHttpServer, Scripted
from tests.integrations.test_broker_integration import WINDOW
from tests.integrations.world import IntegrationWorld, broker_for, make_world, request

pytestmark = requires_postgres

#: Deeper than CPython's recursion limit, so ``json.loads`` raises ``RecursionError``.
DEEPLY_NESTED = b"[" * 200_000 + b"]" * 200_000

SLACK_PATH = "/api/chat.postMessage"


def _execution(app_engine: sa.Engine, world: IntegrationWorld) -> ToolExecution:
    with Session(bind=app_engine) as session:
        bind_tenant(session, world.tenant_id)
        return session.scalars(
            sa.select(ToolExecution).where(ToolExecution.tenant_id == world.tenant_id)
        ).one()


def _audit_events(app_engine: sa.Engine, world: IntegrationWorld) -> list[AuditEventType]:
    with Session(bind=app_engine) as session:
        bind_tenant(session, world.tenant_id)
        return list(
            session.scalars(
                sa.select(AuditRecord.event_type).where(AuditRecord.tenant_id == world.tenant_id)
            )
        )


def _read(app_engine: sa.Engine, world: IntegrationWorld, capability: str, arguments: Any) -> Any:
    with Session(bind=app_engine, expire_on_commit=False) as session:
        broker = broker_for(app_engine, session, world, registry=ToolRegistry.read_only())
        try:
            return broker.invoke(
                session,
                request=request(world, capability, arguments),
                contract=G4_EVIDENCE_COLLECTOR,
            )
        finally:
            session.commit()
            broker.close()


def _notify(app_engine: sa.Engine, world: IntegrationWorld, event_id: str) -> Any:
    arguments = {
        "event_id": event_id,
        "event_type": "incident_escalated",
        "incident_reference": "INC-0001",
        "severity": "sev2",
        "status": "escalated",
        "summary": "checkout latency",
    }
    with Session(bind=app_engine, expire_on_commit=False) as session:
        broker = broker_for(
            app_engine,
            session,
            world,
            registry=ToolRegistry.integrations(),
            max_risk_tier=RiskTier.R1,
        )
        try:
            return broker.invoke(
                session,
                request=request(
                    world,
                    "notify.slack_channel",
                    arguments,
                    node_id=NodeId.S2_NOTIFICATION_SERVICE,
                ),
                contract=S2_NOTIFICATION_SERVICE,
            )
        finally:
            session.commit()
            broker.close()


class TestUnparseableReads:
    @pytest.mark.parametrize(
        ("label", "scripted"),
        [
            ("deep_nesting", Scripted(raw=DEEPLY_NESTED)),
            ("not_json", Scripted(raw=b"<html>gateway</html>")),
            ("wrong_type", Scripted(body=["not", "an", "object"])),
            ("missing_field", Scripted(body={"status": "success", "data": {}})),
            (
                "numeric_overflow",
                Scripted(
                    body={
                        "status": "success",
                        "data": {
                            "resultType": "matrix",
                            "result": [{"metric": {}, "values": [["1e400", "0.2"]]}],
                        },
                    }
                ),
            ),
            (
                "unicode_edge",
                Scripted(
                    raw=json.dumps({"status": "success\ud800"}).encode("utf-8", "surrogatepass")
                ),
            ),
        ],
    )
    def test_a_read_that_cannot_be_parsed_is_a_typed_clean_failure(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        label: str,
        scripted: Scripted,
    ) -> None:
        server.route("GET", "/api/v1/query_range", scripted)
        world = make_world(owner_engine, endpoint=server.url, kinds=(IntegrationKind.PROMETHEUS,))
        result = _read(
            app_engine, world, "read.metrics", {**WINDOW, "metric": "http_requests_total"}
        )

        assert not result.succeeded, label
        assert result.outcome is ToolExecutionOutcome.FAILED_CLEAN
        execution = _execution(app_engine, world)
        assert execution.outcome is ToolExecutionOutcome.FAILED_CLEAN
        assert execution.failure_class in (
            IntegrationFailureClass.MALFORMED_RESPONSE,
            IntegrationFailureClass.INVALID_REQUEST,
        )
        assert AuditEventType.TOOL_EXECUTED in _audit_events(app_engine, world)

    @pytest.mark.parametrize(
        "stamp",
        [
            "99999999999999999999999999999",  # OverflowError converting to a float
            "-99999999999999999999",  # OSError / ValueError on the platform conversion
            "18446744073709551616000000000",
            "not-a-number",
        ],
    )
    def test_a_loki_timestamp_outside_the_representable_range_is_classified(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        stamp: str,
    ) -> None:
        server.route(
            "GET",
            "/loki/api/v1/query_range",
            Scripted(
                body={
                    "status": "success",
                    "data": {
                        "resultType": "streams",
                        "result": [
                            {"stream": {"level": "error"}, "values": [[stamp, "boom"]]},
                        ],
                    },
                }
            ),
        )
        world = make_world(owner_engine, endpoint=server.url, kinds=(IntegrationKind.LOKI,))
        result = _read(app_engine, world, "read.logs", {**WINDOW})

        assert result.outcome is ToolExecutionOutcome.FAILED_CLEAN
        assert result.failure is not None
        assert result.failure.failure_class is IntegrationFailureClass.MALFORMED_RESPONSE
        assert _execution(app_engine, world).failure_class is (
            IntegrationFailureClass.MALFORMED_RESPONSE
        )

    def test_a_valid_response_still_succeeds(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        server.route(
            "GET",
            "/api/v1/query_range",
            Scripted(
                body={
                    "status": "success",
                    "data": {
                        "resultType": "matrix",
                        "result": [{"metric": {}, "values": [[NOW.timestamp(), "0.2"]]}],
                    },
                }
            ),
        )
        world = make_world(owner_engine, endpoint=server.url, kinds=(IntegrationKind.PROMETHEUS,))
        result = _read(
            app_engine, world, "read.metrics", {**WINDOW, "metric": "http_requests_total"}
        )
        assert result.succeeded
        assert result.payload["samples"]


class TestUnparseableWrites:
    def _world(self, owner_engine: sa.Engine, server: LocalHttpServer) -> IntegrationWorld:
        return make_world(
            owner_engine,
            endpoint=server.url,
            kinds=(IntegrationKind.SLACK,),
            settings={IntegrationKind.SLACK: {"channel_id": "C0123456789"}},
        )

    @pytest.mark.parametrize(
        ("label", "scripted"),
        [
            ("deep_nesting", Scripted(raw=DEEPLY_NESTED)),
            ("not_json", Scripted(raw=b"<html>accepted?</html>")),
            ("wrong_type", Scripted(body=[1, 2, 3])),
        ],
    )
    def test_an_effectful_response_that_cannot_be_parsed_is_unknown_not_clean(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        label: str,
        scripted: Scripted,
    ) -> None:
        server.route("POST", SLACK_PATH, scripted)
        world = self._world(owner_engine, server)
        event = uuid.uuid4().hex + uuid.uuid4().hex

        result = _notify(app_engine, world, event)

        assert result.outcome is ToolExecutionOutcome.UNKNOWN, label
        execution = _execution(app_engine, world)
        assert execution.outcome is ToolExecutionOutcome.UNKNOWN
        assert execution.failure_class in (
            IntegrationFailureClass.MALFORMED_RESPONSE,
            IntegrationFailureClass.UNKNOWN_OUTCOME,
        )
        assert AuditEventType.TOOL_EXECUTED in _audit_events(app_engine, world)

        # The request was sent once and its effect is unknown, so it is never sent again.
        server.route("POST", SLACK_PATH, Scripted(body={"ok": True, "ts": "1726488000.000200"}))
        again = _notify(app_engine, world, event)
        assert not again.succeeded
        assert len(server.calls("POST", SLACK_PATH)) == 1

    def test_no_vendor_payload_or_credential_reaches_the_durable_record(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        marker = "VENDOR-BODY-MARKER-a9f3"
        server.route(
            "POST",
            SLACK_PATH,
            Scripted(raw=json.dumps({"ok": True, "detail": marker, "ts": marker}).encode()),
        )
        world = self._world(owner_engine, server)
        result = _notify(app_engine, world, uuid.uuid4().hex + uuid.uuid4().hex)

        execution = _execution(app_engine, world)
        with Session(bind=app_engine) as session:
            bind_tenant(session, world.tenant_id)
            payloads = [
                json.dumps(dict(row.payload_redacted), default=str)
                for row in session.scalars(
                    sa.select(AuditRecord).where(AuditRecord.tenant_id == world.tenant_id)
                )
            ]
        rendered = json.dumps(
            [execution.failure_reason, str(result.failure), payloads], default=str
        )
        assert marker not in rendered
        for secret in SECRETS.values():
            assert secret not in rendered
