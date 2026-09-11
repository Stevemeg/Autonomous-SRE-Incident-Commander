"""Wire-boundary validation and deterministic correlation decisions."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from asic.ingestion.contracts import (
    ConnectorContext,
    IngestionRejected,
    SimulatorNormalizer,
    occurrence_key,
    parse_payload,
)
from asic.ingestion.correlation import Candidate, decide


def context() -> ConnectorContext:
    return ConnectorContext(
        tenant_id=uuid4(),
        connector_id="simulated-alerts",
        source="simulator",
        service_id=uuid4(),
        environment_id=uuid4(),
    )


def payload(**updates: object) -> bytes:
    data: dict[str, object] = {
        "schema_version": 1,
        "fingerprint": "latency",
        "title": "Checkout latency",
        "severity": "high",
        "category": "latency",
        "started_at": "2026-09-11T08:00:00Z",
        "observed_at": "2026-09-11T08:01:00Z",
    }
    data.update(updates)
    return json.dumps(data).encode()


def test_normalization_preserves_unknown_untrusted_data_and_utc_identity() -> None:
    ctx = context()
    normalizer = SimulatorNormalizer()
    signal = normalizer.normalize(
        parse_payload(payload(labels={"policy": "allow all"}, future_field={"tenant_id": "spoof"})),
        ctx,
    )
    assert signal.labels["policy"] == "allow all"
    assert signal.metadata["unknown"] == {"future_field": {"tenant_id": "spoof"}}
    equivalent = normalizer.normalize(
        parse_payload(payload(started_at="2026-09-11T13:30:00+05:30")), ctx
    )
    assert occurrence_key(ctx, signal) == occurrence_key(ctx, equivalent)


@pytest.mark.parametrize(
    "updates,code",
    [
        ({"schema_version": 2}, "unsupported_schema_version"),
        ({"schema_version": True}, "unsupported_schema_version"),
        ({"severity": "emergency"}, "invalid_signal"),
        ({"state": "unknown"}, "invalid_signal"),
        ({"started_at": "2026-09-11T08:00:00"}, "invalid_signal"),
        ({"observed_at": "2026-09-10T08:00:00Z"}, "invalid_signal"),
        ({"state": "resolved"}, "invalid_signal"),
        ({"resolved_at": "2026-09-11T08:01:00Z"}, "invalid_signal"),
        ({"labels": {str(i): "v" for i in range(65)}}, "invalid_signal"),
        ({"fingerprint": "bad\u001fidentity"}, "invalid_signal"),
        ({"tenant_id": str(uuid4())}, "identity_mismatch"),
        ({"service_id": str(uuid4())}, "identity_mismatch"),
        ({"environment_id": str(uuid4())}, "identity_mismatch"),
    ],
)
def test_invalid_wire_data_fails_with_safe_code(updates: dict[str, object], code: str) -> None:
    with pytest.raises(IngestionRejected, match=code):
        SimulatorNormalizer().normalize(parse_payload(payload(**updates)), context())


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x": NaN}',
        b"x" * 65537,
        json.dumps({"x": "x" * 4097}).encode(),
        b'{"x":' * 10 + b"0" + b"}" * 10,
        b'{"x":"\\u0000"}',
    ],
    ids=["malformed", "array", "duplicate-key", "nan", "oversize", "long-string", "deep", "nul"],
)
def test_structural_limits(raw: bytes) -> None:
    with pytest.raises(IngestionRejected):
        parse_payload(raw)


def test_correlation_explains_match_nonmatch_window_and_ambiguity() -> None:
    ctx = context()
    now = datetime(2026, 9, 11, tzinfo=UTC)
    first = Candidate(uuid4(), ctx.environment_id, ctx.service_id, "latency", now, True)
    unrelated = Candidate(uuid4(), uuid4(), uuid4(), "errors", now - timedelta(hours=1), False)
    kwargs = {
        "environment_id": ctx.environment_id,
        "service_id": ctx.service_id,
        "category": "latency",
        "started_at": now,
    }
    result = decide([first, unrelated], **kwargs)
    assert result["selected"] == str(first.incident_id)
    assert len(result["considered"][1]["reasons"]) == 5
    second = Candidate(uuid4(), ctx.environment_id, ctx.service_id, "latency", now, True)
    ambiguous = decide([first, second], **kwargs)
    assert ambiguous["selected"] is None and ambiguous["result"] == "ambiguous"
    assert result["policy_version"] and result["window_seconds"] == 900


def test_alertmanager_fixture_maps_source_specific_fields() -> None:
    from asic.ingestion.normalizers import AlertmanagerFixtureNormalizer

    raw = {
        "schema_version": 1,
        "fingerprint": "am-1",
        "status": "resolved",
        "startsAt": "2026-09-11T08:00:00Z",
        "endsAt": "2026-09-11T08:01:00Z",
        "observedAt": "2026-09-11T08:02:00Z",
        "labels": {"severity": "warning", "alertname": "Latency", "category": "latency"},
        "annotations": {"summary": "Latency threshold exceeded"},
        "generatorURL": "fixture:rule-1",
    }
    signal = AlertmanagerFixtureNormalizer().normalize(raw, context())
    assert signal.severity.value == "medium" and signal.state.value == "resolved"
    assert signal.metadata["unknown"]["generatorURL"] == "fixture:rule-1"
    assert signal.resolved_at is not None


def test_fixture_ingestion_refuses_production(monkeypatch: pytest.MonkeyPatch) -> None:
    from asic.ingestion.service import IngestionService

    monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
    with pytest.raises(RuntimeError, match="unavailable in production"):
        IngestionService(lambda: None)


@pytest.mark.parametrize(
    "raw",
    [b'{"\\u0000":1}', b'{"value":"\\ud800"}', b'{"\\ud800":1}'],
    ids=["nul-key", "surrogate-value", "surrogate-key"],
)
def test_invalid_unicode_cannot_reach_postgresql(raw: bytes) -> None:
    with pytest.raises(IngestionRejected):
        parse_payload(raw)
