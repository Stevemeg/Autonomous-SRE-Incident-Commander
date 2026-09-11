"""Wire-boundary validation and deterministic correlation decisions."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from asic.ingestion.contracts import (
    ConnectorContext,
    IngestionPolicy,
    IngestionRejected,
    SimulatorNormalizer,
    occurrence_key,
    parse_payload,
)
from asic.ingestion.correlation import Candidate, decide
from asic.ingestion.locks import INGESTION_TENANT_LOCK_NAMESPACE, advisory_lock_key


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
    assert ambiguous["result"] == "join"
    assert ambiguous["reason"] == "deterministic_tie_break"
    assert ambiguous["selected"] == min(str(first.incident_id), str(second.incident_id))
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


@pytest.mark.parametrize(
    "timestamp",
    [
        "0001-01-01T00:00:00Z",
        "0001-01-01T00:00:00+14:00",
        "1999-12-31T23:59:59Z",
        "2100-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        "9999-12-31T23:59:59-12:00",
    ],
)
def test_unsupported_timestamp_boundaries_are_typed(timestamp: str) -> None:
    with pytest.raises(IngestionRejected, match="unsupported_timestamp"):
        SimulatorNormalizer().normalize(
            parse_payload(payload(started_at=timestamp, observed_at=timestamp)), context()
        )


def test_timestamp_normalization_is_utc_and_boundaries_are_explicit() -> None:
    signal = SimulatorNormalizer().normalize(
        parse_payload(
            payload(
                started_at="2000-01-01T14:00:00+14:00",
                observed_at="2099-12-31T11:59:59-12:00",
            )
        ),
        context(),
    )
    assert signal.started_at == datetime(2000, 1, 1, tzinfo=UTC)
    assert signal.observed_at == datetime(2099, 12, 31, 23, 59, 59, tzinfo=UTC)


@pytest.mark.parametrize(
    "delta,accepted",
    [
        (timedelta(minutes=4, seconds=59), True),
        (timedelta(minutes=5), True),
        (timedelta(minutes=5, microseconds=1), False),
        (timedelta(days=365), False),
    ],
)
def test_future_skew_policy_has_an_inclusive_five_minute_boundary(
    delta: timedelta, accepted: bool
) -> None:
    now = datetime(2026, 9, 11, 8, tzinfo=UTC)
    observed = now + delta
    signal = SimulatorNormalizer().normalize(
        parse_payload(
            payload(
                started_at=now.isoformat(),
                observed_at=observed.isoformat(),
            )
        ),
        context(),
    )
    if accepted:
        IngestionPolicy().validate_observation_time(signal, now)
    else:
        with pytest.raises(IngestionRejected, match="future_observation"):
            IngestionPolicy().validate_observation_time(signal, now)


def test_advisory_lock_keys_are_namespaced() -> None:
    tenant_id = uuid4()
    ingestion = advisory_lock_key(INGESTION_TENANT_LOCK_NAMESPACE, tenant_id)
    another_domain = advisory_lock_key("asic.some-future-lock.v1", tenant_id)
    assert ingestion[0] != another_domain[0]
    assert ingestion != another_domain


def test_non_key_update_lock_compiles_to_postgresql_no_key_update() -> None:
    statement = sa.select(sa.literal(1)).with_for_update(key_share=True)
    assert str(statement.compile(dialect=postgresql.dialect())).endswith("FOR NO KEY UPDATE")


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
