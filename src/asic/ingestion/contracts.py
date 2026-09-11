"""Bounded wire data and connector-owned identity. All source fields are DATA."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from asic.domain.enums import AlertSeverity

Text = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x1f]+$")]

MIN_SUPPORTED_TIMESTAMP = datetime(2000, 1, 1, tzinfo=UTC)
MAX_SUPPORTED_TIMESTAMP = datetime(2100, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class IngestionPolicy:
    """Versioned bounds applied after source normalization and before state changes."""

    version: str = "signal-validation/2"
    allowed_future_skew: timedelta = timedelta(minutes=5)
    minimum_timestamp: datetime = MIN_SUPPORTED_TIMESTAMP
    maximum_timestamp: datetime = MAX_SUPPORTED_TIMESTAMP

    def validate_observation_time(self, signal: Signal, ingested_at: datetime) -> None:
        try:
            latest = ingested_at.astimezone(UTC) + self.allowed_future_skew
        except (OverflowError, ValueError) as exc:
            raise IngestionRejected("unsupported_ingestion_time") from exc
        if signal.observed_at > latest:
            raise IngestionRejected("future_observation")


class IngestionRejected(ValueError):
    """Safe reason code; never includes the rejected source text."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceState(StrEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class ConnectorContext(BaseModel):
    """Constructed by trusted wiring/authentication, never from a source body.

    Phase 9/10 must authenticate before constructing this context. This library does not
    authenticate webhooks. One connector is bound to one service and environment.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    tenant_id: UUID
    connector_id: Text
    source: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")]
    service_id: UUID
    environment_id: UUID


class Signal(BaseModel):
    """Canonical v1 source observation, independent of ingestion processing status."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    kind: Literal["alert", "change"] = "alert"
    source_event_id: Text | None = None
    fingerprint: Text
    severity: AlertSeverity = AlertSeverity.INFO
    state: SourceState = SourceState.FIRING
    title: Annotated[str, Field(min_length=1, max_length=2048)]
    category: Text = "uncategorized"
    started_at: AwareDatetime
    observed_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    labels: dict[str, str] = Field(default_factory=dict, max_length=64)
    annotations: dict[str, str] = Field(default_factory=dict, max_length=64)
    correlation_ids: dict[str, str] = Field(default_factory=dict, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("started_at", "observed_at", "resolved_at", mode="before")
    @classmethod
    def explicit_timestamp(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, (str, datetime)):
            raise ValueError("timestamps require explicit timezone-bearing representations")
        return value

    @field_validator("started_at", "observed_at", "resolved_at")
    @classmethod
    def supported_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        try:
            normalized = value.astimezone(UTC)
        except (OverflowError, ValueError) as exc:
            raise PydanticCustomError(
                "unsupported_timestamp", "timestamp cannot be represented in UTC"
            ) from exc
        if not MIN_SUPPORTED_TIMESTAMP <= normalized < MAX_SUPPORTED_TIMESTAMP:
            raise PydanticCustomError(
                "unsupported_timestamp",
                "timestamp is outside the supported operational range",
            )
        return normalized

    @model_validator(mode="after")
    def timestamps(self) -> Signal:
        if self.observed_at < self.started_at:
            raise ValueError("observation precedes occurrence")
        if self.state is SourceState.RESOLVED:
            if self.resolved_at is None or not (
                self.started_at <= self.resolved_at <= self.observed_at
            ):
                raise ValueError("resolution timestamp inconsistent")
        elif self.resolved_at is not None:
            raise ValueError("firing signal cannot have resolution timestamp")
        if self.kind == "change" and self.state is not SourceState.FIRING:
            raise ValueError("change signals are observations, not alert resolutions")
        for mapping in (self.labels, self.annotations, self.correlation_ids):
            if any(len(k) > 128 or len(v) > 2048 for k, v in mapping.items()):
                raise ValueError("metadata string exceeds bounds")
        return self

    def canonical(self) -> dict[str, Any]:
        result = self.model_dump(mode="json")
        for key in ("started_at", "observed_at", "resolved_at"):
            value = getattr(self, key)
            result[key] = value.astimezone(UTC).isoformat() if value is not None else None
        return result


class NormalizedEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    context: ConnectorContext
    signal: Signal
    ingested_at: AwareDatetime
    correlation_id: UUID
    provenance: Literal["retrieved"] = "retrieved"
    normalizer_version: str
    raw_payload_ref: None = None


class Normalizer(Protocol):
    source: str
    version: str

    def normalize(self, payload: dict[str, Any], context: ConnectorContext) -> Signal: ...


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def parse_payload(raw: bytes) -> dict[str, Any]:
    if len(raw) > 65536:
        raise IngestionRejected("payload_too_large")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise IngestionRejected("duplicate_json_key")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IngestionRejected("malformed_json") from exc
    pending = [(payload, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 8 or count > 2048:
            raise IngestionRejected("structure_limit")
        if isinstance(value, dict):
            for key in value:
                if len(key) > 128 or "\x00" in key:
                    raise IngestionRejected("metadata_key_limit")
                try:
                    key.encode("utf-8")
                except UnicodeError as exc:
                    raise IngestionRejected("invalid_unicode") from exc
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, str) and (len(value) > 4096 or "\x00" in value):
            raise IngestionRejected("string_limit")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                raise IngestionRejected("invalid_unicode") from exc
        elif isinstance(value, float):
            import math

            if not math.isfinite(value):
                raise IngestionRejected("nonfinite_number")
    if not isinstance(payload, dict):
        raise IngestionRejected("expected_object")
    return payload


class SimulatorNormalizer:
    """Explicit fixture wire format. Future adapters implement Normalizer independently."""

    source = "simulator"
    version = "simulator/1"

    def normalize(self, payload: dict[str, Any], context: ConnectorContext) -> Signal:
        body = dict(payload)
        for key in ("tenant_id", "service_id", "environment_id"):
            if key in body and body.pop(key) != str(getattr(context, key)):
                raise IngestionRejected("identity_mismatch")
        if type(body.get("schema_version", 1)) is not int or body.get("schema_version", 1) != 1:
            raise IngestionRejected("unsupported_schema_version")
        # Unknown top-level metadata is retained in a separate, untrusted data slot.
        extras = {k: body.pop(k) for k in list(body) if k not in Signal.model_fields}
        try:
            signal = Signal.model_validate(body)
            return signal.model_copy(
                update={"metadata": {"source": signal.metadata, "unknown": extras}}
            )
        except ValidationError as exc:
            code = (
                "unsupported_timestamp"
                if any(error["type"] == "unsupported_timestamp" for error in exc.errors())
                else "invalid_signal"
            )
            raise IngestionRejected(code) from exc


def occurrence_key(context: ConnectorContext, signal: Signal) -> str:
    # Explicit UTC encoding matches the Phase 3 digest on UTC hosts. The service also
    # looks up the natural occurrence tuple for historical keys from non-UTC hosts.
    from asic.domain.idempotency import _digest

    return _digest(
        "alert",
        context.tenant_id,
        context.source,
        signal.fingerprint,
        signal.started_at.astimezone(UTC).isoformat(),
    )
