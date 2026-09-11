"""Deterministic source-format fixtures. No webhook server or external client."""

from typing import Any

from asic.ingestion.contracts import (
    ConnectorContext,
    IngestionRejected,
    Signal,
    SimulatorNormalizer,
)


class AlertmanagerFixtureNormalizer:
    """One simulated Alertmanager alert observation, not a production webhook adapter.

    Fixture wrapper requires observedAt because startsAt alone cannot order updates.
    Batch delivery/signatures/retries belong to the future authenticated connector.
    Source-specific aliases live here rather than in correlation/domain code.
    """

    source = "alertmanager_fixture"
    version = "alertmanager-fixture/1"

    def normalize(self, payload: dict[str, Any], context: ConnectorContext) -> Signal:
        labels, annotations = payload.get("labels", {}), payload.get("annotations", {})
        if not isinstance(labels, dict) or not isinstance(annotations, dict):
            raise IngestionRejected("invalid_signal")
        severity = labels.get("severity", "info")
        aliases = {"critical": "critical", "error": "high", "warning": "medium", "info": "info"}
        if not isinstance(severity, str) or severity not in aliases:
            raise IngestionRejected("invalid_severity")
        body = dict(payload)
        for key in ("startsAt", "endsAt", "observedAt", "status"):
            body.pop(key, None)
        body.update(
            {
                "severity": aliases[severity],
                "state": payload.get("status"),
                "started_at": payload.get("startsAt"),
                "observed_at": payload.get("observedAt"),
                "resolved_at": payload.get("endsAt")
                if payload.get("status") == "resolved"
                else None,
                "title": annotations.get("summary", labels.get("alertname")),
                "category": labels.get("category", "uncategorized"),
            }
        )
        return SimulatorNormalizer().normalize(body, context)
