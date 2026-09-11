"""Render persisted source-controlled alert fields only as untrusted model data."""

from __future__ import annotations

import json
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import Alert, SignalReceipt
from asic.domain.enums import ProvenanceLabel
from asic.domain.untrusted import UntrustedBlock

MAX_ALERT_BLOCKS: Final[int] = 16
MAX_ALERT_BLOCK_CHARS: Final[int] = 16_384


def incident_alert_blocks(
    session: Session, *, tenant_id: UUID, incident_id: UUID
) -> tuple[UntrustedBlock, ...]:
    """Load bounded alert DATA; persistence never upgrades its provenance."""
    receipts = list(
        session.scalars(
            sa.select(SignalReceipt)
            .where(
                SignalReceipt.tenant_id == tenant_id,
                SignalReceipt.incident_id == incident_id,
                SignalReceipt.kind == "alert",
                SignalReceipt.envelope != {},
            )
            .order_by(SignalReceipt.created_at, SignalReceipt.id)
            .limit(MAX_ALERT_BLOCKS)
        )
    )
    blocks: list[UntrustedBlock] = []
    seen_alerts: set[UUID] = set()
    for receipt in receipts:
        signal = receipt.envelope.get("signal", {})
        content = json.dumps(
            {
                key: signal.get(key)
                for key in ("title", "labels", "annotations", "correlation_ids", "metadata")
                if key in signal
            },
            sort_keys=True,
            ensure_ascii=True,
        )[:MAX_ALERT_BLOCK_CHARS]
        blocks.append(
            UntrustedBlock(
                source=f"alert-receipt:{receipt.id}",
                provenance=ProvenanceLabel.RETRIEVED,
                content=content,
            )
        )
        if receipt.alert_id is not None:
            seen_alerts.add(receipt.alert_id)

    remaining = MAX_ALERT_BLOCKS - len(blocks)
    if remaining <= 0:
        return tuple(blocks)
    alerts = list(
        session.scalars(
            sa.select(Alert)
            .where(
                Alert.tenant_id == tenant_id,
                Alert.incident_id == incident_id,
                Alert.id.not_in(seen_alerts) if seen_alerts else sa.true(),
            )
            .order_by(Alert.started_at, Alert.id)
            .limit(remaining)
        )
    )
    for alert in alerts:
        content = json.dumps(
            {"title": alert.title, "labels": alert.labels, "annotations": alert.annotations},
            sort_keys=True,
            ensure_ascii=True,
        )[:MAX_ALERT_BLOCK_CHARS]
        blocks.append(
            UntrustedBlock(
                source=f"alert:{alert.id}",
                provenance=ProvenanceLabel.RETRIEVED,
                content=content,
            )
        )
    return tuple(blocks)


__all__ = ["MAX_ALERT_BLOCKS", "incident_alert_blocks"]
