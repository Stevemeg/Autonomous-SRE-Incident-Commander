"""Explainable correlation policy v1. No weights, model calls, or implicit causation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

POLICY_VERSION = "service-category-window/2"
WINDOW_SECONDS = 900
MAX_CANDIDATES = 256


@dataclass(frozen=True)
class Candidate:
    incident_id: UUID
    environment_id: UUID
    service_id: UUID | None
    category: str | None
    started_at: datetime
    active: bool


def explain(
    candidate: Candidate,
    *,
    environment_id: UUID,
    service_id: UUID,
    category: str,
    started_at: datetime,
) -> dict[str, Any]:
    factors = {
        "environment_equal": candidate.environment_id == environment_id,
        "service_equal": candidate.service_id == service_id,
        "category_equal": candidate.category == category,
        "within_window": abs((candidate.started_at - started_at).total_seconds()) <= WINDOW_SECONDS,
        "incident_active": candidate.active,
    }
    return {
        "incident_id": str(candidate.incident_id),
        "factors": factors,
        "anchor_started_at": candidate.started_at.isoformat(),
        "matched": all(factors.values()),
        "reasons": [key for key, passed in factors.items() if not passed],
    }


def decide(
    candidates: list[Candidate],
    *,
    environment_id: UUID,
    service_id: UUID,
    category: str,
    started_at: datetime,
) -> dict[str, Any]:
    considered = [
        explain(
            c,
            environment_id=environment_id,
            service_id=service_id,
            category=category,
            started_at=started_at,
        )
        for c in candidates
    ]
    matches = sorted(
        (c for c in considered if c["matched"]),
        key=lambda item: (
            abs((datetime.fromisoformat(item["anchor_started_at"]) - started_at).total_seconds()),
            item["incident_id"],
        ),
    )
    selected = matches[0]["incident_id"] if matches else None
    return {
        "policy_version": POLICY_VERSION,
        "window_seconds": WINDOW_SECONDS,
        "candidate_scope": (
            "same tenant, environment, service, category and active state; opening anchor "
            "within +/- window; predicates applied before the bound"
        ),
        "outside_window": "excluded by fixed anchor-time predicate",
        "unanchored_incidents": "excluded: no ingestion correlation anchor",
        "cross_tenant": "excluded by authenticated context and RLS",
        "considered": considered,
        "selected": selected,
        "result": "join" if matches else "new",
        "reason": "unique_match"
        if len(matches) == 1
        else "deterministic_tie_break"
        if matches
        else "no_match",
        "tie_break": {
            "method": "minimum_absolute_anchor_delta_then_incident_uuid",
            "ordered_matches": [item["incident_id"] for item in matches],
            "winner": selected,
        },
    }
