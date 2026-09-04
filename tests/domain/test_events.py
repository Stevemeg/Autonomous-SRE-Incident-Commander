"""Event envelope contract, classification and timeline projection rules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from asic.domain.enums import (
    ActorType,
    EventCategory,
    IncidentEventType,
    ProvenanceLabel,
    TimelineCategory,
)
from asic.domain.events import (
    AUDIT_CRITICAL_EVENTS,
    CURRENT_PAYLOAD_SCHEMA_VERSION,
    TIMELINE_RULES,
    EventEnvelope,
    classify,
    is_visible_on_timeline,
    timeline_rule,
    unmapped_event_types,
)

NOW = datetime(2026, 3, 11, 2, 14, tzinfo=UTC)


def _envelope(**overrides: object) -> EventEnvelope:
    defaults: dict[str, object] = {
        "event_id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "incident_id": uuid.uuid4(),
        "sequence": 1,
        "event_type": IncidentEventType.EVIDENCE_RECORDED,
        "category": EventCategory.INTERNAL,
        "source": "g4_evidence_collector",
        "occurred_at": NOW,
        "recorded_at": NOW,
        "correlation_id": uuid.uuid4(),
        "causation_id": None,
        "actor_type": ActorType.AGENT_NODE,
        "actor_id": "g4_evidence_collector",
        "provenance": ProvenanceLabel.VERIFIED_FACT,
        "payload_schema_version": CURRENT_PAYLOAD_SCHEMA_VERSION,
    }
    return EventEnvelope(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestClassification:
    def test_alert_received_is_external(self) -> None:
        assert classify(IncidentEventType.ALERT_RECEIVED) is EventCategory.EXTERNAL

    def test_correlation_decided_is_derived(self) -> None:
        assert classify(IncidentEventType.CORRELATION_DECIDED) is EventCategory.DERIVED

    def test_node_emitted_events_are_internal(self) -> None:
        assert classify(IncidentEventType.HYPOTHESIS_FORMED) is EventCategory.INTERNAL

    def test_every_event_type_classifies(self) -> None:
        for event_type in IncidentEventType:
            assert isinstance(classify(event_type), EventCategory)


class TestEnvelopeInvariants:
    def test_valid_envelope_constructs(self) -> None:
        assert _envelope().sequence == 1

    def test_sequence_starts_at_one(self) -> None:
        with pytest.raises(ValueError, match="sequence starts at 1"):
            _envelope(sequence=0)

    def test_naive_timestamps_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            _envelope(occurred_at=datetime(2026, 3, 11, 2, 14))

    def test_category_must_match_the_event_type(self) -> None:
        """A caller cannot relabel an external event as internal to smuggle authority."""
        with pytest.raises(ValueError, match="is a external event"):
            _envelope(
                event_type=IncidentEventType.ALERT_RECEIVED,
                category=EventCategory.INTERNAL,
                provenance=ProvenanceLabel.RETRIEVED,
            )

    @pytest.mark.parametrize("provenance", [ProvenanceLabel.SYSTEM, ProvenanceLabel.HUMAN])
    def test_external_events_cannot_carry_authority(self, provenance: ProvenanceLabel) -> None:
        """SEC-I4: content arriving from outside our boundary is never authoritative."""
        with pytest.raises(ValueError, match="may not carry authority-bearing provenance"):
            _envelope(
                event_type=IncidentEventType.ALERT_RECEIVED,
                category=EventCategory.EXTERNAL,
                provenance=provenance,
            )

    def test_external_event_with_untrusted_provenance_is_accepted(self) -> None:
        envelope = _envelope(
            event_type=IncidentEventType.ALERT_RECEIVED,
            category=EventCategory.EXTERNAL,
            provenance=ProvenanceLabel.RETRIEVED,
            actor_type=ActorType.EXTERNAL_SYSTEM,
        )
        assert envelope.provenance.is_untrusted


class TestProvenanceAuthority:
    def test_only_system_and_human_confer_authority(self) -> None:
        authority = {p for p in ProvenanceLabel if p.confers_authority}
        assert authority == {ProvenanceLabel.SYSTEM, ProvenanceLabel.HUMAN}

    def test_retrieved_and_model_claims_are_untrusted(self) -> None:
        assert ProvenanceLabel.RETRIEVED.is_untrusted
        assert ProvenanceLabel.MODEL_CLAIM.is_untrusted

    def test_verified_fact_is_citable_but_not_authoritative(self) -> None:
        """Evidence is true; it still does not authorise an action."""
        assert not ProvenanceLabel.VERIFIED_FACT.confers_authority
        assert not ProvenanceLabel.VERIFIED_FACT.is_untrusted


class TestTimelineProjection:
    def test_every_event_type_has_a_projection_rule(self) -> None:
        """Adding an event type must force a projection decision, not default silently."""
        assert unmapped_event_types() == frozenset()

    def test_rules_cover_exactly_the_vocabulary(self) -> None:
        assert set(TIMELINE_RULES) == set(IncidentEventType)

    def test_bookkeeping_events_are_recorded_but_not_shown(self) -> None:
        assert not is_visible_on_timeline(IncidentEventType.WORKFLOW_CHECKPOINTED)
        assert not is_visible_on_timeline(IncidentEventType.ALERT_NORMALISED)

    def test_decision_events_are_visible(self) -> None:
        for event_type in (
            IncidentEventType.POLICY_EVALUATED,
            IncidentEventType.APPROVAL_GRANTED,
            IncidentEventType.EXECUTION_COMPLETED,
            IncidentEventType.VERIFICATION_RESULT,
        ):
            assert is_visible_on_timeline(event_type), event_type

    def test_safety_events_are_categorised_as_decisions_or_actions(self) -> None:
        assert timeline_rule(IncidentEventType.POLICY_EVALUATED).category is (
            TimelineCategory.DECISION
        )
        assert timeline_rule(IncidentEventType.EXECUTION_STARTED).category is (
            TimelineCategory.ACTION
        )


class TestAuditCriticalEvents:
    def test_every_approval_and_execution_event_is_audit_critical(self) -> None:
        must_be_critical = {
            e
            for e in IncidentEventType
            if e.value.startswith(("approval.", "execution.", "compensation."))
            or e is IncidentEventType.POLICY_EVALUATED
        }
        missing = must_be_critical - AUDIT_CRITICAL_EVENTS
        assert missing == set(), f"not marked audit-critical: {sorted(e.value for e in missing)}"
