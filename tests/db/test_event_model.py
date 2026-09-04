"""Event log, projections and duplicate handling against a real database.

The event log is the system of record, so these tests exercise the properties that make it
trustworthy: gapless sequencing, idempotent append, immutability, and a derived status and
timeline that cannot disagree with the log they came from.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from asic.db.models import Alert, IncidentEvent, TimelineEvent
from asic.db.projections import (
    append_incident_event,
    apply_transition,
    assert_status_matches_log,
    event_sequence_gaps,
    project_timeline,
    recompute_incident_status,
)
from asic.db.session import bind_tenant
from asic.domain.enums import (
    ActorType,
    AlertSeverity,
    AlertStatus,
    EventCategory,
    IncidentEventType,
    IncidentStatus,
    ProvenanceLabel,
    TerminationReason,
)
from asic.domain.errors import IllegalStateTransition
from asic.domain.idempotency import alert_key
from tests.conftest import make_environment, make_incident, make_service, make_tenant

pytestmark = pytest.mark.postgres

NOW = datetime.now(UTC)


def _setup(session: Session, slug: str = "acme"):
    tenant = make_tenant(session, slug)
    bind_tenant(session, tenant.id)
    env = make_environment(session, tenant)
    incident = make_incident(session, tenant, env)
    return tenant, env, incident


def _append(session: Session, incident, event_type=IncidentEventType.EVIDENCE_RECORDED, **kw):
    return append_incident_event(
        session,
        incident=incident,
        event_type=event_type,
        source="test",
        actor_type=ActorType.SYSTEM,
        correlation_id=kw.pop("correlation_id", uuid.uuid4()),
        **kw,
    )


class TestGaplessSequencing:
    def test_sequences_start_at_one_and_increment(self, app_session: Session) -> None:
        _, _, incident = _setup(app_session)
        results = [_append(app_session, incident) for _ in range(5)]
        assert [r.event.sequence for r in results] == [1, 2, 3, 4, 5]

    def test_no_gaps_are_produced(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        for _ in range(10):
            _append(app_session, incident)
        assert event_sequence_gaps(app_session, tenant_id=tenant.id, incident_id=incident.id) == []

    def test_the_gap_detector_actually_detects_a_gap(self, app_session: Session) -> None:
        """A gaplessness check that cannot fail proves nothing."""
        tenant, _, incident = _setup(app_session)
        for _ in range(3):
            _append(app_session, incident)
        # Simulate a lost event by inserting out of band at sequence 5.
        app_session.add(
            IncidentEvent(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                incident_id=incident.id,
                sequence=5,
                event_type=IncidentEventType.EVIDENCE_RECORDED,
                category=EventCategory.INTERNAL,
                source="test",
                occurred_at=NOW,
                correlation_id=uuid.uuid4(),
                actor_type=ActorType.SYSTEM,
                provenance=ProvenanceLabel.SYSTEM,
            )
        )
        app_session.flush()
        assert event_sequence_gaps(app_session, tenant_id=tenant.id, incident_id=incident.id) == [4]

    def test_duplicate_sequence_is_refused(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        _append(app_session, incident)
        app_session.add(
            IncidentEvent(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                incident_id=incident.id,
                sequence=1,
                event_type=IncidentEventType.EVIDENCE_RECORDED,
                category=EventCategory.INTERNAL,
                source="test",
                occurred_at=NOW,
                correlation_id=uuid.uuid4(),
                actor_type=ActorType.SYSTEM,
                provenance=ProvenanceLabel.SYSTEM,
            )
        )
        with pytest.raises(IntegrityError, match="uq_incident_event_sequence"):
            app_session.flush()


class TestIdempotentAppend:
    def test_the_same_key_appends_once(self, app_session: Session) -> None:
        _, _, incident = _setup(app_session)
        key = uuid.uuid4().hex * 2

        first = _append(app_session, incident, idempotency_key=key)
        second = _append(app_session, incident, idempotency_key=key)

        assert first.created is True
        assert second.created is False
        assert second.event.id == first.event.id
        assert first.event.sequence == 1

    def test_a_redelivery_does_not_consume_a_sequence_number(self, app_session: Session) -> None:
        """A duplicate must not leave a hole in the stream."""
        tenant, _, incident = _setup(app_session)
        key = uuid.uuid4().hex * 2
        _append(app_session, incident, idempotency_key=key)
        _append(app_session, incident, idempotency_key=key)
        _append(app_session, incident)

        assert event_sequence_gaps(app_session, tenant_id=tenant.id, incident_id=incident.id) == []

    def test_events_without_a_key_are_legitimately_repeatable(self, app_session: Session) -> None:
        """Two checkpoints are two events, not a duplicate."""
        _, _, incident = _setup(app_session)
        a = _append(app_session, incident, event_type=IncidentEventType.WORKFLOW_CHECKPOINTED)
        b = _append(app_session, incident, event_type=IncidentEventType.WORKFLOW_CHECKPOINTED)
        assert a.event.id != b.event.id

    def test_keys_do_not_collide_across_tenants(self, app_session: Session) -> None:
        key = uuid.uuid4().hex * 2
        _, _, acme_incident = _setup(app_session, "acme")
        _append(app_session, acme_incident, idempotency_key=key)

        from asic.db.session import clear_tenant

        clear_tenant(app_session)
        _, _, globex_incident = _setup(app_session, "globex")
        result = _append(app_session, globex_incident, idempotency_key=key)
        assert result.created is True


class TestExternalEventProvenance:
    def test_an_external_event_cannot_be_stored_as_authoritative(
        self, app_session: Session
    ) -> None:
        """SEC-I4, enforced by the database rather than only by the envelope class."""
        tenant, _, incident = _setup(app_session)
        app_session.add(
            IncidentEvent(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                incident_id=incident.id,
                sequence=1,
                event_type=IncidentEventType.ALERT_RECEIVED,
                category=EventCategory.EXTERNAL,
                source="alertmanager",
                occurred_at=NOW,
                correlation_id=uuid.uuid4(),
                actor_type=ActorType.EXTERNAL_SYSTEM,
                provenance=ProvenanceLabel.SYSTEM,  # forbidden for external content
            )
        )
        with pytest.raises(IntegrityError, match="external_events_are_not_authoritative"):
            app_session.flush()

    def test_an_external_event_with_untrusted_provenance_is_accepted(
        self, app_session: Session
    ) -> None:
        _, _, incident = _setup(app_session)
        result = _append(
            app_session,
            incident,
            event_type=IncidentEventType.ALERT_RECEIVED,
            provenance=ProvenanceLabel.RETRIEVED,
        )
        assert result.event.category is EventCategory.EXTERNAL


class TestStateTransitionsAgainstTheLog:
    def test_a_transition_writes_status_and_event_together(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        apply_transition(
            app_session,
            incident=incident,
            target=IncidentStatus.INVESTIGATING,
            actor_type=ActorType.SYSTEM,
            source="g2_incident_coordinator",
            correlation_id=uuid.uuid4(),
        )
        assert incident.status is IncidentStatus.INVESTIGATING
        derived = recompute_incident_status(
            app_session, tenant_id=tenant.id, incident_id=incident.id
        )
        assert derived is IncidentStatus.INVESTIGATING
        assert_status_matches_log(app_session, tenant_id=tenant.id, incident_id=incident.id)

    def test_an_illegal_transition_writes_nothing(self, app_session: Session) -> None:
        """The machine validates before touching the database, so a refused transition
        leaves neither a status change nor an event behind.

        Deliberately no rollback here: rolling back would also discard the incident and
        make the assertion below true for the wrong reason.
        """
        _, _, incident = _setup(app_session)
        # A real event first, so "nothing was written" is distinguishable from "nothing
        # exists".
        _append(app_session, incident)
        before = app_session.execute(
            sa.select(sa.func.count()).select_from(IncidentEvent)
        ).scalar_one()

        with pytest.raises(IllegalStateTransition, match="not a permitted transition"):
            apply_transition(
                app_session,
                incident=incident,
                target=IncidentStatus.RESOLVED,
                actor_type=ActorType.SYSTEM,
                source="test",
                correlation_id=uuid.uuid4(),
                termination_reason=TerminationReason.SUCCESS,
            )

        after = app_session.execute(
            sa.select(sa.func.count()).select_from(IncidentEvent)
        ).scalar_one()
        assert after == before == 1
        assert incident.status is IncidentStatus.DETECTED, "status must be unchanged"

    def test_terminal_transition_records_reason_and_timestamp(self, app_session: Session) -> None:
        _, _, incident = _setup(app_session)
        cid = uuid.uuid4()
        apply_transition(
            app_session,
            incident=incident,
            target=IncidentStatus.INVESTIGATING,
            actor_type=ActorType.SYSTEM,
            source="test",
            correlation_id=cid,
        )
        apply_transition(
            app_session,
            incident=incident,
            target=IncidentStatus.UNCERTAIN,
            actor_type=ActorType.SYSTEM,
            source="test",
            correlation_id=cid,
            termination_reason=TerminationReason.INSUFFICIENT_EVIDENCE,
        )
        assert incident.terminated_at is not None
        assert incident.termination_reason is TerminationReason.INSUFFICIENT_EVIDENCE

    def test_status_divergence_from_the_log_is_detected(self, app_session: Session) -> None:
        """If something writes the status column without an event, say so loudly."""
        tenant, _, incident = _setup(app_session)
        apply_transition(
            app_session,
            incident=incident,
            target=IncidentStatus.INVESTIGATING,
            actor_type=ActorType.SYSTEM,
            source="test",
            correlation_id=uuid.uuid4(),
        )
        app_session.execute(
            sa.text(
                "UPDATE incident SET status = 'escalated', terminated_at = now(), "
                "termination_reason = 'human_escalation' WHERE id = :i"
            ),
            {"i": incident.id},
        )
        app_session.expire_all()
        with pytest.raises(IllegalStateTransition, match="written without a corresponding"):
            assert_status_matches_log(app_session, tenant_id=tenant.id, incident_id=incident.id)


class TestTimelineProjection:
    def test_projection_is_derived_and_cites_its_source(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        apply_transition(
            app_session,
            incident=incident,
            target=IncidentStatus.INVESTIGATING,
            actor_type=ActorType.SYSTEM,
            source="test",
            correlation_id=uuid.uuid4(),
        )
        created = project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        assert created == 1

        entries = list(app_session.execute(sa.select(TimelineEvent)).scalars())
        assert all(e.source_event_id is not None for e in entries)

    def test_projection_is_idempotent(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        _append(app_session, incident)
        first = project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        second = project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        assert first == 1
        assert second == 0, "re-running the projection must not duplicate entries"

    def test_bookkeeping_events_are_recorded_but_not_projected(self, app_session: Session) -> None:
        tenant, _, incident = _setup(app_session)
        _append(app_session, incident, event_type=IncidentEventType.WORKFLOW_CHECKPOINTED)
        created = project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        assert created == 0

    def test_projection_is_deterministic(self, app_session: Session) -> None:
        """Identical events must yield an identical timeline."""
        tenant, _, incident = _setup(app_session)
        for _ in range(3):
            _append(app_session, incident)
        project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        first = [
            (e.sequence, e.category, e.summary)
            for e in app_session.execute(
                sa.select(TimelineEvent).order_by(TimelineEvent.sequence)
            ).scalars()
        ]

        app_session.execute(sa.delete(TimelineEvent))
        project_timeline(app_session, tenant_id=tenant.id, incident_id=incident.id)
        second = [
            (e.sequence, e.category, e.summary)
            for e in app_session.execute(
                sa.select(TimelineEvent).order_by(TimelineEvent.sequence)
            ).scalars()
        ]
        assert first == second


class TestDuplicateAlerts:
    def _alert(self, tenant, service, env, started: datetime, source="alertmanager") -> Alert:
        return Alert(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            source=source,
            source_fingerprint="abc123",
            idempotency_key=alert_key(
                tenant_id=tenant.id,
                source=source,
                source_fingerprint="abc123",
                started_at=started,
            ),
            service_id=service.id,
            environment_id=env.id,
            severity=AlertSeverity.HIGH,
            title="checkout latency p99 breached",
            started_at=started,
        )

    def test_redelivery_of_the_same_alert_is_refused(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        service = make_service(app_session, tenant)

        app_session.add(self._alert(tenant, service, env, NOW))
        app_session.flush()
        app_session.add(self._alert(tenant, service, env, NOW))
        with pytest.raises(IntegrityError, match="uq_alert_idempotency"):
            app_session.flush()

    def test_a_later_firing_of_the_same_rule_is_a_new_alert(self, app_session: Session) -> None:
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        service = make_service(app_session, tenant)

        app_session.add(self._alert(tenant, service, env, NOW))
        app_session.add(self._alert(tenant, service, env, NOW + timedelta(hours=2)))
        app_session.flush()
        count = app_session.execute(sa.select(sa.func.count()).select_from(Alert)).scalar_one()
        assert count == 2

    def test_a_dead_lettered_alert_must_record_why(self, app_session: Session) -> None:
        """FR-ING-05: nothing is silently dropped."""
        tenant = make_tenant(app_session, "acme")
        bind_tenant(app_session, tenant.id)
        env = make_environment(app_session, tenant)
        service = make_service(app_session, tenant)

        alert = self._alert(tenant, service, env, NOW)
        alert.status = AlertStatus.DEAD_LETTERED
        app_session.add(alert)
        with pytest.raises(IntegrityError, match="dead_letter_has_reason"):
            app_session.flush()
