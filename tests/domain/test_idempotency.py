"""Idempotency key derivation.

The property that matters is *discrimination*: keys must collide for genuinely identical
operations and differ for genuinely different ones. A key that never collides makes
deduplication useless; a key that collides too eagerly suppresses real work.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest

from asic.domain.idempotency import (
    KEY_LENGTH,
    action_version_hash,
    alert_key,
    approval_callback_key,
    incident_event_key,
    remediation_request_key,
    tool_execution_key,
    verification_callback_key,
)

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
INCIDENT = uuid.UUID("33333333-3333-3333-3333-333333333333")
ACTION = uuid.UUID("44444444-4444-4444-4444-444444444444")
STARTED = datetime(2026, 3, 11, 2, 14, tzinfo=UTC)


class TestAlertKey:
    def test_redelivery_of_the_same_alert_collides(self) -> None:
        """Alertmanager re-delivers until acknowledged; this is the common path."""
        a = alert_key(
            tenant_id=TENANT, source="alertmanager", source_fingerprint="abc", started_at=STARTED
        )
        b = alert_key(
            tenant_id=TENANT, source="alertmanager", source_fingerprint="abc", started_at=STARTED
        )
        assert a == b
        assert len(a) == KEY_LENGTH

    def test_a_new_firing_of_the_same_rule_is_a_new_alert(self) -> None:
        """Same fingerprint, later start time: a genuinely new occurrence, not a duplicate."""
        first = alert_key(
            tenant_id=TENANT, source="alertmanager", source_fingerprint="abc", started_at=STARTED
        )
        second = alert_key(
            tenant_id=TENANT,
            source="alertmanager",
            source_fingerprint="abc",
            started_at=STARTED + timedelta(hours=3),
        )
        assert first != second

    def test_tenants_do_not_collide(self) -> None:
        a = alert_key(
            tenant_id=TENANT, source="alertmanager", source_fingerprint="abc", started_at=STARTED
        )
        b = alert_key(
            tenant_id=OTHER_TENANT,
            source="alertmanager",
            source_fingerprint="abc",
            started_at=STARTED,
        )
        assert a != b

    def test_sources_do_not_collide(self) -> None:
        a = alert_key(
            tenant_id=TENANT, source="alertmanager", source_fingerprint="abc", started_at=STARTED
        )
        b = alert_key(
            tenant_id=TENANT, source="pagerduty", source_fingerprint="abc", started_at=STARTED
        )
        assert a != b

    def test_naive_timestamps_are_rejected(self) -> None:
        """A naive datetime produces different keys in different processes."""
        with pytest.raises(ValueError, match="timezone-aware"):
            alert_key(
                tenant_id=TENANT,
                source="alertmanager",
                source_fingerprint="abc",
                started_at=datetime(2026, 3, 11, 2, 14),
            )

    def test_equal_instants_in_different_zones_collide(self) -> None:
        """The same moment expressed in another offset is the same alert."""
        kolkata = timezone(timedelta(hours=5, minutes=30))
        utc = alert_key(tenant_id=TENANT, source="am", source_fingerprint="x", started_at=STARTED)
        shifted = alert_key(
            tenant_id=TENANT,
            source="am",
            source_fingerprint="x",
            started_at=STARTED.astimezone(kolkata),
        )
        assert utc == shifted


class TestToolExecutionKey:
    def test_same_effect_collides_regardless_of_which_action_asked(self) -> None:
        """The key is composed from the *effect*, deliberately not from the action id.

        Two different proposals asking for the same change must collide. Including the
        action id would let them both execute, which is the double-apply this key exists
        to prevent.
        """
        scope = {"cluster": "prod-eu", "namespace": "checkout", "deployment": "checkout-api"}
        a = tool_execution_key(
            tenant_id=TENANT,
            tool_name="k8s.deployment.rollback",
            tool_major_version=1,
            scope_arguments=scope,
        )
        b = tool_execution_key(
            tenant_id=TENANT,
            tool_name="k8s.deployment.rollback",
            tool_major_version=1,
            scope_arguments=dict(reversed(list(scope.items()))),
        )
        assert a == b, "argument ordering must not affect the key"

    def test_different_targets_do_not_collide(self) -> None:
        base = {"cluster": "prod-eu", "namespace": "checkout", "deployment": "checkout-api"}
        other = {**base, "namespace": "payments"}
        a = tool_execution_key(
            tenant_id=TENANT,
            tool_name="k8s.deployment.rollback",
            tool_major_version=1,
            scope_arguments=base,
        )
        b = tool_execution_key(
            tenant_id=TENANT,
            tool_name="k8s.deployment.rollback",
            tool_major_version=1,
            scope_arguments=other,
        )
        assert a != b

    def test_major_version_participates_but_the_key_is_stable_within_it(self) -> None:
        scope = {"cluster": "prod-eu"}
        v1 = tool_execution_key(
            tenant_id=TENANT, tool_name="t", tool_major_version=1, scope_arguments=scope
        )
        v2 = tool_execution_key(
            tenant_id=TENANT, tool_name="t", tool_major_version=2, scope_arguments=scope
        )
        assert v1 != v2


class TestActionVersionHash:
    def test_identical_actions_hash_identically(self) -> None:
        kwargs = {
            "action_id": ACTION,
            "tool_name": "k8s.deployment.rollback",
            "tool_version": "1.2.0",
            "arguments": {"namespace": "checkout", "to_revision": 846},
            "permission_scope": {"namespaces": ["checkout"]},
            "preconditions": ["deployment_exists"],
            "risk_tier": "r1",
        }
        assert action_version_hash(**kwargs) == action_version_hash(**kwargs)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "field,mutation",
        [
            ("arguments", {"namespace": "payments", "to_revision": 846}),
            ("arguments", {"namespace": "checkout", "to_revision": 800}),
            ("permission_scope", {"namespaces": ["checkout", "payments"]}),
            ("preconditions", ["deployment_exists", "extra"]),
            ("risk_tier", "r2"),
            ("tool_version", "2.0.0"),
        ],
    )
    def test_any_material_change_invalidates_the_approval(
        self, field: str, mutation: object
    ) -> None:
        """SI-6: approve a small change, execute a large one - must be impossible."""
        base = {
            "action_id": ACTION,
            "tool_name": "k8s.deployment.rollback",
            "tool_version": "1.2.0",
            "arguments": {"namespace": "checkout", "to_revision": 846},
            "permission_scope": {"namespaces": ["checkout"]},
            "preconditions": ["deployment_exists"],
            "risk_tier": "r1",
        }
        approved = action_version_hash(**base)  # type: ignore[arg-type]
        mutated = action_version_hash(**{**base, field: mutation})  # type: ignore[arg-type]
        assert approved != mutated


class TestCallbackKeys:
    def test_approval_callback_is_bound_to_the_action_version(self) -> None:
        """A reply to an earlier version must not satisfy a re-proposed action."""
        first = approval_callback_key(
            tenant_id=TENANT, action_id=ACTION, action_version_hash_value="aaa"
        )
        second = approval_callback_key(
            tenant_id=TENANT, action_id=ACTION, action_version_hash_value="bbb"
        )
        assert first != second

    def test_duplicate_approval_delivery_collides(self) -> None:
        a = approval_callback_key(
            tenant_id=TENANT, action_id=ACTION, action_version_hash_value="aaa"
        )
        b = approval_callback_key(
            tenant_id=TENANT, action_id=ACTION, action_version_hash_value="aaa"
        )
        assert a == b

    def test_verification_attempts_are_distinct(self) -> None:
        first = verification_callback_key(tenant_id=TENANT, action_id=ACTION, attempt=1)
        second = verification_callback_key(tenant_id=TENANT, action_id=ACTION, attempt=2)
        assert first != second

    def test_remediation_request_dedupes_replanning_loops(self) -> None:
        hypothesis = uuid.uuid4()
        scope = {"namespace": "checkout"}
        a = remediation_request_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            hypothesis_id=hypothesis,
            tool_name="t",
            scope_arguments=scope,
        )
        b = remediation_request_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            hypothesis_id=hypothesis,
            tool_name="t",
            scope_arguments=scope,
        )
        assert a == b


class TestIncidentEventKey:
    def test_same_subject_and_type_collides(self) -> None:
        subject = uuid.uuid4()
        a = incident_event_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            event_type="execution.started",
            subject_id=subject,
        )
        b = incident_event_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            event_type="execution.started",
            subject_id=subject,
        )
        assert a == b

    def test_discriminator_allows_legitimate_repetition(self) -> None:
        """A second checkpoint for the same subject is a new event, not a duplicate."""
        subject = uuid.uuid4()
        first = incident_event_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            event_type="workflow.checkpointed",
            subject_id=subject,
            occurrence_discriminator="1",
        )
        second = incident_event_key(
            tenant_id=TENANT,
            incident_id=INCIDENT,
            event_type="workflow.checkpointed",
            subject_id=subject,
            occurrence_discriminator="2",
        )
        assert first != second
