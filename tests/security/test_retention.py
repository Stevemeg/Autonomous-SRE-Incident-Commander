"""Phase 13 data-retention controls: classification, policy and the dry-run planner.

The application role cannot delete anything (see ``test_tenancy_and_grants.py``), so these
tests prove the *policy* layer is complete and cannot be tricked into recommending removal of
protected evidence - and that the preview a lifecycle job would act on is tenant-bound,
bounded and deterministic.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ApiIdempotencyRecord, Base
from asic.db.session import bind_tenant
from asic.retention import (
    CLASS_POLICIES,
    TABLE_CLASSIFICATION,
    RetentionAction,
    RetentionClass,
    RetentionPolicyError,
    plan_retention,
    validate_retention_policy,
)
from tests.conftest import make_tenant

pytestmark = pytest.mark.security

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


class TestClassification:
    def test_every_table_in_the_schema_is_classified_exactly_once(self) -> None:
        mapped = {m.class_.__tablename__ for m in Base.registry.mappers}
        assert set(TABLE_CLASSIFICATION) >= mapped
        assert set(TABLE_CLASSIFICATION) - mapped <= {"alembic_version"}

    @pytest.mark.postgres
    def test_the_classification_equals_the_live_schema(self, owner_session: Session) -> None:
        live = set(
            owner_session.scalars(
                sa.text(
                    "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' AND c.relkind = 'r'"
                )
            )
        )
        assert live == set(TABLE_CLASSIFICATION), (
            f"unclassified: {sorted(live - set(TABLE_CLASSIFICATION))}; "
            f"stale: {sorted(set(TABLE_CLASSIFICATION) - live)}"
        )

    def test_authority_and_identity_tables_are_never_in_a_time_eligible_class(self) -> None:
        """Nothing that decides who may do what ages out by time alone."""
        for table in (
            "audit_record",
            "approval",
            "user_role_assignment",
            "app_user",
            "connector_scope_binding",
            "integration_connector",
            "tenant_tool_grant",
        ):
            assert not CLASS_POLICIES[TABLE_CLASSIFICATION[table]].time_eligible, table

    def test_only_the_operational_cache_is_ever_previewed_as_eligible(self) -> None:
        previewable = {
            c
            for c, p in CLASS_POLICIES.items()
            if c is RetentionClass.OPERATIONAL_CACHE and p.time_eligible
        }
        assert previewable == {RetentionClass.OPERATIONAL_CACHE}
        cache_tables = {
            t for t, c in TABLE_CLASSIFICATION.items() if c is RetentionClass.OPERATIONAL_CACHE
        }
        assert cache_tables == {"api_idempotency_record"}

    def test_protected_evidence_is_never_time_eligible_and_has_a_floor(self) -> None:
        protected = CLASS_POLICIES[RetentionClass.PROTECTED_EVIDENCE]
        assert protected.time_eligible is False
        assert protected.minimum_days == 2555  # a platform default, not a legal claim
        for table in (
            "audit_record",
            "approval",
            "policy_decision",
            "verification",
            "remediation_action",
            "remediation_target",
            "remediation_baseline",
            "tool_execution",
            "model_call_reservation",
            "connector_scope_binding",
        ):
            assert TABLE_CLASSIFICATION[table] is RetentionClass.PROTECTED_EVIDENCE


class TestPolicyValidation:
    def test_empty_policy_resolves_to_platform_defaults(self) -> None:
        resolved = validate_retention_policy(None)
        assert resolved[RetentionClass.OPERATIONAL_CACHE].days == 30
        assert resolved[RetentionClass.PROTECTED_EVIDENCE].days is None
        assert not any(entry.hold for entry in resolved.values())

    def test_a_tenant_may_lengthen_but_never_shorten_below_the_floor(self) -> None:
        assert (
            validate_retention_policy({"protected_evidence": {"days": 3650}})[
                RetentionClass.PROTECTED_EVIDENCE
            ].days
            == 3650
        )
        with pytest.raises(RetentionPolicyError):
            validate_retention_policy({"protected_evidence": {"days": 30}})
        with pytest.raises(RetentionPolicyError):
            validate_retention_policy({"incident_record": {"days": 364}})

    @pytest.mark.parametrize(
        "policy",
        [
            {"audit": {"days": 9999}},  # unknown class (typo must not mean "no policy")
            {"knowledge_content": {"days": 10}},  # not configurable by age
            {"global_catalogue": {"days": 10}},
            {"operational_cache": {"days": "30"}},
            {"operational_cache": {"days": True}},
            {"operational_cache": {"days": 0}},
            {"operational_cache": {"days": 366}},
            {"operational_cache": {"days": -5}},
            {"operational_cache": {"days": 3.5}},
            {"operational_cache": {"days": 10, "unexpected": 1}},
            {"operational_cache": {"hold": "yes"}},
            {"operational_cache": "30"},
            {"operational_cache": None},
            {1: {"days": 5}},
            {"operational_cache": {"days": 10**9}},
        ],
    )
    def test_malformed_or_unsafe_policies_are_refused(self, policy: dict[object, object]) -> None:
        with pytest.raises(RetentionPolicyError) as info:
            validate_retention_policy(policy)  # type: ignore[arg-type]
        assert "10000000" not in str(info.value)  # caller values are not echoed

    def test_a_hold_is_accepted_for_any_configurable_class(self) -> None:
        resolved = validate_retention_policy({"operational_cache": {"days": 30, "hold": True}})
        assert resolved[RetentionClass.OPERATIONAL_CACHE].hold is True


def _record(session: Session, tenant_id: uuid.UUID, age_days: int, key: str) -> uuid.UUID:
    record = ApiIdempotencyRecord(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        principal_id=uuid.uuid4(),
        idempotency_key=key,
        operation="op",
        request_digest="0" * 64,
        response_body={},
        created_at=NOW - timedelta(days=age_days),  # set at insert: no role may UPDATE it
    )
    session.add(record)
    session.flush()
    return record.id


@pytest.mark.postgres
class TestPlanner:
    def test_the_plan_covers_every_table_with_a_reason_and_deletes_nothing(
        self, owner_session: Session
    ) -> None:
        tenant = make_tenant(owner_session, f"ret-{uuid.uuid4().hex[:8]}")
        bind_tenant(owner_session, tenant.id)
        plan = plan_retention(owner_session, tenant_id=tenant.id, policy={}, now=NOW)
        assert plan.dry_run is True
        assert [r.table for r in plan.rows] == sorted(TABLE_CLASSIFICATION)
        assert all(r.reason for r in plan.rows)
        by_table = {r.table: r for r in plan.rows}
        assert by_table["audit_record"].action is RetentionAction.RETAIN
        assert by_table["incident"].action is RetentionAction.RETAIN  # no days configured
        assert by_table["tenant"].action is RetentionAction.RETAIN

    def test_configured_time_classes_are_owner_lifecycle_only_never_previewed_as_deletable(
        self, owner_session: Session
    ) -> None:
        tenant = make_tenant(owner_session, f"ret-{uuid.uuid4().hex[:8]}")
        bind_tenant(owner_session, tenant.id)
        plan = plan_retention(
            owner_session,
            tenant_id=tenant.id,
            policy={"incident_record": {"days": 400}, "execution_trace": {"days": 100}},
            now=NOW,
        )
        by_table = {r.table: r for r in plan.rows}
        assert by_table["incident"].action is RetentionAction.OWNER_LIFECYCLE
        assert by_table["trace_span"].action is RetentionAction.OWNER_LIFECYCLE
        assert by_table["incident"].cutoff == NOW - timedelta(days=400)
        assert plan.eligible() == ()  # only the cache can ever be counted as eligible

    def test_the_preview_counts_exactly_the_rows_a_direct_query_finds(
        self, owner_session: Session
    ) -> None:
        tenant = make_tenant(owner_session, f"ret-{uuid.uuid4().hex[:8]}")
        bind_tenant(owner_session, tenant.id)
        for age, key in ((45, "old-1"), (31, "old-2"), (29, "fresh-1"), (1, "fresh-2")):
            _record(owner_session, tenant.id, age, f"{key}-{uuid.uuid4().hex[:6]}")
        plan = plan_retention(owner_session, tenant_id=tenant.id, policy={}, now=NOW)
        (row,) = [r for r in plan.eligible() if r.table == "api_idempotency_record"]
        cutoff = NOW - timedelta(days=30)
        direct = owner_session.scalar(
            sa.select(sa.func.count())
            .select_from(ApiIdempotencyRecord)
            .where(ApiIdempotencyRecord.created_at < cutoff)
        )
        assert row.eligible_rows == direct == 2
        assert row.cutoff == cutoff and row.action is RetentionAction.PREVIEW_ELIGIBLE
        # Deterministic: the same inputs give an identical plan.
        assert plan == plan_retention(owner_session, tenant_id=tenant.id, policy={}, now=NOW)

    def test_the_batch_bound_caps_the_preview_and_says_so(self, owner_session: Session) -> None:
        tenant = make_tenant(owner_session, f"ret-{uuid.uuid4().hex[:8]}")
        bind_tenant(owner_session, tenant.id)
        for index in range(7):
            _record(owner_session, tenant.id, 60, f"bulk-{index}-{uuid.uuid4().hex[:6]}")
        plan = plan_retention(owner_session, tenant_id=tenant.id, policy={}, now=NOW, batch_limit=5)
        (row,) = plan.eligible()
        assert row.eligible_rows == 5 and row.truncated_to_batch is True

    def test_a_hold_suspends_eligibility(self, owner_session: Session) -> None:
        tenant = make_tenant(owner_session, f"ret-{uuid.uuid4().hex[:8]}")
        bind_tenant(owner_session, tenant.id)
        _record(owner_session, tenant.id, 90, f"held-{uuid.uuid4().hex[:6]}")
        plan = plan_retention(
            owner_session,
            tenant_id=tenant.id,
            policy={"operational_cache": {"days": 30, "hold": True}},
            now=NOW,
        )
        row = next(r for r in plan.rows if r.table == "api_idempotency_record")
        assert row.action is RetentionAction.HELD and plan.eligible() == ()

    def test_the_preview_is_tenant_bound_through_row_level_security(
        self, app_session: Session
    ) -> None:
        """Under the unprivileged role, another tenant's aged rows are simply invisible."""
        mine = make_tenant(app_session, f"ret-a-{uuid.uuid4().hex[:6]}")
        theirs = make_tenant(app_session, f"ret-b-{uuid.uuid4().hex[:6]}")
        bind_tenant(app_session, theirs.id)
        _record(app_session, theirs.id, 90, f"theirs-{uuid.uuid4().hex[:6]}")
        bind_tenant(app_session, mine.id)
        plan = plan_retention(app_session, tenant_id=mine.id, policy={}, now=NOW)
        assert plan.eligible() == ()  # nothing of *theirs* is counted for *mine*
        bind_tenant(app_session, theirs.id)
        assert (
            len(plan_retention(app_session, tenant_id=theirs.id, policy={}, now=NOW).eligible())
            == 1
        )

    @pytest.mark.parametrize("limit", [0, -1, 100_001])
    def test_batch_limit_is_bounded(self, owner_session: Session, limit: int) -> None:
        with pytest.raises(ValueError, match="batch_limit"):
            plan_retention(
                owner_session, tenant_id=uuid.uuid4(), policy={}, now=NOW, batch_limit=limit
            )

    def test_an_invalid_tenant_policy_stops_the_plan(self, owner_session: Session) -> None:
        with pytest.raises(RetentionPolicyError):
            plan_retention(
                owner_session,
                tenant_id=uuid.uuid4(),
                policy={"protected_evidence": {"days": 1}},
                now=NOW,
            )
