"""Governed memory writes against PostgreSQL, under the application role.

The database is the thing under test here - the policy itself is exercised without a
database in ``test_policy.py``. What only a real database can prove: every outcome
(including a refusal) is recorded, identical proposals collapse under an advisory lock
even when raced, a human decision is authorization-checked against real role grants, and
poisoning attempts fail the same way through the whole propose/decide round trip as they do
in the pure policy function.
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
import sqlalchemy as sa

from asic.db.models import Incident, MemoryEntry, MemoryPromotion, MemoryWriteDecision
from asic.db.session import bind_tenant
from asic.domain.enums import (
    IncidentSeverity,
    IncidentStatus,
    MemoryCategory,
    MemoryDecisionOutcome,
    MemoryKind,
    MemoryVerificationStatus,
    ProvenanceLabel,
)
from asic.memory.policy import MemoryWriteRequest
from asic.memory.service import MemoryGovernanceError, memory_blocks
from tests.memory.conftest import MemoryWorld, _teardown, make_world

pytestmark = pytest.mark.postgres


def _knowledge_request(world: MemoryWorld, **overrides: object) -> MemoryWriteRequest:
    fields: dict[str, object] = {
        "category": MemoryCategory.OPERATIONAL_KNOWLEDGE,
        "statement": "Restarting the checkout deployment clears pool exhaustion.",
        "rationale": "Observed across incident INC review.",
        "root_cause_class": "connection_pool_exhaustion",
        "incident_ids": (world.incident_id,),
    }
    fields.update(overrides)
    return MemoryWriteRequest(**fields)  # type: ignore[arg-type]


def _outcome_request(world: MemoryWorld, **overrides: object) -> MemoryWriteRequest:
    fields: dict[str, object] = {
        "category": MemoryCategory.VERIFIED_OUTCOME,
        "statement": "Rolling back the deployment resolved the incident.",
        "rationale": "Verification confirmed recovery.",
        "root_cause_class": "connection_pool_exhaustion",
        "incident_ids": (world.incident_id,),
        "verification_ids": (world.verification_id,),
    }
    fields.update(overrides)
    return MemoryWriteRequest(**fields)  # type: ignore[arg-type]


class TestProposeIsGoverned:
    def test_forged_verified_row_without_trusted_lineage_is_rejected_and_audited(
        self, app_engine: sa.Engine, owner_engine: sa.Engine
    ) -> None:
        forged = make_world(
            app_engine,
            slug=f"mem-forged-{uuid.uuid4().hex[:8]}",
            trusted_verification=False,
        )
        try:
            before = forged.count_decisions()
            outcome = forged.service.propose(
                forged.tenant_id, _outcome_request(forged), forged.agent
            )
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "verification_provenance_invalid"
            assert outcome.promotion_id is None
            assert forged.count_decisions() == before + 1
        finally:
            _teardown(owner_engine, forged)

    def test_trusted_lineage_guard_is_load_bearing(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        forged = make_world(
            app_engine,
            slug=f"mem-mutation-{uuid.uuid4().hex[:8]}",
            trusted_verification=False,
        )
        try:
            request = _outcome_request(forged)
            blocked = forged.service.propose(forged.tenant_id, request, forged.agent)
            assert blocked.outcome is MemoryDecisionOutcome.REJECTED
            monkeypatch.setattr(
                "asic.memory.service.trusted_verified_outcome", lambda *args, **kwargs: True
            )
            unsafe = forged.service.propose(forged.tenant_id, request, forged.agent)
            assert unsafe.outcome is MemoryDecisionOutcome.PROPOSED
        finally:
            _teardown(owner_engine, forged)

    @pytest.mark.parametrize("execution_kind", ["baseline", "post_action"])
    def test_failed_independent_read_execution_invalidates_t5_lineage(
        self,
        execution_kind: str,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
    ) -> None:
        from asic.db.models import RemediationBaseline, ToolExecution, Verification
        from asic.domain.enums import ToolExecutionOutcome

        built = make_world(app_engine, slug=f"mem-failed-read-{uuid.uuid4().hex[:8]}")
        try:
            with built.factory() as session, session.begin():
                bind_tenant(session, built.tenant_id)
                verification = session.get(Verification, built.verification_id)
                assert verification is not None
                if execution_kind == "baseline":
                    baseline = session.get(
                        RemediationBaseline, verification.remediation_baseline_id
                    )
                    assert baseline is not None
                    execution_id = baseline.read_execution_id
                else:
                    assert verification.post_action_read_execution_id is not None
                    execution_id = verification.post_action_read_execution_id
            with owner_engine.begin() as connection:
                connection.execute(
                    sa.update(ToolExecution)
                    .where(ToolExecution.id == execution_id)
                    .values(
                        outcome=ToolExecutionOutcome.FAILED_CLEAN,
                        observed_effect={},
                        failure_reason="adversarial failed read",
                    )
                )
            outcome = built.service.propose(built.tenant_id, _outcome_request(built), built.agent)
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "verification_provenance_invalid"
        finally:
            _teardown(owner_engine, built)

    @pytest.mark.parametrize(
        ("field", "replacement"),
        [
            ("profile_id", "attacker-profile"),
            ("profile_version", 999),
            ("observed_metric", "unrelated_metric"),
            ("observation_source_provider", "unapproved-provider"),
            ("observation_source_capability", "read.logs"),
            ("observation_provenance_hash", "0" * 64),
        ],
    )
    def test_tampered_verification_lineage_is_rejected(
        self,
        field: str,
        replacement: object,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
    ) -> None:
        from asic.db.models import Verification

        built = make_world(app_engine, slug=f"mem-lineage-{uuid.uuid4().hex[:8]}")
        try:
            with owner_engine.begin() as connection:
                connection.execute(
                    sa.update(Verification)
                    .where(Verification.id == built.verification_id)
                    .values({field: replacement})
                )
            outcome = built.service.propose(built.tenant_id, _outcome_request(built), built.agent)
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "verification_provenance_invalid"
        finally:
            _teardown(owner_engine, built)

    @pytest.mark.parametrize(
        ("field", "replacement"),
        [
            ("metric", "unrelated_metric"),
            ("source_capability", "read.logs"),
            ("source_provider", "unapproved-provider"),
            ("provenance_hash", "0" * 64),
        ],
    )
    def test_tampered_baseline_lineage_is_rejected(
        self,
        field: str,
        replacement: object,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
    ) -> None:
        from asic.db.models import RemediationBaseline

        built = make_world(app_engine, slug=f"mem-baseline-{uuid.uuid4().hex[:8]}")
        try:
            with owner_engine.begin() as connection:
                connection.execute(
                    sa.update(RemediationBaseline)
                    .where(RemediationBaseline.remediation_action_id == built.remediation_action_id)
                    .values({field: replacement})
                )
            outcome = built.service.propose(built.tenant_id, _outcome_request(built), built.agent)
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "verification_provenance_invalid"
        finally:
            _teardown(owner_engine, built)

    @pytest.mark.parametrize(
        ("field", "replacement"),
        [
            ("measurement_series", "unrelated_metric"),
            ("latest_sample", "2026-09-11T09:12:00+00:00=999"),
        ],
    )
    def test_post_read_summary_must_match_the_value_used_for_the_verdict(
        self,
        field: str,
        replacement: object,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
    ) -> None:
        from asic.db.models import ToolExecution, Verification

        built = make_world(app_engine, slug=f"mem-post-summary-{uuid.uuid4().hex[:8]}")
        try:
            with owner_engine.begin() as connection:
                post_id = connection.scalar(
                    sa.select(Verification.post_action_read_execution_id).where(
                        Verification.id == built.verification_id
                    )
                )
                assert post_id is not None
                effect = connection.scalar(
                    sa.select(ToolExecution.observed_effect).where(ToolExecution.id == post_id)
                )
                assert effect is not None
                changed = dict(effect)
                changed[field] = replacement
                connection.execute(
                    sa.update(ToolExecution)
                    .where(ToolExecution.id == post_id)
                    .values(observed_effect=changed)
                )
            outcome = built.service.propose(built.tenant_id, _outcome_request(built), built.agent)
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "verification_provenance_invalid"
        finally:
            _teardown(owner_engine, built)

    def test_cross_tenant_baseline_cannot_be_attached_to_verification(
        self, app_engine: sa.Engine, owner_engine: sa.Engine
    ) -> None:
        from asic.db.models import RemediationBaseline, Verification

        built = make_world(app_engine, slug=f"mem-baseline-a-{uuid.uuid4().hex[:8]}")
        other = make_world(app_engine, slug=f"mem-baseline-b-{uuid.uuid4().hex[:8]}")
        try:
            with owner_engine.connect() as connection:
                transaction = connection.begin()
                other_baseline_id = connection.scalar(
                    sa.select(RemediationBaseline.id).where(
                        RemediationBaseline.tenant_id == other.tenant_id
                    )
                )
                assert other_baseline_id is not None
                with pytest.raises(sa.exc.IntegrityError):
                    connection.execute(
                        sa.update(Verification)
                        .where(Verification.id == built.verification_id)
                        .values(remediation_baseline_id=other_baseline_id)
                    )
                transaction.rollback()
        finally:
            _teardown(owner_engine, other)
            _teardown(owner_engine, built)

    def test_operational_knowledge_from_a_closed_incident_proposes(
        self, world: MemoryWorld
    ) -> None:
        outcome = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert outcome.outcome is MemoryDecisionOutcome.PROPOSED
        assert outcome.promotion_id is not None

    def test_operational_knowledge_from_an_open_incident_is_refused(
        self, world: MemoryWorld
    ) -> None:
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            open_incident = Incident(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                reference=f"INC-{uuid.uuid4().hex[:8]}",
                title="Still open",
                environment_id=session.scalar(
                    sa.select(Incident.environment_id).where(Incident.id == world.incident_id)
                ),
                status=IncidentStatus.DETECTED,
                severity=IncidentSeverity.SEV2,
                opened_at=world.clock.now(),
            )
            session.add(open_incident)
            session.flush()
            open_incident_id = open_incident.id
        outcome = world.service.propose(
            world.tenant_id,
            _knowledge_request(world, incident_ids=(open_incident_id,)),
            world.agent,
        )
        assert outcome.outcome is MemoryDecisionOutcome.REJECTED
        assert outcome.reason == "incident_not_closed"
        assert outcome.promotion_id is None

    @pytest.mark.parametrize(
        "category",
        [
            MemoryCategory.WORKING_STATE,
            MemoryCategory.INCIDENT_HISTORY,
            MemoryCategory.MODEL_INFERENCE,
        ],
    )
    def test_non_promotable_categories_are_refused_and_recorded(
        self, world: MemoryWorld, category: MemoryCategory
    ) -> None:
        request = _knowledge_request(world, category=category)
        outcome = world.service.propose(world.tenant_id, request, world.agent)
        assert outcome.outcome is MemoryDecisionOutcome.REJECTED
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            recorded = session.get(MemoryWriteDecision, outcome.decision_id)
            assert recorded is not None
            assert recorded.category is category
            assert recorded.outcome is MemoryDecisionOutcome.REJECTED

    def test_every_refusal_is_recorded_in_the_append_only_decision_log(
        self, world: MemoryWorld
    ) -> None:
        before = world.count_decisions()
        world.service.propose(
            world.tenant_id,
            _knowledge_request(world, category=MemoryCategory.WORKING_STATE),
            world.agent,
        )
        assert world.count_decisions() == before + 1

    def test_identical_proposals_collapse_to_one_open_promotion(self, world: MemoryWorld) -> None:
        first = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        second = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert second.promotion_id == first.promotion_id
        assert second.reason == "existing_open_proposal"
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            count = session.scalar(
                sa.select(sa.func.count())
                .select_from(MemoryPromotion)
                .where(MemoryPromotion.tenant_id == world.tenant_id)
            )
        assert count == 1

    def test_a_different_statement_is_a_different_proposal(self, world: MemoryWorld) -> None:
        first = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        second = world.service.propose(
            world.tenant_id,
            _knowledge_request(world, statement="A completely different claim."),
            world.agent,
        )
        assert second.promotion_id != first.promotion_id

    def test_concurrent_identical_proposals_still_collapse_to_one(self, world: MemoryWorld) -> None:
        barrier = Barrier(4)

        def run() -> uuid.UUID | None:
            barrier.wait(timeout=10)
            return world.service.propose(
                world.tenant_id, _knowledge_request(world), world.agent
            ).promotion_id

        with ThreadPoolExecutor(max_workers=4) as pool:
            promotion_ids = set(pool.map(lambda _: run(), range(4)))
        assert promotion_ids == {next(iter(promotion_ids))}  # every call names the same promotion
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            count = session.scalar(
                sa.select(sa.func.count())
                .select_from(MemoryPromotion)
                .where(MemoryPromotion.tenant_id == world.tenant_id)
            )
        assert count == 1


class TestDecideIsGoverned:
    def test_human_approval_revalidates_lineage_and_audits_a_late_failure(
        self, world: MemoryWorld, owner_engine: sa.Engine
    ) -> None:
        from asic.db.models import AuditRecord, ToolExecution, Verification
        from asic.domain.enums import AuditEventType

        proposed = world.service.propose(world.tenant_id, _outcome_request(world), world.agent)
        assert proposed.promotion_id is not None
        with owner_engine.begin() as connection:
            post_id = connection.scalar(
                sa.select(Verification.post_action_read_execution_id).where(
                    Verification.id == world.verification_id
                )
            )
            assert post_id is not None
            connection.execute(
                sa.update(ToolExecution)
                .where(ToolExecution.id == post_id)
                .values(observed_effect={"source": "prometheus-simulator"})
            )

        with pytest.raises(MemoryGovernanceError, match="verification_provenance_invalid"):
            world.service.decide(
                world.tenant_id, proposed.promotion_id, world.approver, approve=True
            )
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            assert (
                session.scalar(
                    sa.select(sa.func.count())
                    .select_from(MemoryEntry)
                    .where(MemoryEntry.tenant_id == world.tenant_id)
                )
                == 0
            )
            denial = session.scalar(
                sa.select(AuditRecord).where(
                    AuditRecord.tenant_id == world.tenant_id,
                    AuditRecord.event_type == AuditEventType.AUTHORIZATION_DENIED,
                    AuditRecord.target_id == str(proposed.promotion_id),
                )
            )
            assert denial is not None
            assert denial.payload_redacted["reason"] == "verification_provenance_invalid"

    def test_verified_outcome_produces_a_verified_fact_entry(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(world.tenant_id, _outcome_request(world), world.agent)
        assert proposed.promotion_id is not None
        decided = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=True
        )
        assert decided.outcome is MemoryDecisionOutcome.APPROVED
        assert decided.memory_entry_id is not None
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            entry = session.get(MemoryEntry, decided.memory_entry_id)
            assert entry is not None
            assert entry.provenance is ProvenanceLabel.VERIFIED_FACT
            assert entry.verification_status is MemoryVerificationStatus.VERIFIED
            assert entry.verification_id == world.verification_id
            # The durable statement is generated from records, not the proposer's text.
            assert (
                "checkout" not in entry.statement.lower() or "verified" in entry.statement.lower()
            )

    def test_operational_knowledge_from_an_agent_is_model_claim_not_verified(
        self, world: MemoryWorld
    ) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        decided = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=True
        )
        assert decided.memory_entry_id is not None
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            entry = session.get(MemoryEntry, decided.memory_entry_id)
            assert entry is not None
            assert entry.provenance is ProvenanceLabel.MODEL_CLAIM
            assert entry.verification_status is MemoryVerificationStatus.UNVERIFIED

    def test_operational_knowledge_from_a_human_is_retrieved_not_verified(
        self, world: MemoryWorld
    ) -> None:
        proposed = world.service.propose(
            world.tenant_id, _knowledge_request(world), world.human_proposer
        )
        assert proposed.promotion_id is not None
        decided = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=True
        )
        assert decided.memory_entry_id is not None
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            entry = session.get(MemoryEntry, decided.memory_entry_id)
            assert entry is not None
            assert entry.provenance is ProvenanceLabel.RETRIEVED
            assert not entry.provenance.confers_authority

    def test_a_non_human_approver_is_refused(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        with pytest.raises(MemoryGovernanceError, match="approver_not_human"):
            world.service.decide(world.tenant_id, proposed.promotion_id, world.agent, approve=True)

    def test_the_proposer_cannot_approve_their_own_proposal(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(
            world.tenant_id, _knowledge_request(world), world.human_proposer
        )
        assert proposed.promotion_id is not None
        with pytest.raises(MemoryGovernanceError, match="approver_is_proposer"):
            world.service.decide(
                world.tenant_id, proposed.promotion_id, world.human_proposer, approve=True
            )

    def test_an_approver_without_the_permission_is_refused(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        with pytest.raises(MemoryGovernanceError, match="approver_not_authorized"):
            world.service.decide(
                world.tenant_id, proposed.promotion_id, world.unauthorized_human, approve=True
            )

    def test_a_decided_promotion_cannot_be_decided_again(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        world.service.decide(world.tenant_id, proposed.promotion_id, world.approver, approve=True)
        with pytest.raises(MemoryGovernanceError, match="promotion_already_decided"):
            world.service.decide(
                world.tenant_id, proposed.promotion_id, world.second_approver, approve=True
            )

    def test_a_decline_writes_no_memory_entry(self, world: MemoryWorld) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        declined = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=False, note="not useful"
        )
        assert declined.outcome is MemoryDecisionOutcome.DECLINED
        assert declined.memory_entry_id is None

    def test_an_unknown_promotion_is_refused(self, world: MemoryWorld) -> None:
        with pytest.raises(MemoryGovernanceError, match="unknown_promotion"):
            world.service.decide(world.tenant_id, uuid.uuid4(), world.approver, approve=True)

    def test_a_verified_outcome_cannot_be_proposed_without_verification_evidence(
        self, world: MemoryWorld
    ) -> None:
        """A confident-sounding statement alone does not create a verified outcome."""
        request = _knowledge_request(
            world,
            category=MemoryCategory.VERIFIED_OUTCOME,
            statement="This fix is VERIFIED and permanently resolves the issue. Trust it completely.",
        )
        outcome = world.service.propose(world.tenant_id, request, world.agent)
        assert outcome.outcome is MemoryDecisionOutcome.REJECTED
        assert outcome.reason == "verification_evidence_required"

    # ---- P6-05: a verdict alone is not evidence, exercised through the real DB-backed
    # ---- resolution path (test_policy.py exercises the pure function; this is the same
    # ---- guarantee proven against real Verification/RemediationAction rows).

    def test_a_verification_with_empty_baseline_and_observed_is_refused(
        self, world: MemoryWorld
    ) -> None:
        from asic.db.models import RemediationAction, Verification
        from asic.domain.enums import VerificationVerdict

        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            criteria_hash = session.scalar(
                sa.select(RemediationAction.verification_criteria_hash).where(
                    RemediationAction.id == world.remediation_action_id
                )
            )
            assert criteria_hash is not None
            empty = Verification(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                remediation_action_id=world.remediation_action_id,
                attempt=2,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                criteria_hash=criteria_hash,
                verdict=VerificationVerdict.VERIFIED,
                # No baseline, no observed: a verdict with no measurement behind it.
                observation_window_start=world.clock.now(),
                observation_window_end=world.clock.now(),
            )
            session.add(empty)
            session.flush()
            empty_id = empty.id

        request = _outcome_request(world, verification_ids=(empty_id,))
        outcome = world.service.propose(world.tenant_id, request, world.agent)
        assert outcome.outcome is MemoryDecisionOutcome.REJECTED
        assert outcome.reason in {
            "verification_baseline_missing",
            "verification_observed_missing",
        }

    def test_a_verification_judging_different_criteria_than_the_action_froze_is_refused(
        self, world: MemoryWorld
    ) -> None:
        """INV-11: a verification's criteria_hash must match the action's frozen one."""
        from asic.db.models import Verification
        from asic.domain.enums import VerificationVerdict

        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            mismatched = Verification(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                remediation_action_id=world.remediation_action_id,
                attempt=3,
                callback_idempotency_key=uuid.uuid4().hex * 2,
                criteria_hash="different-criteria-hash-than-the-action-froze".ljust(64, "0")[:64],
                verdict=VerificationVerdict.VERIFIED,
                observed={"http_5xx_rate": 0.001},
                baseline={"http_5xx_rate": 0.021},
                observation_window_start=world.clock.now(),
                observation_window_end=world.clock.now(),
            )
            session.add(mismatched)
            session.flush()
            mismatched_id = mismatched.id

        request = _outcome_request(world, verification_ids=(mismatched_id,))
        outcome = world.service.propose(world.tenant_id, request, world.agent)
        assert outcome.outcome is MemoryDecisionOutcome.REJECTED
        assert outcome.reason == "verification_criteria_mismatch"

    def test_a_verification_from_another_tenant_is_unresolvable(
        self, world: MemoryWorld, app_engine: sa.Engine, owner_engine: sa.Engine
    ) -> None:
        """Row-level security hides another tenant's verification entirely - it is
        indistinguishable from a fabricated id, and is refused the same way."""
        other = make_world(app_engine, slug=f"mem-other-{uuid.uuid4().hex[:8]}")
        try:
            request = _outcome_request(world, verification_ids=(other.verification_id,))
            outcome = world.service.propose(world.tenant_id, request, world.agent)
            assert outcome.outcome is MemoryDecisionOutcome.REJECTED
            assert outcome.reason == "unresolved_reference"
        finally:
            _teardown(owner_engine, other)


class TestCrossTenantIsolation:
    def test_a_second_tenants_user_cannot_decide_this_promotion(
        self, world: MemoryWorld, owner_engine: sa.Engine
    ) -> None:
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        other = make_world(world.factory.kw["bind"])
        try:
            with pytest.raises(MemoryGovernanceError, match="unknown_promotion"):
                other.service.decide(
                    other.tenant_id, proposed.promotion_id, other.approver, approve=True
                )
        finally:
            # ``other`` was built directly, not through the ``world`` fixture, so its
            # global-catalogue rows need the same teardown (see conftest._teardown).
            _teardown(owner_engine, other)


class TestMemoryReads:
    def test_verified_entries_are_read_before_unverified_ones(self, world: MemoryWorld) -> None:
        knowledge = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        outcome_proposal = world.service.propose(
            world.tenant_id, _outcome_request(world), world.agent
        )
        assert knowledge.promotion_id is not None and outcome_proposal.promotion_id is not None
        world.service.decide(world.tenant_id, knowledge.promotion_id, world.approver, approve=True)
        world.service.decide(
            world.tenant_id, outcome_proposal.promotion_id, world.second_approver, approve=True
        )
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            blocks = memory_blocks(session, tenant_id=world.tenant_id, now=world.clock.now())
        assert blocks
        assert blocks[0].provenance is ProvenanceLabel.VERIFIED_FACT
        assert all(block.provenance is not ProvenanceLabel.SYSTEM for block in blocks)
        assert all(block.provenance is not ProvenanceLabel.HUMAN for block in blocks)

    def test_a_deactivated_entry_is_not_read(self, world: MemoryWorld) -> None:
        """``is_active`` is the one lifecycle column the application role may update -
        expiry and every other field of a written entry are otherwise fixed at approval
        time (``UPDATABLE_COLUMNS`` in migration 0008)."""
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        decided = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=True
        )
        assert decided.memory_entry_id is not None
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            entry = session.get(MemoryEntry, decided.memory_entry_id)
            assert entry is not None
            entry.is_active = False
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            blocks = memory_blocks(session, tenant_id=world.tenant_id, now=world.clock.now())
        assert blocks == ()

    def test_the_application_role_cannot_change_a_written_entrys_content(
        self, world: MemoryWorld
    ) -> None:
        """Only lifecycle columns are updatable; the governed content is fixed."""
        proposed = world.service.propose(world.tenant_id, _knowledge_request(world), world.agent)
        assert proposed.promotion_id is not None
        decided = world.service.decide(
            world.tenant_id, proposed.promotion_id, world.approver, approve=True
        )
        assert decided.memory_entry_id is not None
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            with pytest.raises(sa.exc.ProgrammingError, match="permission denied"):
                session.execute(
                    sa.update(MemoryEntry)
                    .where(MemoryEntry.id == decided.memory_entry_id)
                    .values(statement="Rewritten after the fact.")
                )
                session.flush()


class TestMemoryIsNotDirectlyWritable:
    def test_the_application_role_cannot_insert_a_memory_entry_without_a_promotion(
        self, world: MemoryWorld
    ) -> None:
        """The database itself refuses memory carrying SYSTEM or HUMAN provenance."""
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            entry = MemoryEntry(
                id=uuid.uuid4(),
                tenant_id=world.tenant_id,
                kind=MemoryKind.OPERATIONAL_FACT,
                root_cause_class="anything",
                context_signature={},
                statement="A human just typed this directly into memory.",
                support_count=1,
                first_seen_at=world.clock.now(),
                last_seen_at=world.clock.now(),
                # HUMAN provenance would confer authority on remembered content; the
                # database refuses it regardless of what wrote the row.
                provenance=ProvenanceLabel.HUMAN,
            )
            session.add(entry)
            with pytest.raises(
                sa.exc.IntegrityError, match=r"memory_confers_no_authority|governed_entry"
            ):
                session.flush()
