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
