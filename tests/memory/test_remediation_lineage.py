"""The real G10 lineage is the only remediation evidence that may enter T5."""

from __future__ import annotations

import uuid
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import MemoryEntry, RemediationBaseline, Verification
from asic.domain.clock import FrozenClock
from asic.domain.enums import ActorType, MemoryCategory, MemoryDecisionOutcome, ProvenanceLabel
from asic.memory.policy import MemoryActor, MemoryWriteRequest
from asic.memory.service import MemoryGovernanceService
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.memory.conftest import _grant_decide_permission, _user
from tests.orchestration.test_remediation import (
    _remediation_scenario,
    _resume_remediation,
    _run_remediation,
)
from tests.orchestration.test_remediation_security import _prepared

pytestmark = requires_postgres


def test_real_g10_verification_requires_human_governance_then_enters_t5(
    kernel_session: Session,
    session_factory: Callable[[], Session],
    resolver: CapabilityResolver,
    remediation_resolver: CapabilityResolver,
    clock: FrozenClock,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session,
        session_factory,
        resolver,
        clock,
        f"memory-g10-{uuid.uuid4().hex[:8]}",
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    clock.advance(90)
    outcome = _resume_remediation(session_factory, remediation_resolver, clock, fixture, outcome)
    assert outcome.terminated

    kernel_session.expire_all()
    verification = kernel_session.scalar(
        sa.select(Verification).where(Verification.tenant_id == fixture.tenant_id)
    )
    assert verification is not None and verification.remediation_baseline_id is not None
    assert kernel_session.get(RemediationBaseline, verification.remediation_baseline_id) is not None

    proposer_id = _user(kernel_session, fixture.tenant_id, "g10-memory-proposer")
    approver_id = _user(kernel_session, fixture.tenant_id, "g10-memory-approver")
    _grant_decide_permission(kernel_session, fixture.tenant_id, approver_id)
    kernel_session.commit()
    memory_factory = sessionmaker(
        bind=kernel_session.get_bind(), expire_on_commit=False, autoflush=False
    )
    service = MemoryGovernanceService(memory_factory, clock=clock)
    request = MemoryWriteRequest(
        category=MemoryCategory.VERIFIED_OUTCOME,
        statement="The independently verified remediation recovered the service.",
        rationale="Persist the governed outcome after independent verification.",
        root_cause_class="deployment_regression",
        incident_ids=(fixture.incident.id,),
        verification_ids=(verification.id,),
    )
    proposed = service.propose(
        fixture.tenant_id,
        request,
        MemoryActor(ActorType.AGENT_NODE, actor_id="g12-memory-proposal"),
    )
    assert proposed.outcome is MemoryDecisionOutcome.PROPOSED
    assert proposed.promotion_id is not None
    assert (
        kernel_session.scalar(
            sa.select(sa.func.count())
            .select_from(MemoryEntry)
            .where(MemoryEntry.tenant_id == fixture.tenant_id)
        )
        == 0
    )
    decided = service.decide(
        fixture.tenant_id,
        proposed.promotion_id,
        MemoryActor(ActorType.HUMAN, user_id=approver_id),
        approve=True,
    )
    assert decided.outcome is MemoryDecisionOutcome.APPROVED
    assert decided.memory_entry_id is not None
    kernel_session.expire_all()
    entry = kernel_session.get(MemoryEntry, decided.memory_entry_id)
    assert entry is not None and entry.provenance is ProvenanceLabel.VERIFIED_FACT
    assert proposer_id != approver_id
