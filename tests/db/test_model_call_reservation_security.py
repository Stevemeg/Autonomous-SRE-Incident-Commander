"""Database-enforced model reservation lifecycle and replay integrity."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from asic.db.models import ModelCallReservation, RemediationAction
from asic.db.session import bind_tenant
from asic.domain.budget import BudgetState
from asic.domain.enums import NodeId
from asic.llm.accounting import DurableModelBudget
from asic.llm.port import ModelCallEstimate, ModelResponse
from tests.memory.conftest import MemoryWorld, _teardown, make_world

pytestmark = pytest.mark.postgres


def _response(text: str, *, tokens: int = 6, cost: float = 0.01) -> ModelResponse:
    return ModelResponse(
        text=text,
        provider="deterministic-simulator",
        model_id="scripted-1",
        input_tokens=tokens - 1,
        output_tokens=1,
        cost_usd=cost,
        finish_reason="stop",
    )


def _world_run(world: MemoryWorld) -> uuid.UUID:
    factory = world.factory
    with factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        run_id = session.scalar(
            sa.select(RemediationAction.workflow_run_id).where(
                RemediationAction.id == world.remediation_action_id
            )
        )
        assert run_id is not None
        return run_id


def test_application_role_can_settle_once_but_cannot_mutate_reservation_authority(
    app_engine: sa.Engine, owner_engine: sa.Engine
) -> None:
    world = make_world(app_engine, slug=f"reservation-db-{uuid.uuid4().hex[:8]}")
    factory = sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    run_id = _world_run(world)
    durable = DurableModelBudget(factory, world.tenant_id, run_id)
    estimate = ModelCallEstimate(8, 4, 0.05)
    budget = BudgetState.initial()
    key = f"{NodeId.G3_INVESTIGATION_PLANNER.value}:db-transition:1"
    original = _response('{"action":"stop"}')
    try:
        with factory() as session:
            bind_tenant(session, world.tenant_id)
            session.add(
                ModelCallReservation(
                    id=uuid.uuid4(),
                    tenant_id=world.tenant_id,
                    workflow_run_id=run_id,
                    invocation_key=f"{NodeId.G3_INVESTIGATION_PLANNER.value}:forged-complete:1",
                    node_id=NodeId.G3_INVESTIGATION_PLANNER,
                    reserved_tokens=8,
                    reserved_cost_usd=0.05,
                    actual_input_tokens=5,
                    actual_output_tokens=1,
                    actual_cost_usd=0.01,
                    response={
                        "text": "forged",
                        "provider": "deterministic-simulator",
                        "model_id": "scripted-1",
                        "input_tokens": 5,
                        "output_tokens": 1,
                        "cost_usd": 0.01,
                        "finish_reason": "stop",
                    },
                    status="completed",
                )
            )
            with pytest.raises(DBAPIError) as denied:
                session.flush()
            assert getattr(denied.value.orig, "pgcode", None) == "42501"
            session.rollback()

        assert durable.reserve(key, estimate, budget) is None
        durable.settle(key, original)

        # Idempotent settlement observes completion and never rewrites it.
        durable.settle(key, _response('{"action":"altered"}', tokens=3, cost=0.001))
        replay = durable.reserve(key, estimate, budget)
        assert replay == original

        mutations = (
            "id = gen_random_uuid()",
            "invocation_key = invocation_key || '-changed'",
            "response = response || jsonb_build_object('text', 'changed')",
            "actual_input_tokens = actual_input_tokens + 1",
            "actual_output_tokens = actual_output_tokens + 1",
            "actual_cost_usd = actual_cost_usd + 0.001",
            "reserved_tokens = reserved_tokens + 1",
            "reserved_cost_usd = reserved_cost_usd + 0.001",
            "tenant_id = gen_random_uuid()",
            "workflow_run_id = gen_random_uuid()",
            "node_id = 'g5_hypothesis_engine'",
            "created_at = created_at + interval '1 second'",
            "updated_at = updated_at + interval '1 second'",
            "status = 'reserved', response = NULL",
            "response = response || jsonb_build_object('provider', 'changed')",
            "response = response || jsonb_build_object('model_id', 'changed')",
        )
        for assignment in mutations:
            with factory() as session:
                bind_tenant(session, world.tenant_id)
                with pytest.raises(DBAPIError) as denied:
                    session.execute(
                        sa.text(
                            f"UPDATE model_call_reservation SET {assignment} "
                            "WHERE workflow_run_id = :run_id AND invocation_key = :key"
                        ),
                        {"run_id": run_id, "key": key},
                    )
                assert getattr(denied.value.orig, "pgcode", None) == "42501"
                session.rollback()

        with factory() as session:
            bind_tenant(session, world.tenant_id)
            with pytest.raises(DBAPIError) as denied:
                session.execute(
                    sa.delete(ModelCallReservation).where(
                        ModelCallReservation.workflow_run_id == run_id,
                        ModelCallReservation.invocation_key == key,
                    )
                )
            assert getattr(denied.value.orig, "pgcode", None) == "42501"
            session.rollback()

        reserved_key = f"{NodeId.G5_HYPOTHESIS_ENGINE.value}:reserved-immutable:1"
        assert durable.reserve(reserved_key, estimate, budget) is None
        with factory() as session:
            bind_tenant(session, world.tenant_id)
            with pytest.raises(DBAPIError) as denied:
                session.execute(
                    sa.text(
                        "UPDATE model_call_reservation SET response = "
                        "jsonb_build_object('text', 'premature') "
                        "WHERE workflow_run_id = :run_id AND invocation_key = :key"
                    ),
                    {"run_id": run_id, "key": reserved_key},
                )
            assert getattr(denied.value.orig, "pgcode", None) == "42501"
            session.rollback()
    finally:
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("DELETE FROM model_call_reservation WHERE tenant_id = :tenant_id"),
                {"tenant_id": world.tenant_id},
            )
        _teardown(owner_engine, world)


def test_concurrent_settlement_preserves_one_immutable_response(
    app_engine: sa.Engine, owner_engine: sa.Engine
) -> None:
    world = make_world(app_engine, slug=f"reservation-race-{uuid.uuid4().hex[:8]}")
    factory = sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    run_id = _world_run(world)
    durable = DurableModelBudget(factory, world.tenant_id, run_id)
    estimate = ModelCallEstimate(8, 4, 0.05)
    budget = BudgetState.initial()
    key = f"{NodeId.G6_REMEDIATION_PLANNER.value}:concurrent-settlement:1"
    responses = (_response("first"), _response("second", tokens=5, cost=0.02))
    try:
        assert durable.reserve(key, estimate, budget) is None
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda response: durable.settle(key, response), responses))
        replay = durable.reserve(key, estimate, budget)
        assert replay in responses
        with factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            rows = list(
                session.scalars(
                    sa.select(ModelCallReservation).where(
                        ModelCallReservation.workflow_run_id == run_id,
                        ModelCallReservation.invocation_key == key,
                    )
                )
            )
            assert len(rows) == 1
            assert rows[0].status == "completed"
            assert rows[0].response == {
                "text": replay.text,
                "provider": replay.provider,
                "model_id": replay.model_id,
                "input_tokens": replay.input_tokens,
                "output_tokens": replay.output_tokens,
                "cost_usd": replay.cost_usd,
                "finish_reason": replay.finish_reason,
            }
    finally:
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text("DELETE FROM model_call_reservation WHERE tenant_id = :tenant_id"),
                {"tenant_id": world.tenant_id},
            )
        _teardown(owner_engine, world)
