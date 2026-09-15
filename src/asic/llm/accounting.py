"""Durable, attempt-scoped model budget reservation and replay."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import asdict

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models.incident import ModelCallReservation, WorkflowRun
from asic.db.session import bind_tenant
from asic.domain.budget import BudgetState
from asic.domain.enums import NodeId
from asic.domain.errors import ModelProviderError
from asic.llm.port import ModelCallEstimate, ModelResponse


class DurableModelBudget:
    """Reserve before a call and settle immediately when its usage becomes known."""

    def __init__(self, factory: Callable[[], Session], tenant_id: uuid.UUID, run_id: uuid.UUID):
        self._factory = factory
        self._tenant_id = tenant_id
        self._run_id = run_id

    def reserve(
        self, invocation_key: str, estimate: ModelCallEstimate, budget: BudgetState
    ) -> ModelResponse | None:
        budget.require_headroom(tokens=estimate.max_total_tokens, cost_usd=estimate.max_cost_usd)
        with self._factory() as session:
            bind_tenant(session, self._tenant_id)
            existing = session.scalar(
                sa.select(ModelCallReservation).where(
                    ModelCallReservation.workflow_run_id == self._run_id,
                    ModelCallReservation.invocation_key == invocation_key,
                )
            )
            if existing is not None:
                session.commit()
                if existing.status == "completed" and existing.response:
                    return ModelResponse(**existing.response)
                raise ModelProviderError(
                    "model attempt has an unresolved durable reservation; refusing replay",
                    transient=False,
                )
            run = session.scalar(
                sa.select(WorkflowRun).where(WorkflowRun.id == self._run_id).with_for_update()
            )
            if run is None:
                raise ModelProviderError(
                    "workflow run disappeared during model admission", transient=False
                )
            durable = BudgetState.from_dict(dict(run.budget_consumed))
            durable.require_headroom(
                tokens=estimate.max_total_tokens, cost_usd=estimate.max_cost_usd
            )
            charged = durable.charge(
                tokens=estimate.max_total_tokens, cost_usd=estimate.max_cost_usd
            )
            run.budget_consumed = charged.to_dict()
            session.add(
                ModelCallReservation(
                    id=uuid.uuid4(),
                    tenant_id=self._tenant_id,
                    workflow_run_id=self._run_id,
                    invocation_key=invocation_key,
                    node_id=NodeId(invocation_key.split(":", 1)[0]),
                    reserved_tokens=estimate.max_total_tokens,
                    reserved_cost_usd=estimate.max_cost_usd,
                    status="reserved",
                )
            )
            session.commit()
        return None

    def settle(self, invocation_key: str, response: ModelResponse) -> None:
        with self._factory() as session:
            bind_tenant(session, self._tenant_id)
            row = session.scalar(
                sa.select(ModelCallReservation)
                .where(
                    ModelCallReservation.workflow_run_id == self._run_id,
                    ModelCallReservation.invocation_key == invocation_key,
                )
                .with_for_update()
            )
            if row is None:
                raise ModelProviderError(
                    "model reservation disappeared before settlement", transient=False
                )
            if row.status == "completed":
                session.commit()
                return
            run = session.scalar(
                sa.select(WorkflowRun).where(WorkflowRun.id == self._run_id).with_for_update()
            )
            if run is None:
                raise ModelProviderError(
                    "workflow run disappeared during model settlement", transient=False
                )
            durable = BudgetState.from_dict(dict(run.budget_consumed))
            # Reservations are exact for the only enabled deterministic provider. Keep any
            # unused headroom conservatively charged for future providers until a stronger
            # provider-side cancellation contract exists.
            row.actual_input_tokens = response.input_tokens
            row.actual_output_tokens = response.output_tokens
            row.actual_cost_usd = response.cost_usd
            row.response = asdict(response)
            row.status = "completed"
            run.budget_consumed = durable.to_dict()
            session.commit()


__all__ = ["DurableModelBudget"]
