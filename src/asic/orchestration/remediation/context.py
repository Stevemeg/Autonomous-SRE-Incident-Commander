"""What a remediation node is given.

Reuses :class:`~asic.orchestration.context.RunContext` and
:class:`~asic.orchestration.context.UnitOfWork` unchanged - identity and the per-node
transaction boundary mean the same thing here as they do for investigation. Only the
dependency bundle itself is new, because its ``objective`` is a
:class:`~asic.contracts.remediation_state.RemediationObjective`, not an
:class:`~asic.contracts.state.InvestigationObjective`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.contracts.remediation_state import RemediationObjective
from asic.contracts.state import BudgetSnapshot
from asic.db.models.incident import WorkflowRun
from asic.domain.budget import BudgetLedger, BudgetPolicy, BudgetState
from asic.domain.clock import Clock
from asic.llm.accounting import DurableModelBudget
from asic.llm.port import ModelProvider
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder
from asic.orchestration.context import RunContext, UnitOfWork
from asic.tools.broker import ToolBroker


@dataclass(slots=True)
class RemediationDependencies:
    """Everything a remediation node may use. Nothing here can reach a system unmediated.

    No ``checkpoints`` field: unlike investigation's nodes, no remediation node writes a
    checkpoint itself - the kernel writes exactly one per node boundary, from outside the
    graph, on the same principle investigation already establishes (durability is the
    kernel's concern, not a node's).
    """

    context: RunContext
    objective: RemediationObjective
    unit_of_work: UnitOfWork
    broker: ToolBroker
    model: ModelProvider
    tracer: TraceRecorder
    audit: AuditWriter
    clock: Clock
    run_started_at: datetime
    budget_policy: BudgetPolicy = field(default_factory=BudgetPolicy)
    model_budget: DurableModelBudget | None = None

    @property
    def session(self) -> Session:
        return self.unit_of_work.session

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, (self.clock.now() - self.run_started_at).total_seconds())

    def budget_from(self, snapshot: BudgetSnapshot | None) -> BudgetState:
        base = (
            BudgetState.initial(self.budget_policy)
            if snapshot is None
            else BudgetState(
                policy=self.budget_policy,
                ledger=BudgetLedger.from_dict(snapshot.consumed),
            )
        )
        return base.observe_elapsed(self.elapsed_seconds)

    def durable_budget(self, fallback: BudgetState) -> BudgetState:
        raw = self.session.scalar(
            sa.select(WorkflowRun.budget_consumed).where(
                WorkflowRun.id == self.context.workflow_run_id
            )
        )
        return BudgetState.from_dict(dict(raw)) if raw else fallback


__all__ = ["RemediationDependencies"]
