"""Run context, node dependencies, and the per-node unit of work.

Two things live here, and the second is the more interesting.

:class:`RunContext` is the immutable identity of one run: who, which incident, which trace,
which behaviour version. It is created once and never rewritten, which is what lets a
resumed run prove it is the same run rather than a new one wearing the same id.

:class:`UnitOfWork` is the transaction boundary, and it is **one transaction per node**.
That choice is what makes checkpointing mean anything: a node's durable effects, its trace
spans, its audit records and the checkpoint recording that it finished all commit together,
so a crash leaves the run at a node boundary rather than halfway through one. A single
transaction for the whole run would be simpler and would make every crash lose everything.

:class:`NodeDependencies` is what a node is given, and its shape is a security decision.
A node receives a **broker**, never a provider, never a registry, never a credential and
never a database engine. Everything a node can reach, it reaches through a component that
authorizes, audits and traces the reach. An import-graph test asserts that no node module
imports a provider or a simulator, so the property holds against future edits rather than
resting on this docstring.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final

from sqlalchemy.orm import Session

from asic.contracts.state import InvestigationObjective, RunIdentity, TraceContext
from asic.db.session import bind_tenant
from asic.domain.budget import BudgetPolicy
from asic.domain.clock import Clock
from asic.llm.port import ModelProvider
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder
from asic.orchestration.checkpoint import CheckpointStore
from asic.tools.broker import ToolBroker
from asic.tools.capability import IncidentScope

SessionFactory = Callable[[], Session]

#: Identifies the orchestrator process holding a workflow lease. Distinct per kernel
#: instance so two kernels in one process still contend for the lease correctly.
DEFAULT_LEASE_OWNER_PREFIX: Final[str] = "asic-orchestrator"


@dataclass(frozen=True, slots=True)
class RunContext:
    """Immutable identity and scope for one orchestration run."""

    identity: RunIdentity
    trace: TraceContext
    scope: IncidentScope
    lease_owner: str

    @property
    def tenant_id(self) -> uuid.UUID:
        return uuid.UUID(self.identity.tenant_id)

    @property
    def incident_id(self) -> uuid.UUID:
        return uuid.UUID(self.identity.incident_id)

    @property
    def workflow_run_id(self) -> uuid.UUID:
        return uuid.UUID(self.identity.workflow_run_id)

    @property
    def correlation_id(self) -> uuid.UUID:
        return uuid.UUID(self.trace.correlation_id)


class UnitOfWork:
    """One transaction, opened and committed at each node boundary.

    Not reentrant, and deliberately loud about misuse: reading ``session`` with no open
    transaction raises rather than silently opening one, because an accidental transaction
    is how a node's writes end up committed apart from the checkpoint that describes them.
    """

    __slots__ = ("_factory", "_session", "_tenant_id")

    def __init__(self, factory: SessionFactory, *, tenant_id: uuid.UUID) -> None:
        self._factory = factory
        self._tenant_id = tenant_id
        self._session: Session | None = None

    @property
    def is_open(self) -> bool:
        return self._session is not None

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError(
                "no unit of work is open; the kernel opens one per node boundary, and a "
                "node reaching the database outside one would commit apart from its "
                "checkpoint"
            )
        return self._session

    def begin(self) -> Session:
        if self._session is not None:
            raise RuntimeError("a unit of work is already open; nesting is not supported")
        session = self._factory()
        bind_tenant(session, self._tenant_id)
        self._session = session
        return session

    def commit(self) -> None:
        if self._session is None:
            return
        try:
            self._session.commit()
        finally:
            self._close()

    def rollback(self) -> None:
        if self._session is None:
            return
        try:
            self._session.rollback()
        finally:
            self._close()

    def _close(self) -> None:
        assert self._session is not None
        self._session.close()
        self._session = None

    def __enter__(self) -> Session:
        return self.begin()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()


@dataclass(slots=True)
class NodeDependencies:
    """Everything a node may use. Nothing here can reach a system unmediated."""

    context: RunContext
    objective: InvestigationObjective
    unit_of_work: UnitOfWork
    broker: ToolBroker
    model: ModelProvider
    tracer: TraceRecorder
    audit: AuditWriter
    checkpoints: CheckpointStore
    clock: Clock
    budget_policy: BudgetPolicy = field(default_factory=BudgetPolicy)

    @property
    def session(self) -> Session:
        return self.unit_of_work.session


__all__ = [
    "DEFAULT_LEASE_OWNER_PREFIX",
    "NodeDependencies",
    "RunContext",
    "SessionFactory",
    "UnitOfWork",
]
