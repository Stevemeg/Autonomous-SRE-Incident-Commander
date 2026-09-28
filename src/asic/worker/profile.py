"""Which providers and which model a unit of worker work runs against.

The worker is the same code in every environment; only its *profile* differs, and a profile is
chosen explicitly (``ASIC_WORKER_EXECUTION_MODE``), never inferred.

``live``
    Refused. Live composition exists for the tool side (``compose_live_providers``), but no
    live model provider is implemented (production gap GAP-08, ADR-0016): the only model
    behind the port is the scripted deterministic one. A production worker that ran without
    a model would have to fabricate the planner's and the hypothesis engine's output, which is
    exactly what master specification section 20 forbids. So the worker stops at startup with
    a message naming the gap.

``simulator``
    The deterministic scenario simulator and the scripted model: explicit test infrastructure
    for local deployments, demonstrations and the kind acceptance run. Refused in a deployment
    marked production (and the simulator refuses independently). Two details make it behave
    like a real, stateless backend across restarts rather than like an in-process test:

    * the scripted model is advanced past the calls the run's durable model-call ledger shows
      were already made, so a resumed run is answered the next call, not the first; and
    * a remediation run reads the post-settling fixture once its action has executed, so the
      verifier sees the world the executed action left behind - which is what an independent
      verification against real telemetry would see.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import ModelCallReservation, RemediationAction
from asic.db.session import bind_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import NodeId, RiskTier
from asic.integrations.credentials import is_production_deployment
from asic.knowledge.embedding import DeterministicEmbeddingProvider, EmbeddingService
from asic.knowledge.provider import KnowledgeStoreProvider
from asic.knowledge.retrieval import KnowledgeRetriever
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.orchestration.service import InvestigationService
from asic.postmortem.author import PostmortemAuthor
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry
from asic.worker.settings import ExecutionMode, WorkerConfigurationError, WorkerSettings

if TYPE_CHECKING:  # test infrastructure, excluded from the production image
    from asic.simulators.scenarios import Scenario

SessionFactory = Callable[[], Session]

LIVE_MODEL_UNAVAILABLE = (
    "ASIC_WORKER_EXECUTION_MODE=live needs a live model provider behind the budgeted model "
    "port, and none is implemented (production gap GAP-08). The worker refuses to start rather "
    "than drive investigations without reasoning."
)


class ExecutionProfile(Protocol):
    def investigation_service(
        self, tenant_id: uuid.UUID, run_id: uuid.UUID | None
    ) -> InvestigationService: ...

    def remediation_kernel(
        self, tenant_id: uuid.UUID, run_id: uuid.UUID | None
    ) -> RemediationKernel: ...

    def postmortem_author(self) -> PostmortemAuthor: ...


def build_profile(
    settings: WorkerSettings, factory: SessionFactory, *, clock: Clock | None = None
) -> ExecutionProfile:
    if settings.mode is ExecutionMode.LIVE:
        raise WorkerConfigurationError(LIVE_MODEL_UNAVAILABLE)
    return SimulatorProfile(
        factory,
        scenario_id=settings.simulator_scenario,
        remediation_variant=settings.simulator_remediation_variant,
        clock=clock,
    )


class SimulatorProfile:
    """Deterministic, non-production composition (test infrastructure)."""

    __slots__ = ("_clock", "_factory", "_post", "_pre", "_scenario")

    def __init__(
        self,
        factory: SessionFactory,
        *,
        scenario_id: str,
        remediation_variant: str,
        clock: Clock | None = None,
    ) -> None:
        if is_production_deployment():
            raise WorkerConfigurationError(
                "the simulator profile is test infrastructure and refuses a production "
                "deployment (FR-INT-04)"
            )
        # Imported only when this profile is chosen: the simulator package is not in the
        # production image, and a live-mode worker must import and refuse without it.
        from asic.evaluation.corpus import remediation_fixtures
        from asic.simulators.scenarios import scenario

        try:
            self._scenario = scenario(scenario_id)
        except KeyError as exc:
            raise WorkerConfigurationError(f"unknown simulator scenario {scenario_id!r}") from exc
        self._pre, self._post = remediation_fixtures(remediation_variant)
        self._factory = factory
        self._clock = clock or SystemClock()

    def investigation_service(
        self, tenant_id: uuid.UUID, run_id: uuid.UUID | None
    ) -> InvestigationService:
        from asic.simulators.provider import SimulatorProvider

        retriever = KnowledgeRetriever(
            EmbeddingService(DeterministicEmbeddingProvider()), clock=self._clock
        )
        return InvestigationService(
            session_factory=self._factory,
            providers=[
                KnowledgeStoreProvider(self._factory, retriever),
                SimulatorProvider(self._scenario, clock=self._clock),
            ],
            model=self._model(self._scenario, tenant_id, run_id),
            clock=self._clock,
            budget_policy=self._scenario.budget,
        )

    def remediation_kernel(
        self, tenant_id: uuid.UUID, run_id: uuid.UUID | None
    ) -> RemediationKernel:
        from asic.simulators.provider import SimulatorProvider

        world = (
            self._post if run_id is not None and self._executed(tenant_id, run_id) else self._pre
        )
        return RemediationKernel(
            session_factory=self._factory,
            resolver=CapabilityResolver(ToolRegistry.remediation_full(), max_risk_tier=RiskTier.R2),
            providers=[SimulatorProvider(world, clock=self._clock)],
            model=self._model(self._pre, tenant_id, run_id),
            clock=self._clock,
        )

    def postmortem_author(self) -> PostmortemAuthor:
        return PostmortemAuthor(
            session_factory=self._factory,
            model=DeterministicModelProvider(self._scenario),
            clock=self._clock,
        )

    # ------------------------------------------------------------------ internals

    def _model(
        self, selected: Scenario, tenant_id: uuid.UUID, run_id: uuid.UUID | None
    ) -> DeterministicModelProvider:
        model = DeterministicModelProvider(selected)
        if run_id is None:
            return model
        with self._factory() as session:
            bind_tenant(session, tenant_id)
            made = (
                session.execute(
                    sa.select(ModelCallReservation.node_id, sa.func.count())
                    .where(
                        ModelCallReservation.tenant_id == tenant_id,
                        ModelCallReservation.workflow_run_id == run_id,
                    )
                    .group_by(ModelCallReservation.node_id)
                )
                .tuples()
                .all()
            )
            session.rollback()
        model.resume_after({NodeId(node): int(count) for node, count in made})
        return model

    def _executed(self, tenant_id: uuid.UUID, run_id: uuid.UUID) -> bool:
        with self._factory() as session:
            bind_tenant(session, tenant_id)
            executed = session.scalar(
                sa.select(sa.func.count())
                .select_from(RemediationAction)
                .where(
                    RemediationAction.tenant_id == tenant_id,
                    RemediationAction.workflow_run_id == run_id,
                    RemediationAction.executed_at.is_not(None),
                )
            )
            session.rollback()
        return bool(executed)


__all__ = [
    "LIVE_MODEL_UNAVAILABLE",
    "ExecutionProfile",
    "SimulatorProfile",
    "build_profile",
]
