"""A thin application service, and a command-line entry point for the vertical slice.

The Phase 4 brief is explicit that the FastAPI application is not this phase's work, and
that any entry point needed to demonstrate the kernel must stay thin. This is that entry
point: it wires dependencies together and calls the kernel. There is **no business logic
here** - no routing, no budget arithmetic, no policy - because everything that decides
anything belongs to the domain and the orchestration layers, where it is tested.

Its second purpose is to be the shape an HTTP handler will take in Phase 9: construct the
dependencies, bind the tenant, call the kernel, return the outcome. A handler that did more
than this would be a handler with logic in it.

Run it against a migrated database with::

    python -m asic.orchestration.service --scenario SC-0001-checkout-latency-after-deploy

It refuses to run against a deployment marked production, because it builds a simulator.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from asic.db.models import (
    Alert,
    BehaviourVersion,
    Environment,
    Incident,
    Service,
    Tenant,
    TenantToolGrant,
    ToolDefinition,
)
from asic.db.session import (
    DATABASE_URL_ENV,
    MIGRATION_URL_ENV,
    bind_tenant,
    create_app_engine,
)
from asic.domain.budget import BudgetPolicy
from asic.domain.clock import Clock, FrozenClock, SystemClock
from asic.domain.enums import AlertSeverity, AlertStatus, IncidentSeverity, IncidentStatus
from asic.domain.idempotency import alert_key
from asic.llm.deterministic import DeterministicModelProvider
from asic.llm.port import ModelProvider
from asic.llm.prompts import PROMPT_SET_VERSION
from asic.orchestration.kernel import InvestigationKernel, RunOutcome
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import PRIMARY_SCENARIO_ID, Scenario, scenario
from asic.tools.capability import CapabilityResolver
from asic.tools.catalogue import CATALOGUE_VERSION
from asic.tools.provider import ToolProvider
from asic.tools.registry import ToolRegistry


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    """What a caller must supply to start an investigation."""

    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    behaviour_version_id: uuid.UUID
    service_ids: tuple[uuid.UUID, ...]
    scenario_id: str | None = None
    random_seed: int | None = None
    dispatch_id: uuid.UUID | None = None


class InvestigationService:
    """Wires dependencies and delegates. Deliberately almost empty."""

    __slots__ = ("_budget_policy", "_clock", "_model", "_providers", "_session_factory")

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        providers: Sequence[ToolProvider],
        model: ModelProvider,
        clock: Clock | None = None,
        budget_policy: BudgetPolicy | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._providers = list(providers)
        self._model = model
        self._clock = clock or SystemClock()
        self._budget_policy = budget_policy

    def _kernel(self) -> InvestigationKernel:
        return InvestigationKernel(
            session_factory=self._session_factory,
            resolver=CapabilityResolver(ToolRegistry.read_only()),
            providers=self._providers,
            model=self._model,
            clock=self._clock,
            budget_policy=self._budget_policy,
        )

    def start(
        self, request: InvestigationRequest, *, fixture_refs: dict[str, object] | None = None
    ) -> RunOutcome:
        return self._kernel().start(
            tenant_id=request.tenant_id,
            incident_id=request.incident_id,
            behaviour_version_id=request.behaviour_version_id,
            service_ids=list(request.service_ids),
            fixture_refs=fixture_refs,
            random_seed=request.random_seed,
            dispatch_id=request.dispatch_id,
        )

    def resume(self, *, tenant_id: uuid.UUID, workflow_run_id: uuid.UUID) -> RunOutcome:
        return self._kernel().resume(tenant_id=tenant_id, workflow_run_id=workflow_run_id)


# ------------------------------------------------------------------ demonstration wiring


@dataclass(frozen=True, slots=True)
class SeededIncident:
    """Identifiers for a demonstration incident."""

    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    service_ids: tuple[uuid.UUID, ...]
    behaviour_version_id: uuid.UUID


def seed_demonstration_incident(
    session: Session, *, scenario_obj: Scenario, clock: Clock, slug: str | None = None
) -> SeededIncident:
    """Create a tenant, service, incident and grants for a scenario.

    Development and demonstration wiring, not production onboarding: a real tenant arrives
    through the administrative surface built in a later phase. It lives beside the CLI that
    uses it rather than in the library, so nothing in the orchestration path can call it.
    """
    slug = slug or f"demo-{uuid.uuid4().hex[:8]}"
    now = clock.now()

    tenant = Tenant(id=uuid.uuid4(), slug=slug, display_name=slug)
    session.add(tenant)
    session.flush()
    bind_tenant(session, tenant.id)

    environment = Environment(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name="production",
        display_name="Production",
        is_production=True,
    )
    service = Service(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=scenario_obj.service,
        display_name=scenario_obj.service,
        owner_team="demo",
        namespaces=["checkout"],
    )
    session.add_all([environment, service])
    session.flush()

    incident = Incident(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        reference=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=scenario_obj.title,
        environment_id=environment.id,
        status=IncidentStatus.DETECTED,
        severity=IncidentSeverity.SEV2,
        opened_at=now,
    )
    session.add(incident)
    session.flush()

    started_at = now - timedelta(minutes=5)
    session.add(
        Alert(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            incident_id=incident.id,
            service_id=service.id,
            environment_id=environment.id,
            source="alertmanager",
            source_fingerprint=f"{scenario_obj.scenario_id}-alert",
            title=scenario_obj.title,
            severity=AlertSeverity.HIGH,
            status=AlertStatus.CORRELATED,
            started_at=started_at,
            received_at=now,
            idempotency_key=alert_key(
                tenant_id=tenant.id,
                source="alertmanager",
                source_fingerprint=f"{scenario_obj.scenario_id}-alert",
                started_at=started_at,
            ),
        )
    )

    behaviour = BehaviourVersion(
        id=uuid.uuid4(),
        label=f"demo-{uuid.uuid4().hex[:8]}",
        code_version="0.4.0",
        prompt_set_version=PROMPT_SET_VERSION,
        retriever_config_version="none",
        policy_version="none",
        tool_registry_version=CATALOGUE_VERSION,
        fingerprint=uuid.uuid4().hex,
    )
    session.add(behaviour)
    session.flush()

    for definition in session.execute(sa.select(ToolDefinition)).scalars():
        session.add(
            TenantToolGrant(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                tool_definition_id=definition.id,
                environment_id=environment.id,
                is_enabled=True,
            )
        )
    session.flush()

    return SeededIncident(
        tenant_id=tenant.id,
        incident_id=incident.id,
        service_ids=(service.id,),
        behaviour_version_id=behaviour.id,
    )


def _session_factory(engine: Engine) -> Callable[[], Session]:
    def factory() -> Session:
        return Session(bind=engine, expire_on_commit=False, autoflush=False)

    return factory


def main(argv: Sequence[str] | None = None) -> int:
    """Run one simulated investigation end to end and print its outcome."""
    parser = argparse.ArgumentParser(
        description=(
            "Run one deterministic, simulator-backed investigation through the "
            "orchestration kernel. Read-only: no capability above tier RO is registered."
        )
    )
    parser.add_argument("--scenario", default=PRIMARY_SCENARIO_ID, help="scenario id to run")
    parser.add_argument(
        "--database-url",
        default=os.environ.get(DATABASE_URL_ENV),
        help=f"application connection string (default: ${DATABASE_URL_ENV})",
    )
    parser.add_argument(
        "--admin-database-url",
        default=os.environ.get(MIGRATION_URL_ENV),
        help=(
            "connection string used only to seed the demonstration tenant "
            f"(default: ${MIGRATION_URL_ENV}). Creating a tenant is an administrative "
            "operation: the application role has no INSERT on the global catalogues, and "
            "widening it to make a demo convenient would undo that."
        ),
    )
    parser.add_argument("--seed", type=int, default=42, help="random seed recorded on the trace")
    args = parser.parse_args(argv)

    if not args.database_url:
        parser.error(f"no database URL: pass --database-url or set {DATABASE_URL_ENV}")
    if not args.admin_database_url:
        parser.error(f"no administrative URL: pass --admin-database-url or set {MIGRATION_URL_ENV}")

    scenario_obj = scenario(args.scenario)
    clock = FrozenClock(start=datetime.now(UTC))
    engine = create_app_engine(args.database_url)
    admin_engine = create_app_engine(args.admin_database_url)
    factory = _session_factory(engine)

    try:
        # Seeding runs as an administrator; the investigation itself then runs as the
        # application role, under row-level security, exactly as it would in production.
        with _session_factory(admin_engine)() as session:
            seeded = seed_demonstration_incident(session, scenario_obj=scenario_obj, clock=clock)
            session.commit()

        service = InvestigationService(
            session_factory=factory,
            providers=[SimulatorProvider(scenario_obj, clock=clock)],
            model=DeterministicModelProvider(scenario_obj),
            clock=clock,
            budget_policy=scenario_obj.budget,
        )
        outcome = service.start(
            InvestigationRequest(
                tenant_id=seeded.tenant_id,
                incident_id=seeded.incident_id,
                behaviour_version_id=seeded.behaviour_version_id,
                service_ids=seeded.service_ids,
                random_seed=args.seed,
            ),
            fixture_refs=scenario_obj.fixture_ref(),
        )
    finally:
        engine.dispose()
        admin_engine.dispose()

    print(
        json.dumps(
            {
                "scenario": scenario_obj.scenario_id,
                "workflow_run_id": str(outcome.workflow_run_id),
                "incident_id": str(outcome.incident_id),
                "execution_trace_id": str(outcome.execution_trace_id),
                "terminated": outcome.terminated,
                "termination_reason": (
                    outcome.termination_reason.value if outcome.termination_reason else None
                ),
                "termination_rule": outcome.termination_rule_id,
                "incident_status": outcome.incident_status.value,
                "nodes_executed": list(outcome.nodes_executed),
                "checkpoints_written": outcome.checkpoints_written,
                "expected": {
                    "termination_reason": scenario_obj.expectation.terminal_reason.value,
                    "incident_status": scenario_obj.expectation.terminal_incident_status,
                },
                "summary": dict(outcome.summary),
            },
            indent=2,
        )
    )
    return 0 if outcome.terminated else 1


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
