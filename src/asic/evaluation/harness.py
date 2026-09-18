"""The evaluation harness: arrange, execute through the real kernels, observe, score, seal.

Execution uses the production contracts - ``InvestigationKernel``, ``RemediationKernel``,
``IngestionService``, ``ToolBroker`` and the approval service - with only the provider seams
swapped for deterministic simulators (``simulator`` mode) or recorded fixtures (``replay``
mode). There is no second execution engine to drift from the product.

Everything is persisted in one transaction at the end of a suite: the sealed suite report,
each scenario version, each run's checks and metrics, judge results and replay fixtures.
Results are insert-only for the application role.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import sqlalchemy as sa
from opentelemetry import trace as otel_trace
from sqlalchemy.orm import Session

from asic import __version__ as code_version
from asic.contracts.nodes import G3_INVESTIGATION_PLANNER, G4_EVIDENCE_COLLECTOR
from asic.db.models import (
    EvaluationJudgeResult,
    EvaluationReplayFixture,
    EvaluationRun,
    EvaluationScenario,
    EvaluationSuiteRun,
    Evidence,
    ExecutionTrace,
    Hypothesis,
    Incident,
    RemediationAction,
    RemediationTarget,
)
from asic.db.projections import apply_transition
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    ApprovalDecision,
    EvaluationFailureClass,
    EvaluationRunVerdict,
    ExecutionMode,
    HypothesisStatus,
    IncidentStatus,
    IntegrationKind,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    NodeId,
    RiskTier,
    TrustClass,
)
from asic.evaluation.comparison import compare, gate_status
from asic.evaluation.corpus import (
    SUITE_KEY,
    SUITE_VERSION,
    GoldenScenario,
    WorkflowKind,
    corpus_digest,
    remediation_fixtures,
    scenario_digest,
    select,
)
from asic.evaluation.evaluators import Evaluation, checks_payload, evaluate, invariant_checks
from asic.evaluation.fixture_transport import FixtureTransport
from asic.evaluation.judges import JudgeCase, JudgePanel, PanelResult
from asic.evaluation.observation import active_hypotheses, observe, summary
from asic.evaluation.replay import (
    Recorder,
    ReplayFixture,
    ReplayModelProvider,
    ReplayRefused,
    ReplayToolProvider,
    interaction_signature,
)
from asic.evaluation.versioning import EVALUATOR_VERSION, canonical, digest
from asic.evaluation.world import (
    ScenarioWorld,
    arrange,
    bind_connector,
    ensure_behaviour_version,
    ensure_tenant,
    revoke_connector,
)
from asic.ingestion.contracts import ConnectorContext
from asic.ingestion.service import IngestionService
from asic.integrations.base import AdapterRuntime
from asic.integrations.credentials import StaticCredentialProvider, is_production_deployment
from asic.integrations.provider import NativeIntegrationProvider
from asic.knowledge.contracts import (
    ImportActor,
    ImportContext,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import DeterministicEmbeddingProvider, EmbeddingService
from asic.knowledge.ingestion import KnowledgeIngestionService
from asic.knowledge.provider import KnowledgeStoreProvider
from asic.knowledge.retrieval import KnowledgeRetriever
from asic.llm.deterministic import MODEL_ID, PROVIDER_NAME, DeterministicModelProvider
from asic.llm.port import ModelProvider
from asic.llm.prompts import PROMPT_SET_VERSION
from asic.observability.audit import AuditWriter
from asic.observability.tracing import TraceRecorder, derive_trace_id
from asic.orchestration.kernel import InvestigationKernel
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.remediation import approval_service
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import SCENARIOS, Scenario
from asic.tools.broker import CapabilityRequest, ToolBroker
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.catalogue import CATALOGUE_VERSION
from asic.tools.integration_catalogue import INTEGRATION_CATALOGUE_VERSION
from asic.tools.provider import ToolProvider
from asic.tools.registry import ToolRegistry
from asic.tools.remediation_catalogue import REMEDIATION_CATALOGUE_VERSION

_tracer = otel_trace.get_tracer("asic.evaluation")

#: Fixed logical epoch. Scenario N runs at ``BASE_CLOCK + N days`` so windows never overlap.
BASE_CLOCK: Final[datetime] = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
REMEDIATION_POLICY_VERSION: Final[str] = "2026.09.14-1"
_SETTLING_ADVANCE_SECONDS: Final[int] = 90
_MAX_REMEDIATION_STEPS: Final[int] = 6


class HarnessRefused(RuntimeError):
    """The harness declined to run (production deployment, missing fixtures, tampering)."""


@dataclass(frozen=True, slots=True)
class HarnessConfig:
    tenant_slug: str
    suite: str = SUITE_KEY
    keys: tuple[str, ...] | None = None
    mode: ExecutionMode = ExecutionMode.SIMULATOR
    #: ``latest`` (latest passed suite run of this suite and mode), ``none``, or a suite run id.
    baseline: str = "latest"


@dataclass
class ScenarioOutcome:
    golden: GoldenScenario
    digest: str
    world: ScenarioWorld | None
    verdict: EvaluationRunVerdict
    evaluation: Evaluation
    panel: PanelResult
    wall_clock_ms: int
    workflow_run_id: uuid.UUID | None = None
    #: The execution trace of the evaluated run: the id a tracing backend shows for it.
    trace_id: str | None = None
    signature: str | None = None
    fixture: ReplayFixture | None = None
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def report(self) -> dict[str, Any]:
        return {
            "key": self.golden.key,
            "version": self.golden.version,
            "digest": self.digest,
            "kind": self.golden.kind.value,
            "scenario_class": self.golden.scenario_class.value,
            "covers": list(self.golden.covers),
            "verdict": self.verdict.value,
            "checks_failed": sorted(c.name for c in self.evaluation.checks if not c.passed),
            "zero_tolerance_failures": sorted(
                c.name for c in self.evaluation.zero_tolerance_failures
            ),
            "failure_classes": self.evaluation.failure_classes,
            "metrics": self.evaluation.metrics,
            "judges": {
                "status": self.panel.status,
                "mean_score": self.panel.mean_score,
                "spread": self.panel.spread,
            },
            "signature": self.signature,
            "trace_id": self.trace_id,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class SuiteOutcome:
    suite_run_id: uuid.UUID
    status: str
    report: Mapping[str, Any]


class EvaluationHarness:
    def __init__(
        self,
        *,
        admin_factory: Callable[[], Session],
        app_factory: Callable[[], Session],
        judge_panel: JudgePanel | None = None,
    ) -> None:
        if is_production_deployment():
            raise HarnessRefused("the evaluation harness does not run in a production deployment")
        self._admin = admin_factory
        self._app = app_factory
        self._panel = judge_panel or JudgePanel(())

    # ------------------------------------------------------------------------- suite

    def run(self, config: HarnessConfig) -> SuiteOutcome:
        with _tracer.start_as_current_span(
            "evaluation.suite",
            attributes={
                "asic.evaluation.suite": config.suite,
                "asic.evaluation.mode": config.mode.value,
                "asic.evaluation.evaluator_version": EVALUATOR_VERSION,
            },
            record_exception=False,
        ) as span:
            outcome = self._run(config)
            span.set_attribute("asic.evaluation.suite_run_id", str(outcome.suite_run_id))
            span.set_attribute("asic.evaluation.gate_status", outcome.status)
            return outcome

    def _run(self, config: HarnessConfig) -> SuiteOutcome:
        scenarios = select(config.keys, suite=config.suite)
        started = datetime.now(UTC)
        tenant_id = ensure_tenant(self._admin, config.tenant_slug)
        behaviour_id = ensure_behaviour_version(
            self._admin,
            code_version=code_version,
            prompt_set_version=PROMPT_SET_VERSION,
            model_ids={"*": f"{PROVIDER_NAME}/{MODEL_ID}"},
            retriever_config_version="none",
            policy_version=REMEDIATION_POLICY_VERSION,
            tool_registry_version=(
                f"{CATALOGUE_VERSION}+{REMEDIATION_CATALOGUE_VERSION}+{INTEGRATION_CATALOGUE_VERSION}"
            ),
            judge_set_version=None,
        )
        replay_fixtures: dict[str, ReplayFixture] = {}
        refusals: dict[str, str] = self._unversioned_changes(tenant_id, scenarios)
        if config.mode is ExecutionMode.REPLAY:
            replay_fixtures, unverified = self._load_fixtures(tenant_id, scenarios)
            for key, reason in unverified.items():
                refusals.setdefault(key, reason)
        token = uuid.uuid4().hex[:8]
        outcomes: list[ScenarioOutcome] = []
        for ordinal, golden in enumerate(scenarios):
            outcomes.append(
                self._run_scenario(
                    golden,
                    tenant_id=tenant_id,
                    behaviour_id=behaviour_id,
                    token=token,
                    ordinal=ordinal,
                    mode=config.mode,
                    fixture=replay_fixtures.get(golden.key),
                    refusal=refusals.get(golden.key),
                )
            )

        baseline = self._baseline(tenant_id, config)
        suite_run_id = uuid.uuid4()
        report: dict[str, Any] = {
            "suite_run_id": str(suite_run_id),
            "suite_key": config.suite,
            "suite_version": SUITE_VERSION,
            "corpus_digest": corpus_digest(scenarios),
            "evaluator_version": EVALUATOR_VERSION,
            "execution_mode": config.mode.value,
            "evidence_label": "SIMULATED / REPLAY EVALUATION - not production results",
            "behaviour_version_id": str(behaviour_id),
            "repetitions": 1,
            "judges": "configured (uncalibrated)" if self._panel.configured else "not_measured",
            "scenarios": [o.report() for o in outcomes],
        }
        report["comparison"] = compare(report, baseline[1] if baseline else None)
        report["aggregate"] = aggregate(outcomes)
        status = gate_status(report)
        report["gate_status"] = status.value
        self._persist(
            suite_run_id=suite_run_id,
            tenant_id=tenant_id,
            behaviour_id=behaviour_id,
            config=config,
            baseline_id=baseline[0] if baseline else None,
            report=report,
            outcomes=outcomes,
            started=started,
        )
        return SuiteOutcome(suite_run_id=suite_run_id, status=status.value, report=report)

    # ---------------------------------------------------------------------- scenario

    def _run_scenario(
        self,
        golden: GoldenScenario,
        *,
        tenant_id: uuid.UUID,
        behaviour_id: uuid.UUID,
        token: str,
        ordinal: int,
        mode: ExecutionMode,
        fixture: ReplayFixture | None,
        refusal: str | None = None,
    ) -> ScenarioOutcome:
        with _tracer.start_as_current_span(
            "evaluation.scenario",
            attributes={
                "asic.evaluation.scenario": golden.key,
                "asic.evaluation.scenario_version": golden.version,
                "asic.evaluation.kind": golden.kind.value,
                "asic.evaluation.mode": mode.value,
            },
            record_exception=False,
        ) as span:
            outcome = self._run_scenario_body(
                golden,
                tenant_id=tenant_id,
                behaviour_id=behaviour_id,
                token=token,
                ordinal=ordinal,
                mode=mode,
                fixture=fixture,
                refusal=refusal,
            )
            if outcome.workflow_run_id is not None:
                outcome.trace_id = self._trace_of(tenant_id, outcome.workflow_run_id)
            span.set_attribute("asic.evaluation.verdict", outcome.verdict.value)
            if outcome.trace_id is not None:
                # The link from this evaluation to the product trace it scored.
                span.set_attribute("asic.evaluated_trace_id", outcome.trace_id)
            return outcome

    def _trace_of(self, tenant_id: uuid.UUID, workflow_run_id: uuid.UUID) -> str | None:
        with self._app() as session:
            bind_tenant(session, tenant_id)
            return session.scalar(
                sa.select(ExecutionTrace.trace_id)
                .where(
                    ExecutionTrace.tenant_id == tenant_id,
                    ExecutionTrace.workflow_run_id == workflow_run_id,
                )
                .order_by(ExecutionTrace.started_at, ExecutionTrace.id)
                .limit(1)
            )

    def _run_scenario_body(
        self,
        golden: GoldenScenario,
        *,
        tenant_id: uuid.UUID,
        behaviour_id: uuid.UUID,
        token: str,
        ordinal: int,
        mode: ExecutionMode,
        fixture: ReplayFixture | None,
        refusal: str | None,
    ) -> ScenarioOutcome:
        began = time.perf_counter()
        scenario_hash = scenario_digest(golden)
        world: ScenarioWorld | None = None
        try:
            if refusal is not None:
                raise HarnessRefused(refusal)
            if mode is ExecutionMode.REPLAY and golden.kind in (
                WorkflowKind.INVESTIGATION,
                WorkflowKind.REMEDIATION,
            ):
                if fixture is None:
                    raise HarnessRefused(f"no verified replay fixture for {golden.key}")
                if fixture.scenario_digest != scenario_hash:
                    raise HarnessRefused(
                        f"replay fixture for {golden.key} was recorded for a different scenario version"
                    )
            service = self._service_for(golden)
            world = arrange(
                self._admin,
                tenant_id=tenant_id,
                golden=golden,
                service_name=service,
                suite_token=token,
                ordinal=ordinal,
                clock_start=BASE_CLOCK + timedelta(days=ordinal),
            )
            recorder = Recorder()
            evaluation = Evaluation()
            outcome = ScenarioOutcome(
                golden=golden,
                digest=scenario_hash,
                world=world,
                verdict=EvaluationRunVerdict.ERRORED,
                evaluation=evaluation,
                panel=PanelResult(status="not_measured"),
                wall_clock_ms=0,
            )
            if golden.kind is WorkflowKind.INVESTIGATION:
                self._investigate(golden, world, behaviour_id, recorder, mode, fixture, outcome)
            elif golden.kind is WorkflowKind.REMEDIATION:
                self._remediate(golden, world, behaviour_id, recorder, mode, fixture, outcome)
            elif golden.kind is WorkflowKind.CORRELATION:
                self._correlate(golden, world, outcome)
            else:
                self._probe(golden, world, outcome)
            if golden.kind in (WorkflowKind.INVESTIGATION, WorkflowKind.REMEDIATION):
                with self._app() as session:
                    observation = observe(
                        session, tenant_id=tenant_id, incident_id=world.incident_id
                    )
                scored = evaluate(golden, observation)
                outcome.evaluation.checks.extend(scored.checks)
                outcome.evaluation.metrics.update(scored.metrics)
                outcome.signature = digest(summary(observation))
                if mode is ExecutionMode.REPLAY:
                    _replay_checks(outcome, fixture)
                outcome.workflow_run_id = self._evaluated_run(golden, world, observation)
                if mode is ExecutionMode.SIMULATOR:
                    outcome.fixture = recorder.fixture(
                        scenario_key=golden.key, scenario_digest=scenario_hash
                    )
                if golden.kind is WorkflowKind.INVESTIGATION and self._panel.configured:
                    outcome.panel = self._judge(golden, world, observation)
            outcome.evaluation.metrics["observation_signature"] = outcome.signature
            outcome.verdict = _verdict(outcome.evaluation, outcome.panel)
        except Exception as exc:  # the harness records its own failure as a result, never a pass
            evaluation = Evaluation()
            evaluation.add(
                "harness.completed",
                False,
                f"{type(exc).__name__}: {str(exc)[:300]}",
                EvaluationFailureClass.HARNESS,
            )
            outcome = ScenarioOutcome(
                golden=golden,
                digest=scenario_hash,
                world=world,
                verdict=EvaluationRunVerdict.ERRORED,
                evaluation=evaluation,
                panel=PanelResult(status="not_measured"),
                wall_clock_ms=0,
                error=f"{type(exc).__name__}: {str(exc)[:300]}",
            )
        outcome.wall_clock_ms = int((time.perf_counter() - began) * 1000)
        # Wall clock is harness-measured and non-deterministic: informational only.
        outcome.evaluation.metrics["wall_clock_ms_informational"] = outcome.wall_clock_ms
        return outcome

    def _evaluated_run(
        self, golden: GoldenScenario, world: ScenarioWorld, observation: Any
    ) -> uuid.UUID | None:
        """The workflow run a result is bound to: the remediation run for a remediation
        scenario (its investigation run is setup), otherwise the investigation run."""
        if golden.kind is WorkflowKind.REMEDIATION:
            with self._app() as session:
                bind_tenant(session, world.tenant_id)
                return session.scalar(
                    sa.select(RemediationTarget.workflow_run_id).where(
                        RemediationTarget.tenant_id == world.tenant_id,
                        RemediationTarget.incident_id == world.incident_id,
                    )
                )
        runs: list[uuid.UUID] = observation.workflow_run_ids
        return runs[0] if len(runs) == 1 else None

    @staticmethod
    def _service_for(golden: GoldenScenario) -> str:
        if golden.fixture is not None:
            return SCENARIOS[golden.fixture].service
        return "checkout-api"

    # --------------------------------------------------------------- investigation

    def _providers(
        self,
        simulated: Scenario,
        clock: FrozenClock,
        recorder: Recorder,
        mode: ExecutionMode,
        replay_tools: ReplayToolProvider | None,
        knowledge: ToolProvider | None = None,
    ) -> list[ToolProvider]:
        # The governed knowledge store is internal state rebuilt from versioned documents in
        # every world, so it answers directly in both modes and is never recorded; the broker
        # takes the first provider that supports a tool, so it must come first.
        native = [knowledge] if knowledge is not None else []
        if mode is ExecutionMode.REPLAY:
            assert replay_tools is not None
            return [*native, replay_tools]
        return [*native, *recorder.wrap_tools([SimulatorProvider(simulated, clock=clock)])]

    def _knowledge(
        self, golden: GoldenScenario, world: ScenarioWorld, clock: FrozenClock
    ) -> ToolProvider | None:
        if not golden.knowledge_documents:
            return None
        embeddings = EmbeddingService(DeterministicEmbeddingProvider())
        ingestion = KnowledgeIngestionService(self._app, embeddings, clock=clock)
        for document in golden.knowledge_documents:
            result = ingestion.ingest(
                ImportContext(
                    tenant_id=world.tenant_id,
                    provider="evaluation",
                    source_ref=f"{world.environment_name}/{document.source_ref}",
                    policy=SourceAccessPolicy(
                        document_type=KnowledgeDocumentType.RUNBOOK,
                        trust_class=TrustClass(document.trust_class),
                        service_ids=tuple(world.service_ids),
                        environment_ids=(world.environment_id,),
                    ),
                    actor=ImportActor(
                        actor_type=ActorType.SYSTEM, actor_id="connector:evaluation-corpus"
                    ),
                ),
                SourceDocument(
                    title=document.title,
                    body=document.body.encode("utf-8"),
                    content_format=KnowledgeContentFormat.MARKDOWN,
                ),
            )
            if result.outcome.value != "created":
                raise HarnessRefused(
                    f"{golden.key}: knowledge document {document.source_ref} was not ingested "
                    f"({result.outcome.value})"
                )
        return KnowledgeStoreProvider(self._app, KnowledgeRetriever(embeddings, clock=clock))

    def _model(
        self,
        simulated: Scenario,
        recorder: Recorder,
        mode: ExecutionMode,
        replay_model: ReplayModelProvider | None,
    ) -> ModelProvider:
        if mode is ExecutionMode.REPLAY:
            assert replay_model is not None
            return replay_model
        return recorder.wrap_model(DeterministicModelProvider(simulated))

    def _investigate(
        self,
        golden: GoldenScenario,
        world: ScenarioWorld,
        behaviour_id: uuid.UUID,
        recorder: Recorder,
        mode: ExecutionMode,
        fixture: ReplayFixture | None,
        outcome: ScenarioOutcome,
    ) -> None:
        assert golden.fixture is not None
        simulated = SCENARIOS[golden.fixture]
        replay_tools = ReplayToolProvider(fixture) if fixture else None
        replay_model = (
            ReplayModelProvider(fixture, provider_name=PROVIDER_NAME, model_id=MODEL_ID)
            if fixture
            else None
        )
        knowledge = self._knowledge(golden, world, FrozenClock(start=world.clock_start))
        self._run_investigation(
            simulated,
            world,
            behaviour_id,
            recorder,
            mode,
            replay_tools,
            replay_model,
            golden.key,
            knowledge=knowledge,
        )
        if mode is ExecutionMode.REPLAY:
            _record_replay_observations(outcome, replay_tools, replay_model)

    def _run_investigation(
        self,
        simulated: Scenario,
        world: ScenarioWorld,
        behaviour_id: uuid.UUID,
        recorder: Recorder,
        mode: ExecutionMode,
        replay_tools: ReplayToolProvider | None,
        replay_model: ReplayModelProvider | None,
        key: str,
        *,
        knowledge: ToolProvider | None = None,
    ) -> None:
        clock = FrozenClock(start=world.clock_start)
        kernel = InvestigationKernel(
            session_factory=self._app,
            resolver=CapabilityResolver(ToolRegistry.read_only()),
            providers=self._providers(simulated, clock, recorder, mode, replay_tools, knowledge),
            model=self._model(simulated, recorder, mode, replay_model),
            clock=clock,
            budget_policy=simulated.budget,
        )
        kernel.start(
            tenant_id=world.tenant_id,
            incident_id=world.incident_id,
            behaviour_version_id=behaviour_id,
            service_ids=list(world.service_ids),
            fixture_refs={
                **simulated.fixture_ref(),
                "evaluation_scenario": key,
                "mode": mode.value,
            },
            random_seed=42,
        )

    # ------------------------------------------------------------------ remediation

    def _remediate(
        self,
        golden: GoldenScenario,
        world: ScenarioWorld,
        behaviour_id: uuid.UUID,
        recorder: Recorder,
        mode: ExecutionMode,
        fixture: ReplayFixture | None,
        outcome: ScenarioOutcome,
    ) -> None:
        assert golden.remediation is not None
        pre, post = remediation_fixtures(golden.variant)
        investigation = SCENARIOS["SC-0001-checkout-latency-after-deploy"]
        replay_tools = ReplayToolProvider(fixture) if fixture else None
        replay_model = (
            ReplayModelProvider(fixture, provider_name=PROVIDER_NAME, model_id=MODEL_ID)
            if fixture
            else None
        )
        self._run_investigation(
            investigation,
            world,
            behaviour_id,
            recorder,
            mode,
            replay_tools,
            replay_model,
            golden.key,
        )
        hypothesis_id = self._reopen(world)
        clock = FrozenClock(start=world.clock_start)
        resolver = CapabilityResolver(ToolRegistry.remediation_full(), max_risk_tier=RiskTier.R2)
        # One model instance for the whole remediation run, so its script cursor persists
        # across suspension and resume exactly as a durable provider's would.
        model = self._model(pre, recorder, mode, replay_model)

        def kernel(stage: Scenario) -> RemediationKernel:
            return RemediationKernel(
                session_factory=self._app,
                resolver=resolver,
                providers=self._providers(stage, clock, recorder, mode, replay_tools),
                model=model,
                clock=clock,
            )

        result = kernel(pre).start(
            tenant_id=world.tenant_id,
            incident_id=world.incident_id,
            hypothesis_id=hypothesis_id,
            behaviour_version_id=behaviour_id,
            selected_service_id=world.service_ids[0],
            fixture_refs={
                "remediation_fixture": pre.scenario_id,
                "evaluation_scenario": golden.key,
                "mode": mode.value,
            },
        )
        steps = 0
        approved = False
        while not result.terminated and steps < _MAX_REMEDIATION_STEPS:
            steps += 1
            if result.incident_status is IncidentStatus.AWAITING_APPROVAL:
                if not golden.remediation.approve or approved:
                    break
                self._approve(world, clock)
                approved = True
                result = kernel(pre).resume(
                    tenant_id=world.tenant_id, workflow_run_id=result.workflow_run_id
                )
                continue
            clock.advance(_SETTLING_ADVANCE_SECONDS)
            result = kernel(post).resume(
                tenant_id=world.tenant_id, workflow_run_id=result.workflow_run_id
            )
        outcome.extra["remediation_steps"] = steps
        if mode is ExecutionMode.REPLAY:
            _record_replay_observations(outcome, replay_tools, replay_model)

    def _reopen(self, world: ScenarioWorld) -> uuid.UUID:
        with self._app() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            incident = session.execute(
                sa.select(Incident).where(
                    Incident.tenant_id == world.tenant_id, Incident.id == world.incident_id
                )
            ).scalar_one()
            if incident.status is IncidentStatus.ESCALATED:
                apply_transition(
                    session,
                    incident=incident,
                    target=IncidentStatus.INVESTIGATING,
                    actor_type=ActorType.HUMAN,
                    source="evaluation-operator",
                    correlation_id=uuid.uuid4(),
                    justification="evaluation scenario: reopened to evaluate remediation",
                )
            hypothesis = session.execute(
                sa.select(Hypothesis.id)
                .where(
                    Hypothesis.tenant_id == world.tenant_id,
                    Hypothesis.incident_id == world.incident_id,
                    Hypothesis.status.in_((HypothesisStatus.PROPOSED, HypothesisStatus.ACCEPTED)),
                )
                .order_by(Hypothesis.rank)
                .limit(1)
            ).scalar_one()
            return hypothesis

    def _approve(self, world: ScenarioWorld, clock: FrozenClock) -> None:
        if world.approver_user_id is None:
            raise HarnessRefused("approval requested but the scenario arranged no approver")
        with self._app() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            action = session.execute(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == world.tenant_id,
                    RemediationAction.incident_id == world.incident_id,
                )
            ).scalar_one()
            approval_service.decide(
                session,
                tenant_id=world.tenant_id,
                action_id=action.id,
                actor_user_id=world.approver_user_id,
                decision=ApprovalDecision.APPROVED,
                expected_action_version_hash=action.action_version_hash,
                justification="evaluation scenario approver",
                clock=clock,
            )

    # ------------------------------------------------------------------ correlation

    def _correlate(
        self, golden: GoldenScenario, world: ScenarioWorld, outcome: ScenarioOutcome
    ) -> None:
        assert golden.correlation is not None
        expectation = golden.correlation
        service = IngestionService(self._app, clock=FrozenClock(start=world.clock_start))
        context = ConnectorContext(
            tenant_id=world.tenant_id,
            connector_id="evaluation",
            source="simulator",
            service_id=world.service_ids[0],
            environment_id=world.environment_id,
        )
        started = world.clock_start - timedelta(minutes=2)
        results = []
        for fingerprint, category, _suffix in expectation.alerts:
            body = {
                "schema_version": 1,
                # Scoped to this world: deduplication is tenant-wide, and an earlier suite run
                # in the same tenant must not absorb this run's alerts.
                "fingerprint": f"{fingerprint}-{world.environment_name}",
                "title": f"{category} alert {fingerprint}",
                "severity": "high",
                "category": category,
                "started_at": started.isoformat(),
                "observed_at": (started + timedelta(minutes=1)).isoformat(),
            }
            results.append(service.ingest(context, json.dumps(body).encode()))
        incidents = {r.incident_id for r in results if r.incident_id is not None} - {
            world.incident_id
        }
        duplicates = sum(1 for r in results if r.duplicate)
        evaluation = outcome.evaluation
        evaluation.add(
            "expect.incidents_created",
            len(incidents) == expectation.incidents_created,
            f"{len(incidents)} incident(s) created; expected {expectation.incidents_created}",
            EvaluationFailureClass.PLANNING,
        )
        evaluation.add(
            "expect.duplicates_absorbed",
            duplicates == expectation.duplicate_deliveries,
            f"{duplicates} duplicate delivery(ies); expected {expectation.duplicate_deliveries}",
            EvaluationFailureClass.INTEGRATION,
        )
        evaluation.metrics.update(
            {"alerts": len(results), "incidents_created": len(incidents), "duplicates": duplicates}
        )
        outcome.signature = digest(
            {
                "incidents": len(incidents),
                "duplicates": duplicates,
                "outcomes": sorted(r.outcome for r in results),
            }
        )

    # --------------------------------------------------------------------- security

    def _probe(
        self, golden: GoldenScenario, world: ScenarioWorld, outcome: ScenarioOutcome
    ) -> None:
        assert golden.security is not None
        expectation = golden.security
        clock = FrozenClock(start=world.clock_start)
        adapter_calls: Callable[[], int]
        connector_id: str | None = None
        if expectation.probe == "connector_revocation":
            transport = FixtureTransport.prometheus_ok()
            provider: ToolProvider = NativeIntegrationProvider(
                AdapterRuntime(
                    transport=transport,
                    credentials=StaticCredentialProvider(
                        {"asic/evaluation/read": "evaluation-fixture-token"}
                    ),
                    clock=clock,
                    allow_loopback_http=False,
                )
            )
            connector_id = bind_connector(
                self._admin,
                world,
                kind=IntegrationKind.PROMETHEUS,
                endpoint="https://prometheus.evaluation.invalid",
                credential_ref="asic/evaluation/read",
            )
            adapter_calls = lambda: transport.calls  # noqa: E731
        else:
            simulator = SimulatorProvider(
                SCENARIOS[golden.fixture or "SC-0001-checkout-latency-after-deploy"], clock=clock
            )
            provider = simulator
            adapter_calls = lambda: len(simulator.calls)  # noqa: E731

        arguments = {
            "window_start": world.clock_start - timedelta(minutes=30),
            "window_end": world.clock_start,
            "metric": "http_request_duration_p95_seconds",
        }
        results = []
        with self._app() as session:
            bind_tenant(session, world.tenant_id)
            scope = load_incident_scope(
                session,
                tenant_id=world.tenant_id,
                incident_id=world.incident_id,
                environment_id=world.environment_id,
                service_ids=list(world.service_ids),
            )
            broker = ToolBroker(
                resolver=CapabilityResolver(ToolRegistry.read_only()),
                providers=[provider],
                scope=scope,
                audit=AuditWriter(tenant_id=world.tenant_id, clock=clock),
                tracer=TraceRecorder(
                    tenant_id=world.tenant_id,
                    execution_trace_id=uuid.uuid4(),
                    trace_id=derive_trace_id(uuid.uuid4()),
                    clock=clock,
                ),
                clock=clock,
            )
            try:
                contract = (
                    G3_INVESTIGATION_PLANNER
                    if expectation.probe == "authorization_denial"
                    else G4_EVIDENCE_COLLECTOR
                )
                node = (
                    NodeId.G3_INVESTIGATION_PLANNER
                    if expectation.probe == "authorization_denial"
                    else NodeId.G4_EVIDENCE_COLLECTOR
                )
                request = CapabilityRequest(
                    node_id=node,
                    capability="read.metrics",
                    service_name=world.service_names[0],
                    arguments=arguments,
                    incident_id=world.incident_id,
                    correlation_id=uuid.uuid4(),
                    purpose=f"evaluation probe {expectation.probe}",
                )
                results.append(broker.invoke(session, request=request, contract=contract))
                session.commit()
                if expectation.probe in ("duplicate_execution", "connector_revocation"):
                    if connector_id is not None:
                        revoke_connector(self._admin, world, connector_id)
                    bind_tenant(session, world.tenant_id)
                    results.append(broker.invoke(session, request=request, contract=contract))
                    session.commit()
            finally:
                broker.close()
        final = results[-1]
        evaluation = outcome.evaluation
        refused_stage = final.failure.stage.value if final.failure is not None else None
        evaluation.add(
            "expect.refused_stage",
            refused_stage == expectation.refused_stage,
            f"final request refused at {refused_stage!r}; expected {expectation.refused_stage!r}",
            EvaluationFailureClass.TOOL_AUTHORIZATION,
            zero=expectation.refused_stage is not None,
        )
        evaluation.add(
            "expect.adapter_calls",
            adapter_calls() == expectation.adapter_calls,
            f"{adapter_calls()} adapter call(s); expected {expectation.adapter_calls}",
            EvaluationFailureClass.TOOL_AUTHORIZATION,
            zero=True,
        )
        if expectation.deduplicated:
            evaluation.add(
                "expect.deduplicated",
                final.deduplicated,
                f"second request deduplicated={final.deduplicated}",
                EvaluationFailureClass.TOOL_SELECTION,
                zero=True,
            )
        with self._app() as session:
            observation = observe(session, tenant_id=world.tenant_id, incident_id=world.incident_id)
        invariant_checks(observation, evaluation)
        evaluation.metrics.update(
            {
                "adapter_calls": adapter_calls(),
                "authorization_denials": observation.authorization_denials,
            }
        )
        outcome.signature = digest(
            {
                "stage": refused_stage,
                "adapter_calls": adapter_calls(),
                "deduplicated": final.deduplicated,
            }
        )

    # ----------------------------------------------------------------------- judges

    def _judge(self, golden: GoldenScenario, world: ScenarioWorld, observation: Any) -> PanelResult:
        leading = active_hypotheses(observation)
        if not leading:
            return PanelResult(status="not_applicable")
        with self._app() as session:
            bind_tenant(session, world.tenant_id)
            hypothesis = session.get(Hypothesis, leading[0].id)
            evidence = list(
                session.scalars(
                    sa.select(Evidence).where(
                        Evidence.tenant_id == world.tenant_id,
                        Evidence.incident_id == world.incident_id,
                    )
                )
            )
        assert hypothesis is not None
        case = JudgeCase(
            run_label=golden.key,
            hypothesis_statement=hypothesis.statement,
            root_cause_class=hypothesis.root_cause_class,
            evidence=[(str(e.id), e.domain.value, json.dumps(e.content)[:800]) for e in evidence],
        )
        return self._panel.evaluate(case)

    # ---------------------------------------------------------------------- storage

    def _unversioned_changes(
        self, tenant_id: uuid.UUID, scenarios: Sequence[GoldenScenario]
    ) -> dict[str, str]:
        """Scenarios whose stored definition differs from the corpus at the same version."""
        refused: dict[str, str] = {}
        with self._app() as session:
            bind_tenant(session, tenant_id)
            for golden in scenarios:
                stored = session.scalars(
                    sa.select(EvaluationScenario).where(
                        EvaluationScenario.tenant_id == tenant_id,
                        EvaluationScenario.key == golden.key,
                        EvaluationScenario.version == golden.version,
                    )
                ).one_or_none()
                if stored is not None and dict(stored.fixture_refs).get(
                    "digest"
                ) != scenario_digest(golden):
                    refused[golden.key] = (
                        f"{golden.key} v{golden.version} changed without a version bump; publish "
                        "a new scenario version instead of editing a stored one"
                    )
        return refused

    def _load_fixtures(
        self, tenant_id: uuid.UUID, scenarios: Sequence[GoldenScenario]
    ) -> tuple[dict[str, ReplayFixture], dict[str, str]]:
        loaded: dict[str, ReplayFixture] = {}
        unverified: dict[str, str] = {}
        with self._app() as session:
            bind_tenant(session, tenant_id)
            for golden in scenarios:
                row = session.scalars(
                    sa.select(EvaluationReplayFixture)
                    .where(
                        EvaluationReplayFixture.tenant_id == tenant_id,
                        EvaluationReplayFixture.scenario_key == golden.key,
                    )
                    .order_by(EvaluationReplayFixture.created_at.desc())
                    .limit(1)
                ).one_or_none()
                if row is None:
                    continue
                try:
                    loaded[golden.key] = ReplayFixture.load(row.content, expected_digest=row.digest)
                except ReplayRefused as exc:
                    # The scenario errors: a tampered fixture never replays, and never falls
                    # back to an older recording.
                    unverified[golden.key] = f"replay fixture for {golden.key} refused: {exc}"
        return loaded, unverified

    def _baseline(
        self, tenant_id: uuid.UUID, config: HarnessConfig
    ) -> tuple[uuid.UUID, Mapping[str, Any]] | None:
        if config.baseline == "none":
            return None
        with self._app() as session:
            bind_tenant(session, tenant_id)
            query = sa.select(EvaluationSuiteRun).where(
                EvaluationSuiteRun.tenant_id == tenant_id,
                EvaluationSuiteRun.suite_key == config.suite,
            )
            if config.baseline == "latest":
                query = query.where(EvaluationSuiteRun.gate_status == "passed").order_by(
                    EvaluationSuiteRun.completed_at.desc()
                )
            else:
                query = query.where(EvaluationSuiteRun.id == uuid.UUID(config.baseline))
            row = session.scalars(query.limit(1)).one_or_none()
            if row is None:
                return None
            if digest(dict(row.report)) != row.report_digest:
                raise HarnessRefused("baseline suite report does not match its digest")
            return row.id, dict(row.report)

    def _persist(
        self,
        *,
        suite_run_id: uuid.UUID,
        tenant_id: uuid.UUID,
        behaviour_id: uuid.UUID,
        config: HarnessConfig,
        baseline_id: uuid.UUID | None,
        report: dict[str, Any],
        outcomes: Sequence[ScenarioOutcome],
        started: datetime,
    ) -> None:
        with self._app() as session, session.begin():
            bind_tenant(session, tenant_id)
            session.add(
                EvaluationSuiteRun(
                    id=suite_run_id,
                    tenant_id=tenant_id,
                    suite_key=config.suite,
                    suite_version=SUITE_VERSION,
                    corpus_digest=report["corpus_digest"],
                    behaviour_version_id=behaviour_id,
                    execution_mode=config.mode,
                    evaluator_version=EVALUATOR_VERSION,
                    baseline_suite_run_id=baseline_id,
                    gate_status=report["gate_status"],
                    scenario_count=len(outcomes),
                    report=report,
                    report_digest=digest(report),
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            )
            session.flush()
            for outcome in outcomes:
                scenario_id = self._scenario_row(session, tenant_id, outcome)
                run = EvaluationRun(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    evaluation_scenario_id=scenario_id,
                    scenario_version=outcome.golden.version,
                    behaviour_version_id=behaviour_id,
                    repetition_index=0,
                    verdict=outcome.verdict,
                    metrics=outcome.evaluation.metrics,
                    judge_versions=[
                        f"{v.judge_key}:{v.judge_model}:{v.rubric_id}@{v.rubric_version}"
                        for v in outcome.panel.verdicts
                    ],
                    disagreement=(
                        {"spread": outcome.panel.spread, "status": outcome.panel.status}
                        if outcome.panel.status == "contested"
                        else {}
                    ),
                    suite_run_id=suite_run_id,
                    workflow_run_id=outcome.workflow_run_id,
                    scenario_digest=outcome.digest,
                    execution_mode=config.mode,
                    evaluator_version=EVALUATOR_VERSION,
                    checks=dict(checks_payload(outcome.evaluation)),
                    failure_classes=outcome.evaluation.failure_classes,
                    wall_clock_ms=outcome.wall_clock_ms,
                    completed_at=datetime.now(UTC),
                )
                session.add(run)
                session.flush()
                for verdict in outcome.panel.verdicts:
                    session.add(
                        EvaluationJudgeResult(
                            id=uuid.uuid4(),
                            tenant_id=tenant_id,
                            evaluation_run_id=run.id,
                            judge_key=verdict.judge_key,
                            judge_provider=verdict.judge_provider[:128],
                            judge_model=verdict.judge_model[:128],
                            rubric_id=verdict.rubric_id,
                            rubric_version=verdict.rubric_version,
                            outcome=verdict.outcome,
                            score=verdict.score,
                            calibration_status=verdict.calibration_status,
                            cited_evidence_ids=list(verdict.cited_evidence_ids)[:32],
                            failure_reason=verdict.failure_reason,
                        )
                    )
                if (
                    outcome.fixture is not None
                    and outcome.verdict is not EvaluationRunVerdict.ERRORED
                ):
                    content = outcome.fixture.content()
                    fixture_digest = digest(content)
                    exists = session.scalar(
                        sa.select(EvaluationReplayFixture.id).where(
                            EvaluationReplayFixture.tenant_id == tenant_id,
                            EvaluationReplayFixture.digest == fixture_digest,
                        )
                    )
                    if exists is None:
                        session.add(
                            EvaluationReplayFixture(
                                id=uuid.uuid4(),
                                tenant_id=tenant_id,
                                source_workflow_run_id=outcome.workflow_run_id,
                                scenario_key=outcome.golden.key,
                                scenario_digest=outcome.digest,
                                format_version=outcome.fixture.format_version,
                                digest=fixture_digest,
                                content=content,
                            )
                        )
                        session.flush()

    @staticmethod
    def _scenario_row(
        session: Session, tenant_id: uuid.UUID, outcome: ScenarioOutcome
    ) -> uuid.UUID:
        golden = outcome.golden
        existing = session.scalars(
            sa.select(EvaluationScenario).where(
                EvaluationScenario.tenant_id == tenant_id,
                EvaluationScenario.key == golden.key,
                EvaluationScenario.version == golden.version,
            )
        ).one_or_none()
        if existing is not None:
            if (
                dict(existing.fixture_refs).get("digest") != outcome.digest
                and outcome.verdict is not EvaluationRunVerdict.ERRORED
            ):
                # Refused up front and recorded as errored; reaching here otherwise is a bug.
                raise HarnessRefused(
                    f"{golden.key} v{golden.version} changed without a version bump; publish a new "
                    "scenario version instead of editing a stored one"
                )
            return existing.id
        row = EvaluationScenario(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            key=golden.key,
            version=golden.version,
            title=golden.title,
            scenario_class=golden.scenario_class,
            tags=list(golden.covers),
            fixture_refs={
                "digest": outcome.digest,
                "fixture": golden.fixture,
                "variant": golden.variant,
            },
            input_refs={"kind": golden.kind.value},
            expected_labels=canonical(
                {
                    "investigation": golden.investigation,
                    "remediation": golden.remediation,
                    "correlation": golden.correlation,
                    "security": golden.security,
                }
            ),
            review_state="reviewed",
            labelled_by="asic-evaluation-corpus",
        )
        session.add(row)
        session.flush()
        return row.id


def _record_replay_observations(
    outcome: ScenarioOutcome,
    replay_tools: ReplayToolProvider | None,
    replay_model: ReplayModelProvider | None,
) -> None:
    """Take what the replay seams observed: unconsumed answers, divergences, interaction."""
    outcome.extra["replay_remaining"] = (replay_tools.remaining if replay_tools else 0) + (
        replay_model.remaining if replay_model else 0
    )
    outcome.extra["replay_divergences"] = (replay_tools.divergences if replay_tools else 0) + (
        replay_model.divergences if replay_model else 0
    )
    outcome.extra["replay_interaction_signature"] = interaction_signature(
        replay_tools.consumed if replay_tools else (),
        replay_model.consumed if replay_model else (),
    )


def _replay_checks(outcome: ScenarioOutcome, fixture: ReplayFixture | None) -> None:
    """The three things that make a replay a reproduction rather than a similar-looking run.

    Strict replay raises on divergence, but the broker's job is to let a node degrade rather
    than abort, so a raised divergence reaches the evaluator as an ordinary tool failure. If
    the scenario's expectations happen to survive that failure, the run would otherwise be
    reported as a pass - which is how a replay that asked a question its recording never
    answered used to reach ``passed``. So divergence is counted at the seam and checked here
    in its own right, with zero tolerance, alongside the two completeness properties.
    """
    divergences = int(outcome.extra.get("replay_divergences", 0))
    outcome.evaluation.add(
        "replay.no_divergence",
        divergences == 0,
        f"{divergences} replay divergence(s): the run asked something the recording "
        "never answered, so this is not a reproduction",
        EvaluationFailureClass.HARNESS,
        zero=True,
    )
    remaining = int(outcome.extra.get("replay_remaining", 0))
    # A replay that left recorded answers unused asked fewer questions than the original
    # run: that is a behaviour change, not a reproduction.
    outcome.evaluation.add(
        "replay.fully_consumed",
        remaining == 0,
        f"{remaining} recorded answer(s) never requested",
        EvaluationFailureClass.HARNESS,
        zero=True,
    )
    consumed = str(outcome.extra.get("replay_interaction_signature", ""))
    expected = fixture.interaction_signature if fixture is not None else ""
    outcome.evaluation.add(
        "replay.interaction_signature",
        bool(expected) and consumed == expected,
        f"consumed interaction {consumed[:16] or 'none'} does not reproduce the recorded "
        f"interaction {expected[:16] or 'none'}",
        EvaluationFailureClass.HARNESS,
        zero=True,
    )


def _verdict(evaluation: Evaluation, panel: PanelResult) -> EvaluationRunVerdict:
    if not evaluation.passed:
        return EvaluationRunVerdict.FAILED
    if panel.status == "contested":
        return EvaluationRunVerdict.CONTESTED
    return EvaluationRunVerdict.PASSED


def aggregate(outcomes: Sequence[ScenarioOutcome]) -> dict[str, Any]:
    """Suite-level profile. Rates are over the scenarios where the metric applies."""

    def rate(name: str) -> float | None:
        values = [o.evaluation.metrics.get(name) for o in outcomes]
        applicable = [v for v in values if isinstance(v, bool)]
        return round(sum(applicable) / len(applicable), 4) if applicable else None

    def total(name: str) -> float:
        return round(sum(float(o.evaluation.metrics.get(name) or 0) for o in outcomes), 6)

    verdicts = [o.verdict.value for o in outcomes]
    panels: dict[str, int] = {}
    for outcome in outcomes:
        panels[outcome.panel.status] = panels.get(outcome.panel.status, 0) + 1
    classes: dict[str, int] = {}
    for outcome in outcomes:
        for failure_class in outcome.evaluation.failure_classes:
            classes[failure_class] = classes.get(failure_class, 0) + 1
    return {
        "scenarios": len(outcomes),
        "passed": verdicts.count("passed"),
        "failed": verdicts.count("failed"),
        "errored": verdicts.count("errored"),
        "contested": verdicts.count("contested"),
        "investigation_success_rate": rate("investigation_success"),
        "rca_top1_accuracy": rate("rca_top1"),
        "rca_top3_accuracy": rate("rca_top3"),
        "verification_success_rate": rate("verification_success"),
        "escalation_rate": rate("escalated"),
        "remediation_correctness_rate": rate("remediation_correct"),
        "unsafe_actions": int(total("unsafe_actions")),
        "false_success": int(total("false_success")),
        "tokens": int(total("tokens")),
        "cost_usd": total("cost_usd"),
        "tool_calls": int(total("tool_calls")),
        "failure_classes": dict(sorted(classes.items())),
        # Panel statuses per scenario. Absent a configured judge provider this is honestly
        # ``not_measured``; judge scores are uncalibrated and never gate anything.
        "llm_judge": "not_measured"
        if set(panels) <= {"not_measured"}
        else dict(sorted(panels.items())),
    }


__all__ = [
    "BASE_CLOCK",
    "EvaluationHarness",
    "HarnessConfig",
    "HarnessRefused",
    "ScenarioOutcome",
    "SuiteOutcome",
    "aggregate",
]
