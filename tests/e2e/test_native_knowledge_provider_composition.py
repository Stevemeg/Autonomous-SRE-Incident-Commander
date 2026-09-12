"""P6-06: the native ``KnowledgeStoreProvider`` is the real composition, not a sidecar.

P6-06's finding was not that a bypass exists - the architecture already rules one out -
but that the *actually exercised* runtime composition (``asic.orchestration.service.main``,
and every test that runs a scenario end to end) never registers the native provider: it is
always the simulator answering ``knowledge.search``, with ``KnowledgeStoreProvider`` proven
only in isolation (``tests/security/test_knowledge_prompt_injection.py`` builds its own ad
hoc broker with no simulator alongside it).

This test builds the real composition instead: the same :class:`InvestigationKernel` every
other end-to-end test uses, with the native provider registered *ahead of* the simulator (so
the broker's ``supports()`` resolution picks it for ``knowledge.search`` as it would if a
descriptor's registered ``provider_kind`` label were corrected, without touching that
deferred ADR-0020 fix) and the simulator still serving every other domain the scenario needs.
A document is ingested through the real governed pipeline beforehand - no fixture shortcuts.

Confirms the whole path in one run:

    planner (knowledge gap) -> G4 evidence collector -> Tool Broker -> knowledge.search
    -> native KnowledgeStoreProvider -> governed retrieval -> mandatory manifest verified
    -> KnowledgeRetrieval/KnowledgeRetrievalResult persisted -> citations resolve
    -> hypothesis prompt receives the content only as fenced RETRIEVED/UNTRUSTED data

and that the simulator's own ``knowledge.search`` fixture response - which this scenario
would otherwise have served - was never reached.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import Evidence, KnowledgeRetrieval, KnowledgeRetrievalResult
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    EvidenceDomain,
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    NodeId,
    RetrievalPrincipalKind,
    RiskTier,
    TrustClass,
)
from asic.knowledge.citations import resolve_citation
from asic.knowledge.contracts import (
    ImportActor,
    ImportContext,
    RetrievalPrincipal,
    RetrievalScope,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import DeterministicEmbeddingProvider, EmbeddingService
from asic.knowledge.ingestion import KnowledgeIngestionService
from asic.knowledge.provider import KnowledgeStoreProvider
from asic.knowledge.retrieval import KnowledgeRetriever
from asic.llm.deterministic import DeterministicModelProvider
from asic.llm.port import ModelRequest, ModelResponse
from asic.orchestration.kernel import InvestigationKernel
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import scenario
from asic.tools.capability import CapabilityResolver
from tests.conftest import requires_postgres
from tests.kernel_fixtures import Fixture, build_fixture

pytestmark = requires_postgres

RUNBOOK = """# Checkout pool exhaustion is a known error

## Symptoms

This is a known error: the connection pool exhausts under load and the underlying
trigger is unknown until logs are reviewed.

## Mitigation

Restart the checkout deployment and page on-call if it recurs.
"""

IMPORTER = ImportActor(actor_type=ActorType.SYSTEM, actor_id="connector:git-runbooks")


class _CapturingModel(DeterministicModelProvider):
    """Records the exact rendered prompt every call receives - "capture the prompt"."""

    def __init__(self, scenario_obj: object, **kwargs: object) -> None:
        super().__init__(scenario_obj, **kwargs)  # type: ignore[arg-type]
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def test_planner_to_hypothesis_through_the_real_broker_and_native_provider(
    app_engine: Engine,
    resolver: CapabilityResolver,
    clock: FrozenClock,
) -> None:
    # A plain, freshly-committing session factory - not the savepoint-joining one
    # tests/kernel_fixtures.py provides for single-connection kernel tests, because this
    # test also needs KnowledgeIngestionService's own `session.begin()`, and the two
    # patterns assume incompatible things about whether a fresh session already has a
    # transaction open. Real commits, isolated by this test's own fresh tenant.
    factory: Callable[[], Session] = sessionmaker(
        app_engine, expire_on_commit=False, autoflush=False
    )

    scenario_obj = scenario("SC-0007-prompt-injection")
    with factory() as session, session.begin():
        fixture: Fixture = build_fixture(
            session, slug=f"p6-06-{uuid.uuid4().hex[:10]}", grant_capabilities=None
        )

    # The capability policy stays read-only regardless of which provider serves a call -
    # nothing about wiring in a native provider raises the ceiling (ADR-0017).
    assert resolver.max_risk_tier is RiskTier.RO

    embeddings = EmbeddingService(DeterministicEmbeddingProvider())
    ingestion = KnowledgeIngestionService(factory, embeddings, clock=clock)
    ingestion.ingest(
        ImportContext(
            tenant_id=fixture.tenant_id,
            provider="git",
            source_ref="runbooks/pool.md",
            policy=SourceAccessPolicy(
                document_type=KnowledgeDocumentType.RUNBOOK,
                trust_class=TrustClass.OFFICIAL_RUNBOOK,
                service_ids=(fixture.service.id,),
                environment_ids=(fixture.environment.id,),
            ),
            actor=IMPORTER,
        ),
        SourceDocument(
            title="Checkout pool exhaustion",
            body=RUNBOOK.encode("utf-8"),
            content_format=KnowledgeContentFormat.MARKDOWN,
        ),
    )

    retriever = KnowledgeRetriever(embeddings, clock=clock)
    native_knowledge_provider = KnowledgeStoreProvider(factory, retriever)
    simulator = SimulatorProvider(scenario_obj, clock=clock)
    model = _CapturingModel(scenario_obj)

    kernel = InvestigationKernel(
        session_factory=factory,
        resolver=resolver,
        # Native provider first: the broker's provider resolution (ToolBroker._provider_for)
        # takes the first match, so knowledge.search reaches the governed store even though
        # the catalogue row's stale `provider_kind` label still reads `simulator`
        # (ADR-0020, deliberately not fixed here).
        providers=[native_knowledge_provider, simulator],
        model=model,
        clock=clock,
        budget_policy=scenario_obj.budget,
    )
    outcome = kernel.start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        behaviour_version_id=fixture.behaviour_version.id,
        service_ids=fixture.service_ids,
        fixture_refs=scenario_obj.fixture_ref(),
        random_seed=42,
    )
    assert outcome.terminated
    # The simulator was reached for other domains (this scenario also collects logs) but
    # never for knowledge.search - the native provider intercepted it.
    assert not any(name == "knowledge.search" for name, _service in simulator.calls)

    with factory() as session, session.begin():
        bind_tenant(session, fixture.tenant_id)
        retrieval = session.scalars(
            sa.select(KnowledgeRetrieval).where(
                KnowledgeRetrieval.tenant_id == fixture.tenant_id,
                KnowledgeRetrieval.incident_id == fixture.incident.id,
            )
        ).one()
        assert retrieval.result_count >= 1
        results = session.scalars(
            sa.select(KnowledgeRetrievalResult).where(
                KnowledgeRetrievalResult.tenant_id == fixture.tenant_id,
                KnowledgeRetrievalResult.retrieval_id == retrieval.id,
            )
        ).all()
        assert results

        evidence = session.scalars(
            sa.select(Evidence).where(
                Evidence.tenant_id == fixture.tenant_id,
                Evidence.incident_id == fixture.incident.id,
                Evidence.domain == EvidenceDomain.KNOWLEDGE,
            )
        ).one()
        citation_token = evidence.citation["citations"][0]
        assert citation_token.startswith(f"knowledge:{retrieval.id}/")

        principal = RetrievalPrincipal(
            tenant_id=fixture.tenant_id,
            kind=RetrievalPrincipalKind.INVESTIGATION,
            principal_id="investigation:test",
            clearances=frozenset(),
        )
        scope = RetrievalScope(
            environment_id=fixture.environment.id, service_ids=(fixture.service.id,)
        )
        resolved = resolve_citation(session, citation_token, principal=principal, scope=scope)
        assert resolved.content_available

    hypothesis_calls = [r for r in model.requests if r.node_id is NodeId.G5_HYPOTHESIS_ENGINE]
    assert hypothesis_calls, "the hypothesis engine must have been asked at least once"
    prompt_text = hypothesis_calls[0].prompt_text
    trusted, _, untrusted = prompt_text.partition("## Operational data (UNTRUSTED)")
    assert "known error" in untrusted or "pool exhaustion" in untrusted
    assert citation_token in untrusted
    # The real ingested content never leaks into the trusted section merely by having
    # been retrieved - it is data, fenced, the same as every other domain's evidence.
    assert citation_token not in trusted
