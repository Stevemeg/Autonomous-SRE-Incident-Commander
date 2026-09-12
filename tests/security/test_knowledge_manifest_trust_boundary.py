"""P6-02: a provider's retrieval manifest is untrusted input, structurally.

P6-02's finding: a provider could mint its own retrieval id, principal, policy, query
digest and score - and still satisfy the old ``validate_manifest`` - and a provider
response with no manifest at all was not rejected. Both are closed:

* a manifest is now mandatory (no manifest -> ``manifest_missing``, refused);
* every claim that could grant authority - principal, clearances, policy version, query
  digest, retrieval identity, and whether a cited chunk is *currently* authorized for the
  recomputed principal and scope - is independently recomputed or checked against the
  database, never accepted merely because the manifest is internally consistent.

Every test here starts from one genuinely valid manifest, produced by the real broker and
the real :class:`~asic.knowledge.provider.KnowledgeStoreProvider`, and tampers with exactly
one field - proving each check is load-bearing rather than vacuous (a tampered-nothing
control is included for the same reason: it must still verify).
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.contracts.nodes import G4_EVIDENCE_COLLECTOR
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    KnowledgeContentFormat,
    KnowledgeDocumentType,
    NodeId,
    TrustClass,
)
from asic.knowledge.authorization import investigation_principal
from asic.knowledge.contracts import (
    ImportContext,
    RetrievalPrincipal,
    RetrievalScope,
    SourceAccessPolicy,
    SourceDocument,
)
from asic.knowledge.embedding import DeterministicEmbeddingProvider, EmbeddingService
from asic.knowledge.ingestion import KnowledgeIngestionService
from asic.knowledge.provider import CAPABILITY, KnowledgeStoreProvider
from asic.knowledge.retrieval import KnowledgeRetriever
from asic.orchestration.knowledge_context import KnowledgeManifestInvalid, validate_manifest
from asic.tools.broker import CapabilityRequest, ToolBroker, ToolResult
from asic.tools.capability import CapabilityResolver, load_incident_scope
from asic.tools.registry import ToolRegistry
from tests.kernel_fixtures import build_fixture
from tests.knowledge.conftest import IMPORTER

pytestmark = pytest.mark.postgres

RUNBOOK = """# Checkout pool exhaustion

## Mitigation

Restart the checkout deployment to clear the exhausted pool.

## Rollback

If the restart does not help, restart the checkout deployment a second time and page
on-call, since a repeated pool exhaustion after a restart of the checkout deployment
usually means a leak rather than transient load.
"""

TOPIC = "restart the checkout deployment"


class _World:
    def __init__(self, engine: sa.Engine) -> None:
        self.factory: sessionmaker[Session] = sessionmaker(
            engine, expire_on_commit=False, autoflush=False
        )
        with self.factory() as session, session.begin():
            fixture = build_fixture(
                session,
                slug=f"kn-trust-{uuid.uuid4().hex[:10]}",
                grant_capabilities=("read.knowledge",),
            )
            self.tenant_id = fixture.tenant.id
            self.incident_id = fixture.incident.id
            self.environment_id = fixture.environment.id
            self.service_id = fixture.service.id
            self.service_name = fixture.service.name
        self.embeddings = EmbeddingService(DeterministicEmbeddingProvider())
        self.clock = FrozenClock(start=fixture.incident.opened_at)
        self.ingestion = KnowledgeIngestionService(self.factory, self.embeddings, clock=self.clock)
        self.retriever = KnowledgeRetriever(self.embeddings, clock=self.clock)
        self.ingestion.ingest(
            ImportContext(
                tenant_id=self.tenant_id,
                provider="git",
                source_ref="runbooks/pool.md",
                policy=SourceAccessPolicy(
                    document_type=KnowledgeDocumentType.RUNBOOK,
                    trust_class=TrustClass.OFFICIAL_RUNBOOK,
                ),
                actor=IMPORTER,
            ),
            SourceDocument(
                title="Checkout pool exhaustion",
                body=RUNBOOK.encode("utf-8"),
                content_format=KnowledgeContentFormat.MARKDOWN,
            ),
        )

    def trusted_context(
        self, correlation_id: uuid.UUID
    ) -> tuple[RetrievalPrincipal, RetrievalScope]:
        with self.factory() as session, session.begin():
            bind_tenant(session, self.tenant_id)
            principal = investigation_principal(
                session,
                tenant_id=self.tenant_id,
                environment_id=self.environment_id,
                principal_id=f"investigation:{correlation_id}",
            )
        scope = RetrievalScope(environment_id=self.environment_id, service_ids=(self.service_id,))
        return principal, scope


@pytest.fixture
def world(app_engine: sa.Engine) -> _World:
    return _World(app_engine)


def _broker(world: _World) -> ToolBroker:
    with world.factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        scope = load_incident_scope(
            session,
            tenant_id=world.tenant_id,
            incident_id=world.incident_id,
            environment_id=world.environment_id,
            service_ids=[world.service_id],
        )
    from asic.observability.audit import AuditWriter
    from asic.observability.tracing import TraceRecorder, derive_trace_id

    return ToolBroker(
        resolver=CapabilityResolver(ToolRegistry.read_only()),
        providers=[KnowledgeStoreProvider(world.factory, world.retriever)],
        scope=scope,
        audit=AuditWriter(tenant_id=world.tenant_id, clock=world.clock),
        tracer=TraceRecorder(
            tenant_id=world.tenant_id,
            execution_trace_id=uuid.uuid4(),
            trace_id=derive_trace_id(uuid.uuid4()),
            clock=world.clock,
        ),
        clock=world.clock,
        sleep=lambda _s: None,
    )


def _genuine_result(world: _World, correlation_id: uuid.UUID, *, topic: str = TOPIC) -> ToolResult:
    """One real, valid manifest, produced by the real broker and native provider.

    ``topic`` participates in the tool's idempotency key: a second call with the same
    topic (regardless of ``correlation_id``) is a deduplicated replay of the first, not a
    fresh retrieval - tests that need two independent retrievals must vary it.
    """
    broker = _broker(world)
    with world.factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        result = broker.invoke(
            session,
            request=CapabilityRequest(
                node_id=NodeId.G4_EVIDENCE_COLLECTOR,
                capability=CAPABILITY,
                service_name=world.service_name,
                arguments={"topic": topic, "limit": 5},
                incident_id=world.incident_id,
                correlation_id=correlation_id,
            ),
            contract=G4_EVIDENCE_COLLECTOR,
        )
    broker.close()
    assert result.succeeded
    assert not result.deduplicated
    assert result.payload.get("retrieval") is not None
    return result


def _check(
    world: _World,
    result: ToolResult,
    correlation_id: uuid.UUID,
    mutate: Callable[[dict], None] | None,
    *,
    topic: str = TOPIC,
) -> None:
    """Apply ``mutate`` to a copy of the manifest, then run it through validate_manifest."""
    manifest = copy.deepcopy(dict(result.payload["retrieval"]))
    if mutate is not None:
        mutate(manifest)
    tampered = result.model_copy(update={"payload": {**result.payload, "retrieval": manifest}})
    principal, scope = world.trusted_context(correlation_id)
    with world.factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        validate_manifest(
            session,
            tenant_id=world.tenant_id,
            correlation_id=correlation_id,
            principal=principal,
            scope=scope,
            query_text=topic,
            result=tampered,
        )


def _expect_refused(
    world: _World,
    result: ToolResult,
    correlation_id: uuid.UUID,
    mutate: Callable[[dict], None] | None,
    *,
    topic: str = TOPIC,
) -> str:
    with pytest.raises(KnowledgeManifestInvalid) as excinfo:
        _check(world, result, correlation_id, mutate, topic=topic)
    return excinfo.value.code


class TestGenuineManifestIsAccepted:
    """The positive control: an unmodified manifest must still verify."""

    def test_untampered_manifest_verifies(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        _check(world, result, correlation_id, None)  # must not raise


class TestNoManifestIsRefused:
    def test_a_result_with_no_manifest_at_all_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        stripped = result.model_copy(
            update={"payload": {k: v for k, v in result.payload.items() if k != "retrieval"}}
        )
        principal, scope = world.trusted_context(correlation_id)
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            with pytest.raises(KnowledgeManifestInvalid) as excinfo:
                validate_manifest(
                    session,
                    tenant_id=world.tenant_id,
                    correlation_id=correlation_id,
                    principal=principal,
                    scope=scope,
                    query_text=TOPIC,
                    result=stripped,
                )
        assert excinfo.value.code == "manifest_missing"


class TestForgedClaimsAreRefused:
    """Every self-asserted claim a malicious provider could mint, one at a time."""

    def test_forged_retrieval_id_naming_no_real_retrieval_is_accepted_but_unauthoritative(
        self, world: _World
    ) -> None:
        # A fresh, never-recorded retrieval_id is not itself forgeable-detectable (nothing
        # is recorded yet to reuse) - but forging a nonexistent CHUNK alongside it is
        # (see test_forged_chunk_id_is_refused). This documents the boundary rather than
        # asserting a false guarantee.
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        _check(
            world,
            result,
            correlation_id,
            lambda m: m.__setitem__("retrieval_id", str(uuid.uuid4())),
        )
        # A fresh, unrecorded id with otherwise-genuine, hash-matched, authorized results
        # verifies: it becomes a legitimate new retrieval identity. Reuse is what is
        # refused (see TestRetrievalIdentityReuseIsRefused below).

    def test_forged_tenant_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world, result, correlation_id, lambda m: m.__setitem__("tenant_id", str(uuid.uuid4()))
        )
        assert code == "manifest_tenant_mismatch"

    def test_forged_principal_id_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world,
            result,
            correlation_id,
            lambda m: m.__setitem__("principal_id", "investigation:someone-else"),
        )
        assert code == "manifest_principal_mismatch"

    def test_forged_principal_kind_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world, result, correlation_id, lambda m: m.__setitem__("principal_kind", "user")
        )
        assert code == "manifest_principal_mismatch"

    def test_forged_clearances_are_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world, result, correlation_id, lambda m: m.__setitem__("clearances", ["top-secret"])
        )
        assert code == "manifest_principal_mismatch"

    def test_forged_policy_version_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world,
            result,
            correlation_id,
            lambda m: m.__setitem__("policy_version", "attacker-chosen-policy/99"),
        )
        assert code == "manifest_policy_mismatch"

    def test_forged_query_digest_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world, result, correlation_id, lambda m: m.__setitem__("query_digest", "0" * 64)
        )
        assert code == "manifest_query_digest_mismatch"

    def test_forged_content_hash_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            m["results"][0]["content_hash"] = "f" * 64

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_content_mismatch"

    def test_forged_unknown_chunk_id_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            m["results"][0]["chunk_id"] = str(uuid.uuid4())

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_unknown_chunk"

    def test_substituted_document_version_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            m["results"][0]["document_version_id"] = str(uuid.uuid4())

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_version_mismatch"

    def test_substituted_source_id_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            m["results"][0]["source_id"] = str(uuid.uuid4())

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_version_mismatch"

    def test_rank_manipulation_breaking_contiguity_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            m["results"][0]["rank"] = 99

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_ranks_not_contiguous"

    def test_duplicated_chunk_across_ranks_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            if len(m["results"]) < 2:
                pytest.skip("needs at least two results to duplicate one")
            m["results"][1]["chunk_id"] = m["results"][0]["chunk_id"]

        code = _expect_refused(world, result, correlation_id, tamper)
        assert code == "manifest_duplicate_chunk"

    def test_added_unpersisted_result_beyond_documents_count_is_refused(
        self, world: _World
    ) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)

        def tamper(m: dict) -> None:
            extra = copy.deepcopy(m["results"][0])
            extra["rank"] = len(m["results"]) + 1
            extra["chunk_id"] = str(uuid.uuid4())
            m["results"].append(extra)

        code = _expect_refused(world, result, correlation_id, tamper)
        # An added result is either an unknown fabricated chunk, or - if it happens to
        # collide with the same id - a document-count mismatch against the untampered
        # ``documents`` label list. Either way it is refused.
        assert code in {"manifest_unknown_chunk", "manifest_document_count_mismatch"}

    def test_forged_idempotency_key_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world,
            result,
            correlation_id,
            lambda m: m.__setitem__("idempotency_key", "attacker-key"),
        )
        assert code == "manifest_not_from_this_call"

    def test_forged_correlation_id_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world,
            result,
            correlation_id,
            lambda m: m.__setitem__("correlation_id", str(uuid.uuid4())),
        )
        assert code == "manifest_correlation_mismatch"

    def test_malformed_manifest_is_refused(self, world: _World) -> None:
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        code = _expect_refused(
            world, result, correlation_id, lambda m: m.__setitem__("results", "not-a-list")
        )
        assert code == "manifest_malformed"


def _workflow_run(world: _World) -> uuid.UUID:
    """A real, persisted workflow run - ``knowledge_retrieval`` FKs to it."""
    from asic.db.models import WorkflowRun
    from tests.conftest import make_behaviour_version

    with world.factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        behaviour_version = make_behaviour_version(session, label=f"bv-{uuid.uuid4().hex[:8]}")
        run = WorkflowRun(
            id=uuid.uuid4(),
            tenant_id=world.tenant_id,
            incident_id=world.incident_id,
            behaviour_version_id=behaviour_version.id,
        )
        session.add(run)
        session.flush()
        return run.id


def _evidence(world: _World, tool_execution_id: uuid.UUID) -> uuid.UUID:
    """A real, persisted evidence row - ``knowledge_retrieval`` FKs to it."""
    from asic.db.models import Evidence
    from asic.domain.enums import EvidenceDomain, ProvenanceLabel

    with world.factory() as session, session.begin():
        bind_tenant(session, world.tenant_id)
        evidence = Evidence(
            id=uuid.uuid4(),
            tenant_id=world.tenant_id,
            incident_id=world.incident_id,
            tool_execution_id=tool_execution_id,
            domain=EvidenceDomain.KNOWLEDGE,
            provenance=ProvenanceLabel.RETRIEVED,
            content={},
            citation={},
            gathered_at=world.clock.now(),
        )
        session.add(evidence)
        session.flush()
        return evidence.id


class TestRetrievalIdentityReuseIsRefused:
    def test_reused_retrieval_id_from_a_prior_recorded_retrieval_is_refused(
        self, world: _World
    ) -> None:
        from asic.orchestration.knowledge_context import record_manifest

        workflow_run_id = _workflow_run(world)

        first_correlation = uuid.uuid4()
        first_result = _genuine_result(world, first_correlation)
        principal, scope = world.trusted_context(first_correlation)
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            verified = validate_manifest(
                session,
                tenant_id=world.tenant_id,
                correlation_id=first_correlation,
                principal=principal,
                scope=scope,
                query_text=TOPIC,
                result=first_result,
            )
            assert verified is not None
            record_manifest(
                session,
                verified,
                tenant_id=world.tenant_id,
                incident_id=world.incident_id,
                workflow_run_id=workflow_run_id,
                tool_execution_id=first_result.tool_execution_id,
                evidence_id=_evidence(world, first_result.tool_execution_id),
            )
        recorded_retrieval_id = verified.retrieval_id

        # A different topic: otherwise this call's idempotency key matches the first and
        # the broker would return a deduplicated replay instead of a fresh retrieval.
        second_topic = "confirm p95 latency recovers"
        second_correlation = uuid.uuid4()
        second_result = _genuine_result(world, second_correlation, topic=second_topic)
        code = _expect_refused(
            world,
            second_result,
            second_correlation,
            lambda m: m.__setitem__("retrieval_id", str(recorded_retrieval_id)),
            topic=second_topic,
        )
        assert code == "manifest_retrieval_id_reused"

    def test_reused_retrieval_id_from_another_tenant_is_refused(self, world: _World) -> None:
        """The primary key is global, not per-tenant: reuse is refused even across tenants."""
        from asic.orchestration.knowledge_context import record_manifest

        other = _World(world.factory.kw["bind"])
        other_correlation = uuid.uuid4()
        other_result = _genuine_result(other, other_correlation)
        other_principal, other_scope = other.trusted_context(other_correlation)
        with other.factory() as session, session.begin():
            bind_tenant(session, other.tenant_id)
            other_verified = validate_manifest(
                session,
                tenant_id=other.tenant_id,
                correlation_id=other_correlation,
                principal=other_principal,
                scope=other_scope,
                query_text=TOPIC,
                result=other_result,
            )
            assert other_verified is not None
            record_manifest(
                session,
                other_verified,
                tenant_id=other.tenant_id,
                incident_id=other.incident_id,
                workflow_run_id=_workflow_run(other),
                tool_execution_id=other_result.tool_execution_id,
                evidence_id=_evidence(other, other_result.tool_execution_id),
            )
        cross_tenant_id = other_verified.retrieval_id

        workflow_run_id = _workflow_run(world)
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        evidence_id = _evidence(world, result.tool_execution_id)
        principal, scope = world.trusted_context(correlation_id)
        manifest = copy.deepcopy(dict(result.payload["retrieval"]))
        manifest["retrieval_id"] = str(cross_tenant_id)
        tampered = result.model_copy(update={"payload": {**result.payload, "retrieval": manifest}})
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            verified = validate_manifest(
                session,
                tenant_id=world.tenant_id,
                correlation_id=correlation_id,
                principal=principal,
                scope=scope,
                query_text=TOPIC,
                result=tampered,
            )
            # The tenant-scoped pre-check cannot see the other tenant's row (RLS), so this
            # passes validation; the primary key collision is caught at record time.
            assert verified is not None
            with pytest.raises(KnowledgeManifestInvalid, match="manifest_retrieval_id_reused"):
                record_manifest(
                    session,
                    verified,
                    tenant_id=world.tenant_id,
                    incident_id=world.incident_id,
                    workflow_run_id=workflow_run_id,
                    tool_execution_id=result.tool_execution_id,
                    evidence_id=evidence_id,
                )


class TestUnauthorizedResultIsRefused:
    def test_a_result_scoped_to_an_acl_the_principal_lacks_is_refused(self, world: _World) -> None:
        """The chunk is real and its hash matches - but it is not authorized for this
        principal. A provider cannot make it authorized merely by naming it."""
        correlation_id = uuid.uuid4()
        result = _genuine_result(world, correlation_id)
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            from asic.db.models import KnowledgeChunk, KnowledgeDocument, KnowledgeSource

            chunk_id = uuid.UUID(result.payload["retrieval"]["results"][0]["chunk_id"])
            source_id = session.scalar(
                sa.select(KnowledgeDocument.source_id)
                .join(KnowledgeChunk, KnowledgeChunk.document_id == KnowledgeDocument.id)
                .where(KnowledgeChunk.tenant_id == world.tenant_id, KnowledgeChunk.id == chunk_id)
            )
            session.execute(
                sa.update(KnowledgeSource)
                .where(
                    KnowledgeSource.tenant_id == world.tenant_id, KnowledgeSource.id == source_id
                )
                .values(acl_labels=["clearance_the_principal_lacks"])
            )
        code = _expect_refused(world, result, correlation_id, None)
        assert code == "manifest_unauthorized_result"
