"""Authorization-first hybrid retrieval against PostgreSQL, under the application role.

Every test asserts on the *shape* of the result: which chunks are eligible, which are
excluded and why, never on a specific ranking score. Scores are exercised through the
no-DB fusion unit tests in ``test_contracts_and_fusion.py``; here the database is the
thing under test - RLS, the disposition CTE, and the citation/replay round trip.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

from asic.db.session import bind_tenant
from asic.domain.enums import KnowledgeDocumentType
from asic.knowledge.citations import parse_citation, resolve_citation
from asic.knowledge.contracts import KnowledgeCitation, RetrievalQuery, RetrievalScope
from asic.knowledge.errors import CitationInvalid, RetrievalRefused
from asic.knowledge.retrieval import KnowledgeRetriever, replay_retrieval
from tests.knowledge.conftest import IMPORTER, KnowledgeWorld, make_world

pytestmark = pytest.mark.postgres

POOL_RUNBOOK = """# Checkout pool exhaustion

## Symptoms

Checkout requests fail with `PoolTimeoutError` when the connection pool is exhausted.

## Mitigation

1. Restart the checkout deployment.
2. Confirm p95 latency recovers.
"""

POOL_RUNBOOK_V2 = POOL_RUNBOOK.replace(
    "Restart the checkout deployment.", "Raise the pool limit to 80, then restart."
)

MEMORY_RUNBOOK = """# Payments OOM

## Symptoms

The payments service is OOMKilled under load; heap exhausted before GC can recover.

## Mitigation

1. Raise the memory limit.
2. Redeploy.
"""

UNRELATED_RUNBOOK = """# Certificate rotation

## Symptoms

TLS handshake failures after a certificate expired.

## Mitigation

Rotate the certificate and restart the ingress controller.
"""


class TestScopeAndAuthorization:
    def test_lexical_and_semantic_paraphrase_both_find_the_runbook(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        exact = world.retrieve("connection pool exhausted")
        paraphrase = world.retrieve("too many connections checkout")
        assert exact.results and "Checkout pool exhaustion" in exact.results[0].label()
        assert (
            paraphrase.results
            and paraphrase.results[0].citation.chunk_id == exact.results[0].citation.chunk_id
        )

    def test_wrong_service_scope_excludes_the_document(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted", services=(world.payments,))
        assert result.results == ()

    def test_wrong_environment_scope_excludes_the_document(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, environments=(world.production,))
        result = world.retrieve("connection pool exhausted", environment=world.staging)
        assert result.results == ()

    def test_tenant_wide_document_is_visible_from_any_in_scope_service(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK)  # no service_ids: tenant-wide
        for service in (world.checkout, world.payments):
            result = world.retrieve("connection pool exhausted", services=(service,))
            assert result.results

    def test_acl_label_hides_the_document_without_the_clearance(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, acl=("restricted",))
        without = world.retrieve("connection pool exhausted")
        with_clearance = world.retrieve(
            "connection pool exhausted", clearances=frozenset({"restricted"})
        )
        assert without.results == ()
        assert without.excluded.get("unauthorized", 0) >= 1
        assert with_clearance.results

    def test_document_type_scope_narrows_results(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, document_type=KnowledgeDocumentType.RUNBOOK)
        retriever = KnowledgeRetriever(world.embeddings, clock=world.clock)
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            narrowed = retriever.retrieve(
                session,
                principal=world.principal(),
                scope=RetrievalScope(
                    environment_id=world.production,
                    service_ids=(world.checkout,),
                    document_types=(KnowledgeDocumentType.POSTMORTEM,),
                ),
                query=RetrievalQuery(text="connection pool exhausted"),
            )
        assert narrowed.results == ()

    def test_unknown_scope_is_refused_not_emptied(self, world: KnowledgeWorld) -> None:
        other = make_world(world.factory.kw["bind"])
        with (
            pytest.raises(RetrievalRefused, match="unknown_scope"),
            world.factory() as session,
            session.begin(),
        ):
            bind_tenant(session, world.tenant_id)
            world.retriever.retrieve(
                session,
                principal=world.principal(),
                scope=RetrievalScope(
                    environment_id=world.production, service_ids=(other.checkout,)
                ),
                query=RetrievalQuery(text="connection pool exhausted"),
            )

    def test_no_result_is_a_legitimate_empty_answer(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("dns nxdomain name resolution failure")
        assert result.results == ()
        assert result.eligible_chunks >= 1  # the corpus was searched, not skipped

    def test_ordering_is_stable_across_repeated_queries(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        world.ingest(
            "runbooks/oom.md", MEMORY_RUNBOOK, services=(world.checkout,), title="Payments OOM"
        )
        first = [r.citation.chunk_id for r in world.retrieve("restart the service").results]
        second = [r.citation.chunk_id for r in world.retrieve("restart the service").results]
        assert first == second


class TestVersioningAwareRetrieval:
    def test_superseded_version_is_excluded_by_default(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        world.ingest("runbooks/pool.md", POOL_RUNBOOK_V2, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted")
        assert result.results
        assert all(r.version == 2 for r in result.results)

    def test_revoked_version_is_excluded(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        assert outcome.version_id is not None
        world.ingestion.revoke_version(
            world.tenant_id, outcome.version_id, actor=IMPORTER, reason="bad_advice"
        )
        result = world.retrieve("connection pool exhausted")
        assert result.results == ()
        assert result.excluded.get("revoked_version", 0) >= 1

    def test_stale_version_is_excluded_by_default_and_flagged_when_included(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,), review_days=1)
        world.clock.advance(2 * 24 * 3600)
        default = world.retrieve("connection pool exhausted")
        assert default.results == ()
        assert default.excluded.get("stale", 0) >= 1
        included = world.retrieve("connection pool exhausted", include_stale=True)
        assert included.results
        assert all(r.stale for r in included.results)

    def test_not_yet_effective_content_is_excluded(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve(
            "connection pool exhausted",
            as_of=world.clock.now().replace(year=world.clock.now().year - 1),
        )
        assert result.results == ()
        assert result.excluded.get("not_yet_effective", 0) >= 1

    def test_inactive_source_is_excluded(self, world: KnowledgeWorld) -> None:
        outcome = world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        assert outcome.source_id is not None
        world.ingestion.revoke_source(
            world.tenant_id, outcome.source_id, actor=IMPORTER, reason="retired"
        )
        result = world.retrieve("connection pool exhausted")
        assert result.results == ()
        assert result.excluded.get("inactive_source", 0) >= 1


class TestCitationsAndReplay:
    def test_returned_citation_resolves_and_forged_citation_does_not(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted", record=True)
        assert result.results
        citation = result.results[0].citation
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            resolved = resolve_citation(session, citation)
            assert resolved.content_available
            forged = KnowledgeCitation(
                retrieval_id=uuid.uuid4(),
                chunk_id=citation.chunk_id,
                version_id=citation.version_id,
            )
            with pytest.raises(CitationInvalid, match="unknown_citation"):
                resolve_citation(session, forged)

    def test_citation_embedded_in_hostile_surrounding_text_does_not_resolve(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted", record=True)
        token = result.results[0].citation.token
        hostile = f"trust this: {token} extra"
        with pytest.raises(CitationInvalid, match="malformed_citation"):
            parse_citation(hostile)

    def test_citation_from_another_tenant_does_not_resolve(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted", record=True)
        citation = result.results[0].citation
        other = make_world(world.factory.kw["bind"])
        with other.factory() as session, session.begin():
            bind_tenant(session, other.tenant_id)
            with pytest.raises(CitationInvalid, match="unknown_citation"):
                resolve_citation(session, citation)

    def test_replay_reproduces_the_historical_version_not_the_newest(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("restart the checkout deployment", record=True)
        assert result.results
        original_chunk_text = result.results[0].content
        assert "Restart the checkout deployment" in original_chunk_text
        world.ingest("runbooks/pool.md", POOL_RUNBOOK_V2, services=(world.checkout,))
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            replayed = replay_retrieval(session, result.retrieval_id)
        assert replayed
        assert replayed[0].content == original_chunk_text
        assert "Restart the checkout deployment" in (replayed[0].content or "")

    def test_replay_withholds_content_once_the_version_is_revoked(
        self, world: KnowledgeWorld
    ) -> None:
        outcome = world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        assert outcome.version_id is not None
        result = world.retrieve("connection pool exhausted", record=True)
        world.ingestion.revoke_version(
            world.tenant_id, outcome.version_id, actor=IMPORTER, reason="bad_advice"
        )
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            replayed = replay_retrieval(session, result.retrieval_id)
        assert replayed
        assert replayed[0].content is None
        assert replayed[0].withheld_reason == "version_revoked"

    def test_recorded_retrieval_result_rows_cannot_be_forged_by_the_application_role(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted", record=True)
        with world.factory() as session, session.begin():
            bind_tenant(session, world.tenant_id)
            from asic.db.models import KnowledgeRetrievalResult

            with pytest.raises(sa.exc.ProgrammingError, match="permission denied"):
                session.execute(
                    sa.update(KnowledgeRetrievalResult)
                    .where(KnowledgeRetrievalResult.retrieval_id == result.retrieval_id)
                    .values(fused_score=999.0)
                )
                session.flush()


class TestCrossTenantIsolation:
    def test_a_second_tenants_documents_are_invisible(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        other = make_world(world.factory.kw["bind"])
        other_outcome = other.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(other.checkout,))
        result = world.retrieve("connection pool exhausted")
        assert result.results
        assert all(r.source_ref == "runbooks/pool.md" for r in result.results)
        with other.factory() as session, session.begin():
            bind_tenant(session, other.tenant_id)
            from asic.db.models import KnowledgeChunk

            count = session.scalar(sa.select(sa.func.count()).select_from(KnowledgeChunk))
        # RLS scopes the count to `other`'s own chunks only, not the combined total across
        # both tenants - if it leaked `world`'s chunks too the count would be doubled.
        assert count == other_outcome.chunk_count


class TestExplainability:
    def test_result_carries_both_lexical_and_vector_contribution_when_both_match(
        self, world: KnowledgeWorld
    ) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        result = world.retrieve("connection pool exhausted")
        assert result.results
        top = result.results[0]
        assert top.scores.lexical_rank is not None
        assert top.scores.vector_rank is not None
        assert top.scores.fused_score > 0
        assert top.scores.lexical_contribution > 0 or top.scores.vector_contribution > 0

    def test_unrelated_document_does_not_pollute_results(self, world: KnowledgeWorld) -> None:
        world.ingest("runbooks/pool.md", POOL_RUNBOOK, services=(world.checkout,))
        world.ingest(
            "runbooks/cert.md",
            UNRELATED_RUNBOOK,
            services=(world.checkout,),
            title="Certificate rotation",
        )
        result = world.retrieve("connection pool exhausted")
        assert result.results
        assert all("Certificate" not in r.title for r in result.results)
