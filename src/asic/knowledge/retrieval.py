"""Authorization-first hybrid retrieval over PostgreSQL full-text search and pgvector.

**Filter before search, and in one snapshot.** One SQL statement classifies every chunk in
the tenant by *disposition* - unauthorized, inactive source, revoked version, not yet
effective, superseded, stale, embedding-model mismatch, or eligible - and only eligible
chunks are ever ranked. Authorization (access labels, service scope, environment scope,
document type) is evaluated first, so content a principal may not read never enters the
candidate set, never influences an ordering, and never reaches a model. Row-level security
enforces the tenant boundary underneath all of it. Because it is one statement, a source
revoked or superseded concurrently is either wholly before or wholly after the snapshot.

**Hybrid by default; reranking off** (ADR-0008). The lexical half is PostgreSQL full-text
search over the chunk text; the vector half is an exact cosine search over the eligible
chunks' embeddings. They are fused with reciprocal rank fusion (:class:`FusionPolicy`),
whose parameters are part of the recorded policy version. Exact search over the filtered
set is deliberate: approximate index search followed by filtering can silently drop
authorized results, and at the corpus sizes this phase targets the exact scan is cheap. The
HNSW index remains for the scale at which that trade-off reverses (ADR-0004).

**Explainable.** Every result carries its lexical rank and score, vector rank and
similarity, both contributions and the fused score; every retrieval records the policy, the
embedding model, the eligible count and the exclusions by reason. Exclusion counts are
corpus counts, independent of the query, so they reveal nothing about what an unauthorized
document says.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from time import monotonic
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import (
    Environment,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeRetrieval,
    KnowledgeRetrievalResult,
    KnowledgeSource,
    Service,
)
from asic.db.session import require_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import KnowledgeDocumentType, TrustClass
from asic.knowledge import telemetry
from asic.knowledge.authorization import current_access
from asic.knowledge.contracts import (
    MAX_RESULT_CONTENT_CHARS,
    KnowledgeCitation,
    RetrievalPrincipal,
    RetrievalQuery,
    RetrievalResultSet,
    RetrievalScope,
    RetrievedChunk,
    ScoreBreakdown,
)
from asic.knowledge.embedding import EmbeddingService
from asic.knowledge.errors import RetrievalRefused

POLICY_VERSION: Final[str] = "knowledge-retrieval/1"


class RetrievalMode(StrEnum):
    """Hybrid is the default; the single-signal modes exist for evaluation ablation."""

    HYBRID = "hybrid"
    LEXICAL = "lexical"
    VECTOR = "vector"


@dataclass(frozen=True, slots=True)
class FusionPolicy:
    """Reciprocal rank fusion: ``score = sum(weight / (k + rank))``.

    ``k = 60`` is the constant from the paper that introduced RRF (Cormack, Clarke and
    Buettcher, SIGIR 2009), where it was reported as robust across collections; it is not
    tuned here, and changing it - or either weight - is a new fusion version.
    """

    version: str = "rrf/1"
    k: int = 60
    lexical_weight: float = 1.0
    vector_weight: float = 1.0


@dataclass(frozen=True, slots=True)
class RetrievalPolicy:
    version: str = POLICY_VERSION
    mode: RetrievalMode = RetrievalMode.HYBRID
    fusion: FusionPolicy = field(default_factory=FusionPolicy)
    lexical_candidates: int = 50
    vector_candidates: int = 50
    #: Below this cosine similarity a vector neighbour is not treated as relevant. The
    #: value is specific to the embedding model: it was calibrated for the deterministic
    #: test model against the Phase 6 evaluation corpus and must be recalibrated - with a
    #: new policy version - for any other model.
    min_vector_similarity: float = 0.2
    #: At most this many chunks from one version, so one long document cannot crowd out
    #: every other source.
    max_chunks_per_version: int = 3

    @property
    def identifier(self) -> str:
        return f"{self.version}:{self.mode.value}:{self.fusion.version}"


#: The identifier the deployed default policy produces. Manifest verification
#: (P6-02, :func:`asic.orchestration.knowledge_context.validate_manifest`) compares a
#: provider's claimed ``policy_version`` against this rather than trusting the claim: the
#: retrieval policy is code, not tenant configuration, so there is exactly one correct
#: answer and no provider ever needs to assert it.
DEFAULT_POLICY_IDENTIFIER: Final[str] = RetrievalPolicy().identifier


_TRUST_ORDER: Final[dict[str, int]] = {
    TrustClass.OFFICIAL_RUNBOOK.value: 0,
    TrustClass.SERVICE_DOCUMENTATION.value: 1,
    TrustClass.HISTORICAL_POSTMORTEM.value: 2,
    TrustClass.COMMUNITY.value: 3,
}

_RETRIEVAL_SQL: Final = sa.text(
    """
WITH base AS (
    SELECT c.id AS chunk_id, c.document_id AS version_id, c.text, c.embedding,
           c.embedding_model_id, c.section_path, c.start_offset, c.end_offset,
           c.start_line, c.end_line, c.content_hash,
           d.version, d.title, d.lifecycle::text AS lifecycle, d.effective_at,
           d.superseded_at, d.fresh_until,
           s.id AS source_id, s.provider, s.source_ref,
           s.document_type::text AS document_type, s.trust_class::text AS trust_class,
           s.status::text AS source_status,
           ((cardinality(s.acl_labels) = 0 OR s.acl_labels && CAST(:clearances AS varchar[]))
            AND (cardinality(s.service_ids) = 0 OR s.service_ids && CAST(:services AS uuid[]))
            AND (cardinality(s.environment_ids) = 0
                 OR s.environment_ids @> ARRAY[CAST(:environment AS uuid)])
            AND s.document_type = ANY(CAST(:document_types AS knowledge_document_type[])))
           AS authorized
    FROM knowledge_chunk c
    JOIN knowledge_document d ON d.tenant_id = c.tenant_id AND d.id = c.document_id
    JOIN knowledge_source s ON s.tenant_id = d.tenant_id AND s.id = d.source_id
    WHERE c.tenant_id = CAST(:tenant_id AS uuid)
),
classified AS (
    SELECT base.*,
        CASE
            WHEN NOT authorized THEN 'unauthorized'
            WHEN source_status <> 'active' THEN 'inactive_source'
            WHEN lifecycle = 'revoked' THEN 'revoked_version'
            WHEN effective_at > CAST(:as_of AS timestamptz) THEN 'not_yet_effective'
            WHEN superseded_at IS NOT NULL AND superseded_at <= CAST(:as_of AS timestamptz)
                THEN 'superseded'
            WHEN NOT CAST(:include_stale AS boolean) AND fresh_until IS NOT NULL
                 AND fresh_until <= CAST(:as_of AS timestamptz) THEN 'stale'
            WHEN embedding_model_id IS DISTINCT FROM :model_id THEN 'embedding_model_mismatch'
            ELSE 'eligible'
        END AS disposition,
        (fresh_until IS NOT NULL AND fresh_until <= CAST(:as_of AS timestamptz)) AS is_stale
    FROM base
),
eligible AS MATERIALIZED (
    SELECT * FROM classified WHERE disposition = 'eligible'
),
lexical AS (
    SELECT e.chunk_id, ts_rank_cd(to_tsvector('english', e.text), q.query, 32) AS score
    FROM eligible e, websearch_to_tsquery('english', :query) AS q(query)
    WHERE to_tsvector('english', e.text) @@ q.query
    ORDER BY score DESC, e.chunk_id
    LIMIT :lexical_limit
),
lexical_ranked AS (
    SELECT chunk_id, score, row_number() OVER (ORDER BY score DESC, chunk_id) AS rnk
    FROM lexical
),
vector AS (
    SELECT e.chunk_id, 1 - (e.embedding <=> CAST(:query_vector AS vector)) AS similarity
    FROM eligible e
    ORDER BY e.embedding <=> CAST(:query_vector AS vector), e.chunk_id
    LIMIT :vector_limit
),
vector_ranked AS (
    SELECT chunk_id, similarity, row_number() OVER (ORDER BY similarity DESC, chunk_id) AS rnk
    FROM vector
),
candidates AS (
    SELECT COALESCE(l.chunk_id, v.chunk_id) AS chunk_id,
           l.rnk AS lexical_rank, l.score AS lexical_score,
           v.rnk AS vector_rank, v.similarity AS vector_similarity
    FROM lexical_ranked l FULL OUTER JOIN vector_ranked v ON v.chunk_id = l.chunk_id
),
meta AS (
    SELECT (SELECT jsonb_object_agg(disposition, n)
            FROM (SELECT disposition, count(*) AS n FROM classified GROUP BY disposition) g)
               AS dispositions,
           (SELECT count(*) FROM lexical) AS lexical_matches,
           (SELECT count(*) FROM vector) AS vector_candidates
)
SELECT m.dispositions, m.lexical_matches, m.vector_candidates,
       e.chunk_id, e.version_id, e.text, e.section_path, e.start_offset, e.end_offset,
       e.start_line, e.end_line, e.content_hash, e.version, e.title, e.effective_at,
       e.fresh_until, e.is_stale, e.source_id, e.provider, e.source_ref,
       e.document_type, e.trust_class,
       c.lexical_rank, c.lexical_score, c.vector_rank, c.vector_similarity
FROM meta m
LEFT JOIN (candidates c JOIN eligible e ON e.chunk_id = c.chunk_id) ON true
"""
)


class KnowledgeRetriever:
    """Runs governed retrievals. The session must already be bound to the principal's tenant."""

    __slots__ = ("_clock", "_embeddings", "_policy")

    def __init__(
        self,
        embeddings: EmbeddingService,
        *,
        policy: RetrievalPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._embeddings = embeddings
        self._policy = policy or RetrievalPolicy()
        self._clock = clock or SystemClock()

    @property
    def policy(self) -> RetrievalPolicy:
        return self._policy

    def retrieve(
        self,
        session: Session,
        *,
        principal: RetrievalPrincipal,
        scope: RetrievalScope,
        query: RetrievalQuery,
    ) -> RetrievalResultSet:
        """Retrieve for ``principal`` within ``scope``.

        An empty result is a legitimate answer and carries its exclusion counts. A refusal
        is not an empty result.

        Raises:
            RetrievalRefused: ``tenant_mismatch`` or ``unknown_scope``.
            EmbeddingFailure: the query could not be embedded.
        """
        started = monotonic()
        retrieval_id = uuid.uuid4()
        policy = self._policy
        with telemetry.stage(
            "retrieve",
            tenant_id=str(principal.tenant_id),
            retrieval_id=str(retrieval_id),
            policy=policy.identifier,
        ) as span:
            if require_tenant(session) != principal.tenant_id:
                telemetry.retrievals.add(1, {"mode": policy.mode.value, "outcome": "refused"})
                raise RetrievalRefused("tenant_mismatch")
            _assert_scope(session, principal.tenant_id, scope)

            as_of = query.as_of or self._clock.now()
            vector = self._embeddings.embed_one(query.text)
            rows = (
                session.execute(
                    _RETRIEVAL_SQL,
                    {
                        "tenant_id": str(principal.tenant_id),
                        "clearances": sorted(principal.clearances),
                        "services": [str(s) for s in scope.service_ids],
                        "environment": str(scope.environment_id),
                        "document_types": [t.value for t in scope.document_types],
                        "as_of": as_of,
                        "include_stale": query.include_stale,
                        "model_id": self._embeddings.model.identifier,
                        "query": query.text,
                        "query_vector": _vector_literal(vector),
                        "lexical_limit": policy.lexical_candidates,
                        "vector_limit": policy.vector_candidates,
                    },
                )
                .mappings()
                .all()
            )

            meta = rows[0]
            dispositions: dict[str, int] = {
                str(k): int(v) for k, v in dict(meta["dispositions"] or {}).items()
            }
            results = _rank(
                [dict(row) for row in rows if row["chunk_id"] is not None],
                retrieval_id=retrieval_id,
                policy=policy,
                limit=query.limit,
            )
            excluded = {k: v for k, v in sorted(dispositions.items()) if k != "eligible"}
            result_set = RetrievalResultSet(
                retrieval_id=retrieval_id,
                principal=principal,
                scope=scope,
                query_text=query.text,
                query_digest=hashlib.sha256(query.text.encode("utf-8")).hexdigest(),
                policy_version=policy.identifier,
                mode=policy.mode.value,
                embedding_model_id=self._embeddings.model.identifier,
                embedding_dimensions=self._embeddings.model.dimensions,
                as_of=as_of,
                include_stale=query.include_stale,
                eligible_chunks=dispositions.get("eligible", 0),
                lexical_matches=int(meta["lexical_matches"] or 0),
                vector_candidates=int(meta["vector_candidates"] or 0),
                excluded=excluded,
                results=results,
                latency_ms=int((monotonic() - started) * 1000),
            )

            span.set_attribute("result_count", len(results))
            span.set_attribute("eligible_chunks", result_set.eligible_chunks)
            span.set_attribute("query_digest", result_set.query_digest)
            telemetry.retrievals.add(
                1,
                {"mode": policy.mode.value, "outcome": "results" if results else "empty"},
            )
            telemetry.retrieval_results.record(len(results), {"mode": policy.mode.value})
            for reason, count in excluded.items():
                telemetry.retrieval_exclusions.add(count, {"reason": reason})
            return result_set


def _rank(
    rows: Sequence[Mapping[str, Any]],
    *,
    retrieval_id: uuid.UUID,
    policy: RetrievalPolicy,
    limit: int,
) -> tuple[RetrievedChunk, ...]:
    fusion = policy.fusion
    scored: list[tuple[tuple[Any, ...], Mapping[str, Any], ScoreBreakdown]] = []
    for row in rows:
        lexical_rank = row["lexical_rank"] if policy.mode is not RetrievalMode.VECTOR else None
        similarity = row["vector_similarity"]
        vector_rank = row["vector_rank"] if policy.mode is not RetrievalMode.LEXICAL else None
        vector_relevant = (
            vector_rank is not None
            and similarity is not None
            and float(similarity) >= policy.min_vector_similarity
        )
        lexical_part = fusion.lexical_weight / (fusion.k + lexical_rank) if lexical_rank else 0.0
        vector_part = (
            fusion.vector_weight / (fusion.k + vector_rank)
            if vector_relevant and vector_rank
            else 0.0
        )
        fused = lexical_part + vector_part
        if fused <= 0.0:
            continue
        breakdown = ScoreBreakdown(
            lexical_rank=row["lexical_rank"],
            lexical_score=float(row["lexical_score"]) if row["lexical_score"] is not None else None,
            vector_rank=row["vector_rank"],
            vector_similarity=float(similarity) if similarity is not None else None,
            lexical_contribution=round(lexical_part, 12),
            vector_contribution=round(vector_part, 12),
            fused_score=round(fused, 12),
        )
        key = (
            -breakdown.fused_score,
            lexical_rank if lexical_rank else 1_000_000,
            vector_rank if vector_relevant and vector_rank else 1_000_000,
            _TRUST_ORDER.get(str(row["trust_class"]), 99),
            str(row["chunk_id"]),
        )
        scored.append((key, row, breakdown))

    scored.sort(key=lambda item: item[0])
    per_version: dict[Any, int] = {}
    chosen: list[RetrievedChunk] = []
    for _, row, breakdown in scored:
        version_id = row["version_id"]
        if per_version.get(version_id, 0) >= policy.max_chunks_per_version:
            continue
        per_version[version_id] = per_version.get(version_id, 0) + 1
        chosen.append(
            RetrievedChunk(
                rank=len(chosen) + 1,
                citation=KnowledgeCitation(
                    retrieval_id=retrieval_id, chunk_id=row["chunk_id"], version_id=version_id
                ),
                source_id=row["source_id"],
                provider=row["provider"],
                source_ref=row["source_ref"],
                document_type=KnowledgeDocumentType(row["document_type"]),
                trust_class=TrustClass(row["trust_class"]),
                title=row["title"],
                section_path=tuple(row["section_path"] or ()),
                version=int(row["version"]),
                stale=bool(row["is_stale"]),
                effective_at=row["effective_at"],
                fresh_until=row["fresh_until"],
                start_line=int(row["start_line"]),
                end_line=int(row["end_line"]),
                start_offset=int(row["start_offset"]),
                end_offset=int(row["end_offset"]),
                content_hash=row["content_hash"],
                scores=breakdown,
                content=str(row["text"])[:MAX_RESULT_CONTENT_CHARS],
            )
        )
        if len(chosen) >= limit:
            break
    return tuple(chosen)


def _vector_literal(vector: Sequence[float]) -> str:
    return "[" + ",".join(format(value, ".9g") for value in vector) + "]"


def _assert_scope(session: Session, tenant_id: uuid.UUID, scope: RetrievalScope) -> None:
    """The scope must name this tenant's catalogue. Refusal, not an empty result."""
    environment = session.scalar(
        sa.select(Environment.id).where(
            Environment.tenant_id == tenant_id, Environment.id == scope.environment_id
        )
    )
    services = set(
        session.scalars(
            sa.select(Service.id).where(
                Service.tenant_id == tenant_id, Service.id.in_(scope.service_ids)
            )
        )
    )
    if environment is None or services != set(scope.service_ids):
        raise RetrievalRefused("unknown_scope")


# ------------------------------------------------------------- recording and replay


def record_retrieval(
    session: Session,
    result_set: RetrievalResultSet,
    *,
    incident_id: uuid.UUID | None = None,
    workflow_run_id: uuid.UUID | None = None,
    tool_execution_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    correlation_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
) -> KnowledgeRetrieval:
    """Persist a retrieval and its ranked results. Append-only; content is not copied."""
    record = KnowledgeRetrieval(
        id=result_set.retrieval_id,
        tenant_id=result_set.principal.tenant_id,
        principal_kind=result_set.principal.kind,
        principal_id=result_set.principal.principal_id,
        clearances=sorted(result_set.principal.clearances),
        incident_id=incident_id,
        workflow_run_id=workflow_run_id,
        tool_execution_id=tool_execution_id,
        evidence_id=evidence_id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        policy_version=result_set.policy_version,
        embedding_model_id=result_set.embedding_model_id,
        embedding_dimensions=result_set.embedding_dimensions,
        query_text=result_set.query_text,
        query_digest=result_set.query_digest,
        scope={
            "environment_id": str(result_set.scope.environment_id),
            "service_ids": sorted(str(s) for s in result_set.scope.service_ids),
            "document_types": sorted(t.value for t in result_set.scope.document_types),
        },
        as_of=result_set.as_of,
        include_stale=result_set.include_stale,
        eligible_chunks=result_set.eligible_chunks,
        lexical_matches=result_set.lexical_matches,
        vector_candidates=result_set.vector_candidates,
        excluded=dict(result_set.excluded),
        result_count=len(result_set.results),
        latency_ms=result_set.latency_ms,
    )
    session.add(record)
    session.flush()
    session.add_all(
        KnowledgeRetrievalResult(
            id=uuid.uuid4(),
            tenant_id=result_set.principal.tenant_id,
            retrieval_id=result_set.retrieval_id,
            rank=result.rank,
            chunk_id=result.citation.chunk_id,
            document_version_id=result.citation.version_id,
            source_id=result.source_id,
            lexical_rank=result.scores.lexical_rank,
            lexical_score=result.scores.lexical_score,
            vector_rank=result.scores.vector_rank,
            vector_similarity=result.scores.vector_similarity,
            fused_score=result.scores.fused_score,
            stale=result.stale,
            content_hash=result.content_hash,
        )
        for result in result_set.results
    )
    session.flush()
    return record


@dataclass(frozen=True, slots=True)
class ReplayedResult:
    rank: int
    citation: KnowledgeCitation
    version: int
    stale_at_retrieval: bool
    fused_score: float
    #: The exact historical chunk text, or ``None`` when access has since been withdrawn.
    content: str | None
    withheld_reason: str | None


def replay_retrieval(
    session: Session,
    retrieval_id: uuid.UUID,
    *,
    principal: RetrievalPrincipal,
    scope: RetrievalScope,
) -> tuple[ReplayedResult, ...]:
    """Reproduce what a past retrieval returned - the exact versions, never the newest.

    Superseded content is returned as it was, because a historical run must be explicable
    against what it actually saw. **Current** hard authorization still governs whether the
    text is actually handed back (P6-03): ``principal`` and ``scope`` are re-evaluated
    against the source and document *as they stand now*, not as the original retrieval
    recorded them. Ranking, identifiers and version references are preserved regardless -
    historical traceability is not the same claim as historical authorization, and only the
    latter can withhold content.
    """
    tenant_id = require_tenant(session)
    rows = session.execute(
        sa.select(KnowledgeRetrievalResult, KnowledgeChunk, KnowledgeDocument, KnowledgeSource)
        .join(
            KnowledgeChunk,
            sa.and_(
                KnowledgeChunk.tenant_id == KnowledgeRetrievalResult.tenant_id,
                KnowledgeChunk.id == KnowledgeRetrievalResult.chunk_id,
            ),
        )
        .join(
            KnowledgeDocument,
            sa.and_(
                KnowledgeDocument.tenant_id == KnowledgeRetrievalResult.tenant_id,
                KnowledgeDocument.id == KnowledgeRetrievalResult.document_version_id,
            ),
        )
        .join(
            KnowledgeSource,
            sa.and_(
                KnowledgeSource.tenant_id == KnowledgeRetrievalResult.tenant_id,
                KnowledgeSource.id == KnowledgeRetrievalResult.source_id,
            ),
        )
        .where(
            KnowledgeRetrievalResult.tenant_id == tenant_id,
            KnowledgeRetrievalResult.retrieval_id == retrieval_id,
        )
        .order_by(KnowledgeRetrievalResult.rank)
    ).all()
    replayed = []
    for result, chunk, version, source in rows:
        withheld = current_access(source=source, document=version, principal=principal, scope=scope)
        replayed.append(
            ReplayedResult(
                rank=result.rank,
                citation=KnowledgeCitation(
                    retrieval_id=retrieval_id, chunk_id=chunk.id, version_id=version.id
                ),
                version=version.version,
                stale_at_retrieval=result.stale,
                fused_score=result.fused_score,
                content=None if withheld else chunk.text,
                withheld_reason=withheld,
            )
        )
    return tuple(replayed)


def current_content(
    session: Session,
    citations: Sequence[KnowledgeCitation],
    *,
    principal: RetrievalPrincipal,
    scope: RetrievalScope,
) -> dict[uuid.UUID, str | None]:
    """Chunk text for citations, withheld (``None``) where access is not currently authorized.

    Used when retrieved content is rendered into a prompt after the retrieval itself, so a
    revocation - of the document, or of ``principal``'s own clearances or scope - that
    lands in between is honoured (P6-03). ``principal`` and ``scope`` must be the caller's
    *current* trusted context, re-derived at render time; passing through what a historical
    retrieval recorded would silently reinstate exactly the defect this closes.
    """
    if not citations:
        return {}
    tenant_id = require_tenant(session)
    rows = session.execute(
        sa.select(KnowledgeChunk, KnowledgeDocument, KnowledgeSource)
        .join(
            KnowledgeDocument,
            sa.and_(
                KnowledgeDocument.tenant_id == KnowledgeChunk.tenant_id,
                KnowledgeDocument.id == KnowledgeChunk.document_id,
            ),
        )
        .join(
            KnowledgeSource,
            sa.and_(
                KnowledgeSource.tenant_id == KnowledgeDocument.tenant_id,
                KnowledgeSource.id == KnowledgeDocument.source_id,
            ),
        )
        .where(
            KnowledgeChunk.tenant_id == tenant_id,
            KnowledgeChunk.id.in_([c.chunk_id for c in citations]),
        )
    ).all()
    available: dict[uuid.UUID, str | None] = {c.chunk_id: None for c in citations}
    for chunk, document, source in rows:
        if (
            current_access(source=source, document=document, principal=principal, scope=scope)
            is None
        ):
            available[chunk.id] = chunk.text
    return available


def as_of_now(clock: Clock | None = None) -> datetime:
    return (clock or SystemClock()).now()


__all__ = [
    "DEFAULT_POLICY_IDENTIFIER",
    "POLICY_VERSION",
    "FusionPolicy",
    "KnowledgeRetriever",
    "ReplayedResult",
    "RetrievalMode",
    "RetrievalPolicy",
    "current_content",
    "record_retrieval",
    "replay_retrieval",
]
