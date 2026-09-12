# ADR-0004: PostgreSQL + pgvector as the single primary datastore

- **Status:** Accepted — pgvector implemented Phase 6 (`knowledge_chunk.embedding`, HNSW index, exact cosine search over a pre-filtered candidate set)
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §8, §13, §15
- **Supersedes / Superseded by:** none

## Context

The system needs relational incident data with strong integrity constraints, an append-only
audit trail, workflow checkpoints, vector search over operational knowledge, and full-text
search over the same corpus. Section 13 proposes PostgreSQL + pgvector; §13 also requires
that dedicated vector databases be evaluated rather than blindly added.

The data-model invariants in
[`../architecture/data-model-and-api.md`](../architecture/data-model-and-api.md) §4 are
mostly *relational* guarantees — foreign keys binding evidence to tool executions, unique
constraints enforcing idempotency, check constraints enforcing separation of duties. Those
invariants are the safety argument, so where they live is not a minor concern.

## Decision

**Use a single PostgreSQL instance with the `pgvector` extension for all persistent state:
relational data, audit, workflow checkpoints, vector embeddings and full-text search.** Do
not adopt a dedicated vector database.

## Alternatives considered

### Option A — PostgreSQL + pgvector, single store (chosen)

- **Pros:** One store to operate, back up, secure and reason about. Row-level security
  covers vectors and relational rows alike, so tenant isolation is enforced once rather than
  per-store. Retrieval filters are ordinary SQL predicates, which makes filter-before-search
  natural. Hybrid search needs no second system — Postgres full-text and pgvector live in
  one query. Transactional consistency between a knowledge document and its chunks.
- **Cons:** pgvector is slower than a specialised engine at very large scale. HNSW index
  builds are memory-hungry. One store is one blast radius.
- **Cost to adopt:** Low; in the §13 baseline.

### Option B — PostgreSQL + a dedicated vector database (rejected)

- **Pros:** Better ANN performance and richer index tuning at scale.
- **Cons:** Two stores, two backup and security models, two tenancy enforcement points.
  **ACL and tenant filtering must be reimplemented in the vector store**, and a mismatch
  between the two implementations is a cross-tenant disclosure. No transactional consistency
  between a document and its embeddings. Section 13 explicitly names this as an
  evaluate-don't-assume choice.
- **Cost to adopt:** Moderate, plus permanent operational overhead.

### Option C — PostgreSQL + OpenSearch for lexical and vector (rejected for v1)

- **Pros:** Strong lexical search; mature; also a candidate log backend (§14).
- **Cons:** Same dual-store tenancy risk as Option B. Heavier to operate. Postgres full-text
  is sufficient for a corpus of runbooks and postmortems.
- **Cost to adopt:** Moderate–high.

## Rationale

The decisive factor is **tenant isolation** (SEC-I2). Our strongest isolation mechanism is
PostgreSQL row-level security. A second store holding the same tenants' content would need
an independent, equally-correct implementation of the same boundary, and a divergence
between the two is exactly the cross-tenant disclosure T04 describes. One store means one
correct implementation.

Scale does not argue otherwise. The corpus is runbooks, service docs, known errors and
postmortems for a handful of tenants — thousands to low hundreds of thousands of chunks.
pgvector with HNSW is comfortable in that range; a dedicated vector database earns its
operational cost at a scale we are not near and may never reach.

Adopting a vector database at this scale would be the résumé-keyword adoption §20 forbids.

## Consequences

- **Positive:** One store; RLS covers everything; hybrid search in one query;
  document-to-chunk transactional consistency; simple local reproduction.
- **Negative / accepted trade-offs:** Retrieval latency will exceed a specialised engine's.
  Index rebuilds on embedding-model change are a maintenance event. Single blast radius,
  mitigated by backups and read replicas.
- **Security and permissions:** Strongly positive — one isolation boundary.
- **Observability and evaluation:** Positive — evaluation runs, traces and incident data
  join directly.
- **Failure modes and recovery:** Concentrated. PostgreSQL availability becomes a hard
  dependency, addressed by managed HA in Phase 14.
- **Operational and cost impact:** Clearly positive.

## Reversal cost and revisit trigger

**Reversal cost: moderate.** Mitigated by keeping retrieval behind a `KnowledgeStore`
interface, so swapping the vector backend does not touch node code.

Revisit if: the chunk corpus exceeds ~5 million and retrieval p95 breaches its budget; index
build time disrupts operations; or a tenant requires physical data separation, which would
change the tenancy model before the vector model.

## Validation

| Test | Passing criterion |
|---|---|
| Retrieval latency | p95 within budget at projected corpus size (Phase 15) |
| Tenant isolation | Property tests: zero cross-tenant chunks under adversarial queries |
| Hybrid quality | Recall@k measured against the retrieval evaluation set |
| Index build | Rebuild completes within a maintenance window |

**None has been run.**

## References

- Master specification §8, §13, §15
- [`../architecture/data-model-and-api.md`](../architecture/data-model-and-api.md)
- [`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md)
