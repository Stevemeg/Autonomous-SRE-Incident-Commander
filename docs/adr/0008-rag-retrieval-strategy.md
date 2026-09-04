# ADR-0008: RAG retrieval — hybrid by default, reranking only if measured

- **Status:** Needs validation
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §8 ("hybrid retrieval/reranking **where justified**")
- **Supersedes / Superseded by:** none

## Context

Section 8 requires production RAG with hybrid retrieval and reranking *"where justified"* —
again the conditional phrasing that makes this a measurement, not a default. The corpus is
operational: runbooks, service docs, known errors and postmortems.

Operational text has a property that matters for this decision: it is dense with **exact
tokens** — error codes, service names, metric names, Kubernetes resource kinds, exception
class names. A query for `CrashLoopBackOff` or `PaymentMapper` wants exact matching, which
is where lexical search beats dense embeddings.

## Decision

**Ship dense + lexical hybrid retrieval with reciprocal rank fusion as the v1 default.
Ship cross-encoder reranking and query expansion disabled**, behind flags, to be enabled
only if the retrieval evaluation set shows an improvement exceeding their latency and cost.

Status is `Needs validation` because the reranking half is explicitly an open measurement.

## Alternatives considered

### Option A — Dense only (rejected)

- **Pros:** Simplest; one index; lowest latency.
- **Cons:** Poor on exact-token queries, which are common here. Embedding models handle rare
  identifiers (a specific service or error code) badly — precisely the queries an
  investigation issues.
- **Cost to adopt:** Lowest.

### Option B — Dense + lexical hybrid with RRF (chosen for v1)

- **Pros:** Covers both semantic and exact-token queries. Reciprocal rank fusion needs no
  training, no extra model and no meaningful latency. Both indexes live in PostgreSQL
  (ADR-0004), so it is one query. Robust when one retriever fails — degrades to the other.
- **Cons:** Two indexes to maintain; fusion weighting needs tuning.
- **Cost to adopt:** Low.

### Option C — Hybrid + cross-encoder reranking (deferred, flag-disabled)

- **Pros:** Usually the largest single quality gain in RAG; strong at discriminating among
  superficially similar chunks.
- **Cons:** An extra model call per query: latency and cost inside the investigation budget
  (§5). Another model in the `behaviour_version` tuple to version and evaluate. **Enabling
  it by default without measurement is exactly the keyword adoption §20 forbids.**
- **Cost to adopt:** Moderate.

### Option D — Hybrid + query expansion (deferred, flag-disabled)

- **Pros:** Helps when the planner's declared gap is phrased unlike the corpus.
- **Cons:** Extra model call; can dilute precision; the planner already declares a
  *structured* gap rather than a vague question, which reduces the need.

## Rationale

Hybrid is the default because the corpus's exact-token density makes lexical search
genuinely complementary rather than redundant, and RRF costs nothing — no model, no
training, negligible latency. That is a free improvement, so it needs no further
justification.

Reranking is different. It is the most commonly cargo-culted RAG component, and it consumes
budget that §5 makes scarce: every millisecond and token spent reranking is unavailable for
gathering evidence. Section 8's *"where justified"* is best read as an instruction to
measure. We therefore build the retrieval evaluation set first
([`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md) §5), establish a
hybrid baseline, and enable reranking only if Recall@k and nDCG improve enough to pay for
the latency.

Building it flag-disabled rather than omitting it means the measurement is cheap to run.

## Consequences

- **Positive:** Strong baseline with no extra model; retrieval failure degrades gracefully;
  the reranking question becomes an experiment rather than an argument.
- **Negative / accepted trade-offs:** Two indexes; fusion weights need tuning; if reranking
  turns out to be clearly necessary we ship v1 slightly weaker than possible.
- **Security and permissions:** Neutral — scope and ACL filters are applied *before* search
  in every configuration (filter-before-search).
- **Observability and evaluation:** Positive — the flag makes an A/B measurement trivial,
  and `rerank_enabled` is a span attribute.
- **Failure modes and recovery:** Positive — either retriever can fail alone.
- **Operational and cost impact:** Positive in v1; reranking would add per-query cost.

## Reversal cost and revisit trigger

**Reversal cost: very low** — a configuration flag, plus re-baselining and a new
`behaviour_version`.

Enable reranking when the retrieval evaluation set shows a material Recall@k / nDCG
improvement whose latency and token cost fit the investigation budget. Revisit the whole
strategy if the corpus grows beyond roughly a million chunks, or if retrieval-miss (`F3`)
becomes a leading failure class in the taxonomy.

## Validation

**This ADR is `Needs validation` precisely because it defines its own experiment.**

| Test | Passing criterion |
|---|---|
| Hybrid vs dense | Hybrid ≥ dense on Recall@k across the evaluation set |
| Rerank A/B | Measured Recall@k, nDCG, added latency and cost per query |
| Exact-token queries | Error codes and service names retrieved reliably |
| Scope violations | **Zero** out-of-scope or out-of-tenant chunks in any configuration |
| Latency budget | p95 retrieval within the investigation step budget |

**None has been run.** No configuration is confirmed until the evaluation set exists.

## References

- Master specification §8
- [`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md) §2.3, §5
- [ADR-0004](./0004-postgresql-pgvector-primary-datastore.md)
