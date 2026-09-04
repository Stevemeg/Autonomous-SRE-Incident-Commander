# Memory and RAG Architecture

- **Status:** Authored — Architecture Package (V3 §23 H). **Proposed; not implemented.**
- **Master specification references:** Sections 8, 10, 15, 23(H)
- **Related:** [`tool-registry.md`](./tool-registry.md) §6 (provenance) · [`data-model-and-api.md`](./data-model-and-api.md)

---

## 1. Memory tiers

Section 8 requires five separated concerns. They are separated because they differ in
**lifetime, write authority and trust** — not merely for tidiness. Collapsing any two
creates a specific, nameable failure.

| Tier | Contents | Lifetime | Written by | Trust | Failure if merged with another tier |
|---|---|---|---|---|---|
| **T1 Working incident state** | Current hypotheses, open gaps, budget ledger, node scratch | Incident duration | Orchestrator, nodes | Internal | If merged with T3, a mid-investigation guess becomes permanent history |
| **T2 Short-term context** | The window assembled for a given model call | One model call | Context assembler | Derived | If merged with T1, prompt-shaping accidentally mutates incident state |
| **T3 Durable incident history** | Closed incidents, events, evidence, actions, outcomes | Retention policy (years) | Append-only, at incident close | `VERIFIED_FACT` where tool-derived | If merged with T4, unreviewed incident detail leaks into advice given to future incidents |
| **T4 Operational knowledge** | Runbooks, service docs, known errors, postmortems | Versioned; superseded not deleted | **Human-approved writes only** | `RETRIEVED` — untrusted | If merged with T5, an unverified suggestion is presented as a proven fix |
| **T5 Verified remediation outcomes** | Action → context → observed effect → verification verdict | Versioned | G12 proposal + human approval | `VERIFIED_FACT` with support count | If merged with T3, one incident becomes a general rule |

### 1.1 The rule that keeps the tiers honest

> **Nothing is promoted upward without an explicit, recorded, human-approved transition.**

T1 → T3 happens at incident close, mechanically, append-only. T3 → T5 and T3 → T4 require
a G12 proposal and a human approval record. There is no automatic path from "this worked
once" to "this is what we do" (§10, SI-12).

```mermaid
flowchart LR
    T1["T1 Working state<br/><i>incident-scoped, mutable</i>"]
    T2["T2 Short-term context<br/><i>per model call, derived</i>"]
    T3["T3 Incident history<br/><i>append-only</i>"]
    T4["T4 Operational knowledge<br/><i>versioned, RETRIEVED</i>"]
    T5["T5 Verified outcomes<br/><i>versioned, VERIFIED_FACT</i>"]
    H(["Human approval gate"])

    T1 -->|"assembled into"| T2
    T3 -->|"advisory retrieval"| T2
    T4 -->|"cited retrieval"| T2
    T5 -->|"cited retrieval"| T2
    T1 -->|"incident close, mechanical"| T3
    T3 --> H
    H -->|"approved promotion"| T4
    H -->|"approved promotion"| T5
```

### 1.2 History informs, never overrides

Section 8 is explicit: *"Historical incidents inform current investigation but never
override current evidence."* Enforced three ways:

1. Historical material enters T2 labelled `RETRIEVED`, never `VERIFIED_FACT`.
2. The Hypothesis Engine (G5) may cite history as *supporting context* but a hypothesis
   whose only support is historical is scored as unsupported by current evidence, and
   ranked accordingly.
3. When current evidence contradicts historical precedent, the contradiction is surfaced as
   counter-evidence rather than resolved silently in favour of either.

---

## 2. RAG pipeline

### 2.1 Ingestion

```mermaid
flowchart LR
    A["Sources<br/>runbooks · service docs<br/>known errors · postmortems"] --> B["Fetch + change detection<br/>content hash"]
    B --> C["<b>Sanitiser</b><br/>strip active content<br/>flag injection patterns"]
    C --> D["Structure-aware chunker"]
    D --> E["Metadata binder<br/>tenant · service · environment<br/>version · freshness · ACL · source"]
    E --> F["Embedder<br/>versioned model ID"]
    F --> G[("knowledge_chunk<br/>pgvector + lexical index")]
    E --> H[("knowledge_document")]
```

**Chunking is structure-aware, not fixed-width.** Operational documents have meaningful
structure — a runbook step, a known-error entry, a postmortem section — and splitting mid
procedure produces chunks that retrieve well and advise badly. A chunk that is half a
rollback procedure is worse than no chunk. Where structure is absent we fall back to
window-with-overlap, and record which strategy produced each chunk so retrieval evaluation
can compare them.

**The embedding model ID is stored per chunk.** Changing the embedding model is a versioned
behaviour change (§10, FR-EVL-09) requiring a re-index and a re-run of retrieval
evaluation — not a config edit.

### 2.2 Metadata

| Field | Purpose |
|---|---|
| `tenant_id` | Isolation boundary; a query predicate, never a post-filter |
| `service_ids`, `environments` | Scoping per FR-KNW-02 |
| `acl_labels` | Access-control filtering per FR-KNW-03 |
| `document_version`, `superseded_by` | Versioning per FR-KNW-05 |
| `source_updated_at`, `ingested_at` | Freshness; staleness is computed, not assumed |
| `content_hash` | Change detection; avoids needless re-embedding |
| `chunk_strategy`, `embedding_model_id` | Reproducibility and evaluation comparability |
| `trust_class` | `official_runbook` ranks above `historical_postmortem` |

### 2.3 Retrieval

```mermaid
flowchart LR
    Q["Declared information gap<br/>from Investigation Planner"] --> QB["Query builder"]
    QB --> F["<b>Scope + ACL predicates</b><br/>applied in the query"]
    F --> D["Dense search<br/>pgvector"]
    F --> L["Lexical search<br/>full-text"]
    D --> FUSE["Fusion"]
    L --> FUSE
    FUSE --> RR["Reranker<br/><i>enabled only if measured to help</i>"]
    RR --> FR["Freshness + trust adjustment"]
    FR --> CB["Citation binder"]
    CB --> OUT["Evidence records<br/>labelled RETRIEVED"]
```

**Filter before search, never after.** Scope and ACL are query predicates, so out-of-scope
content never enters the candidate set. Post-filtering would let inaccessible content
influence scoring and ordering — an information leak even when the content itself is never
returned (NFR-SEC-03).

**Hybrid retrieval is the starting point; reranking is not.** Section 8 says hybrid
retrieval and reranking "where justified". Justification means measurement:

| Stage | v1 default | Promotion criterion |
|---|---|---|
| Dense (pgvector) | Enabled | Baseline |
| Lexical (Postgres FTS) | Enabled | Operational vocabulary is full of exact tokens — error codes, service names, metric names — where lexical beats dense |
| Fusion | Enabled, reciprocal rank fusion | Simple, no extra model, no extra latency |
| Cross-encoder rerank | **Disabled** | Enable only if it produces a measured improvement in retrieval evaluation that exceeds its latency and cost |
| Query expansion | **Disabled** | Same standard |

Shipping a reranker by default would be exactly the résumé-keyword adoption §20 forbids.
The retrieval evaluation set (§5 below) exists so this stays a measurement, not an opinion.

### 2.4 Citations

Every retrieved chunk returns with `document_id`, `chunk_id`, `document_version`,
`source_uri`, `source_updated_at` and the retrieval score. A human can re-derive it; the
Postmortem Author's uncited claims are stripped against exactly these IDs (G11).

---

## 3. Provenance

The five labels, their authority and their rules, are defined normatively in
[`tool-registry.md`](./tool-registry.md) §6.1. Applied to memory:

| Content | Label | Why |
|---|---|---|
| Tool result from the broker | `VERIFIED_FACT` | Origin, query and timestamp are known |
| Knowledge base chunk | `RETRIEVED` | Human-authored text of unknown current accuracy |
| Historical incident detail | `RETRIEVED` | True of *that* incident, not of this one |
| Verified remediation outcome (T5) | `VERIFIED_FACT` with support count | Observed and verified, but support count still bounds generalisation |
| Any model generation | `MODEL_CLAIM` | Untrusted until grounded and schema-validated |
| Policy, registry, configuration | `SYSTEM` | Ours |
| Approval decision, operator input | `HUMAN` | Authenticated |

**Labels are applied at the boundary where origin is known** — the broker, the retriever,
the API — never by asking a model to label its own output. A node cannot promote a label.

---

## 4. Prompt-injection defenses

Retrieved content is the primary injection vector: runbooks and tickets are written by
humans, sometimes by humans outside the tenant, and can be edited by anyone with write
access to a wiki.

| Layer | Mechanism | What it stops |
|---|---|---|
| **Structural (primary)** | The policy gate accepts only a typed `ActionProposal` + `SYSTEM` policy. There is no field capable of carrying `RETRIEVED` content | An injected instruction reaching authorization at all |
| **Positional** | Untrusted content is placed in a delimited data region, never in an instruction position | Instruction confusion |
| **Capability** | The model chooses from a pre-resolved capability menu; it cannot name a new capability | "Grant yourself admin" having any referent |
| **Detection** | Injection-pattern scan at ingestion and at retrieval; flagged, recorded, surfaced | Provides signal and evidence; **not relied upon as the defence** |
| **Sanitisation** | Strip scripts, embedded markup, zero-width and bidirectional control characters | Obfuscated payloads |
| **Output validation** | Model output is schema-validated; cited evidence IDs are verified to exist | Fabricated citations, malformed actions |
| **Egress control** | Only the broker reaches external systems, with scoped credentials | Exfiltration via tool arguments |

The distinction that matters: detection is a **signal**, structure is the **defence**. A
system whose injection protection is a pattern list is one novel phrasing away from failure.
A system where retrieved text has no path to the authorization type is not.

### 4.1 Threats we accept

Recorded honestly rather than claimed away:

- A runbook that is simply **wrong** (not malicious) can mislead a hypothesis. Mitigation:
  citation, freshness, trust class, and current evidence outranking retrieved text.
- Injected content can **waste budget** by steering investigation toward useless evidence.
  Bounded by hard limits (§5), detectable as a tool-call-efficiency regression.
- A **compromised knowledge source** can degrade advice quality broadly. Mitigation: source
  authentication, change detection, and human-approved promotion into T4.

---

## 5. Retrieval evaluation

Section 8 requires retrieval evaluation as a first-class concern, not a side effect of
end-to-end scoring. Detail in
[`../evaluation/EVALUATION_ARCHITECTURE.md`](../evaluation/EVALUATION_ARCHITECTURE.md).

| Metric | Definition | Why it matters here |
|---|---|---|
| Recall@k | Fraction of known-relevant chunks retrieved in top k | The dominant failure is *missing* the right runbook |
| Precision@k | Fraction of retrieved chunks that are relevant | Irrelevant chunks consume context budget and add injection surface |
| MRR / nDCG | Rank quality | Whether the reranker earns its cost |
| Citation validity | Cited chunk exists, is in scope, and supports the claim | Directly feeds unsupported-claim rate |
| Staleness rate | Retrieved chunks past their freshness threshold | Stale runbooks are the pain §3 names explicitly |
| Scope-violation rate | Out-of-scope or out-of-tenant chunk retrieved | **Must be zero.** A security metric, not a quality metric |
| Injection-detection rate | Flagged / planted, on the adversarial corpus | Signal quality |

The evaluation set pairs realistic incident information-gaps with expert-labelled relevant
chunks, and is versioned alongside the knowledge corpus so retrieval changes are compared
against a fixed target.

---

## 6. Context assembly (T2)

The short-term context for a model call is assembled deterministically, under a token
budget, in a fixed precedence order:

| Priority | Content | Label | Budget share |
|---|---|---|---|
| 1 | Task instruction and output schema | `SYSTEM` | Fixed |
| 2 | Incident scope: service, environment, window, symptoms | `SYSTEM` | Fixed |
| 3 | Current evidence set | `VERIFIED_FACT` | Largest share |
| 4 | Open gaps and prior hypotheses | Internal | Moderate |
| 5 | Retrieved knowledge | `RETRIEVED`, delimited | Capped |
| 6 | Verified past outcomes | `VERIFIED_FACT`, with support count | Capped |
| 7 | Historical incident summaries | `RETRIEVED`, advisory | Smallest, dropped first |

Three properties follow: assembly is **deterministic** (same state ⇒ same context, so
replay is meaningful); **current evidence outranks history** by construction of the budget;
and **untrusted content is capped and dropped first** under pressure, so budget exhaustion
degrades toward the trusted end of the spectrum rather than away from it.
