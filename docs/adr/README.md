# Architecture Decision Records

> **Status: no decisions recorded yet.** The index below lists *candidate* decisions
> derived from the master specification, not decisions that have been made. Phase 2
> (architecture, threat model, technology decisions and ADRs) will author them.

## Why ADRs are mandatory here

The master specification requires that **every major choice be justified with
alternatives, trade-offs and rationale** (section 13), and repeatedly forbids adopting
technology for its keyword value:

- *"Compare native adapters vs MCP in an ADR; do not add MCP for résumé keywords."* (section 7)
- *"Compare LangGraph persistence with Temporal or another workflow engine. Introduce a dedicated workflow engine only if requirements justify it."* (section 12)
- *"Evaluate rather than blindly add: Temporal, LiteLLM, MCP, LangSmith, Arize Phoenix, Kafka/NATS, OpenSearch/Elasticsearch and dedicated vector databases."* (section 13)
- *"Never add technology solely for résumé keywords."* (section 20)

An ADR is the artifact that makes a decision defensible under interview pressure
(section 24). A choice with no ADR is an undefended choice.

## Process

1. **One decision per record.** If a record needs the word "and" in its title, it is
   probably two decisions.
2. **Write it before building**, not as retroactive justification.
3. **Alternatives are not optional.** A record that lists no genuinely considered
   alternative is a decision that was not actually made.
4. **State the reversal cost.** Say what it would take to undo the decision, and name the
   observable trigger that should cause us to revisit it.
5. **Records are immutable once Accepted.** To change a decision, write a new ADR and mark
   the old one `Superseded by ADR-NNNN`. Never edit history in place.

## Naming and status

Files are named `NNNN-short-kebab-case-title.md`, numbered sequentially from `0001`.

| Status | Meaning |
|---|---|
| `Proposed` | Written, under review, not yet binding |
| `Accepted` | Binding; implementation must conform |
| `Superseded` | Replaced by a later ADR, which must be named |
| `Deprecated` | No longer applies and has no replacement |
| `Rejected` | Considered and explicitly declined; kept because the reasoning is valuable |

Use [`0000-adr-template.md`](./0000-adr-template.md) as the starting point.

## Index

_No ADRs have been accepted yet._

| ADR | Title | Status | Date |
|---|---|---|---|
| — | — | — | — |

## Candidate decisions for Phase 2

These are the decisions the master specification obliges us to make explicitly. They are
listed here so the scope of Phase 2 is visible; **none has been decided.**

| # | Candidate decision | Spec reference |
|---|---|---|
| 1 | Agent/node topology: which of the 19 candidate nodes are distinct, and which are merged | 4 |
| 2 | Orchestration framework: LangGraph or a justified equivalent | 4, 13 |
| 3 | Workflow durability: LangGraph persistence vs Temporal vs another engine | 12 |
| 4 | Tool boundary: native adapters vs MCP, and the MCP-ready adapter seam | 7 |
| 5 | Primary datastore and vector strategy: PostgreSQL + pgvector vs a dedicated vector database | 8, 13 |
| 6 | Whether Redis is justified, and for what | 13 |
| 7 | Multi-provider LLM abstraction: direct SDKs vs LiteLLM or equivalent | 13 |
| 8 | Retrieval strategy: dense vs hybrid, and whether reranking is justified | 8 |
| 9 | Tenancy and isolation model | 15 |
| 10 | Telemetry backend: Loki vs Elasticsearch/OpenSearch | 14 |
| 11 | Eventing: direct invocation vs Kafka/NATS | 13 |
| 12 | Tracing and evaluation tooling: raw OpenTelemetry vs LangSmith vs Arize Phoenix | 11, 13 |
| 13 | Integration simulator design and replay-fixture format | 14 |
| 14 | Evaluation judge model strategy and calibration approach | 9 |
| 15 | Frontend scope and framework commitment | 13 |
