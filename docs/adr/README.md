# Architecture Decision Records

> **Twenty-three records. Eighteen are Accepted.**
>
> ADRs 0001-0011 were written during the Architecture Package. Later implementation phases
> accepted the decisions whose evidence now exists; the table below is authoritative for
> current status. ADRs 0012-0014 were raised during Phase 3, 0015-0018 during Phase 4 and
> its migration-history correction, 0019 during Phase 5, 0022 during Phase 7, and 0023
> during Phase 8, 0024 during Phase 9, and 0025 during the Phase 6–9 audit correction. ADR 0020 (the `provider_kind` label) was written in Phase 10; 0021 remains reserved by a
> forward reference left in the Phase 6 correction (a retrieval-quality bound) and is
> not yet written; Phase 7 and Phase 8 number their own records 0022 and 0023 rather than
> collide with them.

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
6. **Close calls are recorded as close.** A genuinely marginal decision written up as
   obvious will not survive scrutiny — see ADR-0002.

## Naming and status

Files are named `NNNN-short-kebab-case-title.md`, numbered sequentially from `0001`.

| Status | Meaning |
|---|---|
| `Proposed` | Written and reasoned, under review, **not yet binding** |
| `Needs validation` | Direction chosen, but confirmation depends on a measurement that has not been taken |
| `Deferred` | Deliberately not adopting now; the analysis and the adoption triggers are recorded |
| `Accepted` | Binding; implementation must conform |
| `Superseded` | Replaced by a later ADR, which must be named |
| `Deprecated` | No longer applies and has no replacement |
| `Rejected` | Considered and explicitly declined; kept because the reasoning is valuable |

`Needs validation` and `Deferred` extend the original vocabulary. They exist because
section 9 forbids reporting unmeasured results as fact: a decision whose justification
depends on a measurement we have not taken must not be recorded as `Accepted`.

Use [`0000-adr-template.md`](./0000-adr-template.md) as the starting point.

## Index

Phase 5 implementation decision: [ADR-0019](./0019-transactional-signal-ingestion.md),
transactional ingestion and durable investigation requests. Accepted after the Phase 5
contention, trust-boundary and correlation corrections; it adds no infrastructure and does
not replace an accepted ADR.

| ADR | Title | Status | Spec ref | Date |
|---|---|---|---|---|
| [0001](./0001-agent-topology-consolidation.md) | Agent topology — 19 responsibilities into 12 nodes | `Proposed` | 4, 5, 6, 15 | 2026-09-04 |
| [0002](./0002-orchestration-langgraph-vs-temporal.md) | Orchestration — LangGraph checkpointing vs Temporal | **`Accepted`** | 4, 12, 13 | 2026-09-04 |
| [0003](./0003-tool-boundary-native-adapters-mcp-ready.md) | Tool boundary — native adapters behind an MCP-ready seam | **`Accepted`** | 7, 13, 14, 15, 20 | 2026-09-04 |
| [0004](./0004-postgresql-pgvector-primary-datastore.md) | PostgreSQL + pgvector as the single primary datastore | **`Accepted`** | 8, 13, 15 | 2026-09-04 |
| [0005](./0005-llm-provider-abstraction.md) | LLM provider abstraction — thin internal interface, not LiteLLM | **`Accepted`** | 9, 10, 11, 13 | 2026-09-04 |
| [0006](./0006-redis-necessity.md) | Redis — not adopted in v1 | `Deferred` | 13 | 2026-09-04 |
| [0007](./0007-eventing-message-broker-necessity.md) | Message broker (Kafka/NATS) — not adopted in v1 | `Deferred` | 12, 13 | 2026-09-04 |
| [0008](./0008-rag-retrieval-strategy.md) | RAG retrieval — hybrid default, reranking only if measured | **`Accepted`** (hybrid v1; reranking still unbuilt) | 8 | 2026-09-04 |
| [0009](./0009-memory-architecture-tiers.md) | Memory architecture — five tiers, human-gated promotion | **`Accepted`** | 8, 10 | 2026-09-04 |
| [0010](./0010-observability-and-evaluation-tooling.md) | Observability tooling — OTel-native, not LangSmith or Phoenix | `Proposed` | 9, 10, 11, 13 | 2026-09-04 |
| [0011](./0011-authentication-authorization-tenancy.md) | Authentication, authorization and tenancy model | `Proposed` | 15 | 2026-09-04 |
| [0012](./0012-native-postgresql-enum-types.md) | Native PostgreSQL ENUM types for closed vocabularies | **`Accepted`** | 12, 15, 20 | 2026-09-04 |
| [0013](./0013-composite-tenant-foreign-keys.md) | Composite tenant-scoped foreign keys | **`Accepted`** | 15 | 2026-09-04 |
| [0014](./0014-materialised-incident-status.md) | Materialised incident status, reconciled against the event log | **`Accepted`** | 12 | 2026-09-04 |
| [0015](./0015-domain-owned-checkpointing.md) | Domain-owned checkpointing, not the LangGraph checkpointer | **`Accepted`** | 12 | 2026-09-07 |
| [0016](./0016-deterministic-model-provider.md) | A deterministic model provider for Phase 4; no live provider yet | **`Accepted`** | 9, 10, 11, 14, 20 | 2026-09-07 |
| [0017](./0017-read-only-capability-ceiling.md) | A read-only capability ceiling enforced in three independent places | **`Accepted`** | 6, 7, 15 | 2026-09-07 |
| [0018](./0018-migrations-are-historical-contracts.md) | Migrations are historical contracts and never read live application code | **`Accepted`** | 12, 15, 20 | 2026-09-09 |
| [0019](./0019-transactional-signal-ingestion.md) | Transactional signal ingestion and durable investigation requests | **`Accepted`** | 12, 14, 15, 17 | 2026-09-11 |
| [0020](./0020-provider-kind-label-and-execution-mode-composition.md) | `provider_kind` is a catalogue label; execution mode decides providers | **`Accepted`** | 7, 14, 20 | 2026-09-16 |
| [0022](./0022-bounded-reflection-without-a-new-node.md) | Bounded reflection extends the hypothesis engine's output, not a new graph node | **`Accepted`** | 3, 4, 15 | 2026-09-13 |
| [0023](./0023-bounded-remediation-as-a-separate-graph.md) | Bounded remediation runs as a separate graph/kernel, entered only from a human-reopened investigation | **`Accepted`** | 3, 6, 17 | 2026-09-14 |
| [0024](./0024-phase9-api-and-dashboard.md) | Authenticated API edge and server-rendered incident-command dashboard | **`Accepted`** | 15, 16 | 2026-09-14 |
| [0025](./0025-freeze-remediation-authority-before-effects.md) | Freeze remediation authority before operational effects | **`Accepted`** | 5, 6, 12, 15 | 2026-09-15 |
| [0026](./0026-external-integrations-behind-the-broker.md) | External integrations are native adapters behind the broker, with server-side connector authority | **`Accepted`** | 6, 7, 11, 14, 15, 20 | 2026-09-16 |
| [0027](./0027-loki-as-the-log-backend.md) | Loki is the log backend adapter; Elasticsearch/OpenSearch is not built | **`Accepted`** | 13, 14 | 2026-09-16 |

## Priority order for acceptance

ADRs must be accepted in dependency order. The first four constrain the schema and the node
contract, so they block Phase 3 onward; the rest can be accepted as their evidence arrives.

| Priority | ADR | Blocks | Why this order |
|---:|---|---|---|
| 1 | 0011 Tenancy and authorization | Phase 3 (schema) | `tenant_id` and RLS touch every table; least reversible decision in the project |
| 2 | 0001 Agent topology | Phase 4 | Determines what is built and how permissions are separated. **Four of twelve nodes implemented in Phase 4.** |
| 3 | 0004 Datastore | Phase 3 | Schema, indexing and retrieval all depend on it |
| 4 | 0002 Orchestration | Phase 4 | **Accepted.** Durability implemented in our own code per its own crux clause; see ADR-0015 |
| 5 | 0003 Tool boundary | Phase 4 | **Accepted.** Registry, `ToolProvider` seam and broker implemented; no MCP provider exists |
| 6 | 0009 Memory tiers | Phase 6 | **Accepted.** T4/T5 write governance implemented; the promotion trigger (G12) remains deferred |
| 7 | 0005 LLM abstraction | Phase 4 | **Accepted.** The port exists; the only adapter is deterministic (ADR-0016) |
| 8 | 0010 Observability tooling | Phase 4 | OpenTelemetry spans and metrics emitted; no exporter configured until Phase 12 |
| 9 | 0008 RAG retrieval | Phase 6, revisit Phase 11 | **Accepted.** Hybrid v1 implemented and measured; reranking A/B still not run |
| 10 | 0006 Redis | Revisit Phase 15 | `Deferred` — trigger is a load measurement |
| 11 | 0007 Message broker | Revisit Phase 15 | `Deferred` — trigger is a load measurement |

## Decisions raised by Phase 3

Recorded here because the Phase 3 brief requires that architectural decisions discovered
during implementation become ADRs rather than being made silently:

| ADR | Discovered because | Evidence |
|---|---|---|
| [0012](./0012-native-postgresql-enum-types.md) | Two safety check constraints (`risk_tier <> 'r3'`, external-event provenance) are only meaningful if the column cannot hold an unknown value | `TestEnumTypeParity`; migration round-trip verified |
| [0013](./0013-composite-tenant-foreign-keys.md) | RLS controls what a session *sees*, not what a row *references*; a cross-tenant reference passes RLS | `TestCompositeForeignKeys`; `test_references_between_tenant_scoped_tables_carry_the_tenant` |
| [0014](./0014-materialised-incident-status.md) | "Status is derived from the log" needed a physical answer that did not make the dashboard's main query unaffordable | `test_status_divergence_from_the_log_is_detected` |

## Decisions raised by Phase 4

| ADR | Discovered because | Evidence |
|---|---|---|
| [0015](./0015-domain-owned-checkpointing.md) | ADR-0002 required durability to be ours; a framework checkpointer cannot commit in the node's own transaction, nor reconcile against durable rows | `TestCheckpointing`, `TestResume` |
| [0016](./0016-deterministic-model-provider.md) | Two nodes are model-backed, but nothing in this phase can evaluate a model's output — so a live provider would buy an unreadable signal at the cost of determinism | `test_planner.py`, `test_hypothesis.py`, `test_scenarios.py` |
| [0017](./0017-read-only-capability-ceiling.md) | The remediation authorization path is Phase 8; a registered write tool before it would be a capability authorized by nothing | `TestRiskCeiling`, `TestRefusals`, negative-tested boundary validator |
| [0018](./0018-migrations-are-historical-contracts.md) | A migration deriving its table list from the live model registry silently changed what an earlier migration did, and broke fresh installs | `TestPinnedListsMatchHistory`, `TestMigrationsAreSelfContained`, `TestUpgradePaths` |

## Decisions raised by Phase 7

| ADR | Discovered because | Evidence |
|---|---|---|
| [0022](./0022-bounded-reflection-without-a-new-node.md) | Section 6.2 of the orchestration kernel doc named bounded reflection as deliberately deferred to Phase 7; building it required deciding whether it needed a thirteenth graph node or could extend the existing "model proposes, deterministic guard decides" pattern | `test_reflection.py`, `test_termination.py::TestReflectionDrivenTermination`, `test_hypothesis.py::TestBoundedReflection` |

## Decisions raised by Phase 8

| ADR | Discovered because | Evidence |
|---|---|---|
| [0023](./0023-bounded-remediation-as-a-separate-graph.md) | The already-accepted Phase 3 state machine has no `escalated -> awaiting_approval`/`remediating` edge, only a human-only `escalated -> investigating` one; building remediation required deciding whether it extends investigation's graph or is a separate one entered through that existing transition | `tests/orchestration/test_remediation.py`, `tests/domain/test_policy.py`, `TestRiskCeiling` in `test_broker.py` |

## Decisions raised by Phase 9

| ADR | Discovered because | Evidence |
|---|---|---|
| [0024](./0024-phase9-api-and-dashboard.md) | The first HTTP/dashboard surface required an explicit decision to keep tenant authority in verified identity and current database grants, and to make mutation replay durable | `tests/api/test_auth.py`, `tests/api/test_rate_limit.py`, migration `0012_phase9_api_rbac` |

## Decisions raised by the Phase 6–9 audit correction

| ADR | Discovered because | Evidence |
|---|---|---|
| [0025](./0025-freeze-remediation-authority-before-effects.md) | Target reconstruction, cached write grants, model-selected thresholds and replay-before-authorization each allowed stale or untrusted data to cross an authority boundary | migration `0013_audit_corrections`; remediation, API, budget and lifecycle mutation tests |

## Decisions raised by Phase 10

| ADR | Discovered because | Evidence |
|---|---|---|
| [0020](./0020-provider-kind-label-and-execution-mode-composition.md) | Native adapters arrived for tools whose historical seed label says `simulator`; runtime provider choice needed an explicit, unmixable composition | `TestComposition`, `TestNoSimulatedFallback` |
| [0026](./0026-external-integrations-behind-the-broker.md) | Outbound calls needed tenant connector authority, secret handling, and an honest classification for records that cannot be rolled back | `tests/integrations/`, migration `0016_external_integrations` |
| [0027](./0027-loki-as-the-log-backend.md) | Candidate decision C1 (log backend) had to be settled to build `logs.query` | `tests/integrations/test_adapters.py::TestLoki` |

## Candidate decisions still to be written

Identified during the Architecture Package but not yet ADRs, because the evidence to decide
them does not exist. Recorded so the scope is visible.

| # | Candidate decision | Spec ref | Blocked until |
|---|---|---|---|
| C1 | ~~Telemetry log backend: Loki vs Elasticsearch/OpenSearch~~ | 14 | **Resolved by ADR-0027** |
| C2 | Integration simulator design and replay-fixture format | 14 | Phase 4 — needs the first adapter |
| C3 | Evaluation judge model strategy and calibration approach | 9 | Phase 11 — needs a labelled corpus |
| C4 | Frontend scope and framework commitment beyond Next.js baseline | 13 | Deferred beyond Phase 9; ADR-0024 fixes the Phase 9 baseline |
| C5 | Kubernetes deployment topology and Terraform module boundaries | 13, 16 | Phase 14 |
| C6 | Embedding model selection and re-index strategy | 8 | Phase 6 — needs the retrieval evaluation set |
| C7 | Weighted/graph alert correlation beyond deterministic v2 | 3, 4 | Later — requires an alert corpus and evaluation evidence |
| C8 | Data-retention automation and partition management | 15 | Phase 13 |
