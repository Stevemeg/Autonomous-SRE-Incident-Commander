# ADR review (Phase 16 closeout)

Every ADR was re-read against the code at the closeout. A decision that still holds keeps its
status; a decision the code implemented differently is **amended here** rather than silently
left stale. ADRs are records: their bodies are not rewritten, their status lines point here.

| ADR | Verdict | Notes |
|---|---|---|
| 0001 Agent topology | **Accepted, amended** | Twelve nodes and two derived services remain the structure. Implemented differently: three nodes call the model — the **Investigation Planner**, **Hypothesis Engine** and **Remediation Planner** (which selects from a pre-resolved executor menu and authors only 4 of the 12 proposal fields; tier, scope, preconditions, rollback, approval and timeout come from the registry). The Evidence Collector, Alert Correlator (no model-assisted ranking) and Verifier are deterministic — the verifier deliberately so (SI-12). The **Postmortem Author** (G11) is built in the Phase 16 closure as a worker-run post-incident stage rather than a graph node (the fourth model caller; facts from records, prose validated). The **Memory Curator** (G12) is not built (GAP-31); governed promotion itself exists. As built: 10 LangGraph nodes implement G2-G10 ([agent topology §0](../architecture/agent-topology.md)). The six analyser strategies are deterministic |
| 0002 LangGraph vs Temporal | Accepted, holds | Durability in domain code (ADR-0015); crash matrix confirms |
| 0003 Native adapters, MCP-ready | Accepted, holds | No MCP provider exists; the seam does |
| 0004 PostgreSQL + pgvector | Accepted, holds | Single datastore; RLS, vectors, checkpoints, audit |
| 0005 Thin LLM port | Accepted, holds | Budget reservation before every call; deterministic adapter only |
| 0006 Redis | **Deferred, revisited** | Phase 15 measured ≈ 12 alerts/s per process and the Phase 16 final-image run ≈ 21 successful alerts/s — both below the ~50/s trigger. Ingestion is synchronous (no queue to poll) and the limiter is in memory (no database contention), so neither trigger condition can have fired; where the time goes inside ingestion is not yet profiled (GAP-23). Amended: rate limiting was implemented **in process memory**, not as PostgreSQL token-bucket rows as the ADR assumed; a shared limiter belongs at the gateway (GAP-13) |
| 0007 Message broker | **Deferred, revisited** | Below the ~200 alerts/s trigger; bursts recovered without growing backlog; no second consumer. Trigger not fired |
| 0008 RAG retrieval | Accepted, holds | Hybrid shipped; no reranker because no measurement justified one |
| 0009 Memory tiers | Accepted, holds | Human-gated promotion enforced by the database |
| 0010 Observability tooling | **Accepted, amended** | OpenTelemetry-native, traces persisted in PostgreSQL, Prometheus/Grafana/Loki configuration built (Phase 12). Implemented differently: model calls are attributes of the calling span and do **not** follow the OTel GenAI semantic conventions yet, so adopting Phoenix would need span mapping, not only collector configuration |
| 0011 AuthN/AuthZ/tenancy | **Accepted, amended** | OIDC/JWKS, short-lived tokens (now with a bounded lifetime), RBAC per tenant/environment/tier, shared schema with RLS — implemented and consolidated in ADR-0030. Implemented differently: outbound credentials are per-connector references resolved per call from the secret store, not minted per action; read and write credentials are separate references |
| 0012–0020, 0022–0029 | Accepted, hold | Re-read; the code matches. 0021 remains reserved and unwritten |
| 0030 Security boundary consolidation | Accepted, holds | Phase 15 campaigns found and fixed defects inside it without changing it |
| 0031 Production delivery boundary | Accepted, amended by 0032 and the Phase 16 closure | "No retention Job" narrowed: a suspended dry-run retention CronJob now ships for the idempotency cache. "No worker until a real durable worker entry point exists": that entry point now exists (`python -m asic.worker`), so a worker Deployment ships on the same backend image with its own service account and network policy; its live profile refuses to start until a live model exists (GAP-08). Production database TLS is now an enforced part of the delivery contract (`sslmode=verify-full`) |
| 0032 Bounded retention executor | Accepted (Phase 15) | New |

No ADR was found whose decision the code contradicts without a recorded reason after this review.
