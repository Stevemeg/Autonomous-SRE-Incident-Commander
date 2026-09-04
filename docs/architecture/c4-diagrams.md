# C4 Diagrams

- **Status:** Authored — Architecture Package (V3 §23 E, §16). **Proposed; not implemented.**
- **Master specification references:** Sections 4, 11, 13, 14, 16
- **Context for these views:** [`ARCHITECTURE_OVERVIEW.md`](./ARCHITECTURE_OVERVIEW.md)

Diagrams use Mermaid `flowchart` rather than the C4 plugin syntax, because Mermaid's native
`C4Context` support is still marked experimental and renders inconsistently across GitHub,
IDEs and static site generators. The C4 *levels* are preserved; only the notation is
portable. Structural validity is checked by `scripts/validate_docs.py`.

---

## Level 1 — System context

Who uses the system, and which external systems it depends on.

```mermaid
flowchart TB
    subgraph PEOPLE["People"]
        SRE["On-call SRE (P1)<br/>Reviews evidence, approves actions"]
        PLAT["Platform Engineer (P2)<br/>Defines tool scopes and policy"]
        SEC["Security Architect (P4)<br/>Audits authorization"]
        OWNER["Service Owner (P5)<br/>Consumes timeline and postmortem"]
        OPER["System Operator (P6)<br/>Runs evaluation and replay"]
    end

    SYS["<b>Autonomous SRE Incident Commander</b><br/>Correlates alerts, investigates under bounds,<br/>proposes risk-classified remediation,<br/>executes only after authorization, verifies outcomes"]

    subgraph ALERTING["Alert sources"]
        AM["Prometheus Alertmanager"]
        PD["PagerDuty"]
    end

    subgraph TELEMETRY["Telemetry and control planes (read-only)"]
        PROM["Prometheus<br/>metrics"]
        LOGS["Loki / OpenSearch<br/>logs"]
        OTELB["OpenTelemetry backend<br/>traces"]
        K8S["Kubernetes API<br/>workload state"]
        DEPLOY["Deployment history<br/>releases and config changes"]
        GRAF["Grafana<br/>dashboards"]
    end

    subgraph HUMAN_SYS["Human workflow systems"]
        SLACK["Slack"]
        TEAMS["Microsoft Teams"]
        JIRA["Jira"]
    end

    LLMP["LLM providers<br/>multi-provider abstraction"]

    SRE --> SYS
    PLAT --> SYS
    SEC --> SYS
    OWNER --> SYS
    OPER --> SYS

    AM -->|"alert webhooks"| SYS
    PD -->|"incident events"| SYS

    SYS -->|"read-only queries"| PROM
    SYS -->|"read-only queries"| LOGS
    SYS -->|"read-only queries"| OTELB
    SYS -->|"read state; scoped writes only after approval"| K8S
    SYS -->|"read-only queries"| DEPLOY
    SYS -->|"dashboard links"| GRAF

    SYS -->|"notify; receive approvals"| SLACK
    SYS -->|"notify; receive approvals"| TEAMS
    SYS -->|"create and update issues"| JIRA
    SYS -->|"inference"| LLMP
```

**Boundary note.** Kubernetes is the only external system the product ever writes to in
v1, and only through registered, parameter-validated actions after policy authorization.
Every other telemetry integration is read-only by credential, not by convention (PR-4).

---

## Level 2 — Containers

Deployable and runtime units, and the stores they own.

```mermaid
flowchart TB
    subgraph CLIENT["Client"]
        WEB["<b>Incident Dashboard</b><br/>Next.js + TypeScript<br/>Incidents, evidence, hypotheses,<br/>timeline, approvals"]
    end

    subgraph API_SVC["Container: API service (Python / FastAPI)"]
        ING["Ingestion API<br/>machine-authenticated"]
        INCAPI["Incident API<br/>query and control"]
        APRAPI["Approval API<br/>highest privilege"]
        EVLAPI["Evaluation API"]
        ADMAPI["Admin API<br/>registry, policy, tenants"]
        NORM["Normaliser"]
        CORR["Correlation engine"]
    end

    subgraph ORCH_SVC["Container: Orchestrator worker (Python)"]
        WF["Durable workflow engine<br/>checkpoint · interrupt · resume"]
        AGENTS["Agent nodes<br/>see agent-topology.md"]
        GATE["<b>Policy gate</b><br/>deterministic, non-model"]
        BROKER["<b>Tool broker</b><br/>sole egress point"]
        ADAPT["Adapters<br/>+ deterministic simulators (test only)"]
    end

    subgraph BATCH_SVC["Container: Batch worker (Python)"]
        KING["Knowledge ingestion<br/>chunk · embed · scope"]
        PMT["Postmortem drafting"]
        MEMC["Memory curation<br/>human-gated"]
        EVALR["Evaluation runner"]
    end

    subgraph STORES["Data stores"]
        PG[("<b>PostgreSQL + pgvector</b><br/>incidents · events · evidence<br/>actions · approvals · audit<br/>knowledge chunks · eval runs<br/>workflow checkpoints")]
        OBJ[("Object storage<br/>replay fixtures · large artifacts")]
    end

    subgraph OBS["Observability platform"]
        OTELC["OpenTelemetry collector"]
        PROMS["Prometheus"]
        GRAFS["Grafana"]
        LOKIS["Loki"]
    end

    EXTAL["Alert sources"] --> ING
    WEB --> INCAPI
    WEB --> APRAPI
    WEB --> EVLAPI

    ING --> NORM --> CORR --> WF
    INCAPI --> PG
    APRAPI --> WF
    EVLAPI --> EVALR
    ADMAPI --> PG

    WF --> AGENTS
    AGENTS -->|"typed action proposal"| GATE
    GATE -->|"authorized calls only"| BROKER
    BROKER --> ADAPT
    ADAPT --> EXTSYS["External systems<br/>telemetry · Kubernetes · collaboration"]

    AGENTS --> PG
    WF --> PG
    KING --> PG
    MEMC --> PG
    PMT --> PG
    EVALR --> PG
    EVALR --> OBJ

    API_SVC -.->|"OTLP"| OTELC
    ORCH_SVC -.->|"OTLP"| OTELC
    BATCH_SVC -.->|"OTLP"| OTELC
    OTELC --> PROMS
    OTELC --> LOKIS
    PROMS --> GRAFS
    LOKIS --> GRAFS
    OTELC -->|"execution traces"| EVALR
```

### Container responsibilities and scaling

| Container | Owns | Scales with | Stateless? |
|---|---|---|---|
| API service | Edge authorization, normalisation, correlation | Alert rate | Yes |
| Orchestrator worker | Incident workflows, agent execution, **all authorization and egress** | Concurrent incidents | No — holds workflow leases; state in PostgreSQL |
| Batch worker | Offline knowledge, postmortem, memory, evaluation | Offline job volume | Yes |
| Dashboard | Presentation only; no direct store access | Operator count | Yes |

---

## Level 3 — Components: Orchestrator worker

The security-critical container, expanded. This is where PR-1 ("authority never flows from
the model") is physically enforced.

```mermaid
flowchart TB
    subgraph ORCH["Orchestrator worker"]
        direction TB

        subgraph CONTROL["Control plane"]
            WFE["Workflow engine<br/>checkpointer · interrupt · resume"]
            BUD["<b>Budget supervisor</b><br/>iterations · tool calls<br/>wall-clock · tokens · cost"]
            COORD["Incident Coordinator node"]
        end

        subgraph REASON["Reasoning nodes (LLM-backed)"]
            PLAN["Investigation Planner"]
            COLL["Evidence Collector<br/>+ domain analyser strategies"]
            HYPO["Hypothesis Engine"]
            RPLAN["Remediation Planner"]
            VER["Verifier"]
        end

        subgraph DETERM["Deterministic components (no LLM)"]
            GATE["<b>Policy gate</b>"]
            REG["Tool registry"]
            APRV["Approval service"]
            TL["Timeline projection"]
            NOTIF["Notification service"]
        end

        subgraph EGRESS["Egress plane"]
            BROKER["<b>Tool broker</b><br/>credential resolution · scope enforcement<br/>timeout · retry · idempotency"]
            CRED["Credential resolver<br/>secret manager client"]
            AUD["Audit emitter<br/>append-only"]
        end

        LLMA["LLM provider abstraction<br/>routing · fallback · cost accounting"]
        PROV["Provenance labeller<br/>SYSTEM · VERIFIED_FACT · RETRIEVED · MODEL_CLAIM · HUMAN"]
    end

    WFE --> COORD
    COORD --> PLAN
    PLAN <--> COLL
    PLAN <--> HYPO
    COORD --> RPLAN
    RPLAN -->|"typed ActionProposal"| GATE
    REG --> GATE
    GATE -->|"require approval"| APRV
    APRV -->|"durable interrupt"| WFE
    GATE -->|"authorized"| BROKER
    COLL -->|"read-only tool call"| BROKER
    VER -->|"read-only tool call"| BROKER
    BROKER --> CRED
    BROKER --> AUD
    GATE --> AUD
    BROKER --> PROV
    PROV --> COLL

    REASON --> LLMA
    COORD --> TL
    COORD --> NOTIF
    NOTIF --> BROKER
    BUD -.->|"enforced before every step"| PLAN
    BUD -.-> COLL
    BUD -.-> LLMA
```

### The three properties this view is drawn to make checkable

1. **No reasoning node touches an adapter.** Every arrow leaving the reasoning box
   terminates at the Tool Broker or the Policy Gate. If a future change draws an arrow from
   a reasoning node to an adapter, it is a security regression and should fail review.
2. **The Policy Gate has no LLM edge.** It consumes a typed proposal and the registry, and
   nothing else. Retrieved content and model prose cannot reach it (PR-1, FR-POL-02).
3. **Provenance is applied at the egress boundary**, where the origin of data is actually
   known — not later, by a model asked to self-label.

---

## Level 3 — Components: Knowledge and RAG

Detail and rationale in [`memory-and-rag.md`](./memory-and-rag.md).

```mermaid
flowchart LR
    subgraph INGEST["Ingestion (batch worker)"]
        SRC["Sources<br/>runbooks · service docs<br/>known errors · postmortems"]
        SAN["Sanitiser<br/>strip active content<br/>flag injection patterns"]
        CHUNK["Chunker<br/>structure-aware"]
        META["Metadata binder<br/>tenant · service · environment<br/>version · freshness · ACL"]
        EMB["Embedder"]
    end

    subgraph STORE["Store"]
        DOC[("knowledge_document")]
        CH[("knowledge_chunk<br/>+ pgvector index")]
    end

    subgraph RETRIEVE["Retrieval (query time)"]
        QRY["Query builder<br/>from declared information gap"]
        FILT["<b>Scope + ACL filter</b><br/>applied pre-search"]
        SRCH["Hybrid search<br/>dense + lexical"]
        RANK["Reranker<br/>enabled only if measured to help"]
        CITE["Citation binder"]
    end

    SRC --> SAN --> CHUNK --> META --> EMB --> CH
    META --> DOC
    DOC --> CH

    QRY --> FILT --> SRCH --> RANK --> CITE
    CH --> SRCH
    CITE -->|"labelled RETRIEVED, untrusted"| OUT["Evidence Collector"]
```

**Filter-before-search, not after.** Access control and tenant/service scoping are applied
as query predicates, so out-of-scope content is never embedded into a candidate set and
cannot leak through ranking. Post-filtering would allow a scoring path to be influenced by
content the requester may not see (FR-KNW-03, NFR-SEC-03).

---

## Level 4 — Code

Deliberately not produced. Master specification section 20 requires architecture before
implementation, and a code-level view before any code exists would be speculation. Code
structure will be documented once packages exist, in Phase 3 onward.
