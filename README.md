# Autonomous SRE Incident Commander

An agentic incident-response system for enterprise cloud-native operations: it ingests
alerts and telemetry, correlates them into coherent incidents, performs bounded
investigation across logs, metrics, traces, Kubernetes and deployment history, produces
evidence-backed root-cause hypotheses, plans risk-classified remediation under human
approval, verifies outcomes, and preserves operational memory.

---

> ## Project status: a bounded read-only investigation runs; nothing acts on infrastructure
>
> A simulated incident can now be investigated end to end through a typed, bounded,
> tenant-aware orchestration graph — planning, evidence collection through a capability
> broker, evidence-backed hypotheses, deterministic termination, durable checkpointing and
> a full execution trace. **It is read-only: no capability above risk tier `RO` is
> registered, and none can be until the policy gate exists.**
>
> | | |
> |---|---|
> | **Completed** | Phase 0 bootstrap · Phase 1 requirements · Phase 2 architecture · Phase 3 domain model and persistence · **Phase 4 orchestration kernel** |
> | **In progress** | Nothing — awaiting approval to begin Phase 5 |
> | **Next** | Phase 5 — telemetry ingestion, alert correlation and incident lifecycle |
> | **Remediation, integrations, API, frontend** | None. Deliberately absent, and structurally prevented |
>
> Phase 4 delivered five graph nodes under enforced contracts, a tool broker that is the
> sole egress point, six deterministic simulators, eleven scenarios, budgets checked before
> every step, at-least-once execution with effect-level idempotency, and OpenTelemetry spans
> persisted alongside the work they describe. **433 tests pass** (246 of them with no
> database required).
>
> **Start here:** [`docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md)
> — sections A–Q. Then [`docs/architecture/orchestration-kernel.md`](docs/architecture/orchestration-kernel.md)
> for what the kernel does, what it deliberately does not, and what remains unmeasured.
>
> Section 20 of the specification forbids fake integrations, fabricated metrics and
> placeholder production logic. This README states that a capability exists only once it
> exists and has been validated. **No performance has been measured, and no claim is made
> about the quality of the system's reasoning** — the harness that could measure it is
> Phase 11, and the only model provider wired today is a deterministic one.

---

## What this is intended to be

A commercial-grade incident commander for SRE and platform teams — explicitly **not** a
chatbot, an incident summarizer, a generic RAG demo, a single-agent toy, or an LLM API
wrapper.

The problems it targets are the ones that make on-call expensive: alert overload,
fragmented telemetry, slow triage, difficult root-cause analysis, stale runbooks,
repetitive investigation, unsafe remediation, and operational knowledge that leaves when
people do.

### Intended capabilities

| Capability | Status |
|---|---|
| Intelligent alert correlation into coherent incidents | Not started |
| Autonomous investigation across logs, metrics, traces, Kubernetes, deployments and configuration changes | **Simulator-backed** — orchestration, authorization and the evidence path are built; no real adapter exists |
| Ranked RCA hypotheses with evidence, confidence and counter-evidence | **Structure built** — citation integrity and the confidence ceiling are enforced in code; reasoning quality is unmeasured |
| Operational RAG over runbooks, service docs, known errors and postmortems | Not started — a simulator-backed `knowledge.search` capability exists; there is no retrieval pipeline |
| Evidence-backed incident timeline reconstruction | **Built** — a deterministic projection over the event log |
| Risk-classified remediation planning | Not started |
| Human approval before risky or irreversible actions | Not started |
| Controlled remediation using permission-scoped tools only | Not started |
| Independent post-remediation verification | Not started |
| Slack/Teams collaboration and PagerDuty/Jira workflows | Not started |
| Historical incident replay for testing and evaluation | Not started |
| Governed operational memory and learning | Not started |

Where a row says *built*, it means built against deterministic simulators and covered by
tests — not exercised against production telemetry, which is Phase 10.

### Design commitments

These are the properties the system is being designed around, and the reason the
architecture work comes before the code:

- **Bounded autonomy.** Every run terminates through success, uncertainty, timeout,
  failure or human escalation. Hard limits on iterations, tool calls, wall-clock time,
  token budget and cost are mandatory — there are no unbounded loops.
- **Recommendation is separated from execution.** Ambiguous and high-risk actions stop for
  human approval. Arbitrary model-generated production commands are never executed.
- **Capability-scoped tools.** The model never receives unrestricted infrastructure
  access; it acts only through a registry of tools that declare permission scope, risk
  tier, timeout, idempotency behaviour and audit requirements.
- **Untrusted retrieved content.** Logs, runbooks and tickets are treated as potentially
  hostile input. Retrieved text can never override system policy or tool authorization.
- **Evidence-grounded reasoning.** Verified facts, hypotheses and model-generated claims
  are distinguished explicitly. History informs current investigation but never overrides
  current evidence.
- **Evaluation as a subsystem, not a test script.** Golden scenarios, replay cases,
  regression suites and measured metrics — never invented improvement percentages.
- **Durable workflows.** Incidents are long-running workflows with checkpointing,
  resume-after-failure, idempotent actions, and human-approval waiting states.

## Specification

The authoritative specification is the Word document, preserved unmodified:

- **[`docs/spec/Autonomous SRE Incident Commander - Master Project Prompt V3.docx`](docs/spec/Autonomous%20SRE%20Incident%20Commander%20-%20Master%20Project%20Prompt%20V3.docx)** — authoritative source
- **[`docs/spec/MASTER_PROJECT_PROMPT_V3.md`](docs/spec/MASTER_PROJECT_PROMPT_V3.md)** — verified Markdown transcription, for diffing and review

The transcription is checked in both directions — nothing dropped, nothing invented — by:

```bash
python scripts/verify_spec_transcription.py
```

If the two ever disagree, the `.docx` wins and the Markdown is the defect.

## Repository layout

```
.
├── docs/
│   ├── spec/            Authoritative specification + verified transcription
│   ├── prd/             PRD, SRS (138 requirements), personas, journeys
│   ├── architecture/    A–Q package spine, overview, C4, agent topology,
│   │                    tool registry, safety policy, memory/RAG,
│   │                    observability, data model/API, failure & recovery,
│   │                    requirements traceability, CI/CD and infrastructure
│   ├── adr/             17 Architecture Decision Records        (6 Accepted)
│   ├── security/        Threat model + repository checklist (active)
│   └── evaluation/      Evaluation harness architecture
├── src/asic/
│   ├── domain/          Vocabularies, state machine, events, idempotency,
│   │                    budgets, untrusted content      (no I/O, no database)
│   ├── db/              SQLAlchemy models, tenant session context, projections
│   ├── contracts/       Canonical graph state and enforced node contracts
│   ├── tools/           Registry, capability resolution, the tool broker
│   ├── simulators/      Deterministic scenarios     (explicit test infrastructure)
│   ├── llm/             Model port, versioned prompts, deterministic provider
│   ├── observability/   Tracing, metrics, audit, redaction
│   └── orchestration/   Graph, nodes, kernel, checkpointing, termination
├── migrations/          Alembic: schema, RLS, checkpoints, catalogue seed
├── tests/
│   ├── domain/          Pure unit tests, no database required
│   ├── contracts/       Contract enforcement
│   ├── db/              Isolation, RLS, constraints, event model
│   ├── tools/           Broker pipeline, refusals, idempotency, audit
│   ├── orchestration/   Kernel, checkpoint/resume, planner bounds, tracing
│   ├── security/        Prompt injection and escalation attempts
│   └── e2e/             Every scenario against its declared expectation
├── scripts/             Repository tooling (spec verification, hygiene, doc validation)
└── configs/             Configuration                            (intentionally empty)
```

`configs/` is empty by design; runtime configuration arrives with the services that need
it.

Start with **[`docs/README.md`](docs/README.md)** for the documentation index and reading
order.

## Intended technology baseline

Proposed by the specification and **not yet committed to** — each major choice requires an
ADR with alternatives and trade-offs before adoption (see
[`docs/adr/README.md`](docs/adr/README.md)):

Python · FastAPI · LangGraph or a justified equivalent · PostgreSQL + pgvector · Redis
where justified · Next.js + TypeScript · multi-provider LLM abstraction · OpenTelemetry ·
Prometheus · Grafana · Loki · Docker · Kubernetes · Terraform · GitHub Actions · pytest

All eight technologies the specification flags as "evaluate rather than blindly add" have
been evaluated in ADRs. Three are now `Accepted` because Phase 4 implemented them; the rest
stay open until the phase that would use them:

| Technology | Recommendation | ADR |
|---|---|---|
| Temporal | **Accepted, not adopted**: LangGraph owns the graph, durability is our own code | [0002](docs/adr/0002-orchestration-langgraph-vs-temporal.md), [0015](docs/adr/0015-domain-owned-checkpointing.md) |
| MCP | **Accepted, not adopted** as transport; the `ToolProvider` seam exists and no MCP provider uses it | [0003](docs/adr/0003-tool-boundary-native-adapters-mcp-ready.md) |
| Dedicated vector database | Not adopted; pgvector in the primary store | [0004](docs/adr/0004-postgresql-pgvector-primary-datastore.md) |
| LiteLLM | **Accepted, not adopted**; the thin internal port is built, with a deterministic adapter | [0005](docs/adr/0005-llm-provider-abstraction.md), [0016](docs/adr/0016-deterministic-model-provider.md) |
| Redis | Deferred, with measured adoption triggers | [0006](docs/adr/0006-redis-necessity.md) |
| Kafka / NATS | Deferred, with measured adoption triggers | [0007](docs/adr/0007-eventing-message-broker-necessity.md) |
| LangSmith / Arize Phoenix | Not adopted; OpenTelemetry-native, Phoenix in reserve | [0010](docs/adr/0010-observability-and-evaluation-tooling.md) |
| OpenSearch / Elasticsearch | Deferred to Phase 10 as a log-backend choice | [ADR index](docs/adr/README.md) |

Integrations are built against adapter interfaces with deterministic local simulators and
replay fixtures. The project will not depend on live production infrastructure.

## Roadmap

Taken from section 19 of the master specification. Phases 1 and 2 are documentation
deliverables; **no product capability is implemented.** Four capabilities are pulled
earlier than a literal reading of section 19, each justified in the architecture package
section O.

| Phase | Scope | Status |
|---:|---|---|
| 0 | Repository bootstrap and specification control | **Complete** |
| 1 | Product requirements, personas, business metrics and competitive positioning | **Complete** |
| 2 | Architecture, threat model, technology decisions and ADRs | **Complete** |
| 3 | Domain model, PostgreSQL schema, tenancy and event model | **Complete** |
| 4 | Agent state machine, planner, tool registry and orchestration | **Complete** |
| 5 | Telemetry ingestion, alert correlation and incident lifecycle | Not started |
| 6 | RAG, operational knowledge and governed memory | Not started |
| 7 | Investigation agents, hypothesis management and bounded reflection | Not started |
| 8 | Remediation planning, policy gates, human approval and verification | Not started |
| 9 | Backend APIs and frontend incident-command dashboard | Not started |
| 10 | External integrations | Not started |
| 11 | Evaluation harness, replay and regression framework | Not started |
| 12 | OpenTelemetry, metrics, logs, dashboards and SLOs | Not started |
| 13 | Security, RBAC, tenant isolation and supply-chain controls | Not started |
| 14 | CI/CD, Docker, Kubernetes and Terraform | Not started |
| 15 | Load, resilience, chaos, security and E2E hardening | Not started |
| 16 | Documentation, demo scenarios, portfolio evidence and production-readiness review | Not started |

Phase 0 is not part of the specification's roadmap; it is the repository groundwork that
precedes it.

## Development

There is no application to run yet. The repository tooling requires only Python 3.11+ with
no third-party dependencies:

```bash
# Repository tooling. Standard library only, except the phase-boundary check, which imports
# the capability catalogue so that it validates what the code will actually load.
python scripts/verify_spec_transcription.py   # .md still matches the authoritative .docx
python scripts/check_repo_hygiene.py          # secrets, credentials, generated files
python scripts/validate_docs.py               # links, Mermaid, traceability, phase scope
```

All three must pass before any commit.

### Running a simulated investigation

```bash
export ASIC_MIGRATION_DATABASE_URL=postgresql+psycopg2://asic_owner:<password>@localhost:55432/asic
export ASIC_DATABASE_URL=postgresql+psycopg2://<app_login>:<password>@localhost:55432/asic
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m asic.orchestration.service --scenario SC-0001-checkout-latency-after-deploy
```

Seeding a demonstration tenant uses the administrative URL; the investigation itself runs as
the application role under row-level security, exactly as it would in production. Every
source is a deterministic simulator, and the run refuses to start if the deployment is
marked production.

### Running the test suite

The pure-domain tests need nothing. The database tests need PostgreSQL with `pgvector`:

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"

# Tests that need no database
.venv/Scripts/python -m pytest tests/domain tests/contracts

# Full suite: start PostgreSQL, migrate, then run
docker run -d --name asic-pg -e POSTGRES_PASSWORD=<choose> -e POSTGRES_USER=asic_owner     -e POSTGRES_DB=asic -p 55432:5432 pgvector/pgvector:pg16
export ASIC_MIGRATION_DATABASE_URL=postgresql+psycopg2://asic_owner:<choose>@localhost:55432/asic
.venv/Scripts/python -m alembic upgrade head
export ASIC_TEST_DATABASE_URL=$ASIC_MIGRATION_DATABASE_URL
.venv/Scripts/python -m pytest
```

Database-backed tests skip cleanly when `ASIC_TEST_DATABASE_URL` is unset, so the domain
suite runs anywhere. Connection strings come from the environment and never from a
committed file. The full pre-commit and pre-push procedure is
[`docs/security/REPOSITORY_SECURITY_CHECKLIST.md`](docs/security/REPOSITORY_SECURITY_CHECKLIST.md).

Build, test and deployment instructions will be added when there is something to build.

## Contributing

This is a single-author project. See the repository security checklist above for the
commit and push procedure.

## License

Not yet selected.
