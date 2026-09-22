# Autonomous SRE Incident Commander

An agentic incident-response system for enterprise cloud-native operations: it ingests
alerts and telemetry, correlates them into coherent incidents, performs bounded
investigation across logs, metrics, traces, Kubernetes and deployment history, produces
evidence-backed root-cause hypotheses, plans risk-classified remediation under human
approval, verifies outcomes, and preserves operational memory.

---

> ## Project status: governed incident command surfaces are available
>
> A simulated incident can be investigated end to end through a typed, bounded,
> tenant-aware orchestration graph — planning, evidence collection through a capability
> broker (including read-only retrieval over an operational knowledge base),
> evidence-backed hypotheses, **bounded reflection over those hypotheses (continue on a
> different gap, seek counter-evidence, revise a hypothesis by superseding it, or propose a
> terminal outcome — every proposal validated by a deterministic guard, never trusted as
> stated)**, deterministic termination, durable checkpointing and a full execution trace.
> Phase 8 adds a separate remediation graph with typed simulator-backed R1/R2 actions,
> deterministic policy, an immutable incident/hypothesis/service target, exact-effect human
> approval, current-grant broker-only execution, durable effect claims and independent
> baseline/post-action verification. Investigation remains restricted to its read-only
> registry. R3 actions remain structurally unavailable.
>
> | | |
> |---|---|
> | **Completed** | Phase 0 bootstrap · Phase 1 requirements · Phase 2 architecture · Phase 3 persistence · Phase 4 orchestration · Phase 5 telemetry ingestion and correlation · Phase 6 operational knowledge, RAG and governed memory · Phase 7 bounded investigation · Phase 8 bounded remediation · Phase 9 authenticated API, RBAC and dashboard · Phase 10 external integrations · Phase 11 evaluation, replay and regression harness · Phase 12 observability and SLO instrumentation · **Phase 13 security and governance** |
> | **In progress** | Phase 14 delivery milestone; implementation and validation, pending independent review |
> | **Next** | Independent Phase 14 review; Phase 15 has not begun |
> | **Observability** | OpenTelemetry traces sharing the persisted trace id, catalogued bounded-label metrics counted from committed records, redacted JSON logs, `/livez` and `/readyz`, seven Grafana dashboards, SLO burn-rate alerts with runbooks. Objectives are **INITIAL ENGINEERING TARGETs**; configurations are validated with `promtool` and `otelcol-contrib`, **not deployed** ([SLOs](docs/observability/SLOS.md)) |
> | **Evaluation** | Versioned 18-scenario golden corpus, strict replay at the provider seams, regression comparison and an executable gate. Results are **simulator/replay runs with a scripted model provider only** — they validate the pipeline and safety invariants, not reasoning quality; LLM judges are not measured ([evaluation harness](docs/evaluation/EVALUATION_ARCHITECTURE.md#11-phase-11-implementation-status)) |
> | **External integrations** | Native Prometheus, Loki, Kubernetes, Slack, Teams, PagerDuty, Jira and Grafana adapters behind the broker, validated against **local deterministic servers only** — no live vendor system has been exercised ([integrations](docs/architecture/integrations.md)) |
>
> Phase 4 delivered five graph nodes under enforced contracts, a tool broker that is the
> sole egress point, six deterministic simulators, eleven scenarios, budgets checked before
> every step, at-least-once execution with effect-level idempotency, and OpenTelemetry spans
> persisted alongside the work they describe. Phase 5 adds bounded normalization,
> durable delivery decisions, explainable correlation, and a recoverable investigation
> request. Phase 6 adds versioned knowledge ingestion, authorization-first hybrid
> retrieval, forgery-resistant citations, and a governed memory write path where a human
> — never a model, never storage alone — decides what becomes durable. Phase 7 adds a
> bounded reflection decision on top of the existing hypothesis engine — no new graph node,
> no new model call, no schema migration ([ADR-0022](docs/adr/0022-bounded-reflection-without-a-new-node.md))
> — and hypothesis revision that supersedes a hypothesis rather than silently leaving a
> stale one standing beside it. See
> [telemetry ingestion](docs/architecture/telemetry-ingestion.md),
> [memory and RAG](docs/architecture/memory-and-rag.md) and
> [bounded reflection](docs/architecture/bounded-reflection.md) for guarantees, tests, and
> explicit limitations, and [bounded remediation](docs/architecture/bounded-remediation.md)
> for Phase 8's authorization, crash-recovery and verification boundaries.
> Phase 9 adds the authenticated API and server-rendered incident-command dashboard; see
> [Phase 9 API/dashboard](docs/architecture/phase9-api-dashboard.md). Phase 10 adds native
> external adapters and Phase 11 the evaluation, replay and regression harness.
> The repository gates include the full pytest suite against an unprivileged PostgreSQL role,
> strict typing, lint/format, migration drift and documentation/security validation.
>
> Which timeouts are *enforced* and which are merely declared is set out in
> [`docs/architecture/orchestration-kernel.md`](docs/architecture/orchestration-kernel.md)
> §11 — including the one that is not, and why fixing it needs a different execution model
> rather than a bigger number.
>
> **Start here:** [`docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md)
> — sections A–Q. Then [`docs/architecture/orchestration-kernel.md`](docs/architecture/orchestration-kernel.md)
> for what the kernel does, what it deliberately does not, and what remains unmeasured.
>
> Section 20 of the specification forbids fake integrations, fabricated metrics and
> placeholder production logic. This README states that a capability exists only once it
> exists and has been validated. **No performance has been measured, and no claim is made
> about the quality of the system's reasoning** — the Phase 11 harness exists, but the only
> model provider wired today is a deterministic one, so its runs validate the pipeline rather
> than measure reasoning.

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
| Intelligent alert correlation into coherent incidents | **Deterministic v2 built** — database-filtered service, environment, category and fixed time window with a stable tie-break; no LLM correlation |
| Autonomous investigation across logs, metrics, traces, Kubernetes, deployments and configuration changes | **Native adapters built (Phase 10)** for metrics, logs, Kubernetes state and deployment history, tested against local servers; traces remain simulator-only |
| Ranked RCA hypotheses with evidence, confidence and counter-evidence | **Structure built** — citation integrity and the confidence ceiling are enforced in code; reasoning quality is unmeasured |
| Operational RAG over runbooks, service docs, known errors and postmortems | **Phase 6 built** — governed ingestion, authorization-first hybrid retrieval and current-authority citation replay; semantic quality is unmeasured |
| Evidence-backed incident timeline reconstruction | **Built** — a deterministic projection over the event log |
| Risk-classified remediation planning | **Phase 8 simulator-backed** |
| Human approval before risky or irreversible actions | **Phase 8 exact-effect approval** |
| Controlled remediation using permission-scoped tools only | **Phase 8 broker-enforced** |
| Independent post-remediation verification | **Phase 8 fail-closed verifier** |
| Slack/Teams collaboration and PagerDuty/Jira workflows | **Phase 10 outbound built** — deterministic S2 notifications through the broker; inbound chat approval intentionally not built |
| Historical incident replay for testing and evaluation | **Phase 11 built** — strict replay of recorded harness runs (no production incident has been recorded) |
| Governed operational memory and learning | **Phase 6/8 built** — human-gated T4/T5 promotion; verified remediation memory requires complete trusted G10 baseline and independent post-read lineage |

Where a row says *built*, it means built and covered by tests against deterministic
simulators or local test servers — not exercised against production telemetry or any live
vendor account.

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
│   ├── adr/             19 Architecture Decision Records       (14 Accepted)
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

## Security

Security is built into every phase; Phase 13 consolidated and proved it
([ADR-0030](docs/adr/0030-security-boundary-consolidation.md)). Start with
[`docs/security/SECURITY_ARCHITECTURE.md`](docs/security/SECURITY_ARCHITECTURE.md); the focused
documents cover [authorization](docs/security/AUTHORIZATION.md),
[secrets](docs/security/SECRETS_POLICY.md), [supply chain](docs/security/SUPPLY_CHAIN.md) and
[data retention](docs/security/DATA_RETENTION.md).

```bash
# One command, one machine-readable verdict (exit 0 = pass). CI uses --strict.
python scripts/security_gate.py --strict --json security-verdict.json
# Once production images have been built, release gates also pass both immutable image refs and:
# --require-container-scan
```

Production authentication is OIDC/JWKS only; the shared-secret development verifier is refused
at startup when `ASIC_DEPLOYMENT_ENVIRONMENT=production`. Phase 14 adds non-root production images,
mandatory image scanning/SBOM/provenance, default-deny Kubernetes policy, TLS ingress and distinct
runtime/migration identities. Actual TLS termination, encryption at rest and remote production
deployment are platform obligations and are **not** claimed as executed. Nothing here is a
compliance certification.

## Deployment

Phase 14 provides digest-pinned backend/frontend Dockerfiles, Kustomize bases and local overlays,
provider-neutral Terraform prerequisites, GitHub quality/release/deploy workflows, and a disposable
kind smoke. Production assumes managed PostgreSQL/pgvector and platform-provisioned secrets; no cloud
provider is fabricated. See the [deployment guide](docs/deployment/PHASE14_DEPLOYMENT.md) and
[delivery architecture](docs/architecture/cicd-and-infrastructure.md).

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
| 5 | Telemetry ingestion, alert correlation and incident lifecycle | **Complete** |
| 6 | RAG, operational knowledge and governed memory | **Complete** |
| 7 | Investigation agents, hypothesis management and bounded reflection | **Complete** |
| 8 | Remediation planning, policy gates, human approval and verification | **Complete** |
| 9 | Backend APIs and frontend incident-command dashboard | **Complete** |
| 10 | External integrations | **Complete** |
| 11 | Evaluation harness, replay and regression framework | **Complete** |
| 12 | OpenTelemetry, metrics, logs, dashboards and SLOs | **Complete** |
| 13 | Security, RBAC, tenant isolation and supply-chain controls | **Complete** |
| 14 | CI/CD, Docker, Kubernetes and Terraform | **Implemented; pending independent review** |
| 15 | Load, resilience, chaos, security and E2E hardening | Not started — carries two named obligations from Phase 4: concurrency under a shared connection pool, and preemptible node execution |
| 16 | Documentation, demo scenarios, portfolio evidence and production-readiness review | Not started |

Phase 0 is not part of the specification's roadmap; it is the repository groundwork that
precedes it.

## Development

The API and dashboard are implemented through Phase 9. The Python project targets Python
3.11+ and declares its runtime and development dependencies in `pyproject.toml`. The
transcription and hygiene checks are standalone; the complete documentation validator also
loads the installed capability catalogue:

```bash
# Repository tooling. The phase-boundary check imports the capability catalogue so that it
# validates what the application will actually load.
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

The dashboard's TypeScript and production-build checks are `npm run lint` and
`npm run build` from `frontend/`. Production deployment automation remains a later-phase
deliverable.

## Contributing

This is a single-author project. See the repository security checklist above for the
commit and push procedure.

## License

Not yet selected.
