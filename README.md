# Autonomous SRE Incident Commander

An agentic incident-response system for enterprise cloud-native operations: it ingests
alerts and telemetry, correlates them into coherent incidents, performs bounded
investigation across logs, metrics, traces, Kubernetes and deployment history, produces
evidence-backed root-cause hypotheses, plans risk-classified remediation under human
approval, verifies outcomes, and preserves operational memory.

---

> ## Project status: architecture and design phase
>
> **No product code has been written yet, and nothing described below is implemented.**
>
> The **Project Initiation & Architecture Package** required by section 23 of the master
> specification is complete and awaiting approval. It contains sections A–Q, eleven
> Architecture Decision Records, 138 traced requirements and 21 diagrams — all of it
> *proposed*. No ADR is Accepted, no architecture is binding, and no metric in this
> repository is a measurement.
>
> **Read it here: [`docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](docs/architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md)**
>
> | | |
> |---|---|
> | **Completed** | Phase 0 — repository bootstrap · Phase 1 — product requirements · Phase 2 — architecture package |
> | **In progress** | Nothing — awaiting approval of the architecture package |
> | **Next** | Phase 3 — domain model, PostgreSQL schema, tenancy and event model |
> | **Implemented product features** | None |
>
> Section 20 of the specification forbids fake integrations, fabricated metrics and
> placeholder production logic. This README will state that a capability exists only once
> it exists and has been validated.

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
| Autonomous investigation across logs, metrics, traces, Kubernetes, deployments and configuration changes | Not started |
| Ranked RCA hypotheses with evidence, confidence and counter-evidence | Not started |
| Operational RAG over runbooks, service docs, known errors and postmortems | Not started |
| Evidence-backed incident timeline reconstruction | Not started |
| Risk-classified remediation planning | Not started |
| Human approval before risky or irreversible actions | Not started |
| Controlled remediation using permission-scoped tools only | Not started |
| Independent post-remediation verification | Not started |
| Slack/Teams collaboration and PagerDuty/Jira workflows | Not started |
| Historical incident replay for testing and evaluation | Not started |
| Governed operational memory and learning | Not started |

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
│   ├── adr/             11 Architecture Decision Records      (none Accepted yet)
│   ├── security/        Threat model + repository checklist (active)
│   └── evaluation/      Evaluation harness architecture
├── scripts/             Repository tooling (spec verification, hygiene, doc validation)
├── src/                 Application source                       (intentionally empty)
├── tests/               Test suites                              (intentionally empty)
└── configs/             Configuration                            (intentionally empty)
```

`src/`, `tests/` and `configs/` are empty by design and each contains a README explaining
why. The package layout is an output of the architecture work, not an input to it.

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
now been evaluated in ADRs. The recommendations — **none accepted yet** — are:

| Technology | Recommendation | ADR |
|---|---|---|
| Temporal | Not adopted; LangGraph + PostgreSQL checkpointing instead. *A close call, recorded as close.* | [0002](docs/adr/0002-orchestration-langgraph-vs-temporal.md) |
| MCP | Not adopted as transport; native adapters behind an MCP-ready seam | [0003](docs/adr/0003-tool-boundary-native-adapters-mcp-ready.md) |
| Dedicated vector database | Not adopted; pgvector in the primary store | [0004](docs/adr/0004-postgresql-pgvector-primary-datastore.md) |
| LiteLLM | Not adopted; thin internal provider interface | [0005](docs/adr/0005-llm-provider-abstraction.md) |
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
| 2 | Architecture, threat model, technology decisions and ADRs | **Complete — awaiting approval** |
| 3 | Domain model, PostgreSQL schema, tenancy and event model | Not started |
| 4 | Agent state machine, planner, tool registry and orchestration | Not started |
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
# Verify the Markdown specification still matches the authoritative .docx
python scripts/verify_spec_transcription.py

# Scan for secrets, credentials and generated files before committing
python scripts/check_repo_hygiene.py

# Validate documentation: links, Mermaid structure, requirement traceability
python scripts/validate_docs.py
```

Both must pass before any commit. The full pre-commit and pre-push procedure is
[`docs/security/REPOSITORY_SECURITY_CHECKLIST.md`](docs/security/REPOSITORY_SECURITY_CHECKLIST.md).

Build, test and deployment instructions will be added when there is something to build.

## Contributing

This is a single-author project. See the repository security checklist above for the
commit and push procedure.

## License

Not yet selected.
