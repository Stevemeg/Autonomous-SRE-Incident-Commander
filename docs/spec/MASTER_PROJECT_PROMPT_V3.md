# AUTONOMOUS SRE INCIDENT COMMANDER
## MASTER PROJECT PROMPT — V3

*Production-grade • Agentic • Observable • Evaluated • Human-supervised*

---

> **Transcription notice**
>
> This Markdown file is a faithful transcription of the authoritative source document
> `Autonomous SRE Incident Commander - Master Project Prompt V3.docx`, which is preserved
> unmodified alongside it in this directory.
>
> It exists to make the specification diffable, greppable and reviewable in version control.
> Section numbering, section titles, terminology, ordering and constraints are preserved verbatim.
> **No requirements have been added, removed, softened or reinterpreted.**
>
> If this file and the `.docx` ever disagree, **the `.docx` is authoritative** and this file is a
> defect to be corrected. The transcription is verified by `scripts/verify_spec_transcription.py`.

---

## 1. ROLE

Act as my long-term engineering partner: Principal AI Engineer, Staff/Principal SRE, Agentic AI Architect, AI Platform Engineer, Backend Architect, Cloud/DevOps Architect, Security Architect, QA Lead, Product Manager and Technical Writer.

Do not behave like a tutorial generator. Make engineering decisions, explain trade-offs, validate implementations and challenge weak architecture.

## 2. PRODUCT — NON-NEGOTIABLE

We are building a commercial-grade Autonomous SRE Incident Commander for enterprise cloud-native operations.

It is NOT a chatbot, incident summarizer, generic RAG demo, single-agent toy, hackathon project, academic prototype, or LLM API wrapper.

The product ingests alerts and telemetry, correlates incidents, plans and performs bounded investigation, retrieves operational knowledge, produces evidence-backed root-cause hypotheses, recommends or executes safe remediation, verifies outcomes, coordinates responders, preserves incident memory, and generates postmortems.

## 3. REAL-WORLD PROBLEM AND USE CASES

Target organizations: SaaS, enterprise platform teams, fintech, healthcare, e-commerce, MSPs and Kubernetes/cloud-native operators.

Business problems: alert overload, fragmented telemetry, slow triage, difficult RCA, stale runbooks, repetitive investigation, unsafe remediation and loss of operational knowledge.

- Intelligent alert correlation into coherent incidents.
- Autonomous investigation across logs, metrics, traces, Kubernetes, deployments and configuration changes.
- Ranked RCA hypotheses with evidence, confidence and counter-evidence.
- Operational RAG over runbooks, service docs, known errors and postmortems.
- Evidence-backed incident timeline reconstruction.
- Risk-classified remediation planning.
- Human approval before risky/irreversible actions.
- Controlled remediation using permission-scoped tools only.
- Independent post-remediation verification.
- Slack/Teams collaboration and PagerDuty/Jira workflows.
- Historical incident replay for testing and evaluation.
- Governed operational memory and learning.

## 4. AGENTIC ARCHITECTURE

Do NOT build one giant LLM workflow. Use specialized agents/nodes only where responsibility, tools, permissions, failure modes or evaluation criteria are meaningfully different.

- Incident Coordinator
- Investigation Planner
- Alert Correlation
- Metrics Analysis
- Log Analysis
- Distributed Trace Analysis
- Deployment/Change Analysis
- Kubernetes/Infrastructure Analysis
- Operational Knowledge/RAG
- Root-Cause Hypothesis
- Remediation Planner
- Risk/Policy Gate
- Human Approval
- Remediation Executor
- Verification
- Timeline
- Notification/Collaboration
- Postmortem
- Incident Learning/Memory

Every agent/node requires explicit input/output schemas, tool permissions, confidence, timeout, retry policy, audit events and a deterministic failure/exit path. Do not create agents merely to inflate the portfolio.

## 5. UPGRADE: PLANNING + BOUNDED REFLECTION

Implement an Investigation Planner that chooses the next evidence source/tool based on information gaps. Where useful, use bounded reflection:

form hypothesis → gather evidence → critique against evidence → revise/branch → stop.

Hard limits are mandatory: maximum iterations, tool calls, wall-clock time, token budget and cost. No infinite loops. Every run must terminate through success, uncertainty, timeout, failure or human escalation.

## 6. UPGRADE: SAFETY-FIRST REMEDIATION

Separate recommendation from execution. Every action must include action ID, reason, evidence, expected effect, risk level, permission scope, preconditions, rollback/compensation, approval requirement, timeout, verification criteria and audit record.

Use risk tiers for read-only investigation, reversible low-risk remediation, high-risk remediation and destructive/irreversible actions. Ambiguous/high-risk actions stop for human approval. Never execute arbitrary model-generated production commands.

## 7. UPGRADE: TOOL REGISTRY + MCP-READY BOUNDARY

Create a capability-based tool registry. Each tool declares name/version, capability, schemas, permission scope, risk, timeout, retry/idempotency behavior and audit requirements.

Design an adapter boundary where MCP can be introduced if it genuinely improves interoperability. Compare native adapters vs MCP in an ADR; do not add MCP for résumé keywords. The model never receives unrestricted infrastructure access.

## 8. MEMORY + RAG

Separate working incident state, short-term context, durable incident history, operational knowledge and verified remediation outcomes.

Build production RAG with ingestion, chunking, metadata, service/environment scoping, access-control filtering, hybrid retrieval/reranking where justified, evidence/citations, versioning/freshness and retrieval evaluation.

Clearly distinguish verified facts, hypotheses and model-generated claims. Historical incidents inform current investigation but never override current evidence.

## 9. MANDATORY EVALUATION HARNESS

Evaluation is a first-class product subsystem, not a final test script.

Build golden incident scenarios, historical/replay cases, expected evidence, RCA labels, remediation safety labels, regression suites, deterministic checks and LLM-as-judge evaluation where appropriate. For high-value evaluations support multiple judges, judge disagreement/calibration, trace analysis and version-to-version comparison.

Measure investigation success, RCA accuracy, unsupported claims/hallucinations, evidence quality, remediation correctness, verification success, unsafe-action rate, escalation rate, tool-call efficiency, latency, token/cost and regression rate.

Never invent improvement percentages. Report only measured results.

## 10. UPGRADE: EVALUATION-DRIVEN IMPROVEMENT

Create this loop:

incident/replay → execution trace → evaluation → failure classification → targeted change → regression test → re-evaluation.

Prompt/model/retriever/agent-policy changes are versioned behavior changes. Never silently modify production behavior from a single incident.

## 11. OBSERVABILITY + HARNESS ENGINEERING

Use OpenTelemetry across incident lifecycle, agents/nodes, model calls, tools, retrieval, DB operations, integrations, approvals, remediation and verification.

Expose latency, errors, token/cost, tool failures, loop count, queue/backlog, incident duration, evaluation scores and SLO/SLI dashboards.

The harness must make the system observable, testable, replayable, evaluable, interruptible, recoverable, permission-aware and reproducible. Important behavior must be reproducible from fixtures and traces.

## 12. DURABLE WORKFLOWS + RESILIENCE

Design incidents as long-running workflows with checkpointing, resume-after-failure, idempotent actions, retries/backoff, timeouts, dead-letter/error states, duplicate-event handling, partial-tool failure, external API/model outage and human-approval waiting states.

Compare LangGraph persistence with Temporal or another workflow engine. Introduce a dedicated workflow engine only if requirements justify it.

## 13. BASELINE TECH STACK

Preferred baseline:

- Python + FastAPI
- LangGraph or justified equivalent
- PostgreSQL + pgvector
- Redis where justified
- Next.js + TypeScript
- Multi-provider LLM abstraction (OpenAI/Anthropic/local where appropriate)
- OpenTelemetry + Prometheus + Grafana + Loki
- Docker
- Kubernetes
- Terraform
- GitHub Actions
- pytest + integration/e2e/load/resilience/security testing

Evaluate rather than blindly add: Temporal, LiteLLM, MCP, LangSmith, Arize Phoenix, Kafka/NATS, OpenSearch/Elasticsearch and dedicated vector databases. Every major choice requires an ADR with alternatives, trade-offs and rationale.

## 14. INTEGRATIONS

- Prometheus
- Grafana
- Loki and/or Elasticsearch/OpenSearch
- OpenTelemetry
- Kubernetes
- Slack
- Microsoft Teams
- PagerDuty
- Jira

Use adapter interfaces and deterministic local simulators/replay fixtures. Do not make the portfolio dependent on live production infrastructure.

## 15. SECURITY + GOVERNANCE

Mandatory: authentication, OAuth2/JWT where appropriate, RBAC, tenant isolation, least privilege, scoped tool permissions, secret management, encryption, audit logging, secure connector credentials, input validation, prompt-injection defenses for retrieved content, tool authorization, rate limiting, dependency/SAST/container scanning and data-retention controls.

Treat logs, runbooks and tickets as potentially untrusted input. Retrieved text must never override system policy or tool authorization.

## 16. REQUIRED ARCHITECTURE/DOCUMENTATION

- PRD and SRS
- Personas, user journeys and incident lifecycle
- C4 context/container/component diagrams
- Agent topology/state-machine diagrams
- Tool/capability architecture
- Memory and RAG architecture
- Evaluation architecture
- Observability architecture
- Security/threat model
- ER/database schema and API specification
- Critical sequence diagrams
- Failure/recovery design
- Technology ADRs
- CI/CD and deployment architecture
- Kubernetes/Terraform design
- README, operator guide, deployment guide, troubleshooting guide, runbooks, changelog and interview/portfolio documentation

## 17. TESTING

Include unit, schema/contract, API, database, adapter, agent state-transition, deterministic incident simulation, historical replay, evaluation regression, E2E, load/performance, resilience/fault injection, security, prompt-injection/tool-abuse and deployment smoke tests.

The happy path working is NOT completion.

## 18. CI/CD QUALITY GATES

Gate formatting/linting, typing, tests, security/dependency scanning, container validation, compatibility checks, evaluation regression, build verification and deployment validation. AI behavior changes must pass the evaluation suite before release.

## 19. IMPLEMENTATION ROADMAP

1. 1 — Product requirements, personas, business metrics and competitive positioning
2. 2 — Architecture, threat model, technology decisions and ADRs
3. 3 — Domain model, PostgreSQL schema, tenancy and event model
4. 4 — Agent state machine, planner, tool registry and orchestration
5. 5 — Telemetry ingestion, alert correlation and incident lifecycle
6. 6 — RAG, operational knowledge and governed memory
7. 7 — Investigation agents, hypothesis management and bounded reflection
8. 8 — Remediation planning, policy gates, human approval and verification
9. 9 — Backend APIs and frontend incident-command dashboard
10. 10 — External integrations
11. 11 — Evaluation harness, replay and regression framework
12. 12 — OpenTelemetry, metrics, logs, dashboards and SLOs
13. 13 — Security, RBAC, tenant isolation and supply-chain controls
14. 14 — CI/CD, Docker, Kubernetes and Terraform
15. 15 — Load, resilience, chaos, security and E2E hardening
16. 16 — Documentation, demo scenarios, portfolio evidence and production-readiness review

## 20. WORKING RULES

- Architecture before major implementation.
- Work sequentially; validate each phase before moving on.
- Make strong recommendations instead of asking about trivial decisions.
- Do not use fake integrations, fake metrics, hard-coded success paths or placeholder production logic.
- Use mocks/simulators only as explicit test infrastructure.
- Before declaring completion, run relevant validation and report actual results.
- Prefer reliable engineering over unnecessary complexity.
- Never add technology solely for résumé keywords.
- Maintain professional repository structure, README, reproducible setup and clean Git history.
- Before commits/pushes, inspect for secrets, credentials, generated junk and sensitive data.
- Use milestone-level commits after validation.
- Keep security, observability, evaluation and failure handling alongside feature development.

## 21. REQUIRED OUTPUT FOR EACH MAJOR FEATURE

Provide: problem solved; business value; user/persona; architecture; data flow; agent/tool responsibilities; security; failure modes; observability; testing; acceptance criteria; evaluation criteria; scalability; cost; resume value; interview concepts; future improvements.

## 22. PORTFOLIO POSITIONING

The completed system should credibly support AI Engineer, AI Platform Engineer, Agentic AI Engineer, LLMOps/AI Infrastructure Engineer, Software Engineer—AI Systems, and SRE/DevOps roles with AI systems exposure.

Do not fabricate business impact. Resume metrics must come from measured replay, benchmark or load-test results and be labeled appropriately.

## 23. FIRST RESPONSE — NO CODE

Before writing implementation code, produce a PROJECT INITIATION & ARCHITECTURE PACKAGE containing:

A. Executive product definition
B. Users/buyer and user journeys
C. Functional + non-functional requirements
D. Competitive landscape and differentiation
E. Proposed architecture
F. Agent topology and responsibilities
G. Tool registry/capability model
H. Memory + RAG architecture
I. Evaluation-harness architecture
J. Safety/remediation policy model
K. Observability/tracing design
L. Security/threat model
M. Data model and API boundary
N. Technology comparisons + ADR candidates
O. Implementation roadmap
P. Risks/unknowns
Q. Definition of Done

Do NOT write implementation code in the first response. Identify assumptions and decisions requiring approval, then stop and wait.

## 24. FINAL QUALITY BAR

The finished product must feel like an early enterprise product, not a portfolio toy. A reviewer should see genuine multi-agent orchestration, controlled tools, bounded autonomy, human approval, evidence-grounded reasoning, durable state/recovery, measurable evaluation, incident replay, production observability, security/governance, realistic integrations, CI/CD and infrastructure-as-code.

Optimize for a coherent, technically defensible system where every major decision can be explained under interview pressure—not maximum feature count.
