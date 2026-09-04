# Software Requirements Specification (SRS)

- **Status:** Authored — Architecture Package (V3 §23 C). **No requirement below is implemented.**
- **Authoritative source:** [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)
- **Master specification references:** Sections 2–18, 23(C)
- **Traceability:** every ID below appears in [`../architecture/requirements-traceability.md`](../architecture/requirements-traceability.md)

---

## 0. How to read this document

### 0.1 Requirement classification

Master specification section 20 requires that requirements be distinguished from
assumptions and proposals. Every requirement therefore carries a **source class**:

| Class | Meaning | Change control |
|---|---|---|
| **`[SPEC]`** | Stated or directly entailed by the master specification. Binding. | Cannot be dropped without changing the `.docx` |
| **`[DERIVED]`** | A necessary engineering consequence of a `[SPEC]` requirement | Can be revised if a better mechanism achieves the same `[SPEC]` outcome |
| **`[ASSUMED]`** | Our judgement, not stated in the specification. **Requires review.** | May be removed or changed by the project owner |

`[ASSUMED]` requirements are collected in §5 for explicit sign-off.

### 0.2 Priority

- **M** — Mandatory for v1. The product is not the specified product without it.
- **S** — Should have; deferred only with a recorded reason.
- **C** — Could have; explicitly out of v1 scope but designed for.

### 0.3 Numeric targets

Numeric values in non-functional requirements are **budgets to be validated**, not measured
results (master specification sections 9 and 22). Each is marked with the phase at which it
is first measured. A budget that has not been measured is labelled as such in every report.

---

## 1. System context and actors

| Actor | Type | Interaction |
|---|---|---|
| Alerting sources (Prometheus Alertmanager, PagerDuty) | External system | Push alerts into ingestion |
| Telemetry backends (Prometheus, Loki/OpenSearch, OTel traces, Kubernetes API, deployment source) | External system | Queried read-only by investigation |
| Collaboration platforms (Slack, Teams) | External system | Receive notifications; relay approvals |
| Ticketing (Jira) | External system | Incident and postmortem records |
| On-call SRE (P1), Platform Engineer (P2) | Human | Review, approve, escalate, override |
| Security architect (P4) | Human | Defines policy, audits |
| System operator (P6) | Human | Runs evaluation, replay, rollback |

---

## 2. Functional requirements

### 2.1 Ingestion and alert correlation (`FR-ING`, `FR-COR`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-ING-01 | `[SPEC]` | M | The system shall ingest alerts from external alerting sources over an authenticated ingestion API. (§2, §3, §14) |
| FR-ING-02 | `[SPEC]` | M | The system shall ingest and normalise telemetry references across metrics, logs, traces, Kubernetes state, deployment and configuration change history. (§3) |
| FR-ING-03 | `[SPEC]` | M | Ingestion shall be idempotent under duplicate delivery of the same alert event. (§12) |
| FR-ING-04 | `[DERIVED]` | M | Every ingested alert shall be normalised into a canonical internal `Alert` representation independent of source vendor, carrying tenant, service and environment scope. |
| FR-ING-05 | `[DERIVED]` | M | Alerts that cannot be normalised or authorised shall be routed to a dead-letter store with the rejection reason preserved, never silently dropped. (§12) |
| FR-COR-01 | `[SPEC]` | M | The system shall correlate related alerts into a single coherent incident rather than treating each alert as an incident. (§3) |
| FR-COR-02 | `[DERIVED]` | M | Correlation shall be primarily deterministic (temporal proximity, service-dependency topology, shared labels, deployment coincidence); model assistance may rank or explain, but shall not be the sole basis of a correlation decision. |
| FR-COR-03 | `[DERIVED]` | M | Correlation decisions shall be recorded with the signals that produced them, so a correlation can be audited and replayed. |
| FR-COR-04 | `[DERIVED]` | S | The system shall support late-arriving alerts joining an existing open incident, and shall record the join as an incident event. |

### 2.2 Incident lifecycle (`FR-INC`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-INC-01 | `[SPEC]` | M | Each incident shall be a long-running, durable workflow with explicit states and recorded transitions. (§12) |
| FR-INC-02 | `[SPEC]` | M | Incident state shall survive process restart and resume from the last checkpoint without repeating completed side effects. (§12) |
| FR-INC-03 | `[SPEC]` | M | Every incident shall terminate in exactly one of: resolved-success, resolved-with-uncertainty, timeout, failure, or human escalation. (§5) |
| FR-INC-04 | `[DERIVED]` | M | All incident state changes shall be recorded as append-only incident events; incident status shall be derivable from the event log. |
| FR-INC-05 | `[SPEC]` | M | The system shall reconstruct an evidence-backed incident timeline. (§3) |
| FR-INC-06 | `[DERIVED]` | M | The timeline shall be a deterministic projection over recorded incident events, with every entry traceable to its source event or evidence record. |

### 2.3 Investigation, planning and bounded reflection (`FR-INV`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-INV-01 | `[SPEC]` | M | An Investigation Planner shall select the next evidence source or tool based on current information gaps, not a fixed script. (§5) |
| FR-INV-02 | `[SPEC]` | M | The system shall perform bounded reflection: form hypothesis, gather evidence, critique against evidence, revise or branch, stop. (§5) |
| FR-INV-03 | `[SPEC]` | M | Hard limits shall be enforced on maximum iterations, tool calls, wall-clock time, token budget and cost. (§5) |
| FR-INV-04 | `[SPEC]` | M | No investigation shall loop indefinitely; limit exhaustion shall be a terminating condition producing a partial result, not a silent stall. (§5) |
| FR-INV-05 | `[SPEC]` | M | Investigation shall span logs, metrics, traces, Kubernetes/infrastructure state, deployments/changes, and operational knowledge. (§3, §4) |
| FR-INV-06 | `[DERIVED]` | M | All investigation tool calls shall be read-only; investigation shall be incapable of mutating a target system by construction of its permission scope. |
| FR-INV-07 | `[DERIVED]` | M | Each investigation step shall be persisted with its planner rationale, selected tool, inputs, outputs and cost, sufficient to replay the decision. |
| FR-INV-08 | `[DERIVED]` | S | The planner shall avoid redundant evidence collection by tracking which information gaps a completed step actually closed. |

### 2.4 Evidence and hypotheses (`FR-EVD`, `FR-RCA`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-EVD-01 | `[SPEC]` | M | The system shall structurally distinguish verified facts, hypotheses, and model-generated claims. (§8) |
| FR-EVD-02 | `[DERIVED]` | M | Every evidence record shall carry provenance: source system, query issued, retrieval timestamp, and a citation sufficient for a human to re-derive it. |
| FR-EVD-03 | `[SPEC]` | M | Retrieved operational knowledge shall carry evidence and citations. (§8) |
| FR-EVD-04 | `[SPEC]` | M | Historical incidents may inform the current investigation but shall never override current evidence. (§8) |
| FR-RCA-01 | `[SPEC]` | M | The system shall produce **ranked** root-cause hypotheses, each with supporting evidence, a confidence value, and counter-evidence. (§3) |
| FR-RCA-02 | `[DERIVED]` | M | A hypothesis with no supporting evidence record shall not be presentable as a ranked cause; it may only be presented as an untested conjecture, labelled as such. |
| FR-RCA-03 | `[DERIVED]` | M | Confidence shall be reported with the basis for it (evidence count, strength, contradiction presence), not as an unexplained number. |
| FR-RCA-04 | `[SPEC]` | M | Where evidence is insufficient, the system shall terminate in an explicit uncertainty state rather than assert a cause. (§5) |

### 2.5 Operational knowledge and RAG (`FR-KNW`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-KNW-01 | `[SPEC]` | M | The system shall provide production RAG over runbooks, service documentation, known errors and postmortems, with ingestion, chunking and metadata. (§3, §8) |
| FR-KNW-02 | `[SPEC]` | M | Retrieval shall be scoped by service and environment. (§8) |
| FR-KNW-03 | `[SPEC]` | M | Retrieval shall apply access-control filtering so a requester never receives content they are not entitled to. (§8) |
| FR-KNW-04 | `[SPEC]` | M | Retrieval shall support hybrid retrieval and reranking **where justified by measurement**, not by default. (§8) |
| FR-KNW-05 | `[SPEC]` | M | Knowledge documents shall carry versioning and freshness metadata, and staleness shall be visible to the consumer. (§8) |
| FR-KNW-06 | `[SPEC]` | M | Retrieval quality shall itself be evaluated. (§8) |
| FR-KNW-07 | `[SPEC]` | M | Retrieved text shall never override system policy or tool authorization. (§15) |

### 2.6 Memory (`FR-MEM`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-MEM-01 | `[SPEC]` | M | The system shall separate working incident state, short-term context, durable incident history, operational knowledge, and verified remediation outcomes. (§8) |
| FR-MEM-02 | `[SPEC]` | M | Memory writes derived from incidents shall be governed, not automatic. (§3, §10) |
| FR-MEM-03 | `[SPEC]` | M | Production behaviour shall never be silently modified on the basis of a single incident. (§10) |
| FR-MEM-04 | `[DERIVED]` | M | A promotion from incident outcome into durable operational memory shall require an explicit approval step and shall be recorded as a versioned change. |

### 2.7 Remediation, policy and approval (`FR-REM`, `FR-POL`, `FR-APR`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-REM-01 | `[SPEC]` | M | Recommendation shall be separated from execution. (§6) |
| FR-REM-02 | `[SPEC]` | M | Every proposed action shall carry: action ID, reason, evidence, expected effect, risk level, permission scope, preconditions, rollback/compensation, approval requirement, timeout, verification criteria and audit record. (§6) |
| FR-REM-03 | `[SPEC]` | M | Actions shall be classified into risk tiers: read-only investigation, reversible low-risk remediation, high-risk remediation, and destructive/irreversible. (§6) |
| FR-REM-04 | `[SPEC]` | M | Ambiguous or high-risk actions shall stop for human approval. (§6) |
| FR-REM-05 | `[SPEC]` | M | The system shall never execute arbitrary model-generated production commands. (§6) |
| FR-REM-06 | `[DERIVED]` | M | Executable actions shall be selected from a pre-registered, parameter-validated catalogue; free-form command strings shall not be an executable action type. |
| FR-REM-07 | `[SPEC]` | M | Remediation shall use permission-scoped tools only. (§3) |
| FR-REM-08 | `[DERIVED]` | M | Execution shall be idempotent under retry, keyed by action ID, so a duplicate execution attempt cannot double-apply an effect. (§12) |
| FR-REM-09 | `[DERIVED]` | M | Preconditions shall be re-validated immediately before execution; an action approved against stale state shall fail closed rather than execute. |
| FR-POL-01 | `[DERIVED]` | M | A deterministic, non-model policy gate shall be the sole authorization path for any non-read-only action. |
| FR-POL-02 | `[DERIVED]` | M | The policy gate shall be incapable of being influenced by retrieved content or model output other than through a validated, typed action proposal. |
| FR-POL-03 | `[DERIVED]` | M | Policy decisions (allow, deny, require-approval) shall be recorded with the rule that produced them. |
| FR-APR-01 | `[SPEC]` | M | Human approval shall be required before risky or irreversible actions. (§3, §6) |
| FR-APR-02 | `[SPEC]` | M | The workflow shall support durable human-approval waiting states that survive process restart. (§12) |
| FR-APR-03 | `[DERIVED]` | M | Approval requests shall expire on a defined timeout, and expiry shall be a recorded, non-executing outcome. |
| FR-APR-04 | `[DERIVED]` | M | The approver's identity, decision, justification and timestamp shall be recorded immutably. |
| FR-APR-05 | `[DERIVED]` | M | Approval shall be bound to the exact action version proposed; any change to action parameters shall invalidate the approval. |

### 2.8 Verification (`FR-VRF`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-VRF-01 | `[SPEC]` | M | The system shall perform independent post-remediation verification. (§3) |
| FR-VRF-02 | `[DERIVED]` | M | Verification shall re-derive system state from telemetry rather than trusting the executor's reported success. |
| FR-VRF-03 | `[DERIVED]` | M | Verification criteria shall be fixed at action-proposal time, before execution, to prevent post-hoc redefinition of success. |
| FR-VRF-04 | `[DERIVED]` | M | Verification failure shall trigger a defined path: rollback/compensation where available, otherwise escalation. |

### 2.9 Collaboration, postmortem and integrations (`FR-CLB`, `FR-PMT`, `FR-INT`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-CLB-01 | `[SPEC]` | M | The system shall support Slack/Teams collaboration and PagerDuty/Jira workflows. (§3, §14) |
| FR-CLB-02 | `[DERIVED]` | M | Notification delivery shall be at-least-once with de-duplication keys, and delivery failure shall not fail the incident workflow. |
| FR-CLB-03 | `[DERIVED]` | M | Approval actions received from a collaboration platform shall be authenticated and authorised against the same RBAC model as the primary API; chat identity alone shall not grant approval authority. |
| FR-PMT-01 | `[SPEC]` | M | The system shall generate postmortems. (§2) |
| FR-PMT-02 | `[DERIVED]` | M | Generated postmortems shall cite incident events and evidence records, and shall be marked as drafts requiring human review. |
| FR-INT-01 | `[SPEC]` | M | Integrations shall be built against adapter interfaces: Prometheus, Grafana, Loki and/or Elasticsearch/OpenSearch, OpenTelemetry, Kubernetes, Slack, Teams, PagerDuty, Jira. (§14) |
| FR-INT-02 | `[SPEC]` | M | Each integration shall have a deterministic local simulator and replay fixtures. (§14) |
| FR-INT-03 | `[SPEC]` | M | No test, demonstration or evaluation shall depend on live production infrastructure. (§14) |
| FR-INT-04 | `[SPEC]` | M | Simulators shall be explicit test infrastructure and shall never be reachable as a production code path. (§20) |

### 2.10 Evaluation (`FR-EVL`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-EVL-01 | `[SPEC]` | M | Evaluation shall be a first-class product subsystem, not a final test script. (§9) |
| FR-EVL-02 | `[SPEC]` | M | The harness shall provide golden incident scenarios, historical/replay cases, expected evidence, RCA labels and remediation safety labels. (§9) |
| FR-EVL-03 | `[SPEC]` | M | The harness shall provide regression suites and deterministic checks. (§9) |
| FR-EVL-04 | `[SPEC]` | M | LLM-as-judge evaluation shall be used where appropriate, with multiple judges, disagreement handling and calibration for high-value evaluations. (§9) |
| FR-EVL-05 | `[SPEC]` | M | The harness shall support trace analysis and version-to-version comparison. (§9) |
| FR-EVL-06 | `[SPEC]` | M | The system shall measure: investigation success, RCA accuracy, unsupported claims/hallucinations, evidence quality, remediation correctness, verification success, unsafe-action rate, escalation rate, tool-call efficiency, latency, token/cost, and regression rate. (§9) |
| FR-EVL-07 | `[SPEC]` | M | Improvement percentages shall never be invented; only measured results shall be reported. (§9, §22) |
| FR-EVL-08 | `[SPEC]` | M | The improvement loop shall be: incident/replay, execution trace, evaluation, failure classification, targeted change, regression test, re-evaluation. (§10) |
| FR-EVL-09 | `[SPEC]` | M | Prompt, model, retriever and agent-policy changes shall be treated as versioned behaviour changes. (§10) |
| FR-EVL-10 | `[SPEC]` | M | AI behaviour changes shall pass the evaluation suite before release. (§18) |
| FR-EVL-11 | `[DERIVED]` | M | Every incident execution shall emit a trace in the same schema the harness consumes, so production incidents can become evaluation cases without transformation. |

### 2.11 Observability (`FR-OBS`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-OBS-01 | `[SPEC]` | M | OpenTelemetry instrumentation shall span incident lifecycle, agents/nodes, model calls, tools, retrieval, database operations, integrations, approvals, remediation and verification. (§11) |
| FR-OBS-02 | `[SPEC]` | M | The system shall expose latency, errors, token/cost, tool failures, loop count, queue/backlog, incident duration, evaluation scores, and SLO/SLI dashboards. (§11) |
| FR-OBS-03 | `[SPEC]` | M | Important behaviour shall be reproducible from fixtures and traces. (§11) |
| FR-OBS-04 | `[DERIVED]` | M | A single correlation identifier shall link an incident, its workflow run, its trace, its evidence, its actions and its evaluation record. |
| FR-OBS-05 | `[DERIVED]` | M | Secrets and credential material shall never be emitted into traces, logs, prompts or evaluation artifacts. |

### 2.12 API and administration (`FR-API`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| FR-API-01 | `[DERIVED]` | M | The system shall expose distinct API surfaces for external ingestion, incident query/control, approval, evaluation/replay, and administration, with independent authorization. |
| FR-API-02 | `[DERIVED]` | M | Every API surface shall enforce tenant scoping; no endpoint shall return cross-tenant data. |
| FR-API-03 | `[SPEC]` | M | A frontend incident-command dashboard shall present incidents, evidence, hypotheses, timeline, actions and approvals. (§19 phase 9) |
| FR-API-04 | `[DERIVED]` | S | Administration surfaces (tool registry, policy, tenants, knowledge sources) shall be separately authorised from operational surfaces. |

---

## 3. Non-functional requirements

### 3.1 Security (`NFR-SEC`)

Security invariants are specified normatively in
[`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md). This table states them as
requirements; the threat model states the attacks they defend against.

| ID | Class | Pri | Requirement |
|---|---|---|---|
| NFR-SEC-01 | `[SPEC]` | M | Authentication shall be required for all non-public surfaces, using OAuth2/JWT where appropriate. (§15) |
| NFR-SEC-02 | `[SPEC]` | M | RBAC shall govern all operations, including approval authority. (§15) |
| NFR-SEC-03 | `[SPEC]` | M | Tenant isolation shall be enforced such that no request can read or write another tenant's data. (§15) |
| NFR-SEC-04 | `[SPEC]` | M | Least privilege shall apply to every credential and every tool permission scope. (§15) |
| NFR-SEC-05 | `[SPEC]` | M | Tool permissions shall be scoped; the model shall never receive unrestricted infrastructure access. (§7, §15) |
| NFR-SEC-06 | `[SPEC]` | M | Secrets shall be managed by a secret manager, never committed, never placed in prompts or traces. (§15) |
| NFR-SEC-07 | `[SPEC]` | M | Data shall be encrypted in transit and at rest. (§15) |
| NFR-SEC-08 | `[SPEC]` | M | Audit logging shall cover authentication, authorization decisions, tool executions, approvals and remediation. (§15) |
| NFR-SEC-09 | `[SPEC]` | M | Input validation shall apply to all external input including alerts, webhooks and retrieved content. (§15) |
| NFR-SEC-10 | `[SPEC]` | M | Prompt-injection defenses shall apply to retrieved content. (§15) |
| NFR-SEC-11 | `[SPEC]` | M | Logs, runbooks and tickets shall be treated as untrusted input. (§15) |
| NFR-SEC-12 | `[SPEC]` | M | Rate limiting shall protect ingestion and API surfaces. (§15) |
| NFR-SEC-13 | `[SPEC]` | M | Dependency scanning, SAST and container scanning shall run in CI. (§15, §18) |
| NFR-SEC-14 | `[SPEC]` | M | Data-retention controls shall be enforced per data class. (§15) |
| NFR-SEC-15 | `[SPEC]` | M | Connector credentials shall be stored and transmitted securely and scoped per tenant. (§15) |

### 3.2 Reliability and durability (`NFR-REL`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| NFR-REL-01 | `[SPEC]` | M | Incident workflows shall checkpoint and resume after process failure without duplicating side effects. (§12) |
| NFR-REL-02 | `[SPEC]` | M | Actions shall be idempotent. (§12) |
| NFR-REL-03 | `[SPEC]` | M | Retries with backoff shall be applied where and only where the operation is safely retryable. (§12) |
| NFR-REL-04 | `[SPEC]` | M | Timeouts shall exist at node, tool, model and workflow scope. (§12) |
| NFR-REL-05 | `[SPEC]` | M | Dead-letter and error states shall exist for unprocessable input and unrecoverable steps. (§12) |
| NFR-REL-06 | `[SPEC]` | M | Duplicate events shall be detected and absorbed. (§12) |
| NFR-REL-07 | `[SPEC]` | M | Partial tool failure shall degrade the investigation, not abort the incident. (§12) |
| NFR-REL-08 | `[SPEC]` | M | External API and model outages shall be survivable: the workflow shall pause, degrade or escalate rather than fail destructively. (§12) |
| NFR-REL-09 | `[ASSUMED]` | S | Target: an incident workflow shall resume within 60 seconds of orchestrator recovery. *Budget — first measured in Phase 15.* |

### 3.3 Performance and cost (`NFR-PRF`)

All values are **budgets requiring validation**, first measured in Phase 15 (load,
resilience) unless stated. They are `[ASSUMED]` because the master specification sets no
numeric targets.

| ID | Class | Pri | Requirement |
|---|---|---|---|
| NFR-PRF-01 | `[ASSUMED]` | S | Alert ingestion to incident correlation decision: p95 under 5 seconds. |
| NFR-PRF-02 | `[ASSUMED]` | S | Incident creation to first ranked hypothesis presented: p95 under 3 minutes for golden scenarios. |
| NFR-PRF-03 | `[ASSUMED]` | S | A single investigation shall not exceed its configured wall-clock, token and cost budget; budget exhaustion is a terminating state, not an overrun. (Enforcement is `[SPEC]` per §5; the numeric default is assumed.) |
| NFR-PRF-04 | `[ASSUMED]` | S | Sustained ingestion of 50 alerts/second without backlog growth. |
| NFR-PRF-05 | `[SPEC]` | M | Token and cost per incident shall be measured and reported per run. (§9, §11) |

### 3.4 Observability, maintainability, portability (`NFR-OBS`, `NFR-MNT`, `NFR-PRT`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| NFR-OBS-06 | `[SPEC]` | M | The system shall be observable, testable, replayable, evaluable, interruptible, recoverable, permission-aware and reproducible. (§11) |
| NFR-MNT-01 | `[SPEC]` | M | Every major technology choice shall have an ADR with alternatives, trade-offs and rationale. (§13) |
| NFR-MNT-02 | `[SPEC]` | M | Technology shall never be adopted solely for résumé keywords. (§20) |
| NFR-MNT-03 | `[SPEC]` | M | CI shall gate formatting, linting, typing, tests, security/dependency scanning, container validation, compatibility, evaluation regression, build and deployment validation. (§18) |
| NFR-MNT-04 | `[SPEC]` | M | The repository shall maintain professional structure, reproducible setup and clean Git history. (§20) |
| NFR-PRT-01 | `[SPEC]` | M | The system shall run under Docker and deploy to Kubernetes with Terraform-managed infrastructure. (§13) |
| NFR-PRT-02 | `[SPEC]` | M | The full stack shall be runnable locally with deterministic simulators and no live infrastructure. (§14) |

### 3.5 Testing (`NFR-TST`)

| ID | Class | Pri | Requirement |
|---|---|---|---|
| NFR-TST-01 | `[SPEC]` | M | Test coverage shall include unit, schema/contract, API, database, adapter, agent state-transition, deterministic incident simulation, historical replay, evaluation regression, E2E, load/performance, resilience/fault injection, security, prompt-injection/tool-abuse, and deployment smoke tests. (§17) |
| NFR-TST-02 | `[SPEC]` | M | A working happy path shall not be treated as completion. (§17) |
| NFR-TST-03 | `[DERIVED]` | M | Every safety invariant shall have at least one adversarial test that attempts to violate it. |

---

## 4. Constraints

| ID | Class | Constraint |
|---|---|---|
| CON-01 | `[SPEC]` | Architecture precedes major implementation; phases are validated before proceeding. (§20) |
| CON-02 | `[SPEC]` | No fake integrations, fake metrics, hard-coded success paths or placeholder production logic. (§20) |
| CON-03 | `[SPEC]` | Mocks and simulators are permitted only as explicit test infrastructure. (§20) |
| CON-04 | `[SPEC]` | Agents/nodes shall exist only where responsibility, tools, permissions, failure modes or evaluation criteria genuinely differ. (§4) |
| CON-05 | `[SPEC]` | Baseline stack preference: Python, FastAPI, LangGraph or justified equivalent, PostgreSQL + pgvector, Redis where justified, Next.js + TypeScript, multi-provider LLM abstraction, OpenTelemetry/Prometheus/Grafana/Loki, Docker, Kubernetes, Terraform, GitHub Actions, pytest. (§13) |
| CON-06 | `[SPEC]` | Temporal, LiteLLM, MCP, LangSmith, Arize Phoenix, Kafka/NATS, OpenSearch/Elasticsearch and dedicated vector databases shall be evaluated rather than blindly added. (§13) |
| CON-07 | `[SPEC]` | Security, observability, evaluation and failure handling shall be developed alongside features, not deferred. (§20) |

---

## 5. Assumptions requiring owner approval

Per master specification section 23, assumptions are surfaced rather than silently adopted.
These are the `[ASSUMED]` items above plus design assumptions that materially shape the
architecture.

| ID | Assumption | Why we assumed it | Consequence if rejected |
|---|---|---|---|
| AS-01 | Multi-tenancy is required from day one | §15 mandates tenant isolation, which is not retrofittable cheaply | Simplifies schema and auth significantly; would remove RLS complexity |
| AS-02 | v1 executes reversible low-risk remediation, not merely recommends | §3 and §6 describe execution and verification as product capabilities | Executor and verifier move to v2; §3 capability list becomes partially unmet |
| AS-03 | Kubernetes-native, cloud-agnostic; no cloud-provider control-plane adapters in v1 | §14 lists Kubernetes but no cloud provider APIs | Adds EKS/GKE/AKS adapters and their IAM models to scope |
| AS-04 | Performance budgets in §3.3 | The specification sets no numeric targets, but load testing (§17) needs targets to test against | Budgets are revised; no architectural change expected |
| AS-05 | Correlation is primarily deterministic with model assistance | Reliability and auditability; a model-only correlator is hard to evaluate and explain | A model-first correlator would need its own evaluation suite and confidence calibration |
| AS-06 | Free-form command execution is never an action type | Direct reading of §6 "never execute arbitrary model-generated production commands" | If rejected, a fundamentally different and far larger security model is required |
| AS-07 | English-language operational content only in v1 | No multilingual requirement stated | Retrieval, chunking and judge design would need multilingual evaluation |

---

## 6. Requirement coverage statement

Every numbered section of the master specification that states a product requirement
(sections 2–18) is mapped to at least one requirement ID above, and every requirement ID is
mapped onward to a component, phase, validation strategy and acceptance criterion in
[`../architecture/requirements-traceability.md`](../architecture/requirements-traceability.md).

Coverage is checked mechanically by `scripts/validate_docs.py`, which fails if a
requirement ID defined here is absent from the traceability matrix. Sections 1, 19–24 are
process and meta-requirements governing how the project is run; they are traced in the
matrix under the process scope rather than to product components.
