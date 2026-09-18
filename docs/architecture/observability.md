# Observability Architecture

Phase 5 adds bounded OTel ingestion/dispatch spans, stage counters and duration histograms.
Its [telemetry contract](./telemetry-ingestion.md) distinguishes durable receipt decisions,
execution traces and unexported stage spans. No dashboard or performance claim is added.

- **Status:** Authored — Architecture Package (V3 §23 K). **Implemented in Phase 12** at the
  scope in [§10](#10-phase-12-implementation-status); where §4–§7 below differ from what was
  built, §10 and [ADR-0029](../adr/0029-bounded-telemetry-from-committed-records.md) are authoritative.
- **Master specification references:** Sections 9, 10, 11, 23(K)
- **Related:** [`../evaluation/EVALUATION_ARCHITECTURE.md`](../evaluation/EVALUATION_ARCHITECTURE.md) · [`failure-and-recovery.md`](./failure-and-recovery.md)

Section 11 requires more than instrumentation: the harness must make the system
*observable, testable, replayable, evaluable, interruptible, recoverable, permission-aware
and reproducible*, and important behaviour must be reproducible from fixtures and traces.

That converts the trace from a debugging aid into a **system of record**, which is why the
trace model is designed here, in Phase 2, before any node is written.

---

## 1. One trace, three consumers

The single most consequential decision in this document:

> **The trace emitted in production, the trace consumed by the evaluation harness, and the
> trace used to reproduce a bug are the same artifact in the same schema.**

| Consumer | Needs | Served by |
|---|---|---|
| Operator debugging a live incident | Latency, errors, what the agent did and why | Span tree + attributes |
| Evaluation harness | Every decision, input, output, cost, and terminal state | Same spans, read from storage |
| Replay / reproduction | Enough to re-run deterministically | Spans + fixture references + seeds |

The alternative — operational traces plus a separate evaluation log — guarantees divergence,
and the divergence always appears exactly when a production incident needs to become an
evaluation case. Rejecting that alternative is what makes §10's improvement loop possible.

---

## 2. Correlation identifiers

Section 11 and FR-OBS-04 require one identifier chain linking everything.

| Identifier | Scope | Propagation |
|---|---|---|
| `tenant_id` | Everything | Baggage on every span; a partition key everywhere |
| `incident_id` | One incident, its whole lifetime | Baggage; foreign key on every related row |
| `workflow_run_id` | One orchestration run of an incident | Baggage; survives resume; a resumed run keeps the same ID |
| `trace_id` (W3C) | One OTel trace, root at incident open | Standard context propagation |
| `investigation_step_id` | One planner-selected step | Span attribute; foreign key |
| `evidence_id` | One evidence record | Attribute on the span that produced it |
| `action_id` | Proposal → approval → execution → verification | The join key across the whole safety path |
| `tool_execution_id` | One broker invocation | Attribute; foreign key to audit |
| `behaviour_version` | The version tuple that produced the run | Attribute on the root span |
| `evaluation_run_id` | Present only under the harness | Distinguishes evaluation from production traffic |

### 2.1 The join that matters

```
incident_id
  └─ workflow_run_id ──────────── behaviour_version
       ├─ investigation_step_id
       │    └─ tool_execution_id ── evidence_id
       ├─ hypothesis_id ─────────── cites evidence_id[]
       └─ action_id
            ├─ policy_decision_id
            ├─ approval_id
            ├─ execution_id
            └─ verification_id
```

Any evidence record resolves to the exact tool call, arguments and timestamp that produced
it; any action resolves to the evidence that justified it, the rule that authorized it and
the human who approved it. That chain is what makes the audit trail an *explanation* rather
than a log.

---

## 3. Span taxonomy

Every span carries `tenant_id`, `incident_id`, `workflow_run_id` and `behaviour_version`.

| Span | Parent | Key attributes | Status conditions |
|---|---|---|---|
| `incident` | root | severity, services, environment, terminal_state, duration | Error if terminal state is `failed` |
| `correlation` | `incident` | alert_count, signals_used, decision, confidence | |
| `workflow.phase` | `incident` | phase name, entry/exit state | |
| `node.execute` | `workflow.phase` | node_id, node_version, attempt, outcome | Error on typed failure |
| `planner.step` | `node.execute` | gap_declared, task_selected, expected_gain, budget_remaining | |
| `llm.call` | `node.execute` | provider, model_id, prompt_version, input/output tokens, cost, latency, finish_reason, cache_hit | Error on outage or schema failure |
| `tool.invoke` | `node.execute` | tool_name, tool_version, capability, risk_tier, scope, idempotency_key, attempt, outcome | Error on failure |
| `retrieval.query` | `node.execute` | strategy, k, filters_applied, results, top_score, rerank_enabled | |
| `db.operation` | any | statement_kind, table, rows, duration | |
| `policy.evaluate` | `node.execute` | action_id, rule_id, verdict, risk_tier | **Never error** — a deny is a correct outcome |
| `approval.wait` | `workflow.phase` | action_id, required_role, wait_duration, outcome | Error only on system failure, not on rejection |
| `remediation.execute` | `node.execute` | action_id, tool, idempotency_key, outcome, observed_effect | Error on failure |
| `verification.check` | `node.execute` | action_id, criteria_hash, verdict, window, margin | |
| `integration.call` | `tool.invoke` | system, operation, retry_count, rate_limited | |
| `evaluation.score` | harness root | scenario_id, metric, value, judge_version | |

### 3.1 Rules that make spans evaluable rather than merely readable

1. **Every decision span records the alternatives considered**, not just the choice.
   `planner.step` records candidate tasks and expected gains; without them, tool-call
   efficiency cannot be diagnosed, only measured.
2. **Every span records budget state at entry**, so termination is explicable after the fact.
3. **`policy.evaluate` is never an error span.** A denial is the system working. Marking it
   an error would make dashboards punish correct behaviour.
4. **Model outputs are recorded post-validation with schema result**, so `F1`–`F10` failure
   classification is derivable without re-running.
5. **Prompt content is recorded by reference** (`prompt_version` + hash), not inline. Inline
   prompts inflate traces and risk leaking untrusted or sensitive content into telemetry.

---

## 4. Metrics catalogue

Section 11 names the required exposures. **Superseded on labels by ADR-0029:** the original
design dimensioned every metric by `tenant_id`, `environment` and `behaviour_version`. That was
not built and must not be: identifier labels grow series count with traffic and disclose
tenancy through the scrape endpoint. Metrics carry only closed vocabularies
([`catalogue.py`](../../src/asic/observability/catalogue.py)); tenant, incident and version
questions are answered from records and traces. The table is the design inventory; §10 lists
what exists.

| Domain | Metric | Type |
|---|---|---|
| **Lifecycle** | `incidents_opened_total`, `incidents_terminated_total{terminal_state}` | Counter |
| | `incident_duration_seconds` | Histogram |
| | `incidents_active` | Gauge |
| **Latency** | `time_to_first_hypothesis_seconds`, `time_to_terminal_seconds` | Histogram |
| | `node_duration_seconds{node_id}` | Histogram |
| **Errors** | `node_failures_total{node_id,reason}` | Counter |
| | `schema_violations_total{node_id}` | Counter |
| **Model** | `llm_calls_total{provider,model,outcome}` | Counter |
| | `llm_tokens_total{direction}`, `llm_cost_usd_total` | Counter |
| | `llm_latency_seconds{provider,model}` | Histogram |
| **Tools** | `tool_invocations_total{tool,outcome}`, `tool_failures_total{tool,reason}` | Counter |
| | `tool_latency_seconds{tool}` | Histogram |
| **Loop** | `investigation_iterations`, `tool_calls_per_incident` | Histogram |
| | `budget_exhaustions_total{budget_kind}` | Counter |
| **Retrieval** | `retrieval_queries_total`, `retrieval_latency_seconds`, `retrieval_empty_total` | Counter / Histogram |
| **Queue** | `ingestion_queue_depth`, `ingestion_lag_seconds`, `dead_letter_total{reason}` | Gauge / Counter |
| **Safety** | `policy_decisions_total{verdict,risk_tier}` | Counter |
| | `approvals_total{outcome}`, `approval_wait_seconds` | Counter / Histogram |
| | `remediations_total{outcome}`, `compensations_total{outcome}` | Counter |
| | `verifications_total{verdict}` | Counter |
| | **`unsafe_action_attempts_total`** | Counter |
| | **`injection_flags_total{source}`** | Counter |
| **Evaluation** | `evaluation_score{scenario_set,metric}`, `evaluation_regressions_total` | Gauge / Counter |
| **DB** | `db_query_duration_seconds{operation}`, `checkpoint_write_failures_total` | Histogram / Counter |

---

## 5. SLIs and SLOs

Targets are `[ASSUMED]` budgets (AS-04) to be validated in Phase 15, not measurements.

| SLI | Definition | Proposed SLO | Why this matters |
|---|---|---|---|
| Ingestion availability | Successful ingestion ÷ attempts | 99.9% | A dropped alert is an invisible outage |
| Ingestion latency | Receipt → correlation decision | p95 < 5 s | Late correlation is late paging |
| Investigation completion | Terminating within budget ÷ started | 99% | Hangs, not wrong answers, are the failure mode here |
| Time to first hypothesis | Incident open → first ranked hypothesis | p95 < 3 min | The product's core latency promise |
| Approval responsiveness | Request → delivered to a human | p95 < 30 s | Delivery delay steals the human's decision window |
| Execution correctness | Executions with no double-application | **100%** | A correctness invariant, not a target |
| **Unsafe-action rate** | Authorized actions violating an invariant | **0** | Not a percentage. Any occurrence is an incident |
| Verification accuracy | Verdicts matching ground truth in evaluation | Baseline then improve | False success is the most damaging error |
| Trace completeness | Incidents with a complete span chain | 99.9% | An incomplete trace is an unevaluable incident |
| Audit completeness | Executed actions with an audit record | **100%** | Compliance invariant |

Two of these are deliberately not percentages with slack: unsafe actions and audit
completeness. Expressing them as "99.9%" would license a tolerated violation rate for
things that must not happen at all.

---

## 6. Logging and redaction

| Rule | Detail |
|---|---|
| Structured only | JSON; no free-form message-only logs |
| Correlated | Every line carries `tenant_id`, `incident_id`, `workflow_run_id`, `trace_id` |
| Levels | `ERROR` needs human action; `WARN` is degraded-but-handled; `INFO` is lifecycle; `DEBUG` is off in production |
| **Redaction at emission** | Secrets, tokens, credentials, connection strings, PII redacted *before* the record is constructed, never by a downstream filter |
| Untrusted content | Retrieved and log-derived content is truncated and marked `untrusted:true`; never logged verbatim at volume |
| No prompt bodies | Prompts by version and hash; completions by reference |
| Tenant separation | Tenant is a queryable dimension; cross-tenant log access is an authorization decision |

Redaction at emission rather than in the collector is deliberate: a collector-side filter
fails open the moment a new field name appears, and the record has already left the process.

---

## 7. Dashboards

| Dashboard | Audience | Answers |
|---|---|---|
| **Incident operations** | P1 on-call | What is active, how long, which phase, what is stuck |
| **Agent behaviour** | P6 operator | Iterations, tool efficiency, termination mix, budget exhaustion, schema violations |
| **Model and cost** | P6, P3 | Tokens, cost per incident, provider latency, fallback rate, cache hit rate |
| **Safety** | P4, P2 | Policy verdicts by tier, approval outcomes and wait times, remediation and compensation outcomes, **unsafe attempts, injection flags** |
| **Evaluation** | P6, P3 | Scores by version, regressions, judge agreement, calibration drift |
| **Reliability** | P6 | Checkpoint failures, resumes, dead letters, adapter error rates, queue depth |
| **Tenant health** | P3 | Per-tenant volume, duration, escalation rate, cost |

The Safety dashboard is the one shown to P4 during a security review; it is designed to be
readable as evidence that the invariants in
[`remediation-safety-policy.md`](./remediation-safety-policy.md) hold in practice.

---

## 8. Reproducibility from fixtures and traces

Section 11 requires important behaviour be reproducible. Reproduction has three fidelity
levels, and being explicit about which is achievable prevents overclaiming:

| Level | What is reproduced | Requires | Determinism |
|---|---|---|---|
| **L1 Trace inspection** | What happened, in order, with inputs and outputs | Stored trace | Exact — it is a recording |
| **L2 Deterministic replay** | Re-run against frozen fixtures | Trace + fixtures + seeds + behaviour version | Exact for routing and tool calls; model output varies |
| **L3 Counterfactual replay** | Re-run with a *changed* behaviour version | As L2, new version | Divergence is the point |

**L2 is the level the evaluation harness depends on**, and it is achievable only if every
non-deterministic input is captured at the boundary:

| Non-determinism | Captured how |
|---|---|
| Wall-clock time | Frozen `clock_start`; all time from an injected clock, never `now()` |
| Random selection | Seeded PRNG; seed recorded on the root span |
| External system state | Recorded as fixtures at first query; replay serves the recording |
| Model output | Recorded verbatim; L2 may replay the recording or re-invoke, and which was done is recorded |
| Concurrency ordering | Step sequence recorded; replay serialises to the recorded order |

Requirement on every node: **no node reads the clock, generates randomness, or calls an
external system directly.** All three arrive through injected interfaces. This is a design
constraint on implementation, stated now because retrofitting it means rewriting every node.

---

## 9. Tooling decision

Section 13 requires evaluating LangSmith and Arize Phoenix rather than adopting them.

| Option | Assessment |
|---|---|
| **Raw OpenTelemetry + Postgres + Grafana** (chosen for v1) | §11 and §13 already mandate OTel, Prometheus, Grafana and Loki. Our trace requirements are unusual — the trace is an evaluation system of record with a domain schema and tenant isolation — which a general LLM-observability SaaS does not model. Adds no vendor dependency and no data-egress question for tenant telemetry. |
| **LangSmith** | Strong LLM-call tracing and dataset tooling; would duplicate the OTel pipeline we must build anyway, and puts incident telemetry in a third party — a hard conversation with persona P4. |
| **Arize Phoenix** | Good OSS evaluation tracing; self-hostable. **The closest alternative**, and worth re-examining if our own evaluation UI becomes a significant build cost. |

**Decision:** OpenTelemetry-native for v1, with spans following OTel GenAI semantic
conventions where they exist so that adopting Phoenix later is a collector-configuration
change rather than a re-instrumentation. Recorded as
[ADR-0010](../adr/0010-observability-and-evaluation-tooling.md).

**Revisit trigger:** if building evaluation visualisation exceeds roughly two weeks of
effort, or if judge-calibration tooling becomes a project of its own, adopt Phoenix for the
evaluation UI while keeping OTel as the emission layer.

---

## 10. Phase 12 implementation status

Code: `src/asic/observability/` (`catalogue`, `setup`, `lifecycle`, `logging`, `health`,
`tracing`), `src/asic/api/app.py`, `python -m asic.api`. Configuration:
[`configs/observability/`](../../configs/observability/). SLOs:
[`../observability/SLOS.md`](../observability/SLOS.md). Runbooks: [`../runbooks/`](../runbooks/README.md).

| Area | Implemented | Evidence label |
|---|---|---|
| Traces | Every `TraceRecorder` span (kinds in §10.1) is exported through OpenTelemetry with the persisted `execution_trace.trace_id` as its trace id, parented and current while it runs; OTLP/HTTP export when `ASIC_OTEL_TRACES_EXPORTER=otlp`. Evaluation suite and scenario spans carry the trace id they scored | UNIT, LOCAL SERVICE (OTLP receiver), INTEGRATION |
| Span data safety | Attributes pass redaction; failure descriptions bounded and redacted; exception events are never recorded; no prompt bodies | UNIT, INTEGRATION (prompt-injection scenario) |
| Metrics | 51 catalogued instruments; SDK views enforce each label allowlist and explicit buckets, and a wildcard drop view keeps uncatalogued instruments out of the exposition; identifier labels forbidden; caller-controlled values (HTTP method, path) mapped to closed sets | UNIT, INTEGRATION (exposition after real workflows) |
| Lifecycle metrics | Incidents, transitions, terminations, runs, policy verdicts, approvals and wait, action statuses, verifications, authorization denials, model tokens and cost, evaluation results - counted only from committed rows, whether the row was written through the unit of work or by a Core `UPDATE` (which reports what it changed through `RETURNING`, counted on commit and once per transition) | INTEGRATION (commit, rollback, savepoint, Core/ORM cases) |
| Prometheus endpoint | `/metrics` for this process, off unless `ASIC_METRICS_ENABLED`; distinct from the Phase 10 Prometheus adapter | INTEGRATION |
| Logging | JSON lines with fixed envelope, trace correlation, redaction at emission; lifecycle events for API requests, broker refusals and executions, run completion, approvals, notification failures | UNIT |
| Health | `/livez` (no dependencies), `/readyz` (database at the expected schema revision), `asic.dependency.up` | INTEGRATION |
| Dashboards | Seven Grafana dashboards: incident operations, agent behaviour, tool broker and integrations, model usage and cost, remediation safety, evaluation, API health | UNIT (every query checked against the catalogue) |
| SLOs and alerts | Five objectives (INITIAL ENGINEERING TARGET), multiwindow burn-rate alerts, invariant alerts, a runbook per alert | UNIT (`promtool test rules`), LOCAL SERVICE (`promtool check config`) |
| Collector | OTLP traces to Tempo, JSON log files to Loki's OTLP endpoint with only service and environment as stream labels | LOCAL SERVICE (`otelcol-contrib validate`) |

### 10.1 Differences from §3–§7, and why

- **Span kinds.** The kernels emit `workflow.phase`, `node.execute`, `planner.step`,
  `tool.invoke` and `integration.call`; the policy gate, approval, executor and verifier appear
  as `node.execute` spans of those nodes rather than as `policy.evaluate`, `approval.wait`,
  `remediation.execute` or `verification.check`. Model calls are recorded on the span that made
  them, not as `llm.call` spans, so model usage metrics read any committed span carrying
  model-call metadata. Retrieval appears as `knowledge.*` spans; `incident`, `correlation`,
  `db.operation` and `evaluation.score` are not emitted (evaluation uses `evaluation.suite` and
  `evaluation.scenario`).
- **Metrics not built:** `incidents_active` (a gauge across tenants would need an RLS bypass),
  `time_to_first_hypothesis`, ingestion queue depth and lag (no queue exists), redundant-call
  rate, `unsafe_action_attempts_total` (unsafe actions are refused at the broker and appear as
  refusals by stage), checkpoint write failures (a failed checkpoint dead-letters the run, which
  is counted).
- **Dashboards.** "Tenant health" is not built (no tenant labels by design); "reliability" is
  folded into incident operations and API health.
- **Deployment.** Prometheus, Grafana, Loki, Tempo and the collector are not deployed (Phase 14);
  no metric, latency or availability value has been observed from a running deployment.
