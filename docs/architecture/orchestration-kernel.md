# Orchestration Kernel

- **Status:** **Implemented and tested** — Phase 4.
- **Master specification references:** Sections 4, 5, 7, 11, 12, 15, 17
- **Related:** [`agent-topology.md`](./agent-topology.md) · [`tool-registry.md`](./tool-registry.md) · [`failure-and-recovery.md`](./failure-and-recovery.md) · [`observability.md`](./observability.md) · [ADR-0015](../adr/0015-domain-owned-checkpointing.md) · [ADR-0016](../adr/0016-deterministic-model-provider.md) · [ADR-0017](../adr/0017-read-only-capability-ceiling.md)

This document describes what Phase 4 built: a deterministic, typed, bounded, tenant-aware
execution substrate on which the investigation agents can safely operate. It is **read-only
and simulator-backed**. Nothing here mutates infrastructure, and nothing here can.

---

## 1. What exists, and what does not

| | |
|---|---|
| **Exists** | Typed graph state · five node contracts, enforced · a LangGraph graph with explicit routing · the tool registry, capability resolver and broker · deterministic simulators for six read domains · a versioned prompt set and a model port · budgets checked before every step · checkpointing and resume · execution traces and audit records · a deterministic terminator |
| **Does not exist** | Remediation planning, the policy gate, approval, execution, verification · alert correlation and ingestion · RAG and governed memory · postmortems · external integrations · the HTTP surface · the frontend · the evaluation harness |
| **Not measured** | Latency, throughput, cost, reasoning quality. No performance figure appears in this document because none has been taken. |

The read-only ceiling is a decision, not an omission: a write capability with no policy gate
in front of it is a capability with nothing authorizing it. See
[ADR-0017](../adr/0017-read-only-capability-ceiling.md).

---

## 2. Graph topology

```mermaid
flowchart LR
    START([start]) --> C["<b>coordinator</b><br/><i>G2 · deterministic</i>"]
    C --> P["<b>planner</b><br/><i>G3 · model-backed</i>"]
    P -->|collect_evidence| E["<b>evidence_collector</b><br/><i>G4 · deterministic</i>"]
    P -->|form_hypothesis| H["<b>hypothesis_engine</b><br/><i>G5 · model-backed</i>"]
    P -->|terminate| T
    E --> T["<b>terminator</b><br/><i>G2 · deterministic</i>"]
    H --> T
    T -->|continue| P
    T -->|terminal| END([end])
```

Five graph nodes implementing four of the twelve approved components. `G1` alert
correlation is Phase 5; `G6`–`G10` are the remediation path; `G11`–`G12` are post-incident.
The coordinator contributes two nodes — entry routing and termination — under separate
contracts, so the node that starts a run is not the node that can end it.

Two structural properties, asserted by tests rather than by inspection:

- **Every edge is explicit.** Both conditional edges are given a complete `path_map`, so a
  router returning an unmapped value fails at construction rather than falling through.
- **Every path terminates.** The one cycle passes through the planner, where the budget is
  checked before anything is spent. LangGraph's `recursion_limit` is set from the iteration
  budget as a second, independent bound — a backstop that should never be the thing that
  fires, capped so that a misconfigured budget still cannot produce an unbounded run.

---

## 3. State: four kinds, kept apart

| Kind | Where it lives | Who writes it |
|---|---|---|
| **Durable domain** | `incident`, `investigation_step`, `evidence`, `hypothesis`, `tool_execution` | Nodes, through the persistence layer. **The system of record.** |
| **Ephemeral graph** | `GraphState`, threaded between nodes | Nodes, within their contracts. Rebuilt from durable rows on resume. |
| **Execution trace** | `execution_trace`, `trace_span` | The trace recorder. Append-only. |
| **Audit** | `audit_record` | The broker and the coordinator. Append-only. |

`GraphState` carries **references and scalars, never payloads**. An evidence reference names
an id, a domain, a quality score and a 240-character headline; the log lines stay in
`evidence.content`. Three reasons, and the first is the important one:

1. a checkpoint containing copies of evidence is a **second source of truth**, and the two
   diverge the first time a resume lands on a partial write;
2. untrusted operational content in a checkpoint spreads customer log data into a store with
   a different retention policy;
3. accumulated model messages are the classic way an agent's context and cost grow without
   bound — so there is no `messages` key, and no field able to hold a prompt or a credential.

---

## 4. Node contracts

Every node declares the twelve attributes section 4 requires, and three of them are
**enforced** rather than published:

| Declared | Enforced how |
|---|---|
| `permitted_state_keys` | The kernel validates every returned update; a key outside the contract raises `ContractViolation` |
| `capabilities` | The broker refuses any request whose calling node does not declare the capability |
| `audit_events`, `span_kind` | Contract tests assert a node that stops emitting fails the build |

| Node | Model? | Capabilities | May terminate? |
|---|:-:|---|:-:|
| `coordinator` (G2) | No | none | No |
| `planner` (G3) | Yes | **none** | Proposes only |
| `evidence_collector` (G4) | No *(see §9)* | six `read.*` | No |
| `hypothesis_engine` (G5) | Yes | none | No |
| `terminator` (G2) | No | none | **Yes, solely** |

The planner declaring no capabilities is the design, not an oversight: it reasons about what
to ask and is structurally incapable of asking. Exactly one node can reach an external
system, and it reaches it through the broker.

---

## 5. The tool broker

```
node
  → request validation      does the calling node's contract declare this capability?
  → tenant context          does the bound tenant match the broker's scope?
  → capability resolution    registered, granted for this tenant and environment, on the menu?
  → risk boundary           within the deployment's ceiling? (re-checked, not trusted)
  → argument validation     typed; scope resolved from the incident, never supplied
  → idempotency             has this exact effect already been recorded?
  → adapter invocation      with a deadline, retried per operation class
  → result validation       typed; a malformed result is a failure, not a default
  → audit                   emitted on every path, including refusal
  → trace                   span with tool, version, scope, outcome, duration
```

Three properties are load-bearing, and each has tests written to break it:

**It fails closed.** Every stage's error path leads to a refusal. There is no default-allow
branch and no swallowed exception.

**A node cannot bypass it.** Nodes receive a broker, never a provider. An import-graph test
parses every node module's AST and fails if one imports a provider, a simulator or the
registry — so the property survives future edits rather than resting on convention.

**A failure is never a success.** A refused, failed or timed-out call returns a typed
failure naming the stage that produced it, with an empty payload. Nothing in the broker can
return a plausible-looking result in place of one that did not arrive.

### 5.1 Least privilege

The effective capability set is the intersection of five independent inputs — the bound
tenant, the incident's environment, the calling node's contract, `tenant_tool_grant`, and
the risk ceiling. Nothing in the resolver reads retrieved content or model output; its
inputs are a bound tenant, database rows and a node contract, all `SYSTEM` provenance.
There is no parameter through which a log line could reach it.

### 5.2 Scope is resolved, never supplied

`tenant_id`, `environment`, `service` and `namespace` are marked `scope_resolved` on every
descriptor. A caller supplying one is **rejected, not overwritten** — overwriting would hide
an attempt to widen scope instead of surfacing it. The service must already be one the
incident is about, so choosing between them narrows within an existing bound.

### 5.3 Idempotency and retry

A tool execution is keyed on the *effect* — tenant, tool, major version, and the scope
arguments the descriptor nominates — and is unique per tenant in the database. A repeated
request returns the recorded execution without reaching the adapter. Retry is classified per
operation (`failure-and-recovery.md` §1): a pure read is retried, an empty result never is
(it is a finding), and a malformed result never is (the adapter would produce the same shape
again, and a repaired result would be data we invented).

Timeouts are enforced by running the adapter call on a worker thread with a deadline, so the
deadline binds *for the caller* even if an adapter blocks. The abandoned thread may still
complete — which is precisely why a write timeout is an unknown outcome to be reconciled
rather than a failure to be retried. Every tool here is read-only, so an abandoned read has
no effect to reconcile.

---

## 6. Bounded autonomy

Budgets are checked **before** a step, never after. Checking afterwards means the step that
broke the limit already cost its tokens, its latency and its tool call; checking beforehand
means exhaustion produces a clean partial result with everything gathered so far intact.

| Dimension | Default | Enforced at |
|---|---:|---|
| Planning iterations | 12 | Planner, before the model call |
| Tool calls | 40 | Collector, before the broker call |
| Wall clock | 6 h | Terminator |
| Tokens | 200 000 | Charged after each model call, checked before the next |
| Cost (USD) | 5.00 | As above |

These are *configured* limits, not measured ones. No load test has been run and nothing
claims they are right for production traffic.

A refusal is recorded explicitly as `budget_refusal`, because the ledger alone cannot express
it: the refusal happens before the cost is paid, so a run stopped by a budget still looks
under-budget afterwards. Without that signal the terminator could not tell "we ran out of
allowance" from "we ran out of ideas".

### 6.1 Deterministic overrides of the planner

The model's choice is a *proposal*. Four deterministic rules can override it, and each
override is recorded with its reason:

| Situation | Response |
|---|---|
| Output will not parse | One repair attempt — a fresh request, not the same one resent — then a typed failure |
| Domain maps to a capability not on the menu | **Rejected, never repaired.** Repair would teach the loop that asking for ungranted capability is a negotiation |
| Domain already covered, same gap | Converted to hypothesis formation; a repeat spends budget without closing anything |
| Budget exhausted | Terminates, before the model is called |

### 6.2 Reflection

Not implemented, and deliberately. The loop is plan → collect → analyse → plan, bounded by
iteration and tool-call budgets. A critique-and-revise cycle needs the evaluation harness to
show whether it improves anything; adding it now would add cost and latency to a system that
cannot yet measure the benefit, which is the shape of adding a feature because the project
is called agentic. Phase 7 owns it.

---

## 7. Termination

Ordered, total, and deterministic. Every run leaves with exactly one verdict, naming the
rule that produced it.

| # | Rule | Reason | Incident status |
|---|---|---|---|
| R1 | Unrecoverable node failure | `unrecoverable_failure` | `failed` |
| R2 | Wall clock exhausted | `wall_clock_timeout` | `uncertain` |
| R3 | Any other budget exhausted or refused | `budget_exhausted` | `uncertain` |
| R4 | Planner stopped **and** the evidence supports an actionable cause | `human_escalation` | `escalated` |
| R5 | Planner stopped without one | `insufficient_evidence` | `uncertain` |
| R6 | *(matches unconditionally)* — continue | — | — |

**`resolved` is not reachable, and that is correct.** This deployment gathers evidence and
forms hypotheses; it cannot remediate, so it cannot verify that anything was fixed. An
actionable cause is handed to a human — `escalated`, one of section 5's five categories.
Reporting resolution would claim an outcome the system did not produce.

R4 requires four conditions, all necessary: confidence at or above 0.55, at least two
supporting records, **zero** contradicting records, and at least half the attempted domains
answering. The model's stated confidence is only one of the four, and on its own the weakest.

---

## 8. Distinguishing fact from claim

Three mechanisms, all code rather than prompt instructions.

**Provenance is assigned by the broker.** A node cannot label its own output a verified
fact. A telemetry result is `VERIFIED_FACT`; a knowledge-base document is `RETRIEVED` —
citable, never authoritative. The database refuses anything authority-bearing on an evidence
row.

**Citation integrity is enforced before ranking.** Every evidence id a hypothesis cites is
checked against the persisted set for that incident. A hypothesis citing an id that does not
exist is dropped entirely — not partially kept — so hallucinated citation is an impossible
state rather than a low score. The foreign key on `hypothesis_evidence` makes it impossible
a second time.

**Confidence has a deterministic ceiling.** The model states a number; the node computes a
maximum from the evidence actually available and stores the lower of the two, with both
numbers and the derivation in `confidence_basis` so calibration is measurable later.

| Evidence | Ceiling |
|---|---:|
| None supporting | 0.10 |
| Anything contradicting | 0.35 |
| One supporting record | ≤ 0.40 |
| Two or more, no contradiction | 0.45 + 0.1·min(n,4) + 0.2·quality, capped at 0.95 |

A record cited as both supporting and contradicting counts only as counter-evidence. That is
not tidying up an ambiguous output: counting it twice would inflate the support count, which
is an input to the ceiling — a way to buy confidence by citing the same record twice.

---

## 9. The model boundary

ADR-0005's thin internal interface: one method, taking a rendered prompt and returning text
plus the metadata a trace needs. A provider returns **text, not objects**, so parsing and
validation happen in the node where they can be tested — and one scenario deliberately
returns unparseable output to exercise that path.

**No provider SDK is wired in this phase** ([ADR-0016](../adr/0016-deterministic-model-provider.md)).
The only implementation replays scripted responses from a scenario. Reasoning quality is a
Phase 7 concern and cannot be evaluated before the Phase 11 harness exists; a live provider
now would make every test non-deterministic and every run cost money in exchange for nothing
this phase can measure. The seam is what this phase owes.

**The evidence collector is narrowed away from the model.** The approved topology gives G4
six model-assisted strategies; this implementation has six strategies and no model call.
Collection and normalisation are deterministic, so the first vertical slice has no model
between a tool result and the evidence record derived from it — which is exactly where a
fabricated observation would be hardest to detect. Recorded on the node contract as
`model_backed=False` with a test asserting the divergence from `NodeId.uses_model` is
deliberate.

### 9.1 Prompt handling

Prompts are versioned and referenced by content hash, never inlined into a trace. Untrusted
content reaches only a dedicated data slot, fenced and with marker-like text neutralised
first, so a payload cannot close the fence early and escape into the instruction position.
There is no code path that concatenates retrieved content into an instruction — which is
what makes the resistance structural rather than a request politely made of the model.

---

## 10. Durability

### 10.1 The guarantee, stated exactly

> **At-least-once node execution, with effect-level idempotency.**

Not exactly-once. A process can die after an adapter has answered and before the transaction
commits, and the resumed run will call that adapter again. What cannot happen is a duplicated
*effect*: the broker keys each execution on business identity and returns the recorded result
instead of invoking twice; a resumed run recomputes the same step sequence and the same keys.
Calling this exactly-once would be a claim the design does not support.

### 10.2 One transaction per node

The kernel streams the graph and, at each node boundary, validates the update against the
node's contract, flushes its spans, writes a checkpoint and commits — all in the transaction
the node itself ran in. A crash therefore leaves the run *at a boundary* rather than halfway
through one, and a checkpoint can never describe work that was rolled back.

### 10.3 Resume reconciles

The resume path does not trust the checkpoint for anything the durable rows can answer.
Evidence, steps and hypotheses are re-read from their tables; the checkpoint supplies the
ephemeral remainder — phase, open gaps, last decision, budget ledger. Where they disagree
about how much was written, **the rows win** and the divergence is recorded on the
`workflow.resumed` event. A checkpoint failing its own SHA-256 digest is not resumed from at
all; the run is dead-lettered for inspection rather than resumed from a guess.

### 10.4 Leasing

A single conditional `UPDATE` claims the lease, so two orchestrators racing produce one
winner. Losing stops work immediately rather than retrying: two orchestrators advancing one
incident is the failure with the worst consequence this system can have. The lease outlives
the longest node timeout, so a slow node cannot lose a lease it is still using.

---

## 11. Observability

Every span is emitted twice from one description — an OpenTelemetry span for live tooling,
and a `trace_span` row that is durable, tenant-scoped and queryable. One trace serves
operations, replay and evaluation.

Span identifiers are **ours**, derived from the trace and an ordinal rather than randomly, so
a replay produces identical identifiers; the OTel span carries ours as an attribute so the
two views join. A resumed run continues the numbering, because it is the same trace.

Every node span carries: tenant, incident, run, node id and version, budget headroom at
entry, the decision and the alternatives weighed, and — where applicable — evidence
references, tool execution id, provider, model, prompt version and hash, tokens, cost,
confidence, failure and termination reason. **No prompt text, no tool payloads, no
credentials**: everything written passes through redaction at emission, because filtering on
read cannot un-write a secret.

No exporter is configured. Wiring one is deployment configuration and belongs to Phase 12;
with no provider configured the SDK's no-op meter absorbs the calls, which keeps the
instrumentation honest — it is emitted whether or not anyone is collecting.

---

## 12. Security invariants exercised

| Invariant | How it holds here | Adversarial test |
|---|---|---|
| SEC-I2 tenant isolation | Tenant comes from the bound session; RLS on all 31 tenant-scoped tables | A request naming another tenant is refused; a cross-tenant service is refused |
| SEC-I3 authorization before execution | The broker is the sole egress; nodes hold no provider | Import-graph test over every node module |
| SEC-I4 retrieved content cannot grant authority | The resolver reads no model output and no retrieved content | Injected capability grant, tenant switch and approval bypass all inert |
| SEC-I5 injection resistance is structural | The menu is resolved before the model is invoked | Hostile log line and poisoned runbook: recorded, flagged, no change in reach |
| SEC-I6 no secrets in traces | Redaction at emission; prompts by hash | Secret-shaped values asserted redacted; spans scanned |
| SEC-I7 auditability | Broker emits on allow and on refuse | Every execution reconciled against an audit record |
| SEC-I8 fail closed | Every stage's error path refuses | Unknown, ungranted, disabled and out-of-tier capabilities |
| SI-2 no action outside the catalogue | No argument kind can carry a command; field names checked | Descriptor construction refuses a `command` argument |
| SI-5 R3 not expressible | `ToolDescriptor` refuses tier R3 at construction | Catalogue asserted read-only at start-up and by the boundary validator |

---

## 13. Failure handling

| Failure | Response |
|---|---|
| Malformed node output | One repair attempt, then a typed failure; never coerced |
| Model provider outage | Recorded as a recoverable failure; the run terminates with what it has rather than hanging |
| Tool timeout | Typed failure; the domain is degraded, the investigation continues |
| Tool error (permanent) | Class C5 — not retried; the domain is degraded |
| Tool error (transient) | Class C1 — retried with backoff |
| Duplicate tool request | Recorded execution returned; the adapter is not reached |
| Malformed tool result | Class C6 — rejected, never retried, never coerced |
| Unavailable evidence source | Step marked `degraded` with its reason; coverage recorded |
| Checkpoint digest mismatch | Refused; the run is dead-lettered rather than resumed from a guess |
| Database failure | The unit of work rolls back; the run is dead-lettered |
| Budget exhaustion | Clean partial result, correct termination reason |
| Contradictory evidence | Confidence ceiling applied; not escalated as a cause |
| Insufficient evidence | `uncertain` — a correct outcome, not a failure |
| Unauthorized capability | Refused at the broker and audited |
| Missing tenant context | RLS denies everything; `require_tenant` raises rather than returning empty |

No silent fallback to fabricated data, and no `success` status after an exception.

---

## 14. What Phase 11 will consume

Each scenario declares a `ScenarioExpectation`: the expected termination reason and incident
status, the domains a competent investigation should consult, the expected root-cause class
where there is one, the domains expected to degrade, and whether injection should be flagged.
The end-to-end suite asserts runs against those expectations today; the evaluation harness
will score against the same declarations without redesigning the execution model.

The trace carries the frozen clock, the random seed and the fixture reference, so a run is
reproducible rather than merely re-runnable. **Nothing here computes a score, and no
improvement is claimed.**

---

## 15. Running the vertical slice

```bash
export ASIC_MIGRATION_DATABASE_URL=postgresql+psycopg2://asic_owner:<password>@localhost:55432/asic
export ASIC_DATABASE_URL=postgresql+psycopg2://<app_login>:<password>@localhost:55432/asic
python -m alembic upgrade head
python -m asic.orchestration.service --scenario SC-0001-checkout-latency-after-deploy
```

Seeding a demonstration tenant uses the administrative URL; the investigation itself runs as
the application role, under row-level security, exactly as it would in production. Creating a
tenant is an administrative operation and the application role has no `INSERT` on the global
catalogues — widening it to make a demo convenient would undo that.

---

## 16. Known limitations

Stated because they are real, not because they are comfortable.

| Limitation | Consequence | Where it is addressed |
|---|---|---|
| No real model provider | Reasoning quality is untested and unclaimed | Phase 7, with Phase 11 to measure it |
| No real adapters | Behaviour against live telemetry is unproven | Phase 10 |
| Single-service evidence collection | A multi-service incident collects for the first service in scope | Phase 7 analyser strategies |
| Concurrency under a shared pool untested | Lease correctness is tested; contention is not measured | Phase 15 |
| No performance measured | No latency, throughput or cost figure exists | Phase 15 |
| Node-level timeouts declared but not preemptively enforced | A node that hangs is bounded only by the tool deadline inside it | Phase 12, with async execution |
| Wall-clock budget advanced by the injected clock | Under `SystemClock` it tracks real time; the tests drive it explicitly | — |
