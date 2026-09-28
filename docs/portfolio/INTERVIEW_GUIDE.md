# Interview guide

How to present this project honestly in 2, 10 or 45 minutes, and how to answer the questions it
invites. Every claim here points to evidence in the repository.

## 1. The two-minute version

"On-call is expensive because triage is slow and remediation is risky. I built an incident
commander where an AI agent does the investigating — metrics, logs, Kubernetes, deployments,
runbooks — but can only *act* through deterministic boundaries: a tool broker that is the only
egress, a policy gate with no model in it, and an independent verifier. Anything high-risk, and
anything in production, needs a human approval bound to the exact action; only low-risk
reversible actions outside production may run on their own. A worker drives it from PostgreSQL,
and resolved incidents get a cited, draft-only postmortem. Tenancy is enforced by the database. I
then attacked it: prompt injection in every input, tool abuse, cross-tenant attacks,
crash-at-every-step, chaos on Kubernetes, and a load harness that found two deadlocks I then
fixed. It runs end to end locally and on kind with a deterministic model; I have not run it with
a live LLM or in production, and I say so."

## 2. Ten-minute walkthrough

1. **Run the demo** (`python scripts/demo.py`, [DEMO.md](../demo/DEMO.md)): five investigations,
   a worker killed mid-run and recovered, then the API and worker as separate processes taking an
   alert through human-approved remediation, verification and a postmortem draft, then 18/18
   evaluation scenarios — every outcome read back from the database.
2. **Show the graph**: [agent topology §0](../architecture/agent-topology.md) — as built, 10
   LangGraph nodes (5 investigation, 5 remediation) plus the G11 postmortem stage; 4 components
   call a model. Explain why proposal, gate, approval, execution and verification are separate,
   and why the design's 12 became this.
3. **Show one safety boundary in code**: the broker's `_provenance_for` (only the broker can say
   `verified_fact`), or the approval's action-version hash.
4. **Show one finding**: the pool deadlock ([LOAD_AND_PERFORMANCE.md §3](../testing/LOAD_AND_PERFORMANCE.md#3-defects-the-harness-found-fixed)),
   with its before/after numbers and regression test.
5. **Close with the gap register** ([PRODUCTION_GAP_REGISTER.md](../PRODUCTION_GAP_REGISTER.md)):
   what I would do next and why.

## 3. Design decisions worth discussing

| Decision | Why | Trade-off | ADR |
|---|---|---|---|
| LangGraph for the graph, durability in my own code, not Temporal | Graph semantics fit agent loops; checkpoints are domain rows I can query, replay and audit | I own leases, resume and idempotency | [0002](../adr/0002-orchestration-langgraph-vs-temporal.md), [0015](../adr/0015-domain-owned-checkpointing.md) |
| PostgreSQL + pgvector as the only datastore | One transactional boundary for evidence, audit and vectors; RLS for tenancy | No specialised vector features | [0004](../adr/0004-postgresql-pgvector-primary-datastore.md) |
| Deterministic correlation, deterministic policy | Authorization and incident identity must be explainable and replayable | Less "smart" grouping | [0019](../adr/0019-transactional-signal-ingestion.md), [0025](../adr/0025-freeze-remediation-authority-before-effects.md) |
| A thin model port instead of LiteLLM | Budgets are reserved before every call; the port is tiny and testable | One adapter per provider to write | [0005](../adr/0005-llm-provider-abstraction.md), [0016](../adr/0016-deterministic-model-provider.md) |
| No Redis, no Kafka | No measured need; each ADR names the trigger that would change it | Synchronous ingestion caps throughput per process | [0006](../adr/0006-redis-necessity.md), [0007](../adr/0007-eventing-message-broker-necessity.md) |
| Retention executor for one table only | The only data that genuinely expires without breaking evidence or lineage | Other classes grow until prerequisites exist | [0032](../adr/0032-bounded-retention-executor.md) |
| A PostgreSQL-polling worker, not a queue | The database is already the system of record with leases and idempotency; a broker would add a second source of truth | Discovery cost grows with tenant count (GAP-07) | [0007](../adr/0007-eventing-message-broker-necessity.md) |
| G11 as a post-incident stage, not a graph node | Postmortems apply to incidents resolved with or without a run, and are idempotent per record set | One more worker job kind instead of a graph edge | [agent topology §0](../architecture/agent-topology.md) |

## 4. Stories (problem → evidence → fix → proof)

* **The load test that found two deadlocks.** At 50 alerts/s, 96 % of requests timed out and 15
  connections sat "idle in transaction". The ingestion handler held its request's pooled connection
  while ingestion took a second one. After fixing it, a 96-client burst still timed out: the
  request session bound the tenant — checking out a connection — in one threadpool call, and
  FastAPI validates a sync endpoint's result in another, so requests held connections while waiting
  for threads. Fixes: check scope in a short separate transaction; bind at transaction begin in the
  endpoint's thread; commit and release inside that thread; add an ingestion bulkhead. Each fix has
  a test that fails on the old code. I also ran a control with the old image when latency looked
  worse afterwards — it was the host, not the fix.
* **Quadratic redaction.** A 20 KB hostile log line took 51 s to redact. Rewrote the patterns with
  atomic groups and possessive quantifiers, proved equivalence on a seeded corpus, and added
  100 KB timing tests.
* **Migrations that could overlap.** Deleting a Kubernetes Job does not stop its pod. The deploy
  orchestrator now waits for previous migration pods, bounded and fail-closed; a live chaos
  experiment holds a SIGTERM-ignoring pod and shows at most one migration pod ever runs, with a
  bypass control that shows two.
* **A chaos experiment that failed first.** My Postgres-restart experiment declared that
  `/readyz` would flip; it didn't, because the restart (≈ 2 s) was shorter than the readiness
  cache. I recorded the failure, fixed the expectation and used a separate sustained-outage
  experiment for readiness.

## 5. Hard questions and honest answers

* **"Does it work with a real LLM?"** Not tested. The model port, budgets and prompts are real;
  the provider is deterministic. The evaluation gate is how I would admit a real model.
* **"How good is the RCA?"** Unmeasured for a real model. RCA@1 = 1.0 in simulation only proves
  the pipeline routes evidence correctly; the scenarios were written for it.
* **"Is it production-ready?"** No. It is ready for a controlled pilot once the external
  prerequisites exist; see the [readiness review](../PRODUCTION_READINESS_REVIEW.md).
* **"How does it scale?"** One 2-CPU process ingests ≈ 12–21 successful alerts/s locally, well below
  the 50/s I had assumed; the API is stateless;
  scaling beyond that is unmeasured; my hypothesis — not yet profiled — is that correlation locks
  become the limit.
* **"What stops the agent from doing something destructive?"** R3 is not expressible; write tools
  have no free-form command fields; the gate is deterministic; R2 always needs a human; approvals
  bind to an action hash; the executor re-checks preconditions; the verifier is independent.
* **"Is every action human-approved?"** No, and the distinction matters. The deterministic
  autonomy matrix allows only R1 (reversible, low-risk) actions in non-production to run without a
  human (rule P6); R1 in production and every R2 require an approval bound to the action's version
  hash; R3 is not expressible. The responder who requested a remediation cannot approve it.
* **"How does the worker work?"** It polls PostgreSQL per tenant for durable work — investigation
  dispatches, remediation requests, suspended runs with something new to act on, resolved
  incidents without a postmortem — and claims each with a session-scoped advisory lock. The lock
  is an efficiency; the kernel lease, the one-live-run index and effect idempotency are the safety
  argument, which is why two racing workers produce one execution and a killed worker's run is
  resumed without repeating an effect. SIGTERM stops claiming and drains; a running node is not
  preemptible, so an unfinished one is recovered by lease (GAP-34). Its live profile refuses to
  start because no live model exists — I would rather it not start than fabricate reasoning.
* **"How do you stop the postmortem from hallucinating?"** Facts are not generated: timeline, root
  cause, remediation and verification are assembled from typed columns and cite the records they
  came from. The model writes only summary and lessons, citing record handles; a deterministic
  validator drops anything uncited, citing a foreign record, resting only on injection-flagged
  evidence, asserting a cause other than the recorded root-cause hypothesis, or stating a number the
  cited records don't contain, and lists it under uncertainties. It cannot judge a faithful
  paraphrase — that needs a labelled evaluation with a real model (GAP-37). The database refuses
  any row that isn't an unreviewed draft.
* **"Is data encrypted?"** In transit to the database: a production process refuses to start
  without `sslmode=verify-full` and a CA, checked before any connection. At rest: that is the
  managed database's job and I have not deployed one (GAP-03), so NFR-SEC-07 is partial.
* **"What is missing from the design?"** G12: governed memory promotion exists and is enforced by
  the database, but nothing proposes promotions, so the product does not learn from incidents yet
  (GAP-31); and there is no historical-incident retrieval (GAP-33). Multi-service incidents collect
  evidence for the first service only (GAP-32). The worker does not send notifications (GAP-38).
* **"What would you build next?"** A live model behind the gate (GAP-08) — it unblocks the
  production worker and a real evaluation — then two-replica chaos on a real cluster (GAP-04), the
  G12 learning trigger (GAP-31) and a postmortem review workflow (GAP-30).
