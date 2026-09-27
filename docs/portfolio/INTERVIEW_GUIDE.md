# Interview guide

How to present this project honestly in 2, 10 or 45 minutes, and how to answer the questions it
invites. Every claim here points to evidence in the repository.

## 1. The two-minute version

"On-call is expensive because triage is slow and remediation is risky. I built an incident
commander where an AI agent does the investigating — metrics, logs, Kubernetes, deployments,
runbooks — but can only *act* through deterministic boundaries: a tool broker that is the only
egress, a policy gate with no model in it, a human approval bound to the exact action, and an
independent verifier. Tenancy is enforced by the database. I then attacked it: prompt injection
in every input, tool abuse, cross-tenant attacks, crash-at-every-step, chaos on Kubernetes, and a
load harness that found two deadlocks I then fixed. It runs end to end locally with a
deterministic model; I have not run it with a live LLM or in production, and I say so."

## 2. Ten-minute walkthrough

1. **Run the demo** (`python scripts/demo.py`, [DEMO.md](../demo/DEMO.md)): five investigations
   read back from the database, then 18/18 evaluation scenarios.
2. **Show the graph**: [agent topology](../architecture/agent-topology.md) — 12 nodes, why
   proposal, gate, approval, execution and verification are separate.
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
* **"How does it scale?"** One 2-CPU process ingests ≈ 12 alerts/s locally; the API is stateless;
  scaling beyond that is unmeasured; my hypothesis — not yet profiled — is that correlation locks
  become the limit.
* **"What stops the agent from doing something destructive?"** R3 is not expressible; write tools
  have no free-form command fields; the gate is deterministic; R2 always needs a human; approvals
  bind to an action hash; the executor re-checks preconditions; the verifier is independent.
* **"What would you build next?"** A live model behind the gate (GAP-08), a worker Deployment
  (GAP-07), two-replica chaos on a real cluster (GAP-04), and postmortem drafting (GAP-10).
