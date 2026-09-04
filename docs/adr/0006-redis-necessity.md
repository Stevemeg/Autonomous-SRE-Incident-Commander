# ADR-0006: Redis — not adopted in v1

- **Status:** Deferred
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §13 ("Redis where justified")
- **Supersedes / Superseded by:** none

## Context

Section 13 lists Redis in the baseline stack with the qualifier **"where justified"** — the
only baseline entry carrying that condition, which reads as an explicit invitation to
justify rather than assume.

Candidate uses in this system: caching telemetry query results, rate limiting, distributed
locking for workflow leases, a task queue, and short-term agent context.

## Decision

**Do not adopt Redis in v1.** Each candidate use is served adequately by PostgreSQL at
expected scale. Record the specific, measurable triggers that would justify adopting it.

## Alternatives considered

### Option A — No Redis; PostgreSQL for everything (chosen)

| Candidate use | PostgreSQL approach | Adequate? |
|---|---|---|
| Telemetry result caching | Evidence records are already persisted and reused within an incident | Yes — the natural cache is the evidence table |
| Rate limiting | Token-bucket rows with row-level locking, per tenant/source | Yes at expected request volume |
| Workflow leases | `SELECT … FOR UPDATE SKIP LOCKED` with heartbeat columns | Yes — and transactionally consistent with workflow state |
| Task queue | `SKIP LOCKED` queue table | Yes at expected job volume |
| Short-term context (T2) | Assembled per model call, never persisted | Not needed |

- **Pros:** One stateful service. Leases stay transactionally consistent with the workflow
  state they protect — a genuine correctness advantage, not merely simplicity. No cache
  invalidation class of bug. Simpler local reproduction (§14).
- **Cons:** PostgreSQL carries load Redis would absorb. `SKIP LOCKED` queues are slower than
  a purpose-built broker.
- **Cost to adopt:** Zero.

### Option B — Adopt Redis now (rejected)

- **Pros:** Faster caching and rate limiting; mature primitives; removes queue load from the
  primary database.
- **Cons:** A second stateful service to run, secure, back up and isolate per tenant. **A
  distributed lock in Redis is not transactionally consistent with PostgreSQL workflow
  state**, which introduces exactly the split-brain risk failure-and-recovery §3.3 works to
  eliminate. Cache invalidation bugs. Adds a component with no measured need — the §20
  keyword-adoption failure.
- **Cost to adopt:** Moderate, plus permanent operational overhead.

## Rationale

The decisive factor is the **workflow lease**. Redis is the conventional choice for
distributed locking, but our leases guard remediation execution, where a split-brain double
execution is the worst failure the system can produce (F6/F1). A `FOR UPDATE SKIP LOCKED`
lease in the same transaction as the workflow checkpoint is *more* correct than a Redis
lock, because lease and state cannot diverge. Here the simpler choice is also the safer one.

For the remaining uses, expected scale — tens to low hundreds of incidents per day — does
not stress PostgreSQL. Adopting a second stateful service to solve a load problem we have
not measured is precisely what §13's "where justified" and §20's keyword rule forbid.

This is `Deferred` rather than `Rejected`: the analysis stands, and the triggers below are
concrete enough to act on.

## Consequences

- **Positive:** One stateful service; transactionally consistent leases; simpler local
  stack, deployment and security review.
- **Negative / accepted trade-offs:** PostgreSQL is a busier single point; queue and rate
  limiting are slower; a burst of ingestion load lands on the database.
- **Security and permissions:** Positive — one datastore to isolate per tenant.
- **Observability and evaluation:** Neutral.
- **Failure modes and recovery:** Positive — removes a lock/state divergence failure mode.
- **Operational and cost impact:** Positive.

## Reversal cost and revisit trigger

**Reversal cost: low.** Caching and rate limiting sit behind interfaces; adopting Redis is
an implementation swap. **Leases would deliberately stay in PostgreSQL even if Redis is
adopted**, for the consistency reason above.

Adopt Redis when **any** is measured:

- Ingestion sustained above ~50 alerts/second with rate-limit contention on the database.
- Queue polling contributes more than ~15% of database CPU.
- Repeated identical telemetry queries across concurrent incidents become a measurable cost
  (an evidence-cache hit rate worth exploiting).
- p95 API latency breaches its budget with database contention identified as the cause.

## Validation

| Test | Passing criterion |
|---|---|
| Queue throughput | `SKIP LOCKED` sustains target job rate (Phase 15) |
| Lease correctness | No split-brain under forced contention |
| Rate limiting | Enforced accurately under burst load |
| Database headroom | CPU and connection use within budget at target load |

**None has been run.** If any fails, this ADR is revisited immediately.

## References

- Master specification §13
- [`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md) §3.3
