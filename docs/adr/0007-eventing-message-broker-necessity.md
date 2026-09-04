# ADR-0007: Message broker (Kafka/NATS) — not adopted in v1

- **Status:** Deferred
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §12, §13 (Kafka/NATS listed as "evaluate rather than blindly add")
- **Supersedes / Superseded by:** none

## Context

Alert ingestion is an event stream; §12 requires duplicate-event handling, dead-letter
states and durable processing. Those are broker-shaped requirements, which makes Kafka or
NATS an obvious candidate — and §13 explicitly requires evaluating rather than assuming.

Expected ingestion volume: bursts of tens of alerts per second during an alert storm,
averaging far less. Alerts are also inherently retried by their sources — Alertmanager
re-sends until acknowledged — which changes the durability calculus.

## Decision

**Do not adopt a message broker in v1.** Use an authenticated HTTP ingestion endpoint
writing to a PostgreSQL-backed queue with `SELECT … FOR UPDATE SKIP LOCKED`, idempotency by
alert fingerprint, and an explicit dead-letter table.

## Alternatives considered

### Option A — PostgreSQL-backed queue (chosen)

- **Pros:** No new infrastructure. The queue is transactionally consistent with incident
  state, so "alert consumed" and "incident created" commit together — no dual-write problem.
  Dead-lettering is a table, queryable and replayable with SQL. Trivial local reproduction
  (§14). Idempotency by fingerprint is a unique index.
- **Cons:** Lower throughput ceiling. Polling has latency and database cost. No stream
  replay for other consumers. Retention and partitioning are ours to manage.
- **Cost to adopt:** Zero.

### Option B — Kafka (rejected for v1)

- **Pros:** High throughput; durable retention; replayable streams; natural fan-out to
  future consumers; strong ordering guarantees per partition.
- **Cons:** Substantial operational weight — brokers, coordination, topic management,
  consumer-group semantics, rebalancing. **Introduces a dual-write problem**: consuming an
  alert and creating an incident are no longer one transaction, requiring an outbox or
  idempotent-consumer pattern we would otherwise not need. Heavy for local development,
  which conflicts with §14. Wildly over-provisioned for tens of events per second.
- **Cost to adopt:** High, plus permanent operations.

### Option C — NATS / JetStream (rejected for v1)

- **Pros:** Much lighter than Kafka; good durability with JetStream; simple to run.
- **Cons:** Still a second stateful service and still a dual-write boundary, for a
  throughput problem we do not have. **The strongest alternative** if the trigger fires.
- **Cost to adopt:** Moderate.

## Rationale

Two factors decide it.

First, **transactional consistency**. With a database queue, consuming an alert and opening
an incident happen in one transaction. With a broker, they cannot, and we would need an
outbox or idempotent-consumer pattern to avoid losing or duplicating incidents. That is real
complexity purchased to solve a throughput problem we do not have.

Second, **alerts are already durably retried at the source.** Alertmanager and PagerDuty
re-deliver until acknowledged. Much of a broker's durability value is therefore already
provided upstream; what we must get right is *idempotent consumption*, which is a unique
index on fingerprint regardless of transport.

At tens of events per second, a broker is infrastructure for a scale we do not have and may
never reach. Adopting one now is the §20 keyword-adoption failure.

## Consequences

- **Positive:** No new stateful service; transactional consumption; SQL-queryable
  dead-letter; simple local stack; idempotency by index.
- **Negative / accepted trade-offs:** Lower throughput ceiling; polling latency and database
  load; no stream replay for future consumers; ingestion spikes land on the database.
- **Security and permissions:** Positive — no additional service to secure and isolate.
- **Observability and evaluation:** Neutral; queue depth and lag are ordinary metrics.
- **Failure modes and recovery:** Positive — removes the dual-write failure class.
- **Operational and cost impact:** Clearly positive.

## Reversal cost and revisit trigger

**Reversal cost: moderate.** Ingestion sits behind an `EventIngestor` interface, but
adopting a broker means introducing the outbox pattern the database queue avoids — that is
the real cost, not the transport swap.

Adopt a broker (NATS/JetStream first) when **any** is measured:

- Sustained ingestion above ~200 alerts/second, or bursts causing queue depth to grow
  without recovery.
- A second consumer genuinely needs the alert stream (analytics, a customer-facing feed).
- Queue polling exceeds ~15% of database CPU.
- Multi-region ingestion requires geographic distribution.

## Validation

| Test | Passing criterion |
|---|---|
| Burst handling | 50 alerts/second sustained without queue-depth growth (Phase 15) |
| Idempotency | Duplicate delivery creates no duplicate incident |
| Dead-letter | Malformed alerts captured with reason and replayable |
| Transactional consumption | Crash mid-consume loses no alert and creates no orphan incident |

**None has been run.**

## References

- Master specification §12, §13
- [`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md) §5, §8
