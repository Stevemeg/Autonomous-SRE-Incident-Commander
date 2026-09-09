# ADR-0015: Domain-owned checkpointing, not the LangGraph checkpointer

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** Project owner (Phase 4 approved implementation)
- **Spec reference:** §12
- **Supersedes / Superseded by:** none

## Context

[ADR-0002](./0002-orchestration-langgraph-vs-temporal.md) chose LangGraph with PostgreSQL
persistence, and made one clause the crux of the decision:

> implement the safety-critical durability guarantees — idempotency keys, precondition
> re-validation, reconciliation of unknown outcomes, and the outbox for side effects — **in
> our own code, independent of the engine**.

Phase 4 had to turn that clause into an implementation, which forced a concrete question:
does the run's durable state live in a LangGraph checkpointer, or in our own tables?

The two are not interchangeable, because they answer different questions. A framework
checkpointer stores *the graph's* state — enough to re-enter the graph where it left off. It
knows nothing about whether the evidence row that state refers to was committed, whether the
tool that produced it actually ran, or whether the incident is still in a status that permits
investigation. Those are the questions a resume has to answer correctly, and getting them
wrong is how a resumed run duplicates work or reasons over evidence that does not exist.

A secondary, practical consideration: `langgraph-checkpoint-postgres` uses psycopg 3, while
this project's persistence layer is on psycopg 2 through SQLAlchemy. Adopting it would put
two PostgreSQL drivers, two connection pools and two transaction boundaries in one process —
and the checkpoint would then commit in a transaction *different* from the one the node's
durable writes committed in, which is precisely the divergence a checkpoint exists to prevent.

## Decision

**The kernel owns checkpointing. No LangGraph checkpointer is attached.**

Concretely:

1. A new append-only table, `workflow_checkpoint`, holds one row per node boundary.
2. The kernel streams the graph and commits **once per node**, writing the checkpoint in the
   same transaction as that node's durable effects, spans and audit records.
3. The checkpoint stores only the **ephemeral remainder** — phase, iteration, open gaps, the
   last planner decision, the budget ledger, the capability menu. Evidence, steps and
   hypotheses are not copied into it.
4. Resume rebuilds working state from the durable rows and takes only the remainder from the
   checkpoint. Where the two disagree about how much was written, the rows win and the
   divergence is recorded on the `workflow.resumed` event.
5. Each checkpoint carries a SHA-256 digest of its own state. A checkpoint that fails its
   digest is not resumed from; the run is dead-lettered for inspection.

LangGraph keeps what it is good at: the graph shape, typed state threading, conditional
routing with explicit path maps, and an independent recursion bound.

## Alternatives considered

### Option A — the LangGraph PostgreSQL checkpointer (rejected)

- **Pros:** less code; the framework's documented path; automatic state versioning.
- **Cons:** a second database driver and connection pool in-process; the checkpoint commits
  in a different transaction from the node's domain writes, so a crash between them leaves a
  checkpoint describing work that did not happen; the checkpoint blob becomes a second source
  of truth for evidence the domain tables already own; resume cannot reconcile against
  durable rows because the framework does not know they exist; the persistence API has moved
  faster than our schema, so an upgrade could invalidate in-flight runs.
- **Decisive objection:** it cannot express "the rows win". That is the property that makes
  a resume safe.

### Option B — checkpoint into `workflow_run.checkpoint_ref` (rejected)

- **What it is:** reuse the existing column, storing the latest state as JSONB on the run.
- **Pros:** no new table.
- **Cons:** one reference can only name the *latest* checkpoint. That is enough to resume and
  not enough to diagnose a resume — the operation most likely to go wrong and hardest to
  reproduce afterwards. Overwriting also destroys the sequence, so a lost checkpoint becomes
  undetectable, whereas a gap in a monotonic sequence is exactly the signal we want.

### Option C — domain-owned append-only checkpoints (chosen)

- **Pros:** one transaction boundary; one driver; a checkpoint can never describe rolled-back
  work; the resume reconciles against the system of record; a gapless sequence makes a lost
  checkpoint detectable; the engine becomes genuinely replaceable, which is what keeps
  ADR-0002 reversible.
- **Cons:** more code than delegating, and we own its correctness. Sequence allocation
  serialises on the run row, which is acceptable because exactly one worker holds the lease.

## Consequences

**What this buys.** The guarantee is stateable exactly: *at-least-once node execution, with
effect-level idempotency*. Not exactly-once — a process can die after an adapter answered and
before the commit, and the resumed run will call that adapter again. What cannot happen is a
duplicated effect, because the broker keys every execution on business identity.

**What it costs.** Checkpoint writing, digesting, rehydration and reconciliation are ours to
maintain and ours to get wrong. They are covered by tests that interrupt a run at a real node
boundary and assert the resumed run neither duplicates an effect nor loses one.

**Reversal cost.** Low, and deliberately so. Adopting a framework checkpointer later means
implementing `CheckpointStore` against it; the resume path's reconciliation against durable
rows would stay, because that is the part doing the safety work.

**When to revisit.** If LangGraph's checkpointer gains a way to participate in an externally
supplied transaction, the strongest objection disappears and Option A becomes worth
re-examining.

## Evidence

- `tests/orchestration/test_kernel.py::TestCheckpointing` — one checkpoint per node boundary,
  gapless sequence, digest matches, no evidence content stored.
- `tests/orchestration/test_kernel.py::TestResume` — an interrupted run resumes, reaches a
  terminal state, and records no duplicate idempotency key.
- `tests/db/test_orchestration_schema.py` — the table is tenant-scoped, RLS-forced,
  append-only, and `UPDATE`/`DELETE` are revoked from the application role.
