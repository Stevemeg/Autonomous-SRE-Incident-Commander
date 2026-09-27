# ADR-0032: A bounded retention executor for the idempotency cache only

- **Status:** Accepted
- **Date:** 2026-09-26
- **Deciders:** Project owner
- **Spec reference:** NFR-SEC-14; sections 12, 15 and 20 of docs/spec/MASTER_PROJECT_PROMPT_V3.md
- **Supersedes / Superseded by:** none (narrows the "no retention Job" boundary of ADR-0031)

## Context

Phase 13 classified every table, validated tenant retention policies and built a dry-run planner,
but nothing could delete anything: the application role holds no `DELETE` (migration 0018), and
ADR-0031 shipped no retention Job "until a bounded executor and durable receipt exist". The API
idempotency replay cache (`api_idempotency_record`) is the one class whose value genuinely expires
- it holds request digests and response bodies for a replay window - so keeping it forever is a
slow, unbounded growth of stored request data. Every other class carries evidence, replay,
verification lineage or memory governance that time-based deletion could break.

## Decision

Add the smallest executor that can be safe: it deletes only expired idempotency records, as a
separate `asic_maintenance` role (migration 0019) granted to a login that is never mounted into
API pods, one tenant per transaction under the existing row-level security, in bounded
oldest-first batches, dry run by default, with each batch committed together with an immutable
`retention_run` receipt. Ship it as a suspended, dry-run CronJob. Delete nothing else.

## Alternatives considered

### Option A — executor for the idempotency cache only, separate role, receipts (chosen)

- **What it is:** fixed table and predicate in code, least-privilege role, receipts as evidence.
- **Pros:** closes the one real unbounded-growth path; every property is enforced by the database
  as well as the code; nothing that is evidence can be touched.
- **Cons:** one more role and table to operate; other classes still grow until their
  prerequisites exist.
- **Cost to adopt:** one migration, one module and CLI, one CronJob; 20 tests and a kind check.

### Option B — a general executor over every time-eligible class (rejected)

- **What it is:** consume `plan_retention` for incident records, traces and evaluation history.
- **Pros:** closes more of NFR-SEC-14.
- **Cons:** without lineage-aware cascades, backup/PITR coordination and legal-hold integration
  it can delete rows that replays, verifications or active incidents still reference, and a
  restore can silently resurrect deleted data.
- **Cost to adopt:** high, and unsafe today.

### Option C — keep no executor (rejected)

- **What it is:** continue with the dry-run planner only.
- **Pros:** zero deletion risk.
- **Cons:** the replay cache grows without bound; NFR-SEC-14 stays entirely on paper.

## Rationale

The decisive factor is blast radius: the idempotency cache is referenced by nothing, so deleting
expired rows cannot break any invariant, while its growth is real. Doing it under a role that can
do nothing else means a bug in the executor cannot become a deletion of evidence.

## Consequences

- **Positive:** bounded storage for the replay cache; auditable, immutable receipts; the runtime
  still cannot delete anything.
- **Negative / accepted trade-offs:** other classes remain retained; prerequisites are recorded in
  the production gap register.
- **Impact on security and permission boundaries:** new `NOLOGIN NOBYPASSRLS` role with
  `SELECT, DELETE` on one table, column-level `SELECT` on `tenant`, and `SELECT, INSERT` on
  receipts; the application role gains only `SELECT` on receipts.
- **Impact on observability and evaluation:** receipts are queryable evidence; the CLI prints one
  JSON receipt per batch.
- **Impact on failure modes and recovery:** a crash loses at most an uncommitted batch, which
  deleted nothing and wrote no receipt; a re-run continues. Two concurrent runs remain correct
  because a DELETE blocked on a row another run deleted skips it.

## Evidence

`tests/security/test_retention_executor.py` (dry-run default, bounded batches, tenant isolation,
holds, rollback before receipt, role confinement, receipt immutability, CLI refusals);
`tests/security/test_retention.py`; `tests/db/test_migration_history.py`; and the kind smoke's
retention step (CronJob admitted and suspended; in-cluster dry run and execute with receipts).
