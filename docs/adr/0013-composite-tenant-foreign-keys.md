# ADR-0013: Composite tenant-scoped foreign keys

- **Status:** Accepted
- **Date:** 2026-09-04
- **Deciders:** Project owner (Phase 3 approved implementation)
- **Spec reference:** §15
- **Supersedes / Superseded by:** none

## Context

Row-level security controls which rows a *session* can see. It does not control what a row
can *reference*. A foreign key is checked by the referential integrity machinery, not by
the RLS policy, so with plain single-column foreign keys this is possible:

```sql
-- tenant context = acme, so RLS is satisfied
INSERT INTO incident (tenant_id, environment_id, ...)
VALUES (acme_id, globex_environment_id, ...);
```

The row belongs to acme, so acme can read it. But it points at globex's environment. Any
join through that reference crosses the tenant boundary — and the join is written by code
that reasonably assumes references stay within a tenant.

Phase 3 had to decide whether to prevent this structurally or by convention.

## Decision

**Every tenant-scoped table carries `UNIQUE (tenant_id, id)`, and every reference between
tenant-scoped tables is a composite foreign key carrying the tenant:**

```sql
FOREIGN KEY (tenant_id, incident_id) REFERENCES incident (tenant_id, id)
```

## Alternatives considered

### Option A — Composite foreign keys (chosen)

- **Pros:** A cross-tenant reference becomes **impossible**, not merely unlikely: the
  tenant is part of the key being matched. Enforced by the database, so it survives an
  application bug. Costs nothing at query time — the composite index is the one queries
  already use, since every query is tenant-filtered.
- **Cons:** Every tenant-scoped table needs a redundant-looking `UNIQUE (tenant_id, id)`
  alongside its primary key. Foreign key declarations are more verbose. `tenant_id` must be
  present on the child, which it is anyway.
- **Cost to adopt:** Low — one helper (`tenant_fk`) and one constraint per table.

### Option B — Single-column foreign keys plus RLS (rejected)

- **Pros:** Conventional, less verbose, one fewer constraint per table.
- **Cons:** Permits the cross-tenant reference above. RLS does not catch it, because the
  inserting session's tenant is correct — it is the *target* that belongs elsewhere.
  Detecting it requires a consistency check that someone has to write, schedule and act on.
- **Cost to adopt:** Lowest, and the risk is invisible until it is exploited.

### Option C — Trigger-based validation (rejected)

- **What it is:** A `BEFORE INSERT/UPDATE` trigger verifying the referent's tenant.
- **Pros:** Keeps single-column foreign keys.
- **Cons:** A trigger per reference, each doing an extra lookup on every write. Triggers
  are easy to disable and easy to forget on a new table. Strictly more machinery and
  strictly less guarantee than a foreign key.

## Rationale

The decisive factor is the same one that motivates RLS: **the mechanism has to hold when
the application is wrong.** Option B leaves a hole that no amount of careful querying
closes, because the hole is in the data rather than in the query.

The cost is genuinely small. The `UNIQUE (tenant_id, id)` constraint looks redundant next
to the primary key but is not wasted: it is the index that supports the composite
reference, and `(tenant_id, ...)` is the leading-column shape every tenant-filtered query
wants anyway.

The one place this is deliberately *not* applied is `audit_record`, whose references are
plain UUID columns with no foreign key at all. An audit record must outlive the thing it
describes: `ON DELETE CASCADE` would delete exactly the evidence a later investigation
needs, and `RESTRICT` would block a lawful retention purge. That exception is documented on
the model and is the only one.

## Consequences

- **Positive:** Cross-tenant references are structurally impossible. The composite index
  matches the access pattern. New tables inherit the pattern through `tenant_fk`.
- **Negative / accepted trade-offs:** More verbose declarations; an extra unique constraint
  per table; `audit_record` needs an explicit, documented exception.
- **Security and permissions:** This is the second isolation layer; strongly positive.
- **Observability and evaluation:** Neutral.
- **Failure modes and recovery:** Positive — removes a class of silent data corruption.
- **Operational and cost impact:** A small amount of extra index storage.

## Reversal cost and revisit trigger

**Reversal cost: high.** Removing composite keys later means rewriting every foreign key
in the schema and losing the guarantee. This is a decision to make once, at the start —
which is why it is made in Phase 3 rather than deferred.

Revisit if: a legitimate cross-tenant reference is ever required (for example a shared
platform-level catalogue referenced by tenant rows) — in which case that specific
reference targets a *global* table and needs no tenant column, which the current design
already supports.

## Validation

| Test | Result |
|---|---|
| `TestCompositeForeignKeys::test_cannot_reference_another_tenants_environment` | Passing — insert refused with `IntegrityError` |
| `test_references_between_tenant_scoped_tables_carry_the_tenant` | Passing — no single-column reference between tenant-scoped tables |
| `test_tenant_scoped_tables_expose_a_composite_identity` | Passing — all 30 tables carry `UNIQUE (tenant_id, id)` |

## References

- Master specification §15
- [`../architecture/tenancy-and-rls.md`](../architecture/tenancy-and-rls.md) §6
- [ADR-0011](./0011-authentication-authorization-tenancy.md)
