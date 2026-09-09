# ADR-0018: Migrations are historical contracts and never read live application code

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** Project owner (Phase 4 correction)
- **Spec reference:** §12, §15, §20
- **Supersedes / Superseded by:** none

## Context

Migration `0003` enabled row-level security on every tenant-scoped table. It found that
list by calling `tenant_scoped_tables()`, which derives it from the **live** SQLAlchemy
model registry at the moment the migration runs.

That was correct on the day it was written and became wrong the moment the models moved
ahead of it. Phase 4 added one tenant-scoped table, `workflow_checkpoint`, created by
migration `0004`. From that commit onward, `0003` — a Phase 3 migration — would try to
enable row-level security on a table that `0002` had never created. A fresh
`alembic upgrade head` failed with `relation "workflow_checkpoint" does not exist`, and the
`0003` downgrade would have failed the same way.

The general shape of the defect is worth naming, because it is not specific to this
project: **a migration whose effect depends on code outside itself is not a migration.** Its
whole value is that running it against a database in a known state produces another known
state, forever. A runtime lookup makes that a moving target, and the target moves silently —
nothing about editing a model announces that it has changed what a migration from three
months ago will do.

The correction was applied during Phase 4 by pinning the table lists into `0003`. That was
the right fix and the wrong process: editing an already-published migration is exactly the
thing this ADR now forbids, so the edit needed evidence rather than assertion.

## Decision

**A migration describes the schema as it stood when the migration was written. It may not
read the application's model registry, or any other live code whose meaning can change.**

Concretely:

1. Table lists, column lists and any other set a migration iterates over are **literal** in
   the migration file.
2. `tests/db/test_migration_history.py::TestMigrationsAreSelfContained` parses every
   migration's AST and fails the build if one imports or calls `tenant_scoped_tables()` or
   `append_only_tables()`.
3. Coverage of the *current* models is asserted separately — the RLS coverage test compares
   the live database against `tenant_scoped_tables()`, and a union test proves every
   tenant-scoped table is named by some migration. Pinning therefore cannot let a new table
   slip through unprotected.
4. Editing a published migration requires evidence that its **effect** is unchanged, and
   that evidence is a test, not a claim.

## The `0003` edit, and why it was retained

The user's instruction was to prefer restoring the original migration and adding a
corrective one, and to retain the edit only against explicit evidence. Both were examined.

### Restoring the original is not technically viable

Demonstrated, not assumed. The original `0003` was checked out into a scratch tree and run
against an empty database with the current models:

```
Running upgrade 0002_domain_schema -> 0003_tenant_isolation_rls
psycopg2.errors.UndefinedTable: relation "workflow_checkpoint" does not exist
```

A corrective migration cannot rescue this, because `0003` fails *before* any later
migration is reached. Restoring the original would leave the project unable to build a
database from scratch — a strictly worse position than the one being corrected.

### The edit provably does not change the migration's effect

The pinned lists were compared against what the original derivation actually produced, by
extracting the models from the Phase 3 commit (`0e263e1`) and computing the sets:

| | Phase 3 models | Pinned in `0003` | Identical |
|---|---:|---:|:-:|
| Tenant-scoped tables | 30 | 30 | yes |
| Append-only tables | 9 | 9 | yes |

Symmetric difference in both cases: empty. So a database that ran `0003` in Phase 3 and a
database that runs it today reach the same state. `TestPinnedListsMatchHistory` performs
this comparison against the commit on every test run, so it cannot quietly stop being true.

### No database consumed the original outside disposable containers

The evidence, stated with its limits:

- The repository contains **no** deployment configuration: no `docker-compose`, no CI
  workflow, no Dockerfile, no `infra/`, `terraform/`, `charts/` or `k8s/` directory.
- The only documented way to obtain a database is the `docker run` command in the README,
  which mounts **no volume** — the database lives in the container's writable layer and is
  destroyed with the container.
- No `asic`-named container or Docker volume exists on the development machine.
- The project has no deployed environment; every phase report to date has stated that no
  product is running.

This establishes that no *persistent* database was ever created by any documented path. It
cannot prove that no undocumented database exists anywhere, and the equivalence proof above
is what makes that gap harmless: even a database that did run the original `0003` reaches
the identical state and upgrades cleanly, which is verified by
`TestUpgradePaths::test_a_database_at_the_pre_phase_4_head_upgrades_to_head`.

## Alternatives considered

### Option A — restore `0003`, add a corrective migration (rejected)

Rejected on the demonstration above: `0003` fails on a fresh database before a corrective
migration could run. This would have been the right answer had the original still worked.

### Option B — restore `0003` and make its derivation defensive (rejected)

Intersect the model-derived list with the tables that exist in the database at that point.
Rejected because it makes a migration's effect depend on database *state* as well as on
application code — less of a contract, not more.

### Option C — pin the lists, and prove the effect is unchanged (chosen)

Retained with the evidence above, plus a permanent guard so the class of defect cannot
recur, plus upgrade-path tests from the pre-Phase-4 head.

## Consequences

**What this costs.** Adding a tenant-scoped table now requires naming it in its own
migration; there is no longer a list that updates itself. That is the intended cost — the
self-updating list was the defect.

**What it buys.** A migration's effect is fixed at the moment it is written. Both upgrade
paths that matter are tested against a real database on every run: a clean database to head,
and a database at the pre-Phase-4 head to head.

**A related limitation, recorded honestly.** Migration `0005`'s downgrade fails on a
database that has executed any tool, because `fk_tool_execution_tool_definition` is
`ON DELETE RESTRICT` and an execution record must outlive nothing — it must keep pointing at
the catalogue entry that explains it. Referential integrity was **not** weakened to make the
downgrade succeed; the constraint is correct, and the behaviour is asserted by
`test_a_downgrade_is_refused_once_execution_history_exists`. A catalogue entry that must go
is deprecated (`is_enabled = false`, `deprecated_at`), not deleted.

**When to revisit.** If a migration ever genuinely needs to know the current schema, the
answer is to write the literal list at that time, not to reintroduce a lookup.

## Evidence

- `tests/db/test_migration_history.py::TestPinnedListsMatchHistory` — the pinned lists equal
  the Phase 3 models' output, compared against the commit.
- `::TestMigrationsAreSelfContained` — no migration reads the live registry; every
  tenant-scoped table is named by some migration; the revision chain is linear and complete.
- `::TestUpgradePaths` — clean database to head; pre-Phase-4 head to head; full downgrade
  leaving no orphan enum types; a second round trip; no schema drift; and the downgrade
  refusal once execution history exists.
