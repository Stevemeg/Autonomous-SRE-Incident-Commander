# Data retention

Implements NFR-SEC-14 as far as it can be made enforceable now (Phase 13, ADR-0030). No number here
is a legal or regulatory obligation and nothing in this repository claims compliance with any
framework (SOC 2, ISO 27001, GDPR, HIPAA or otherwise). They are platform defaults; an operator with
a real obligation configures a longer tenant value.

## 1. What is built, and what deliberately is not

**Built (Phase 13):** a complete classification of every table into a retention class
(`asic.retention.TABLE_CLASSIFICATION`, asserted equal to the live schema), a tenant policy schema
with platform minimums and per-class holds (`validate_retention_policy`), and a deterministic,
tenant-bound, batch-bounded **dry-run planner** (`plan_retention`) that says, for every table, what a
lifecycle job would do and why.

**Built (Phase 15): the smallest safe executor** (`asic.retention.executor`, `python -m
asic.retention`) for the one class whose value genuinely expires and whose deletion cannot break
evidence, replay, verification lineage or memory governance: the API idempotency replay cache
(`operational_cache` / `api_idempotency_record`). Section 5 describes it.

**Deliberately not built: deletion of any other class.** The application role still holds no
`DELETE` on any table (migrations 0018/0019), so the runtime cannot erase anything even if a module
were wrong. Deleting incident records, traces or evaluation history without breaking audit
immutability, replay reproducibility, verification lineage, active incident references or memory
governance needs lineage-aware cascades, backup/PITR coordination and legal-hold integration first
(production gap register). A generic `DELETE ... WHERE created_at < X` would have been the unsafe
option.

## 2. Classes

| Class | Tables (examples) | Platform minimum | Time-eligible | Notes |
|---|---|---|---|---|
| `protected_evidence` | `audit_record`, `approval`, `policy_decision`, `verification`, `remediation_*`, `tool_execution`, `model_call_reservation`, `connector_scope_binding` | 2555 days | **no** | immutable evidence; ages out only through an owner-run, audited decision, never by a time predicate |
| `incident_record` | `incident`, `incident_event`, `alert`, `evidence`, `hypothesis`, `workflow_run`, ... | 365 days | yes (owner job) | must outlive the investigations and replays that use it |
| `execution_trace` | `execution_trace`, `trace_span` | 90 days | yes (owner job) | replay and analysis input |
| `evaluation_history` | `evaluation_*` | 365 days | yes (owner job) | gate history stays comparable |
| `knowledge_content` | `knowledge_*` | none | no | governed by source lifecycle (revoke/delete), not age |
| `operational_memory` | `memory_*` | none | no | governed by promotion and revocation |
| `identity_and_config` | `app_user`, roles, environments, services, grants, connectors | none | no | current configuration; changes audited |
| `operational_cache` | `api_idempotency_record` | 1 day (default 30, max 365) | yes | an idempotency replay window; the **only** class the planner ever counts as eligible |
| `global_catalogue` | `tenant`, `role`, `permission`, `tool_definition`, ... | none | no | platform-owned; outside any tenant's retention |

The 2555-day audit floor restates the seven-year default recorded in `db/models/audit.py`; it is a
platform default, not a claim about any obligation. The earlier retention table in
`THREAT_MODEL.md` §8 (audit 7 years, incident records 2 years, traces 90 days) remains the target
for the owner job; the floors above are the minimums a tenant may not undercut.

## 3. Policy schema (`tenant.retention_policy`)

`{"<class>": {"days": <int>, "hold": <bool>}}`. Validation refuses: an unknown class (a typo must not
silently mean "no policy"), a class that has no time-based semantics, non-integers (booleans included),
values below the platform minimum or above the maximum, unexpected fields, and it never echoes a
caller-supplied value. A **hold** suspends time-based eligibility for the class. Protected evidence
may be *lengthened* but never shortened below its floor.

## 4. Protected evidence

Protected tables are append-only or authority history; they are `RETAIN` in every plan, in every
tenant configuration. The planner never recommends removing them and the database would refuse the
application role if it tried. Aging them out is an explicit owner decision recorded outside this
module.

## 5. The lifecycle executor (Phase 15)

Decision: early enterprise operation needs a working lifecycle for data that is *meant* to expire
(an idempotency replay window kept forever is a slow leak of request bodies), but nothing more.
The executor therefore acts on exactly one class and has each property enforced twice - in code
and by the database:

| Property | Code | Database |
|---|---|---|
| Separate identity | refuses to run without `ASIC_MAINTENANCE_DATABASE_URL` | migration 0019: `asic_maintenance` (`NOLOGIN NOBYPASSRLS`) may `SELECT, DELETE` only `api_idempotency_record`, read `tenant(id, slug, status, retention_policy)` and `SELECT, INSERT` `retention_run`; a deployment grants it to a maintenance login never mounted into API pods |
| Tenant-bound | one tenant per transaction, bound like the runtime | the `tenant_isolation` RLS policies apply to the role |
| Policy and holds | the tenant policy is validated with the planner's rules; a hold or missing policy deletes nothing | receipt check constraints: a held or dry-run batch has `deleted_rows = 0` |
| Bounded, oldest first, restartable | `batch_limit` 1-10 000, `max_batches` 1-1 000; stops when a batch is short | `deleted_rows <= batch_limit` |
| Receipted | each batch commits together with its `retention_run` row; a crash before the receipt rolls the deletion back | `retention_run` is append-only evidence: the runtime and auditor may read it; nobody may update or delete it; the downgrade refuses to drop receipts |
| Dry run by default | `--execute` is required to delete | - |
| No arbitrary SQL | table and predicate fixed in code | the role cannot touch any other table |

**Delivery.** `deploy/kubernetes/maintenance` ships a `CronJob` that is **suspended** and runs a
**dry run** (`--all-tenants --batch-limit=1000 --max-batches=10`, no `--execute`), with
`concurrencyPolicy: Forbid`, `backoffLimit: 0`, a 30-minute deadline, its own tokenless
`asic-maintenance` service account (Terraform) and its own database Secret, and an egress policy
limited to DNS and the database. An operator enables the schedule and adds `--execute` only after
reviewing dry-run receipts.

**Verified.** `tests/security/test_retention_executor.py` (20 tests, real `asic_maintenance`
login): dry run default; bounded oldest-first batches; another tenant untouched; holds and longer
policies respected; a failure before the receipt rolls the deletion back; the application role
cannot run it; the maintenance role can do nothing else (8 forbidden statements); receipts readable
by the runtime but immutable; the CLI refuses cleanly without leaking a credential. On kind
(`scripts/deployment_smoke.py`): the CronJob is admitted under `restricted` and stays suspended;
its Job template, run in-cluster as a login holding only `asic_maintenance`, performs a dry run
(3 eligible, 0 deleted) and then an `--execute` run (3 deleted, the recent row kept) with receipts.

**Still required before any other class is deleted** (gap register):

1. Lineage-aware cascades that skip active-incident, open-promotion and verification-lineage rows.
2. Backup/snapshot expiry and PITR coordination, so a restore cannot resurrect deleted data
   unnoticed.
3. Legal-hold integration beyond the per-class `hold` flag, and a separate erasure-request process.
4. Infrastructure lifecycle the database cannot express: log and trace retention in Loki/Tempo and
   the OTLP collector, object-store lifecycle rules.
5. Telemetry/cache lifecycle stays in the observability stack; metric labels contain no tenant or
   incident identifiers by construction.

## 6. Tests

`tests/security/test_retention_executor.py` (section 5) and `tests/security/test_retention.py`: classification equals the live schema; protected evidence is
never time-eligible; policy validation against hostile input; the preview equals a direct count,
is deterministic, batch-bounded, honours holds, and is tenant-bound through row-level security under
the unprivileged application role.
