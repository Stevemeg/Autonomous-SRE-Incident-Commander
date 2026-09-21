# Data retention

Implements NFR-SEC-14 as far as it can be made enforceable now (Phase 13, ADR-0030). No number here
is a legal or regulatory obligation and nothing in this repository claims compliance with any
framework (SOC 2, ISO 27001, GDPR, HIPAA or otherwise). They are platform defaults; an operator with
a real obligation configures a longer tenant value.

## 1. What is built, and what deliberately is not

**Built:** a complete classification of every table into a retention class
(`asic.retention.TABLE_CLASSIFICATION`, asserted equal to the live schema), a tenant policy schema
with platform minimums and per-class holds (`validate_retention_policy`), and a deterministic,
tenant-bound, batch-bounded **dry-run planner** (`plan_retention`) that says, for every table, what a
lifecycle job would do and why.

**Not built: a deletion engine.** The application role holds no `DELETE` on any table (migration
0018), so the runtime cannot erase anything even if this module were wrong. Deleting aged rows
without breaking audit immutability, replay reproducibility, verification lineage, active incident
references or memory governance needs an owner-role lifecycle job with its own change control and an
audit receipt per run. That is a deployment concern (Phase 14 schedules and privileges it). A generic
`DELETE ... WHERE created_at < X` in the application would have been the unsafe option.

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

## 5. Phase 14 obligations

1. An owner-role lifecycle job (not the application role) that consumes `plan_retention`, deletes in
   bounded batches inside one transaction per batch, and writes an audit receipt (`data.deleted`)
   per run: tenant, class, cutoff, counts, reason.
2. Refuse any table whose class is protected; honour holds; skip rows referenced by an active
   incident, an open memory promotion or a verification lineage.
3. Infrastructure lifecycle for what the database cannot express: backup and snapshot expiry, log
   and trace retention in Loki/Tempo and the OTLP collector, object-store lifecycle rules, and
   erasure requests, which are a separate process from time-based retention.
4. Telemetry and cache-like data (metrics, traces, logs) follow the observability stack's own
   retention; metric labels carry no tenant or incident identifiers by construction.

## 6. Tests

`tests/security/test_retention.py`: classification equals the live schema; protected evidence is
never time-eligible; policy validation against hostile input; the preview equals a direct count,
is deterministic, batch-bounded, honours holds, and is tenant-bound through row-level security under
the unprivileged application role.
