# Portfolio evidence

Facts only. Every row names what was measured, how, where and against which commit, so it can be
reproduced or challenged. Environment for all measured rows unless stated: Windows 11 laptop,
8 logical CPUs, 15.8 GiB, Docker Desktop 29.5.3, Python 3.12.13, PostgreSQL 16.15 + pgvector;
runs of 2026-09-27 on the tree committed as `74a202a` (Phase 15).

## Scale of the work

| Fact | Value | Method |
|---|---|---|
| Automated tests | 2,422 passing, 0 skipped | `pytest -q` on a fresh database ([PHASE15_RESULTS.md](../testing/PHASE15_RESULTS.md)) |
| Requirements traced | 131 SRS requirements + 7 constraints; closing status for each | [traceability](../architecture/requirements-traceability.md#final-status-phase-16) |
| Architecture decisions | 31 ADRs, each with alternatives and trade-offs | [ADR index](../adr/README.md) |
| Database migrations | 19, clean from empty to head, no drift (`alembic check`) | [PHASE15_RESULTS.md](../testing/PHASE15_RESULTS.md) |
| Golden evaluation corpus | 18 versioned scenarios, simulator and strict-replay modes | `python -m asic.evaluation.gate` |

## Behaviour demonstrated

| Claim | Evidence | Method |
|---|---|---|
| The agent cannot act outside its menu, tenant or tier, even when told to by injected text | 40-case injection corpus across every input vector; 27 tool-abuse cases; model outputs forging approvals/tenants/tools | `tests/security/test_injection_campaign.py`, `test_tool_abuse_campaign.py`, `tests/resilience/test_model_provider_failure.py` |
| Tenant isolation holds at the database, not only in code | Every tenant-scoped table attacked as the real non-owner role (read, update, delete, mislabelled insert, cross-tenant reference) | `tests/security/test_tenant_campaign.py` |
| A crash never repeats a side effect | Process killed at 11 points (8 investigation node boundaries, 3 remediation points); after a real external patch, exactly one patch before and after recovery | `tests/resilience/test_crash_resume_matrix.py`, E2E scenario F |
| A remediation that does not verify is never "resolved" | Independent verifier; not-verified path | E2E scenario H |
| No two database migrations run at once, even when a Job is deleted mid-flight | Live kind experiment: max concurrent migration pods = 1 over 89 samples; bypass control showed 2 | `scripts/chaos_experiments.py` |
| Database outages degrade instead of crashing | Classified 503 with `Retry-After`; liveness unaffected; recovery without restart | `tests/resilience/test_database_stress.py`, chaos experiments 3–4 |
| No secret reaches any telemetry sink | Canary credentials through 10 entry points, searched in 9 sinks | `tests/security/test_secret_leak_campaign.py` |

## Measured performance (LOCAL BENCHMARK)

API container limited to 2 CPUs / 1 GiB; harness on the same host. Figures vary noticeably between
runs on this host ([variance](../testing/LOAD_AND_PERFORMANCE.md#4-variance-stated-honestly)).

| Measurement | Value |
|---|---|
| Read capacity plateau | ≈ 77 req/s at 4 concurrent clients (other runs that day: up to 102 req/s) |
| Steady 40 req/s for 120 s (mixed, 20 % ingestion) | 4,800/4,800 OK; p95 378 ms |
| 600 s soak at 20 req/s | 12,000/12,000 OK; p95 203 ms; API RSS 117.4 → 117.0 MB |
| 96-client burst | 93.5 % OK, 6.5 % classified 503, 0 timeouts (before the fixes: 96 % timeouts) |
| Sustained ingestion | ≈ 12 alerts/s (the assumed target of 50/s is **not** met) |
| Redaction, 100 KB adversarial input | ≈ 35 ms worst case (was quadratic: 51 s at 20 KB before the fix) |
| Chaos: API pod kill, 1 replica | ≈ 5.8 s unavailable through the Service; replacement ready in 11.0 s |

## Engineering problems found and solved (with evidence)

1. **Two connection-pool deadlocks under concurrency**, invisible to functional tests: ingestion
   held two pooled connections per request; the request session held a connection across a
   FastAPI thread hop. Found by the load harness (96 % client timeouts), each proven by a
   regression test that fails on the old code, fixed, and followed by an ingestion bulkhead.
   ([LOAD_AND_PERFORMANCE.md §3](../testing/LOAD_AND_PERFORMANCE.md#3-defects-the-harness-found-fixed))
2. **Quadratic regular expressions in redaction** (51 s on 20 KB) rewritten with atomic groups and
   possessive quantifiers; equivalence to the old patterns proven on a seeded corpus.
3. **Migration overlap**: deleting a Kubernetes Job does not stop its pod; the deploy orchestrator
   now waits, bounded and fail-closed, and a live experiment proves it.
4. **Secrets persisting in checkpoints, planner rationale and trace events**, found by canary
   tracing and closed at the type level (`ScrubbedText`).

## What this evidence does not show

Reasoning quality with a real model, production traffic, multi-replica availability, live vendor
systems or remote CI. See the [production gap register](../PRODUCTION_GAP_REGISTER.md).
