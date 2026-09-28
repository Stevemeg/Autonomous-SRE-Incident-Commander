# Portfolio evidence

Facts only. Every row names what was measured, how, where and against which code, so it can be
reproduced or challenged. Environment for all measured rows unless stated: Windows 11 laptop,
8 logical CPUs, 15.8 GiB, Docker Desktop, Python 3.12, PostgreSQL 16.15 + pgvector.

**Which code each measurement ran on.** Phase 16 closure rows ran on the final correction images
(backend `sha256:e766bc1e…`, revision label `006f486+p16closure-content-1457df4abac8d003`, a
fingerprint of the image's source; the image's files are the committed Phase 16 closure tree's,
identical except Windows line endings in 38 files the correction did not touch — see
[PHASE16_CLOSURE_RESULTS.md §9](../testing/PHASE16_CLOSURE_RESULTS.md#9-commit-binding)). Phase 15 load rows ran on
`4904d18` **with the then-uncommitted Phase 15 changes** (the evidence files record
`working_tree_dirty: true`); they were later committed as `74a202a`.

## Scale of the work

| Fact | Value | Method |
|---|---|---|
| Automated tests | 2,472 passing, 0 failed, 0 skipped | `pytest` on a fresh PostgreSQL 16 + pgvector database with `jq` on PATH ([PHASE16_CLOSURE_RESULTS.md](../testing/PHASE16_CLOSURE_RESULTS.md)) |
| Requirements traced | 131 SRS requirements + 7 constraints; each status recomputed against its wording: 112 satisfied, 19 partial | [traceability](../architecture/requirements-traceability.md#final-status-phase-16-closure-correction) |
| Architecture decisions | 31 ADRs, each with alternatives and trade-offs; ADR review against the code | [ADR index](../adr/README.md) |
| Database migrations | 20, clean from empty to head (`0020_postmortem_worker`), no drift (`alembic check`) | [PHASE16_CLOSURE_RESULTS.md](../testing/PHASE16_CLOSURE_RESULTS.md) |
| As-built graph | 10 LangGraph nodes (5 investigation, 5 remediation); 4 model-calling components (G3, G5, G6, G11) | [agent topology §0](../architecture/agent-topology.md) |
| Golden evaluation corpus | 18 versioned scenarios, simulator and strict-replay modes | `python -m asic.evaluation.gate` |

## Behaviour demonstrated

| Claim | Evidence | Method |
|---|---|---|
| The deployed product drives an incident end to end without any harness | On kind + Cilium, final images, two worker replicas: signed alert → worker investigation → remediation request → approval via the API bound to the action hash → execution → independent verification → resolved → G11 draft with 19/19 citations resolving; one execution per item | `scripts/worker_acceptance.py`, [PHASE16_CLOSURE_RESULTS.md §3](../testing/PHASE16_CLOSURE_RESULTS.md) |
| A postmortem draft states no unsupported fact and cannot be published | Unsupported causal, uncited, foreign-cited, injection-only and invented-figure claims are removed and listed; the database refuses non-draft rows and the runtime cannot update one | `tests/postmortem/` |
| The agent cannot act outside its menu, tenant or tier, even when told to by injected text | 40-case injection corpus across every input vector; 27 tool-abuse cases; model outputs forging approvals/tenants/tools | `tests/security/test_injection_campaign.py`, `test_tool_abuse_campaign.py`, `tests/resilience/test_model_provider_failure.py` |
| Tenant isolation holds at the database, not only in code | Every tenant-scoped table attacked as the real non-owner role | `tests/security/test_tenant_campaign.py` |
| A crash never repeats a side effect | Process killed at 11 points; a deployed-style worker killed mid-investigation and resumed by another after its lease; after a real external patch, exactly one patch before and after recovery | `tests/resilience/test_crash_resume_matrix.py`, `tests/worker/`, E2E scenario F |
| A remediation that does not verify is never "resolved" | Independent verifier; not-verified path | E2E scenario H |
| Production database traffic must be verified TLS | Plaintext and every mode weaker than `verify-full` refused before connecting, in the final image | `tests/security/test_database_tls.py` |
| No two database migrations run at once, even when a Job is deleted mid-flight | Kind experiment on the final images: max concurrent migration pods = 1 over 95 samples; bypass control showed 2 | `scripts/chaos_experiments.py` |
| Database outages degrade instead of crashing | Classified 503 with `Retry-After`; liveness unaffected; recovery without restart | `tests/resilience/test_database_stress.py`, chaos experiments |
| No secret reaches any telemetry sink | Canary credentials through 10 entry points, searched in 9 sinks | `tests/security/test_secret_leak_campaign.py` |

## Measured performance (LOCAL BENCHMARK)

API container limited to 2 CPUs / 1 GiB; harness on the same host. Figures vary noticeably between
runs on this host ([variance](../testing/LOAD_AND_PERFORMANCE.md#4-variance-stated-honestly)).
"Successful" excludes classified rejections.

| Measurement | Phase 16 final image (2026-09-28) | Phase 15 (`4904d18` + uncommitted changes) |
|---|---|---|
| Read capacity plateau | ≈ 135 req/s at 2 concurrent clients | ≈ 77 req/s at 4 clients (up to 102 that day) |
| Steady 40 req/s for 120 s (mixed, 20 % ingestion) | 4,800/4,800 OK; p95 50 ms | 4,800/4,800 OK; p95 378 ms |
| 600 s soak at 20 req/s | 12,000/12,000 OK; p95 106 ms; API RSS 118.1 → 117.6 MB | 12,000/12,000 OK; p95 203 ms; RSS 117.4 → 117.0 MB |
| 96-client burst | 92.8 % OK, 7.2 % classified 503, 0 timeouts | 93.5 % OK, 6.5 % classified 503, 0 timeouts (before the deadlock fixes: 96 % timeouts) |
| Ingestion at 50 alerts/s offered | ≈ 21 successful/s; 56 % of offered alerts dropped before sending | ≈ 12 responses/s including 46 classified 503s |
| 40 concurrent investigations (8 workers) | 40/40 completed; run p95 3.1 s | 40/40; run p95 3.0 s |
| Redaction, 100 KB adversarial input | — | ≈ 35 ms worst case (was quadratic: 51 s at 20 KB before the fix) |
| Chaos: API pod kill, 1 replica | ≈ 8 s unavailable through the Service; replacement ready endpoint in 10.0 s | ≈ 5.8 s; replacement ready in 11.0 s |

The differences between the two columns are host variance, not an improvement claim: the measured
code paths did not change in Phase 16. The assumed 50 alerts/s is **not** met in either run.

## Engineering problems found and solved (with evidence)

1. **Two connection-pool deadlocks under concurrency**, invisible to functional tests, found by the
   load harness (96 % client timeouts), each proven by a regression test that fails on the old code.
   ([LOAD_AND_PERFORMANCE.md §3](../testing/LOAD_AND_PERFORMANCE.md#3-defects-the-harness-found-fixed))
2. **Quadratic regular expressions in redaction** (51 s on 20 KB) rewritten; equivalence proven.
3. **Migration overlap**: deleting a Kubernetes Job does not stop its pod; the orchestrator waits.
4. **Secrets persisting in checkpoints, planner rationale and trace events**, closed at the type level.
5. **A worker that would have crashed on import in the production image**: the image excludes the
   simulator package, and the worker's live path imported it transitively; found before release by
   running the final image, fixed with lazy imports and a regression test that hides the package.
6. **A retention test that counted across tenants** (owner connections bypass row-level security),
   exposed on kind once another step left rows in a second tenant; fixed to count per tenant and
   to prove a second tenant's rows are untouched.

## What this evidence does not show

Reasoning quality with a real model, production traffic, multi-replica availability, live vendor
systems, remote CI, a published or attested image, or a TLS-serving managed database. See the
[production gap register](../PRODUCTION_GAP_REGISTER.md).
