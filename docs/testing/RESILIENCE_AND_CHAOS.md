# Resilience, fault injection and chaos (Phase 15.2–15.12, 15.30)

Two layers of evidence:

1. **Process-level fault suites** (`tests/resilience`, in the normal test matrix): faults injected
   deterministically between the application's own components and real PostgreSQL / local HTTP
   dependencies.
2. **Declared chaos experiments on Kubernetes** (`scripts/chaos_experiments.py`, run by
   `scripts/deployment_smoke.py --chaos` on a disposable kind 1.34 cluster with Cilium 1.20.2).

All numbers below are **LOCAL** measurements: a single-node kind cluster on a Windows 11 laptop
(Docker Desktop), one replica per Deployment. They show behaviour, not production availability.
Raw evidence: [`evidence/phase15-kind-smoke-chaos.json`](evidence/phase15-kind-smoke-chaos.json).

## 1. Process-level fault suites

| Suite | Tests | Faults | Invariants asserted |
|---|---|---|---|
| `test_database_stress.py` | 19 | pool exhaustion, concurrent overload, slow database (latency proxy), lock contention, conflicting concurrent controls, severed connections, full outage (refusing proxy), TCP keepalives | classified 503 with `Retry-After` (never an opaque 500), bounded time (≤ 15 s per faulted request), not-ready during the outage, recovery without restart, no tenant context leaking into the next request |
| `test_dependency_fault_matrix.py` | 63 | every native adapter × connection refused, receive timeout, dropped connection, 5xx, malformed body, truncated body, rate limit, slow-in-deadline, recovery | always a classified `IntegrationError`/`IntegrationUnknownOutcome`; an effectful call whose request may have been sent is never "not applied"; no credential in errors; bounded by its deadline; next call succeeds after recovery |
| `test_model_provider_failure.py` | 21 | timeout, arbitrary exception, malformed/truncated output, bad token accounting, estimate failure, budget exhaustion, well-formed output forging approval/tenant/environment/risk tier/tool/verification | no tool outside the read-only menu, no remediation/approval/verification rows from investigation, tenant/environment unchanged, never "resolved", deterministic ending |
| `test_crash_resume_matrix.py` | 11 | process death (no clean-up) after every investigation node boundary (8 points) and at remediation approval, execution-after-approval and verification | second worker refused while the lease is valid; takes over after expiry, continues the same run to the same ending; no side effect twice; no fabricated success. A death after approval but before dispatch is fail-closed: lease recovery (15 min) outlives the approval's validity, so the stale approval is not reused and the incident escalates for a fresh decision (the operational cost is one re-approval, GAP-20) |
| `test_event_storms.py` | 4 | webhook redelivery storm, client retry storm on one key, shuffled late/out-of-order/resolved events, distinct events | never a 5xx; one alert per occurrence; one incident and one investigation request per group; no out-of-order resolution; status equals the event-log projection |
| `test_retry_and_bulkhead.py` | 4 | sustained outage, `Retry-After`, concurrent runs failing together, a wedged dependency in one run | at most `max_attempts`, equal-jitter backoff in [base/2, base], `Retry-After` capped at 5 s, no lockstep retries, another run is not starved (per-run two-thread executor) |
| `test_resource_bounds.py` | 3 | repeated API workloads, repeated investigations, unique rate-limit keys | pool/checked-out connections, sessions, threads, sockets, traced memory, running workflows, temp files and limiter cardinality stop growing after warm-up |
| `test_telemetry_outage.py` | 1 | OTLP exporter pointed at a closed port | span creation never waits on the network; memory bounded by the 2048-span queue; exporter gives up within its deadline |
| E2E scenario E/F (`tests/e2e`) | 3 | source outage, model outage, crash after an external side effect | see [E2E_VALIDATION.md](E2E_VALIDATION.md) |

| `test_request_pool_deadlock.py` | 2 | 32 concurrent reads and ingests through 3 worker threads and 2 connections; a full ingestion bulkhead | every request answered promptly (no pool/thread deadlock); a full bulkhead is a fast `503 ingestion_busy` with `Retry-After` while reads still succeed |

**Defects these suites found and Phase 15 fixed:** database failures were opaque 500s; a lost
optimistic-lock race was a 500 (now 409); the planner let `BudgetExhausted` escape instead of
ending the run; retries had no jitter (concurrent runs retried in lockstep); database connections
had no TCP keepalives (a silently dead peer went unnoticed until the OS timeout). The load harness
found two connection-pool deadlocks that no functional test could see (ingestion holding two
connections per request; the request session holding a connection across a thread hop) - see
[LOAD_AND_PERFORMANCE.md](LOAD_AND_PERFORMANCE.md) - and led to the ingestion bulkhead.

**Observed limitation (not fixed):** with the default 10 s OTLP exporter timeout, a full span queue
drains in tens of seconds at shutdown during a collector outage, so a stopping pod may use its whole
termination grace period and lose those spans. `OTEL_EXPORTER_OTLP_TIMEOUT` bounds it; losing spans
is acceptable, blocking requests is not (and does not happen — see experiment 5).

## 2. Chaos experiments on kind

Every experiment's hypothesis, invariant, fault, expected signal, recovery condition, maximum
duration and cleanup is declared in code (`EXPERIMENTS`) and printed **before** its fault is
injected; a unit test refuses an undeclared experiment, and cleanup runs even after a failure. The
cluster itself is destroyed at the end of every run.

Measurement: in-pod samplers poll at a 0.25 s interval (outage windows are approximate to that);
an authenticated probe runs as a seeded `system_operator` principal on every third sample so it
stays under the per-principal rate limit.

| # | Experiment | Fault | Result (final images, 2026-09-27) |
|---|---|---|---|
| 1 | `api_pod_kill` | force-delete the only API pod | **passed.** API unreachable through its Service for ≈ 5.8 s (1 replica: an outage is expected); ready endpoint 11.0 s after the kill; frontend liveness 200 in all 43 samples and not restarted; the replacement pod's 8 internet connection attempts while starting were all dropped by Cilium (0 connected) |
| 2 | `frontend_pod_kill` | force-delete the only frontend pod | **passed.** Ready endpoint after 8.2 s; all 171 API samples (liveness, readiness, authenticated request) healthy; API not restarted |
| 3 | `postgres_restart` | `pg_ctl stop -m fast` in the database container | **passed.** Database back in 1.4 s with the schema revision (`0019_retention_maintenance`) and data intact; authenticated requests returned a classified 503 during the outage, never a 500, then 200 on the same pod; API liveness 200 throughout, no restart. `/readyz` did not flip: the outage was shorter than its 2 s readiness cache |
| 4 | `readiness_failure_database_access_revoked` | `ALTER ROLE asic_app NOLOGIN` + terminate sessions, held 30 s | **passed.** API `/readyz` 503 for ≈ 29.4 s; API endpoint removed after 14.9 s (3 × 5 s readiness probe); frontend endpoint removed 0.1 s after that; authenticated requests 503 (never 500); endpoints back 4.6 s (API) and 3.5 s (frontend) after LOGIN was restored; zero restarts on either pod |
| 5 | `otel_collector_unavailable` | OTLP exporter pointed at `10.255.255.1:4318`, dropped by egress policy; API rolled | **passed.** 227 samples all healthy; authenticated request p50 14.6 ms, p95 19.9 ms, max 164 ms; no restart; 2 exporter error log lines recorded; configuration restored and smoke passed afterwards |
| 6 | `migration_pod_overlap` | a SIGTERM-ignoring migration pod held for its 40 s grace period after its Job was deleted | **passed.** Job object gone after 0.3 s; old pod last seen 40.3 s after the delete; orchestrator logged the wait and created the new Job at 42.2 s; **maximum concurrent migration pods = 1** over 89 samples; migration complete. Timeout case (20 s allowance, 150 s grace): refused after 22.7 s with "the replacement was NOT created", 0 Jobs created, 0 manifests applied. Non-vacuity: bypassing the orchestrator produced **2** concurrent pods, so the sampler detects an overlap |

**First run (recorded, not hidden).** Experiment 3 initially declared `/readyz` 503 as an expected
signal and failed: the container restarted in about 2 s, inside the readiness cache, so readiness
never flipped, while requests correctly returned 503. The same run showed that a probe using an
unknown principal draws 401s and trips the per-peer authentication-failure limiter (429), which
would mask later 503s. The declaration was revised (readiness is covered by experiment 4, designed
for a sustained outage) and the probe now uses a real principal. The second run passed all six
experiments on the same images; the final run above, on the images that include the Phase 15
connection-pool fixes and ingestion bulkhead (backend image
`sha256:5fd927dff0a4...`), passed all six again with similar figures.

**Also verified in the same smoke run:** Terraform apply/no-drift/destroy; PSA `restricted`
rejection of a privileged pod; failing migration detected in 9.3 s with no application applied and a
non-vacuous guard mutation; network policy (frontend→DB, internet egress and cross-namespace denied);
API scaled to zero (frontend live, not ready, not restarted, smoke fails as required); rollback of a
broken image; the redeployment matrix (repeat, template change, failed migration then fix-forward,
finalizer-held deletion, active-migration refusal, Job deleted mid-wait in 8.6 s, never-ready
release); and the retention CronJob (admitted, suspended, in-cluster dry run then execute).

### Not exercised on the cluster

* **Model provider outage:** the deployed provider is in-process and deterministic, so there is no
  network fault to inject; covered by `test_model_provider_failure.py` and E2E scenario E.
* **Multi-replica availability, node loss, zone loss:** kind has one node and the local overlay one
  replica. The base manifests set 2 replicas, PDBs and `maxUnavailable: 0`, but availability during
  a pod loss with 2 replicas is **not measured** (production gap register).

## 3. Reproduce

```bash
docker build -t asic-backend:local . && docker build -t asic-frontend:local frontend
python scripts/deployment_smoke.py --backend asic-backend:local --frontend asic-frontend:local --chaos
python -m pytest tests/resilience -q     # needs PostgreSQL (ASIC_TEST_DATABASE_URL)
```

## 4. Cleanup (15.30)

The smoke deletes its kind cluster in a `finally` block and keeps Terraform state and kubeconfig in
a temporary directory; the fault proxy threads are daemons and close their listeners. After the
recorded run, `kind get clusters` reported no clusters and no kind node container remained.
