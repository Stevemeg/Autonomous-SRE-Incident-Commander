# Load and performance (Phase 15.1–15.3, 15.14)

> **LOCAL BENCHMARK.** One Windows 11 laptop (8 logical CPUs, 15.8 GiB), Docker Desktop 29.5.3,
> the API in one container limited to **2 CPUs and 1 GiB**, PostgreSQL 16.15 + pgvector in another,
> the harness on the host. These numbers describe this setup on 2026-09-27. They are not
> production capacity, not a service-level commitment and not comparable to any other system.
> Run-to-run variance on this host is large (see §4): read them as orders of magnitude and as
> *behaviour* (degrades or collapses, recovers or not), not as precise figures.

Raw results: [`evidence/phase15-load-final.json`](evidence/phase15-load-final.json) (final image,
fresh database) and [`evidence/phase15-load-before-fix.json`](evidence/phase15-load-before-fix.json)
(the run that found the defects in §3). Database credentials are removed from both.

## 1. Method

`scripts/load_harness.py` drives the **real** API over HTTP with HS256 development tokens for
real, seeded principals (one isolated tenant per run: 400 readers, 40 services each with its own
signed connector), against a migrated database, through authentication, RBAC, row-level security,
rate limiting and idempotency. The concurrency profile additionally runs the real ingest →
dispatch → investigation pipeline in-process with the deterministic simulator and model provider.
Remediation is never driven. Open-loop profiles schedule requests at a fixed rate and measure
latency **from the scheduled slot** (no coordinated omission); a request that cannot start within
1 s of its slot is counted as dropped. A sampler records container memory, threads, file
descriptors and database connections by role and state every 5 s.

| Profile | Shape |
|---|---|
| smoke | every operation ×5 at low concurrency; any unexpected status fails the run |
| capacity | closed-loop read mix at 1, 2, 4, 8, … concurrent clients for 20 s each; stops when throughput stops growing (< 10 %), errors exceed 1 % or p95 exceeds 1 s — the *observed* saturation point |
| steady | open loop, 40 req/s for 120 s: reads (list, detail, timeline, evidence, hypotheses, actions, approvals, evaluation, admin, probes) plus 20 % alert ingestion |
| ingest | open loop, alert ingestion only at 50 alerts/s for 60 s (the NFR-PRF-04 assumption) |
| burst | 5 s idle, then 96 concurrent clients for 15 s on the mixed workload, then a 10 s recovery check |
| concurrency | 60 distinct alerts ingested concurrently, then 40 investigations through `InvestigationDispatcher` with 8 workers |
| soak-lite | open loop, 20 req/s mixed for 600 s while sampling resources |

Reproduce: see the header of `scripts/load_harness.py` (start PostgreSQL and the API container,
create a login in role `asic_app`, run `--profile all`).

## 2. Results — final image

| Profile | Result |
|---|---|
| smoke | 45/45 expected statuses |
| capacity | 25.6 req/s at 1 client (p95 53 ms) → 77.1 req/s at 4 (p95 68 ms) → plateau at 8 (75.9 req/s, p95 148 ms). Zero errors throughout. Observed saturation: ≈ 4 concurrent clients on 2 CPUs |
| steady (40 req/s) | 4,800/4,800 OK, 0 dropped; p50 59 ms, p95 378 ms, p99 653 ms. Reads p95 94–122 ms; ingestion p50 259 ms, p95 678 ms |
| ingest (50 alerts/s) | **Not sustained.** 11.9 alerts/s achieved; 2,209 of 3,000 slots could not start within 1 s; of 791 sent, 745 OK and 46 classified 503 (backpressure); p95 6.4 s. **NFR-PRF-04 (50 alerts/s) is not met in this setup** |
| burst (96 clients) | 49.4 req/s; 871 OK (93.5 %), 61 classified 503 (6.5 %), **0 timeouts**; p50 866 ms, p95 5.6 s. Recovery at 4 clients immediately after: 695/695 OK, p95 85 ms |
| concurrency | 60 concurrent ingests all OK (p95 1.5 s); 40/40 investigations completed with 8 workers: 216.6 runs/min, run p95 3.0 s |
| soak-lite (600 s) | 12,000/12,000 OK, 0 dropped; p50 50 ms, p95 203 ms, p99 250 ms. API RSS 117.4 → 117.0 MB, threads and file descriptors bounded, database connections 5 idle at start and end — no growth |

Related assumed targets (SRS §5, `[ASSUMED]`):

* NFR-PRF-01 (ingestion to correlation decision p95 < 5 s): met at 8 alerts/s (p95 678 ms in
  steady); **not met** beyond ingestion capacity (p95 6.4 s at the 50/s offered load).
* NFR-PRF-02 (incident to first ranked hypothesis p95 < 3 min for golden scenarios): investigation
  run p95 3.0 s — **with the deterministic model provider**; a live LLM's latency is not measured.
* NFR-PRF-04 (50 alerts/s sustained): **not met** (≈ 12 alerts/s per 2-CPU API process here).
  Ingestion is synchronous validation + correlation under per-group locks; scaling it needs more
  API processes and a measured correlation-lock profile (production gap register).

## 3. Defects the harness found (fixed)

The first full run (pre-fix image) exposed two connection-pool deadlocks no functional test could
see. Both were fixed with regression tests (`tests/resilience/test_event_storms.py`,
`tests/resilience/test_request_pool_deadlock.py`), each proven to fail on the old code.

| Profile | Before the fix | After |
|---|---|---|
| ingest (50/s) | 409 of 428 requests **timed out** (10 s); 15 connections left *idle in transaction*; the API stalled for other traffic | 745 OK, 46 fast classified 503, 0 timeouts |
| burst (96 clients) | 192 of 199 requests **timed out**; the recovery check after it also timed out (4/4) | 93.5 % OK, 6.5 % classified 503, 0 timeouts; recovery 695/695 OK |
| concurrency (ingest phase) | p95 6.8 s | p95 1.5 s |

1. **Ingestion held two connections per request.** The handler kept the request's session (an
   open transaction) while ingestion checked out a second connection; at concurrency ≥ pool size
   every request held one and waited for another. Now the connector scope is checked in its own
   short transaction, closed before ingestion.
2. **Requests held a connection across a thread hop.** The request-session dependency bound the
   tenant (checking out a connection) in its own threadpool call, and FastAPI validates a sync
   endpoint's result in another threadpool call before the dependency returns the connection. With
   more requests in flight than threads plus connections, threads waited on the pool and
   connections waited on threads. Now the binding happens at transaction begin in the endpoint's
   thread, and the endpoint's thread commits and returns the connection.
3. **Bulkhead.** Ingestion is limited to 4 concurrent alerts per process; excess waits without a
   connection and, after 5 s, gets `503 ingestion_busy` with `Retry-After`, so an alert burst
   cannot take the pool away from reads and approvals.

## 4. Variance, stated honestly

Three runs of the steady profile on the same host within two hours: pre-fix image, first run —
p50 32 ms / p95 125 ms; pre-fix image again later (control) — p50 59 ms / p95 347 ms; final image
— p50 59 ms / p95 378 ms. The pre-fix control run shows the change between runs is environmental
(host state), not the fixes. Capacity peaks measured the same day ranged from 77 to 102 req/s.
Nothing here supports a precise latency claim.

## 5. Redaction timing (15.14)

`scripts/redaction_benchmark.py`, same host, worst case over inputs shaped to defeat each pattern:

| Input | `scrub_text` (telemetry/audit) | `deploy_release.redact` (deployment diagnostics) |
|---|---|---|
| 1 KB | 0.33 ms | 0.33 ms |
| 5 KB | 1.65 ms | 3.42 ms |
| 20 KB | 8.66 ms | 6.30 ms |
| 100 KB | 35.1 ms | 34.2 ms |

Growth 20 KB → 100 KB: ×4.1 and ×5.4 (linear ≈ ×5; the quadratic patterns before the fix took 7 s
and 51 s at 20 KB). In production `scrub_text` also truncates values before scanning.

## 6. What is not measured

Multi-process or multi-replica scaling, a live LLM, production data volumes, network latency
between services, and long soaks (hours). See the production gap register.
