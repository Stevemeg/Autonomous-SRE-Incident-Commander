# Load and performance (Phase 15.1–15.3, 15.14)

> **LOCAL BENCHMARK.** One Windows 11 laptop (8 logical CPUs, 15.8 GiB), Docker Desktop 29.5.3,
> the API in one container limited to **2 CPUs and 1 GiB**, PostgreSQL 16.15 + pgvector in another,
> the harness on the host. These numbers describe this setup on 2026-09-27. They are not
> production capacity, not a service-level commitment and not comparable to any other system.
> Run-to-run variance on this host is large (see §4): read them as orders of magnitude and as
> *behaviour* (degrades or collapses, recovers or not), not as precise figures.

**What each evidence file was measured on — exactly as recorded** (Phase 16 closure correction):

| File | Recorded `commit` | `working_tree_dirty` | What that means |
|---|---|---|---|
| [`evidence/phase15-load-before-fix.json`](evidence/phase15-load-before-fix.json) | `4904d18` | `true` | Phase 14 commit plus the uncommitted Phase 15 work in progress, *before* the pool-deadlock fixes (§3) |
| [`evidence/phase15-load-final.json`](evidence/phase15-load-final.json) | `4904d18` | `true` | The same base plus the uncommitted Phase 15 changes including the fixes, run before they were committed as `74a202a`. Earlier documents attributed these figures to `74a202a`; the file itself records `4904d18` with a dirty tree, and that is what it shows |
| [`evidence/phase16-closure-load.json`](evidence/phase16-closure-load.json) | `006f486` | `true` | The Phase 16 closure re-measurement (§2a) on the final correction image, run before the correction commit existed (so the harness's checkout is `006f486` plus the uncommitted correction). The harness now also records the API image ID and its revision label, whose content fingerprint is checked against the final commit in [PHASE16_CLOSURE_RESULTS.md](PHASE16_CLOSURE_RESULTS.md) |

Database credentials are removed from all three. The Phase 15 figures in §2 are kept as measured,
with the provenance above; they were not re-labelled as measured on any other commit.

**Terminology** (corrected in Phase 16; earlier text called all answered requests "throughput"):

| Term | Meaning |
|---|---|
| offered rate | Scheduled attempts per second in an open-loop profile, whether or not they could start |
| dropped | Scheduled attempts that could not start within 1 s of their slot (offered, never sent) |
| responses per second | Every answered request, including classified rejections |
| classified rejections | `503`/`429` answers with a code and `Retry-After` - backpressure, not throughput |
| successful throughput | Successful responses per second (`throughput_rps` in the evidence files from Phase 16 on) |

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

### Reproduce

Needs Docker and the locked Python environment. Build the backend image, start the measured
environment with one command, run the profiles, then remove it:

```bash
docker build -t asic-backend:phase14-local .
python scripts/load_environment.py up --image asic-backend:phase14-local
# up prints the exact harness command for this run (generated passwords and signing key); e.g.
python scripts/load_harness.py --admin-url "<printed>" --app-url "<printed>" \
    --api-url http://127.0.0.1:18080 --jwt-secret <printed> --api-container asic-load-api \
    --profile steady --output tmp/load-steady.json
# repeat with --profile ingest | burst | concurrency | soak (or --profile all)
python scripts/load_environment.py down
```

`up` starts `pgvector/pgvector:pg16` on 127.0.0.1:55480, migrates it to head as the owner, creates
the login `asic_load_runtime` in role `asic_app` (no BYPASSRLS, no DELETE), and starts
`python -m asic.api` from the given image on 127.0.0.1:18080 limited to 2 CPUs and 1 GiB, with
development HS256 authentication in the local profile.

## 2. Results — Phase 15 (recorded commit `4904d18`, dirty tree; see provenance above)

*Read "throughput" in this table as responses per second, rejections included (the pre-Phase 16
terminology); the ingest row's 11.9/s includes 46 classified 503s.*

| Profile | Result |
|---|---|
| smoke | 45/45 expected statuses |
| capacity | 25.6 req/s at 1 client (p95 53 ms) → 77.1 req/s at 4 (p95 68 ms) → plateau at 8 (75.9 req/s, p95 148 ms). Zero errors throughout. Observed saturation: ≈ 4 concurrent clients on 2 CPUs |
| steady (40 req/s) | 4,800/4,800 OK, 0 dropped; p50 59 ms, p95 378 ms, p99 653 ms. Reads p95 94–122 ms; ingestion p50 259 ms, p95 678 ms |
| ingest (50 alerts/s) | **Not sustained.** 11.9 alerts/s achieved; 2,209 of 3,000 slots could not start within 1 s; of 791 sent, 745 OK and 46 classified 503 (backpressure); p95 6.4 s. **NFR-PRF-04 (50 alerts/s) is not met in this setup** |
| burst (96 clients) | 49.4 req/s; 871 OK (93.5 %), 61 classified 503 (6.5 %), **0 timeouts**; p50 866 ms, p95 5.6 s. Recovery at 4 clients immediately after: 695/695 OK, p95 85 ms |
| concurrency | 60 concurrent ingests all OK (p95 1.5 s); 40/40 investigations completed with 8 workers: 216.6 runs/min, run p95 3.0 s |
| soak-lite (600 s) | 12,000/12,000 OK, 0 dropped; p50 50 ms, p95 203 ms, p99 250 ms. API RSS 117.4 → 117.0 MB, threads and file descriptors bounded, database connections 5 idle at start and end — no growth |

## 2a. Results — Phase 16 closure re-measurement (final correction image)

Final correction backend image `sha256:e766bc1e…` (revision label
`006f486+p16closure-content-1457df4abac8d003`), fresh database, `scripts/load_environment.py`, same
host and container limits as above, 2026-09-28. Raw:
[`evidence/phase16-closure-load.json`](evidence/phase16-closure-load.json).

| Profile | Offered | Successful throughput | Classified rejections | Latency (p50 / p95 / p99) | Errors, timeouts, drops |
|---|---|---|---|---|---|
| smoke | 45 requests | 45/45 expected statuses | 0 | 10.9 / 43.3 / 48.4 ms | none |
| capacity (closed loop, reads) | 1, 2, 4 clients × 20 s | 98.0 req/s at 1 client → **135.4 at 2** → 128.7 at 4 (plateau; observed saturation ≈ 2–4 clients) | 0 | p95 13.7 → 20.2 → 42.2 ms | 0 errors |
| steady (mixed, 20 % ingestion) | 40 req/s × 120 s (4,800) | **40.0/s**, 4,800/4,800 OK | 0 | 15 / 50 / 72 ms (max 159); reads p95 22–25 ms; ingestion p50 44, p95 72 ms | 0 dropped |
| ingest | 50 alerts/s × 60 s (3,000) | **20.9 alerts/s** (1,330 sent, all 200) | 0 | from the scheduled slot: 4.06 / 4.47 / 4.67 s | **1,670 dropped** (could not start within 1 s). NFR-PRF-04 (50/s) **not met** |
| burst | 96 clients × 15 s after 5 s idle | 58.3/s; 1,042 of 1,123 OK (92.8 %) | **81 × 503** (7.2 %), 4.5/s | 591 ms / 5.33 s / 6.23 s | **0 timeouts**; recovery at 4 clients: 816/816 OK, p95 70.6 ms |
| concurrency | 60 concurrent ingests, then 40 investigations with 8 dispatch workers | ingests 60/60 OK; **40/40 investigations completed**, 201 runs/min | 0 | ingest p95 960 ms; run p50 2.3 s, p95 3.1 s | none |
| soak-lite | 20 req/s × 600 s (12,000) | **20.0/s**, 12,000/12,000 OK | 0 | 25 / 106 / 134 ms (max 241) | 0 dropped |

**Resource behaviour.** API RSS 118.1 MB at the start of the soak and 117.6 MB at its end; threads
and open file descriptors bounded; 5 idle runtime database connections at the start and end of
every profile — no growth. During the ingest profile open file descriptors rose to 76 and returned.

**Reading these against Phase 15.** Most figures are better than §2's. That is **not** a measured
improvement: the code paths measured here did not change in Phase 16, and §4 shows run-to-run host
variance of the same size. The ingest row is the clearest example of the corrected terminology:
Phase 15's "11.9 alerts/s" counted 46 classified 503s among its responses; this run had no
rejections and 20.9 successful alerts/s, with most offered alerts dropped before they could be sent.
Neither run meets the assumed 50/s.

Related assumed targets (SRS §5, `[ASSUMED]`), judged on the Phase 16 final-image run:

* NFR-PRF-01 (ingestion to correlation decision p95 < 5 s): met at 8 alerts/s (steady: ingestion
  p95 72 ms); at the 50/s offered load the sent alerts' p95 from their slot was 4.47 s, but 56 % of
  offered alerts were dropped before sending, so **not met** beyond ingestion capacity.
* NFR-PRF-02 (incident to first ranked hypothesis p95 < 3 min for golden scenarios): investigation
  run p95 3.1 s — **with the deterministic model provider**; a live LLM's latency is not measured.
* NFR-PRF-04 (50 alerts/s sustained): **not met** (≈ 21 successful alerts/s per 2-CPU API process
  in this run; Phase 15 measured ≈ 12/s responses including rejections). Ingestion is synchronous
  validation + correlation under per-group locks; scaling it needs more API processes and a measured
  correlation-lock profile (production gap register, GAP-23).

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
