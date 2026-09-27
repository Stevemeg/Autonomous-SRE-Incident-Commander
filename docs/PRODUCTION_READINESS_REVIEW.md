# Production readiness review

Scope: the repository at the Phase 16 closeout (Phase 15 evidence: `74a202a`). This review asks,
area by area, whether the system could be operated in production **as built**, and on what
evidence. It is written to be checked, not believed: every verdict names its source.

| Verdict | Meaning |
|---|---|
| **READY** | Built, tested adversarially, and verified end to end in the local environment; nothing known is missing for this area |
| **CONDITIONALLY READY** | Built and verified locally, with a named condition that must hold (or be supplied) in production |
| **NOT VERIFIED** | Built, but the evidence that matters for production can only come from an environment this repository has not run in |
| **EXTERNAL PREREQUISITE** | Depends on infrastructure or people outside this repository |

Gap identifiers refer to the [production gap register](PRODUCTION_GAP_REGISTER.md).

## 1. Summary

| Area | Verdict | Condition or reason |
|---|---|---|
| Safety of remediation (policy, approval, execution, verification) | **READY** | Invariants SI-1…SI-15 each attacked; E2E scenarios B, F, H; crash matrix; tool-abuse campaign |
| Tenant isolation | **READY** | RLS + composite tenant FKs + mechanical schema audit; schema-wide tenant campaign as the real non-owner role |
| Authentication and authorization | **CONDITIONALLY READY** | Requires a real OIDC/JWKS issuer (no live-IdP interop test) and IdP token lifetimes ≤ `ASIC_JWT_MAX_LIFETIME_SECONDS` |
| Input handling and API robustness | **READY** | Seeded fuzzing of every route: bounded 4xx or classified 503, never a 500 |
| Secrets and telemetry hygiene | **READY** | Canary campaign across every sink; gitleaks history and tree clean; linear-time redaction |
| Investigation workflow (bounded, durable, replayable) | **CONDITIONALLY READY** | Proven with the deterministic model provider only; a live model needs GAP-08 and re-evaluation; no worker Deployment (GAP-07) |
| Database schema and migrations | **CONDITIONALLY READY** | Migration chain clean from empty; fail-closed ordering and overlap-safe Job replacement proven on kind; expand/contract not guaranteed (GAP-06) |
| Delivery pipeline and supply chain | **NOT VERIFIED** | Every gate executed locally (security gate 11/11, SBOMs, Trivy, evaluation, kind smoke); remote GitHub Actions/GHCR/attestation never run (GAP-01) |
| Kubernetes deployment | **CONDITIONALLY READY** | PSA `restricted`, default-deny network policy, probes, rollback verified on kind; needs a cluster with ingress/TLS (GAP-02) and a managed database (GAP-03) |
| Resilience to dependency failure | **READY** | Database stress, dependency fault matrix, model failure, telemetry outage, 6/6 chaos experiments on kind |
| Behaviour under load | **CONDITIONALLY READY** | No deadlock or collapse under burst after the Phase 15 fixes; capacity measured only locally, ingestion ≈ 12 alerts/s per 2-CPU process (GAP-23) |
| High availability | **NOT VERIFIED** | Manifests declare 2 replicas and PDBs; only single-replica behaviour measured (GAP-04) |
| Disaster recovery, backups | **EXTERNAL PREREQUISITE** | GAP-03, GAP-05 |
| Encryption in transit and at rest | **EXTERNAL PREREQUISITE** | GAP-02, GAP-03, GAP-29 |
| Observability and alerting | **CONDITIONALLY READY** | Metrics, traces, logs, dashboards, alerts and runbooks validated as configuration; backends and routing not deployed (GAP-22) |
| Operations documentation | **READY** | Runbook per alert plus operational runbooks, troubleshooting and operator guides |
| Data retention | **CONDITIONALLY READY** | Idempotency cache lifecycle executor with receipts; every other class retained until GAP-15 prerequisites exist |
| External integrations | **NOT VERIFIED** | Local deterministic servers only (GAP-16) |
| AI quality (RCA accuracy with a real model, judge calibration) | **NOT VERIFIED** | GAP-08, GAP-09; simulated evaluation validates the pipeline, not reasoning |
| Rate limiting across replicas | **EXTERNAL PREREQUISITE** | Per-process limits; gateway limiter required (GAP-13) |

**Overall:** the system is **not ready for unsupervised production use** and does not claim to be.
It is ready for a controlled pilot on a real cluster **once** the external prerequisites in the
summary are supplied (ingress/TLS, managed PostgreSQL with PITR, OIDC issuer, observability
backends, gateway rate limiting) and the NOT VERIFIED items are exercised there: a remote CI run,
two-replica chaos, and live vendor sandboxes. Autonomous remediation should stay restricted to R1
in non-production until a live model has passed the evaluation gate.

## 2. Evidence by area

### Safety of remediation — READY

Proposal, policy gate, approval, executor and verifier are separate nodes; the gate is
deterministic and takes no retrieved or model content; approvals bind to an action-version hash;
effects are claimed before dispatch and never repeated after a crash (E2E scenario F: exactly one
patch reached the cluster before and after recovery); verification is independent and a failed
verification is never reported resolved (scenario H). Sources:
[remediation-safety-policy.md](architecture/remediation-safety-policy.md),
[E2E_VALIDATION.md](testing/E2E_VALIDATION.md),
[SECURITY_HARDENING.md](testing/SECURITY_HARDENING.md).

### Tenant isolation — READY

Row-level security with `FORCE`, one canonical policy per table, composite tenant foreign keys
and a mechanical audit of the live schema; the application role holds no `DELETE`. The Phase 15
campaign attacked every tenant-scoped table and every GET route as the real non-owner role.
Sources: [tenancy-and-rls.md](architecture/tenancy-and-rls.md),
`tests/security/test_tenant_campaign.py`.

### Authentication and authorization — CONDITIONALLY READY

OIDC/JWKS verification (asymmetric only, bounded key cache, fail-closed after the stale bound),
token lifetime bounded, RBAC matrix over every route. Condition: a real identity provider, whose
interoperability has not been tested here. Sources:
[AUTHORIZATION.md](security/AUTHORIZATION.md), `tests/security/test_auth_campaign.py`.

### Delivery and supply chain — NOT VERIFIED

Digest-pinned images running as UID 10001, Trivy HIGH/CRITICAL gate, CycloneDX SBOMs bound to image
IDs, OIDC provenance attestation and a verification script, least-privilege workflows. All checks
pass when run locally ([PHASE15_RESULTS.md](testing/PHASE15_RESULTS.md)); none has run on GitHub's
runners.

### Resilience — READY

See [RESILIENCE_AND_CHAOS.md](testing/RESILIENCE_AND_CHAOS.md): database outages are classified
503s with recovery and no restart; unknown integration outcomes are reconciled, never retried
blindly; a failing or hostile model cannot gain authority; the migration orchestrator never lets
two migration pods overlap (measured max = 1, with a non-vacuity control).

### Load — CONDITIONALLY READY

See [LOAD_AND_PERFORMANCE.md](testing/LOAD_AND_PERFORMANCE.md). The load harness found two
connection-pool deadlocks that made the API stop answering under concurrency; both are fixed with
regression tests, and a burst of 96 concurrent clients now degrades to classified 503s without
timeouts. The condition is capacity: the measured figures are one laptop's.

## 3. Cost and scale

Nothing below is a measured production cost. It explains how cost and scale behave, from the
design and the local measurements, so that a pilot knows what to measure.

**Model cost.** Every model call is reserved against a per-run token and cost budget before it is
made, and settled afterwards; exhaustion terminates the run cleanly. The only provider wired today
is deterministic and uses a **nominal** price table (`src/asic/llm/deterministic.py`: "not a quoted
rate for any provider"), so the evaluation's `cost_usd` (0.30 for 18 scenarios, 71,930 tokens)
demonstrates the accounting, not a bill. Real cost per incident = tokens per run × the chosen
model's price; the budget caps it by construction.

**Compute.** The API is stateless apart from per-process limiters; it scales horizontally. One
2-CPU process served ≈ 77–102 read req/s at saturation locally and ≈ 12 alerts/s of ingestion.
Ingestion is synchronous validation plus correlation under per-group locks, so adding processes
is expected to raise throughput until correlation contention dominates; that scaling is **not
measured** (GAP-23).

**Database.** Each API process holds at most 15 pooled connections (SQLAlchemy defaults 5 + 10);
PostgreSQL's default `max_connections` is 100, so more than about six API processes needs a larger
connection budget or a pooler. Tables that grow with incidents are retained by policy (only the
idempotency cache is deleted), so storage grows with incident volume until GAP-15 is closed.

**Telemetry.** Metric labels are bounded (no tenant or incident identifiers), so metric cardinality
does not grow with tenants; span export is best-effort with a bounded queue.

**Scaling path, in order:** gateway rate limiting (GAP-13) → multiple API replicas on a real
cluster with 2-replica chaos (GAP-04) → a worker Deployment (GAP-07) → a measured ingestion
scaling curve (GAP-23) → a live model with the evaluation gate (GAP-08).
