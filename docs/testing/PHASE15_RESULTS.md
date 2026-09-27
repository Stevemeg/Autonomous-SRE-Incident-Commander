# Phase 15 validation results

Baseline: `4904d18` (Phase 14 closure). Validation run: 2026-09-27, on the working tree that became
the Phase 15 commit. Host: Windows 11 laptop, 8 logical CPUs, 15.8 GiB; Python 3.12.13; Docker
Desktop 29.5.3; PostgreSQL 16.15 + pgvector (fresh containers, migrated empty → head).
Every result below is **LOCAL**; nothing was executed against a remote or production environment.

## 1. Validation matrix

| Check | Command (abridged) | Result |
|---|---|---|
| Full test suite | `pytest -q` with `ASIC_TEST_DATABASE_URL` on a fresh database, `jq` on `PATH` | **2,422 passed, 0 failed, 0 skipped** (baseline: 2,035 passed + 15 skipped for missing `jq`; +372 test cases) |
| Lint / format | `ruff check .`, `ruff format --check .` | clean (419 files) |
| Types | `mypy --strict src` | no issues (158 files) |
| Migrations | empty database → `alembic upgrade head`; `alembic check` | head `0019_retention_maintenance`; no drift |
| Clean install | `scripts/verify_clean_install.py` | clean: installs from metadata alone, imports, migration chain resolves |
| Docs | `scripts/validate_docs.py` | links, Mermaid, requirement traceability (both directions), spec coverage, scope boundary, unmeasured-claim and invariant-ID checks |
| Spec transcription | `scripts/verify_spec_transcription.py` | verified (0 dropped, 0 invented lines) |
| Hygiene / dependencies | `check_repo_hygiene.py`, `check_runtime_dependencies.py`, `check_dependency_lock.py` (via the gate) | clean |
| Security gate | `security_gate.py --strict --require-container-scan` with both final images | **11/11 passed**: tenancy schema, security suite, SAST (ruff S), dependency lock, runtime deps, hygiene, pip-audit, npm audit, gitleaks history, gitleaks tree, Trivy HIGH/CRITICAL |
| SBOM | Trivy CycloneDX for both images → `validate_sbom.py` | 0 findings each (expected packages present, bound to image ID) |
| Frontend | `npm ci`, `npm run lint` (`tsc --noEmit`), `npm run build`, `npm audit --omit=dev --audit-level=high`, `npm run test:health` | pass; 0 vulnerabilities; health contract passed (the SIGSTOP case is Linux-only and skipped on Windows) |
| Evaluation | `asic.evaluation.gate --suite golden --mode simulator` / `--mode replay --baseline latest` | **18/18 passed** in both modes; 0 unsafe actions, 0 false successes; labelled "SIMULATED / REPLAY EVALUATION – not production results"; replay reports `no_baseline` on the fresh database (F-09: a baseline must match mode and full selection) |
| Kubernetes | `kubectl kustomize` for base, migration, maintenance and 4 local overlays | all render |
| Workflows | `actionlint 1.7.7` | clean |
| Observability config | `scripts/check_observability.sh` (promtool rules + unit tests, otelcol validate) | success |
| Terraform | `fmt -check`; `init`/`validate`/`apply`/no-drift `plan`/`destroy` inside the kind smoke | pass |
| Deployment smoke + chaos | `deployment_smoke.py --chaos` with the final images | **passed**, including 6/6 chaos experiments and the retention CronJob; cluster destroyed afterwards |
| Load | `load_harness.py --profile all` on the final image, fresh database | see [LOAD_AND_PERFORMANCE.md](LOAD_AND_PERFORMANCE.md) |
| Redaction timing | `scripts/redaction_benchmark.py` | linear; 100 KB worst case ≈ 35 ms |

Final images: backend `sha256:5fd927dff0a43a014aa56f12ab21186125c0155a26076e86ad986db60a155b3d`,
frontend `sha256:78be086986d176c6bb642a2c27653193ba207647cdcbfe468c1bcbb90a549136` (tagged
`:phase14-p15final` for the gate, whose container policy accepts only digests or the pipeline's
`phase14-*` tags; the policy was not relaxed).

## 2. Security tools

No threshold was lowered and no finding was suppressed. During this run gitleaks' working-tree
pass reported two synthetic canaries (a JWT and an `sk-` key) in the new secret-leak campaign; they
are now assembled at runtime so no token-shaped literal is in the source, and the campaign's runtime
values are unchanged. The repository hygiene scanner's per-line
`hygiene: synthetic-secret-fixture` marker was added to seven intentional fixtures, following the
existing convention (each exemption is visible on its own line).

## 3. Measured results (sources)

| Area | Result | Source |
|---|---|---|
| Load | capacity plateau ≈ 77 req/s at 4 clients (2-CPU API); steady 40 req/s 0 errors (p95 378 ms); soak 600 s 12,000/12,000 OK, no resource growth; burst 96 clients 93.5 % OK / 6.5 % classified 503 / 0 timeouts; 50 alerts/s **not sustained** (≈ 12/s) | [LOAD_AND_PERFORMANCE.md](LOAD_AND_PERFORMANCE.md), `evidence/phase15-load-final.json` |
| Chaos | 6/6 experiments passed; API pod kill ≈ 5.8 s outage with 1 replica; max concurrent migration pods = 1 | [RESILIENCE_AND_CHAOS.md](RESILIENCE_AND_CHAOS.md), `evidence/phase15-kind-smoke-chaos.json` |
| Security campaigns | 9 campaign suites, defects fixed as listed | [SECURITY_HARDENING.md](SECURITY_HARDENING.md) |
| End-to-end | scenarios A–H, 9 tests passed | [E2E_VALIDATION.md](E2E_VALIDATION.md) |
| Redaction | 20 KB: 7 s / 51 s before → 8.7 ms / 6.3 ms after | [LOAD_AND_PERFORMANCE.md §5](LOAD_AND_PERFORMANCE.md#5-redaction-timing-1514) |

## 4. Carry-forward debt — final status

| Item | Status | Evidence |
|---|---|---|
| N-3 renderer CIDR policy | **FIXED** | public prefix floor /24 (/48), ≤ 64 entries, special-purpose ranges refused; `tests/packaging/test_deployment_rendering.py`, SSRF campaign |
| N-4 real 600 s wait in the mutation smoke | **FIXED** | mutant run bounded (`migration_timeout=180`, `pod_timeout=60`) |
| P13-SEC-05 token lifetime | **FIXED** | `iat` required, `exp − iat` ≤ 3600 s default (300–5400 s) in both verifiers; auth campaign |
| F-07 unreachable alert status | **FIXED** | `AsicRemediationPartialEffect`; selector reachability test |
| F-09 silent comparison omissions | **FIXED** | evaluation hardening tests |
| F-10 unwritable gate output traceback | **FIXED** | controlled `errored` exit |
| F-12 `unsafe_actions` semantics | **FIXED** | exact count of unauthorised mutating executions |
| F-17 collector environment label | **FIXED** | collector resource processor; config test + otelcol validate |
| INFO explicit baseline id | **FIXED** | malformed/nonexistent id refused |
| Retention executor | **FIXED (scoped)** | idempotency cache only (ADR-0032); other classes INTENTIONALLY DEFERRED WITH EXPLICIT PRODUCTION PREREQUISITE (lineage-aware cascades, PITR coordination, legal hold) |
| Migration pod overlap | **FIXED** | bounded, fail-closed wait; proven live on kind |
| Phase 14 INFO items | **VERIFIED NOT A DEFECT / FIXED** | redaction linearity fixed; diagnostics bare-token redaction added |
| Remote GitHub Actions / GHCR / attestation | **UNVERIFIED EXTERNAL ENVIRONMENT LIMITATION** | workflows statically validated only |
| Remote TLS | **INTENTIONALLY DEFERRED WITH EXPLICIT PRODUCTION PREREQUISITE** | ingress controller + certificate management |
| High availability | **UNVERIFIED EXTERNAL ENVIRONMENT LIMITATION** | 1-replica kind only; pod-kill outage measured, 2-replica availability not measured |
| Disaster recovery / PITR | **INTENTIONALLY DEFERRED WITH EXPLICIT PRODUCTION PREREQUISITE** | managed database with PITR, restore drill |
| Zero-downtime migrations | **INTENTIONALLY DEFERRED WITH EXPLICIT PRODUCTION PREREQUISITE** | per-migration expand/contract review |

## 5. Defects found in Phase 15 (all fixed, each with a regression test)

Quadratic redaction (4 patterns); opaque 500s on database failures; lost optimistic-lock race as
500; `NaN` input as 500 and client input echoed in 422s; limiter O(n) prune; planner letting
`BudgetExhausted` escape; unjittered retries; missing TCP keepalives; percent-encoded egress hosts
accepted; secrets persisting in checkpoints, planner rationale, trace failure events and 422
locations; bare tokens in deployment diagnostics; migration pod overlap; **two connection-pool
deadlocks under concurrency** (ingestion holding two connections; request session held across a
thread hop), found only by the load harness. A pre-existing order-dependent assertion in
`tests/e2e/test_scenarios.py` (two reservations with equal timestamps) was made order-independent.

## 6. Exit gate

No known CRITICAL or HIGH finding remains open. Remaining MEDIUM items are external prerequisites
or deliberately deferred capabilities recorded in the production gap register, none of which is a
defect in delivered code. Known limits that bound any claim: per-process rate limiting,
deterministic-only model provider, no deployed worker, single-replica local measurements,
ingestion capacity below the assumed 50 alerts/s.
