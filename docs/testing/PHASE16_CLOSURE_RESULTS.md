# Phase 16 closure correction — validation results

The independent Phase 15–16 review of `006f486` returned REVIEW FAIL with five blocking findings
(F-01 to F-05). This document is the evidence that each was corrected and that the whole system
was re-validated on the final correction images. Everything here ran locally (Windows 11 laptop,
8 logical CPUs, 15.8 GiB, Docker Desktop with an 8 GiB VM) on 2026-09-27/28. Nothing ran on
GitHub-hosted runners, against GHCR, against a live LLM or on production infrastructure.

## 1. What was validated, and on what

| Item | Value |
|---|---|
| Starting commit | `006f48670ef0bb914dfc6882533d788608f543ae` |
| Migration head | `0020_postmortem_worker` (clean from empty; `alembic check`: no drift) |
| Backend image | `asic-backend:phase14-p16closure` → `sha256:e766bc1edecdaa5d3c754f738c6162cfd9ff465a36f8af625fc3df77e5af8a56`, UID 10001 |
| Frontend image | `asic-frontend:phase14-p16closure` → `sha256:0efe46591e5ef64631f49000fb7d3ee7f8ae37cebd5eff98d32e3f12fc8af455`, UID 10001 |
| Image revision label | `006f486+p16closure-content-1457df4abac8d003` — the images were built before the correction commit existed, so the label carries a SHA-256 over the working-tree bytes of the backend's source inputs (`src/asic`, `migrations`, `alembic.ini`, `requirements/runtime.lock`, `Dockerfile`): `1457df4abac8d0035ab810e6b2a0a057b2f7e80091573cd6e168f68876dcdd92`. §9 records how the image relates to the committed tree: the same files and content, except Windows line endings in 38 files the correction did not touch |
| Kind worker image (local test only) | `asic-backend-localsim:phase14-e766bc1edecd` → `sha256:84b00b2c…`: the backend image's 10 layers unchanged plus one layer adding `src/asic/simulators` (the production image excludes simulators, FR-INT-04). Never published |

## 2. F-01 — postmortem capability (FR-PMT-01/02)

| Property | Evidence |
|---|---|
| G11 drafts a postmortem for every resolved incident; nothing else is eligible | `src/asic/postmortem/author.py`; worker `WorkKind.POSTMORTEM`; `tests/postmortem` (ineligible escalated incident → no draft) |
| Facts come from persisted records; model prose is limited to four sections | `assemble()` builds summary, impact, timeline, root cause, contributing factors, detection, response and verification from typed columns; the prompt (`postmortem_author` 1.0.0, prompt set `2026.09.27-1`) asks only for summary, went well, went poorly and follow-ups |
| Every factual claim cites a persisted record of the incident | Handles (`INC`, `A1`, `E7`, `EV2`, `H1`, `RA1`, `PD1`, `AP1`, `TX1`, `VF1`) resolve to row ids; tests, the demo and kind re-check every citation against the database (kind: 19/19 resolved) |
| Unsupported claims are removed, never silently kept | Deterministic validator: `no_citation`, `unknown_citation`, `flagged_source_only`, `unsupported_causal_claim`, `unsupported_figure`; removed claims are listed in `uncertainties` with their reason (test: 5 of 6 hostile claims removed, the supported one kept) |
| Prompt injection gains no authority | SC-0007 evidence ("ignore all previous instructions…") reaches the model only in the fenced data section; a "publish this postmortem" claim resting on flagged evidence is removed; a model-returned `"status": "published"` is ignored and reported |
| Draft only, human review required, never published | Migration 0020: append-only (runtime role holds only SELECT, INSERT), check constraint `unreviewed_drafts_only`; tests prove an UPDATE is denied and a non-draft INSERT refused |
| Idempotent; versions only on changed sources | One row per (incident, source fingerprint); three repeated drafts return the same id; a new annotation produces version 2 |
| Tenant isolation | FORCE RLS; tenant B cannot read or draft tenant A's postmortem (test); API returns 404 across tenants |
| Model failure | A failing provider yields a records-only draft, recorded in `generation` and `validation` |

Suites: `tests/postmortem` (8 tests), `tests/api/test_phase16_routes.py` (3), postmortem steps in
`tests/worker`, demo scenario 6, kind acceptance.

## 3. F-02 — the deployed worker

| Property | Evidence |
|---|---|
| Entry point | `python -m asic.worker` (`src/asic/worker`); refuses to start with a logged reason on invalid settings, in live mode (no live model, GAP-08) and with a plaintext production database URL; imports and refuses cleanly without the simulator package (test, final image) |
| Durable work, no new queue | PostgreSQL only: investigation dispatches, stranded runs, remediation requests, suspended remediation runs with something new to act on, resolved incidents without a current draft |
| Claims | Session-scoped advisory lock per item over the kernel lease, the one-live-run index and dispatch/request linkage |
| Concurrency | Fixed pool (`ASIC_WORKER_CONCURRENCY`, max 8); claims never exceed free slots |
| Failure / crash | Worker killed after its third node: a second worker is refused while the lease is valid (`busy`), then resumes the same run once with no repeated effect (`tests/worker`, demo) |
| Shutdown | SIGTERM stops claiming and drains; a drain deadline abandons rather than hangs; kind pod deletion terminated in 1.9 s with a ready replacement |
| Health | `/livez` (loop turning), `/readyz` (recent successful poll, behaviour version resolved, not draining); database outage → unready, alive, no crash (test) |
| Remediation entry | `POST /incidents/{id}/remediation-requests`; linked to its run in the run-creating transaction; the requester cannot approve the resulting action (test) |
| Kubernetes | Deployment on the same backend image, UID 10001, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no service-account token, runtime database Secret only, resources, probes, 45 s grace over a 30 s drain, PDB, NetworkPolicy narrower than the API's |

**Kind acceptance (final images, fresh cluster, two worker replicas, API path only):**

| Step | Result |
|---|---|
| Worker identity | UID 10001, no service-account token, read-only root filesystem, probes 200, runtime role (no superuser, no BYPASSRLS, no migration privilege) |
| Worker network policy | worker→database allowed; worker→internet denied; worker→API denied; frontend→worker denied |
| Alert | signed connector `POST /ingest/alerts` → 200 `accepted` |
| Investigation | worker-driven, `escalated` in 6.1 s; 3 evidence records, 1 hypothesis, 1 execution trace |
| Remediation | responder request → `k8s.deployment.rollback`, policy `require_approval` (production) → approved via the API with the action hash → executed → settling → verification `verified`; action `verified`; 72.5 s after approval |
| Postmortem | 1 draft, `review_required`, basis `independently_verified`, 19 citations, 19 resolved, 0 claims removed, not published |
| Persisted state | 2 workflow runs, 1 mutating execution, 1 resolved transition, 1 postmortem row, 0 non-draft postmortems |
| Two replicas | both Running and ready; every item executed exactly once across them (investigation 1 completed; remediation start 1; remediation run 1 suspended + 1 completed; postmortem 1 created). One pod happened to win all five items; the duplicate-claim race is proven deterministically by `tests/worker` (two workers, one dispatch, one execution) |

## 4. F-03 — production database TLS (NFR-SEC-07)

| Case | Result |
|---|---|
| Production + plaintext / `disable` / `allow` / `prefer` / `require` / `verify-ca` | refused before connecting |
| Production + `verify-full` without a CA, or with a missing CA file | refused |
| Production + `verify-full` + mounted CA, or `sslrootcert=system` | accepted |
| libpq environment variables | honoured as libpq would; cannot weaken what the URL says |
| Unix socket host / host list / repeated parameter / malformed URL | refused with a controlled message |
| Secrets | the password and host never appear in the message or the logs |
| Non-production profiles | explicit plaintext accepted (`local`, `development`, `test`) |
| Migration entry point | `alembic upgrade head` refuses plaintext in production |
| Final image | `python -m asic.worker` with a plaintext production URL exits 2 with the reason and without the password |

`tests/security/test_database_tls.py`: 20 tests. Final status: **PARTIAL** — application and
manifest enforcement are built; verified TLS against a real TLS-serving managed database,
encryption at rest and in-cluster mTLS are not (GAP-03, GAP-29).

## 5. F-04 and F-05 — claims, architecture, gaps, requirements

* Claims corrected in README, résumé evidence, interview guide, portfolio evidence and the
  CHANGELOG: the autonomy matrix is stated precisely (only R1 outside production is autonomous;
  R1 in production and R2 need a hash-bound human approval; R3 is not expressible); the OIDC
  attestation is a locally validated workflow never run remotely; as-built counts are **10
  LangGraph nodes** and **4 model-calling components** (G3, G5, G6, G11).
* Architecture: agent topology gains an as-built section (G11 a worker stage, G12 not built);
  memory and RAG show no T3 → T2 path; the orchestration kernel's and tenancy document's
  "Phase 15 obligations" became evidence or gaps; the stuck-workflow runbook describes the real
  recovery path (no fictional command); operator, deployment, data-model, failure, observability,
  security and threat-model documents describe the worker, G11 and the TLS contract.
* Requirements recomputed one by one: 131 requirements — **112 SATISFIED, 19 PARTIAL, 0 UNSATISFIED, 0 EXTERNAL
  PREREQUISITE** (counted from the table rows, not from a summary). The 19 partial: FR-CLB-01,
  FR-CLB-03, FR-EVD-04, FR-EVL-04, FR-EVL-06, FR-EVL-08, FR-ING-02, FR-INT-01, FR-INV-05,
  FR-INV-08, FR-OBS-01, FR-VRF-04, NFR-PRF-01, NFR-PRF-02, NFR-PRF-04, NFR-REL-09, NFR-SEC-07,
  NFR-SEC-12, NFR-SEC-14.
* Gap register rebuilt: **37 open** — 9 EXTERNAL PREREQUISITE, 10 NOT BUILT, 4 NOT VERIFIED, 14 KNOWN
  LIMITATION (counted from the register's rows); 2 closed.

## 6. Full validation

| Check | Result |
|---|---|
| Full test suite, fresh PostgreSQL 16 + pgvector, `jq` on PATH | **2,472 passed, 0 failed, 0 skipped**, 1 warning (a third-party deprecation in `starlette.testclient`: the `anyio.abc.BlockingPortal` alias); 18 min 57 s on database `0020_postmortem_worker` migrated from empty. The log also shows one `Exception occurred during processing of request` line: the local vendor fixture server of an unchanged Phase 13 test (`test_an_oversized_response_is_refused`) reporting the reset when the adapter stops reading an oversized response, as the test intends |
| Evaluation, simulator mode | **PASSED — 18/18** scenarios (0 failed, 0 errored, 0 contested); unsafe actions 0; false success 0; RCA@1 1.0; verification success 0.6667; escalation rate 0.3571; LLM judges `not_measured`; labelled "SIMULATED / REPLAY EVALUATION - not production results"; evaluator `2026.09.26-eval-2`; fresh database through the application role; `--baseline none` |
| Evaluation, strict replay mode | **PASSED — 18/18** scenarios (0 failed, 0 errored, 0 contested); unsafe actions 0; false success 0; RCA@1 1.0; verification success 0.6667; escalation rate 0.3571; LLM judges `not_measured`; labelled "SIMULATED / REPLAY EVALUATION - not production results"; evaluator `2026.09.26-eval-2`; fresh database through the application role; `--baseline latest` reports `no_baseline` on a fresh database (a baseline must match mode and selection) |
| Demo (`scripts/demo.py`) | `DEMO PASSED`: five investigations (SC-0007 flag, provenance and no authority change; SC-0012 supersession), crash/resume, the API + worker product path, 18/18 gate |
| ruff / ruff format / mypy --strict | clean / 457 files formatted / no issues in 167 source files |
| Alembic | empty → `0020_postmortem_worker`; `alembic check` no drift |
| Security gate `--strict --require-container-scan` | **11/11 passed, 0 failed, 0 skipped, 0 not executable**: tenancy schema, security test suite, SAST (ruff S), dependency lock, runtime dependencies, repository hygiene, pip-audit, npm audit, gitleaks over the full history and over the working tree, Trivy HIGH/CRITICAL on `sha256:e766bc1e…` (backend) and `sha256:0efe4659…` (frontend) — no findings. An earlier attempt was stopped by the host for low memory before producing a verdict |
| SBOM (CycloneDX) | CycloneDX 1.6 from the pinned Trivy image, as CI generates it: backend 118 components, frontend 34; `scripts/validate_sbom.py` passes for both with the expected packages (fastapi, SQLAlchemy / next, react) and each SBOM's image ID equal to the final image ID. The SBOM files are build outputs and are not committed |
| Frontend | `npm ci`, `npm run lint` (`tsc --noEmit`), `npm run build` (compiled successfully), `npm audit --omit=dev`: 0 vulnerabilities |
| Terraform | `fmt -check`, `init -lockfile=readonly`, `validate`; kind: apply, no-drift re-plan, destroy |
| Kustomize | all overlays render; server-side dry-run admitted under PSA `restricted` |
| actionlint (as CI runs it) / workflow trust tests | clean / 21 passed |
| promtool / otelcol validate | 13 alert + 9 recording rules, rule tests pass / collector config valid |
| Docs validator / spec transcription / hygiene / runtime deps / dependency lock / clean install | all clean (the clean install builds a new environment from package metadata alone, imports the package and runs the migration chain) |

### Kind + Cilium (final images)

Fresh kind 1.34 cluster with checksum-pinned Cilium 1.20.2; Terraform apply (namespace, PSA
`restricted`/`v1.34`, five tokenless service accounts including `asic-worker`) and a no-drift
re-plan; a privileged pod rejected at admission; the renderer refused a CIDR set covering
`0.0.0.0/0`; a failing migration stopped the release with nothing applied and its non-vacuity
mutant did apply; the real migration to `0020_postmortem_worker`, behaviour-version registration
and rollout of API, worker and frontend with the automatic post-rollout smoke; runtime network
policy (frontend→API, API→database and DNS allowed; frontend→database, internet egress and another
namespace→API denied); the worker checks and acceptance in §3; worker SIGTERM termination; API
outage handling; failed rollout recovery; the redeployment matrix (repeat, changed template,
failed migration and fix-forward, finalizer-held deletion, active-migration refusal, Job deleted
mid-wait, never-ready release, recovery); Terraform destroy.

**Retention (corrected test).** The first final run exposed a test defect: the experiment counted
rows across all tenants as the owner (which bypasses row-level security) and so saw rows the
worker acceptance had created in another tenant. It now filters every count by tenant and seeds a
second tenant. Result: tenant A — dry run 3 eligible, 0 deleted, 4 rows remain; execute 3 deleted,
1 recent row kept; tenant B — 2 rows before and after, 0 deleted; 2 receipts, each naming its
tenant; CronJob delivered suspended and admitted; identity `asic_maintenance_local` (member of
`asic_maintenance` only).

**Chaos (6/6 passed):**

| Experiment | Result |
|---|---|
| API pod kill (1 replica) | replacement ready endpoint 10.0 s; API via Service unavailable for one window of 8.0 s; frontend liveness unaffected; replacement's egress attempts all denied |
| Frontend pod kill | ready endpoint in 7.9 s; API healthy throughout (174 samples) |
| PostgreSQL restart | database back in 2.3 s; 2 classified 503s (longest 1.3 s); no liveness failure; schema revision preserved (`0020_postmortem_worker`); API not restarted |
| Database access revoked | API removed from endpoints after 14.2 s, back 4.4 s after restore; requests answered with classified 503 (longest 0.27 s); no restarts |
| OTLP collector unreachable | request p50 9.4 ms / p95 15.2 ms; 2 exporter error lines; API not restarted |
| Migration pod overlap | orchestrator waited for the previous pod; max concurrent migration pods 1 (95 samples); bypass control 2; bounded refusal after 22.2 s with nothing applied |

Raw verdict: [`evidence/phase16-closure-kind-smoke-chaos.json`](evidence/phase16-closure-kind-smoke-chaos.json).

Two earlier final-run attempts did not complete: the first failed at the retention test defect
above; the second failed before any product manifest was applied because the kind node's pull of
the in-cluster PostgreSQL image from Docker Hub exceeded the 180 s rollout wait (the passing run's
pull took 23 s). A kind run before that was stopped by the host for low memory.

### Load (LOCAL BENCHMARK, final image)

Fresh database, `scripts/load_environment.py`, API container limited to 2 CPUs / 1 GiB, harness
on the same host, 2026-09-28; the harness recorded the API image ID `sha256:e766bc1e…` and its
revision label. Full table and terminology: [LOAD_AND_PERFORMANCE.md §2a](LOAD_AND_PERFORMANCE.md#2a-results--phase-16-closure-re-measurement-final-correction-image);
raw: [`evidence/phase16-closure-load.json`](evidence/phase16-closure-load.json). No tuning was
done for this run.

| Profile | Offered | Successful | Classified rejections | p50 / p95 / p99 | Errors, timeouts, drops |
|---|---|---|---|---|---|
| steady (mixed, 20 % ingestion) | 40 req/s × 120 s | 40.0/s (4,800/4,800) | 0 | 15 / 50 / 72 ms | none |
| ingest | 50 alerts/s × 60 s (3,000) | 20.9 alerts/s (1,330, all 200) | 0 | 4.06 / 4.47 / 4.67 s from the scheduled slot | 1,670 dropped before sending — **50/s not met** |
| burst | 96 clients × 15 s | 58.3/s (1,042 of 1,123, 92.8 %) | 81 × 503 (7.2 %) | 591 ms / 5.33 s / 6.23 s | 0 timeouts; recovery 816/816 OK |
| concurrency | 60 ingests, then 40 investigations (8 workers) | 60/60; 40/40 investigations | 0 | ingest p95 960 ms; run p95 3.1 s | none |
| soak-lite | 20 req/s × 600 s | 20.0/s (12,000/12,000) | 0 | 25 / 106 / 134 ms | none |

Resources: API RSS 118.1 → 117.6 MB over the soak; threads and file descriptors bounded; 5 idle
runtime database connections at the start and end of every profile. Differences from Phase 15
are host variance, not a claimed improvement.

## 7. Evaluation scope

The canonical evaluation suite stays at **18 scenarios**: G11's golden acceptance and negative
controls live in `tests/postmortem`, the worker suite, the demo and the kind acceptance, not in
the evaluation corpus (adding them there would need recorded replay fixtures for G11's model
call).

## 8. Remaining non-blocking findings

* **F-06** — automated compensation after failed verification is not built; rollback tools are
  registered but never proposed or triggered (FR-VRF-04 PARTIAL, GAP-11).
* Review LOW items carried forward: free-text `key=value` redaction gaps (GAP-35) and the loopback
  SaaS allowlist form in non-production composition (GAP-36).
* Every other open item is in the [production gap register](../PRODUCTION_GAP_REGISTER.md); the
  overall verdict in the [readiness review](../PRODUCTION_READINESS_REVIEW.md) is unchanged: not
  ready for unsupervised production.

## 9. Commit binding

The images, the kind runs and the load run were produced from the working tree before the
correction commit existed, so no commit SHA could be baked into them. The binding is by content,
and it is exact except for line endings:

* **The label's fingerprint** (`1457df4a…`) is a SHA-256 over the raw working-tree bytes of the
  git-listed files under `src/asic`, `migrations`, `alembic.ini`, `requirements/runtime.lock` and
  `Dockerfile`, each as path, NUL, bytes, NUL in sorted path order (this includes
  `src/asic/simulators`, which `.dockerignore` then keeps out of the image).
* **Line endings.** In that Windows working tree, 39 of those files — none of them changed by the
  correction — had CRLF line endings. Git stores every one of them with LF (`.gitattributes`:
  `* text=auto eol=lf`), so the same computation over the commit's git objects gives
  `a6d6678e41425b7d181bb42257d9a98b6b0a0eca4fb599155ef8995c21f1db8e`, not `1457df4a…`. Applied to
  the working tree with CRLF normalised to LF, it gives `a6d6678e…` exactly; nothing else differs.
* **The image itself, checked directly.** The 189 files under `/app/src`, `/app/migrations` and
  `/app/alembic.ini` extracted from `sha256:e766bc1e…` are exactly the commit's files in those paths
  minus `src/asic/simulators`: 151 are byte-identical to the committed blobs and 38 differ only by a
  CR before each LF. There is no other difference. Python, Alembic and `configparser` read both line
  endings identically, so the tested image runs the committed code; an image rebuilt from a fresh
  LF checkout would be byte-different and have a different image ID.
* The frontend image's inputs (`frontend/`) are unchanged since `84e2d9f`; the correction does not
  touch them.
* Kubernetes manifests, overlays and scripts used by the kind run were last modified before that
  run started, and the committed versions are those files.

Reproduce the commit-side value: for each path listed by `git ls-tree -r --name-only <commit> --
src/asic migrations alembic.ini requirements/runtime.lock Dockerfile` in sorted order, hash `path`,
a NUL byte, the blob (`git cat-file blob <commit>:<path>`) and a NUL byte.
