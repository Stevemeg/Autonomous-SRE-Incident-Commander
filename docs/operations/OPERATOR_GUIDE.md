# Operator guide

For the people who run the Incident Commander. It describes the running system as it exists in
this repository; anything that needs infrastructure outside it is marked as such and listed in the
[production gap register](../PRODUCTION_GAP_REGISTER.md).

## 1. Components

| Component | What it is | Where |
|---|---|---|
| API (`asic-api`) | FastAPI: ingestion, incidents, approvals, evaluation results, administration (read-only), `/livez`, `/readyz`, `/metrics` | `python -m asic.api`; `deploy/kubernetes/base` |
| Frontend (`asic-frontend`) | Next.js incident-command dashboard behind an identity proxy session | `frontend/` |
| Migration Job (`asic-migration`) | One-shot Alembic upgrade run before every rollout, with its own database role | `deploy/kubernetes/migration` |
| Retention CronJob (`asic-retention`) | Idempotency-cache lifecycle; delivered **suspended** and **dry-run** | `deploy/kubernetes/maintenance` |
| PostgreSQL 16 + pgvector | The single datastore; row-level security for every tenant table | managed service in production (GAP-03) |
| Worker (`asic-worker`) | Drives recorded work from PostgreSQL: investigation dispatches, remediation requests and runs, and G11 postmortem drafts for resolved incidents; probes on `:8081` (`/livez`, `/readyz`, optional `/metrics`) | `python -m asic.worker`; `deploy/kubernetes/base/worker-deployment.yaml`. **Live mode refuses to start** until a live model exists (GAP-08); only the non-production simulator profile runs today (GAP-07) |

The API and the worker share one backend image and the runtime credential; the worker has its
own service account and a narrower network policy (database, trace collector, egress gateway;
no direct HTTPS, reachable only for probes and metrics).

Database roles: `asic_app` (runtime; no `DELETE`, no DDL, no `BYPASSRLS`), the migration owner,
`asic_auditor` (read), `asic_maintenance` (retention executor only). Each deployment login holds
exactly one of them.

## 2. Configuration

Non-secret settings come from the `asic-runtime` ConfigMap; secrets from platform-provisioned
Secrets. Production must set `ASIC_JWT_ISSUER`, `ASIC_JWT_AUDIENCE`, `ASIC_OIDC_JWKS_URL` (HTTPS)
and `OTEL_EXPORTER_OTLP_ENDPOINT`; the pod fails closed otherwise. Useful knobs:

| Setting | Default | Notes |
|---|---|---|
| `ASIC_JWT_MAX_LIFETIME_SECONDS` | 3600 | allowed 300–5400; IdP tokens must not exceed it |
| `ASIC_OTEL_TRACES_EXPORTER` | `none` (code) / `otlp` (base ConfigMap) | export is best-effort and never blocks requests |
| `ASIC_OTLP_ALLOW_INSECURE` | unset | allows plain-HTTP OTLP to a non-loopback collector (mesh-provided mTLS only) |
| `ASIC_SECRETS_DIR` | unset | connector credentials, resolved per call |
| `ASIC_BEHAVIOUR_VERSION_LABEL` | `asic-release` (base ConfigMap) | the registered behaviour version the worker runs as; must match the image's prompt set and tool catalogue |
| `ASIC_WORKER_EXECUTION_MODE` | `live` | `live` refuses to start (GAP-08); `simulator` is non-production test infrastructure |
| `ASIC_WORKER_CONCURRENCY` / `_POLL_SECONDS` / `_DRAIN_SECONDS` | 2 / 5 / 30 | slots per pod (max 8); discovery interval; SIGTERM drain, below the 45 s grace period |

**Database transport (production).** With `ASIC_DEPLOYMENT_ENVIRONMENT=production`, every backend
process (API, worker, migration Job, retention CronJob) refuses to start unless its database URL
uses `sslmode=verify-full`, names one TCP host and sets `sslrootcert` to a readable CA file or
`system`. Mount the CA from a Secret named `asic-database-ca` (optional in the manifests, at
`/etc/asic/database-ca`) and use, for example,
`postgresql+psycopg2://USER@HOST:5432/asic?sslmode=verify-full&sslrootcert=/etc/asic/database-ca/ca.crt`.
The refusal names the failing setting and never prints the URL. The local kind overlay is an
explicit local-test profile (`ASIC_DEPLOYMENT_ENVIRONMENT=local`) with plaintext to a disposable
in-cluster database.

**Registering a release's behaviour version.** An administrator (owner credentials) inserts one
`behaviour_version` row per release with the label the ConfigMap names and the image's prompt set
and tool-catalogue versions (`python -c "from asic.llm.prompts import PROMPT_SET_VERSION; from
asic.tools.catalogue import CATALOGUE_VERSION; print(PROMPT_SET_VERSION, CATALOGUE_VERSION)"` run
in the image). Until it exists the worker stays alive, unready, logs `worker.blocked` and claims
nothing; it resumes by itself once the row is present. `deploy_release.run_deployment` accepts an
`after_migration` step for exactly this registration.

Per-process protections (not configurable per tenant today): per-principal rate limit 120/min,
failed-authentication limit 30/min per peer, ingestion bulkhead of 4 concurrent alerts with a 5 s
wait, statement timeout 10 s, pool timeout 10 s.

## 3. Deploying

Follow [PHASE14_DEPLOYMENT.md](../deployment/PHASE14_DEPLOYMENT.md). The orchestrator
(`scripts/deploy_release.py`) validates manifests, replaces a finished previous migration Job,
waits for any previous migration pod to stop, migrates, rolls out, and runs a post-rollout smoke.
It never downgrades the database. Failures: [migration](../runbooks/operations/migration-failure.md),
[deployment](../runbooks/operations/deployment-failure.md).

## 4. Daily operation

* **Health.** `/livez` touches nothing external; `/readyz` reports the database (reachability and
  schema revision) and is what removes a pod from Service endpoints. Dashboards and alerts:
  [SLOS.md](../observability/SLOS.md); every alert links a runbook.
* **Remediation.** An escalated incident's hypothesis is handed to the worker with
  `POST /api/v1/incidents/{id}/remediation-requests` (incident control). The request carries no
  authority: the policy gate decides, and production actions still wait for an approver.
* **Approvals.** Pending actions: `GET /api/v1/approvals/pending`. An approval binds to one action
  version; expiry escalates, never executes. The responder who requested a remediation cannot
  approve it.
* **Postmortems.** `GET /api/v1/incidents/{id}/postmortems` lists G11 drafts. Every draft is
  `draft` and `review_required`; nothing publishes it (GAP-30). Uncited or unsupported claims are
  listed under `uncertainties` with the reason they were removed.
* **Worker.** `kubectl -n asic-system logs deploy/asic-worker` shows one `worker.item` record per
  item (kind, outcome, tenant, item id); `asic_worker_items_total{kind,outcome}` counts them.
  `worker.blocked` means the behaviour version is missing or mismatched.
* **Ingestion backpressure.** `503 ingestion_busy` with `Retry-After` means the bulkhead is full;
  senders should retry, and redeliveries are deduplicated.
* **Retention.** Review dry-run receipts (`retention_run`) before enabling `--execute` and the
  schedule ([DATA_RETENTION.md](../security/DATA_RETENTION.md)).
* **Evaluation.** Any prompt, model, retriever or policy change is a behaviour change: run
  `python -m asic.evaluation.gate --suite golden --mode simulator --baseline latest` and the replay
  mode before release.

## 5. Capacity planning (LOCAL figures only)

One 2-CPU API process served ≈ 77–135 read req/s at saturation and ≈ 12–21 successful alerts/s of
ingestion across the Phase 15 and Phase 16 runs
locally ([LOAD_AND_PERFORMANCE.md](../testing/LOAD_AND_PERFORMANCE.md)). Each process uses up to 15
database connections. Multi-replica scaling is not measured (GAP-23).

## 6. When something goes wrong

Start with the alert's runbook, then the [troubleshooting guide](TROUBLESHOOTING.md) and the
[operational runbooks](../runbooks/README.md#operational-runbooks-no-alert-fires-them-directly).
