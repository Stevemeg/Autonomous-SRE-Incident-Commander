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
| Investigation dispatcher / kernels | LangGraph investigation and remediation graphs with durable checkpoints | in-process today; no worker Deployment (GAP-07) |

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
* **Approvals.** Pending actions: `GET /api/v1/approvals/pending`. An approval binds to one action
  version; expiry escalates, never executes.
* **Ingestion backpressure.** `503 ingestion_busy` with `Retry-After` means the bulkhead is full;
  senders should retry, and redeliveries are deduplicated.
* **Retention.** Review dry-run receipts (`retention_run`) before enabling `--execute` and the
  schedule ([DATA_RETENTION.md](../security/DATA_RETENTION.md)).
* **Evaluation.** Any prompt, model, retriever or policy change is a behaviour change: run
  `python -m asic.evaluation.gate --suite golden --mode simulator --baseline latest` and the replay
  mode before release.

## 5. Capacity planning (LOCAL figures only)

One 2-CPU API process served ≈ 77–102 read req/s at saturation and ≈ 12 alerts/s of ingestion
locally ([LOAD_AND_PERFORMANCE.md](../testing/LOAD_AND_PERFORMANCE.md)). Each process uses up to 15
database connections. Multi-replica scaling is not measured (GAP-23).

## 6. When something goes wrong

Start with the alert's runbook, then the [troubleshooting guide](TROUBLESHOOTING.md) and the
[operational runbooks](../runbooks/README.md#operational-runbooks-no-alert-fires-them-directly).
