# Runbook: API availability error budget burning

- **Alert:** `AsicApiAvailabilityFastBurn` / `AsicApiAvailabilitySlowBurn`
- **Severity:** page (fast burn), ticket (slow burn)
- **Protects:** API availability SLO: 99.5% of non-probe requests are not 5xx over 30 days
- **Dashboard:** [`asic-api-health`](../../configs/observability/grafana/dashboards/asic-api-health.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

The share of API requests answered with a 5xx status is high enough that, if it continues, the monthly error budget is exhausted early. Probe and scrape routes are excluded.

## Impact

Operators cannot read incidents, approve or reject remediation, or ingest alerts. Approval windows can expire while the API is failing, which blocks remediation (it never executes without approval).

## Diagnose

1. On the API health dashboard, find which `route` carries the 5xx (panel *Requests by route and status class*).
2. Check *Database dependency*: a value below 1 points to [database not ready](./database-not-ready.md).
3. Query logs: `{service_name="asic-api"} | json | event="api.request" | status >= 500`, and follow a line's `trace_id` to its trace.
4. Correlate with a recent deploy or migration (`/readyz` reports `schema_revision_mismatch` when code and schema disagree).

## Mitigate

- If one release introduced it, roll the API back to the previous release.
- If the database is degraded, follow the database runbook first; the API recovers when readiness does.
- If load-related, scale API replicas; the rate limiter protects the database from a single tenant.

## Do not

- Do not retry approval or ingestion requests with new idempotency keys to "get them through" - replay the same key.
- Do not disable authentication or tenant binding to reduce errors.
