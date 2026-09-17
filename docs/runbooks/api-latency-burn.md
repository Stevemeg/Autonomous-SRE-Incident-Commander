# Runbook: API latency objective burning

- **Alert:** `AsicApiLatencyBurn`
- **Severity:** ticket
- **Protects:** API latency SLO: 99% of non-probe requests complete within 2.5 s over 30 days
- **Dashboard:** [`asic-api-health`](../../configs/observability/grafana/dashboards/asic-api-health.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

More than 14.4x the tolerated share of requests are slower than 2.5 s over the last hour.

## Impact

Dashboard views and approval decisions are slow; approval windows keep running while the human waits.

## Diagnose

1. *Request duration p95 by route* identifies the slow route.
2. Slow list routes: check for large tenants paging with high `limit` values.
3. Database pressure: statement timeouts (`SET LOCAL statement_timeout`) cancel runaway queries - look for 5xx on the same route.
4. Follow slow requests' `trace_id` from logs to see where time is spent.

## Mitigate

- Reduce page size limits for the offending client, or scale the database.
- If a single query regressed after a release, roll back.

## Do not

- Do not raise statement timeouts to make latency alerts stop; that trades a latency problem for a database outage.
