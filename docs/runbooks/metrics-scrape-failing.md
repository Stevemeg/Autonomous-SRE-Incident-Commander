# Runbook: Metrics scrape failing

- **Alert:** `AsicMetricsScrapeFailing`
- **Severity:** page
- **Protects:** Observability of every other SLO
- **Dashboard:** [`asic-api-health`](../../configs/observability/grafana/dashboards/asic-api-health.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

Prometheus cannot scrape an ASIC API target for five minutes.

## Impact

Every metric-based alert is blind for that target.

## Diagnose

1. Is the process up (`/livez`)? If not, this is an outage, not a metrics problem.
2. Is `ASIC_METRICS_ENABLED` set for the process? `/metrics` is not served otherwise.
3. Network policy between Prometheus and the internal scrape port.

## Mitigate

- Restore the target or the scrape path. Metrics are not persisted by the process; the gap cannot be backfilled.

## Do not

- Do not expose `/metrics` publicly to work around network policy.
