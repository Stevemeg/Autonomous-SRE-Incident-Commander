# Runbook: Database not ready

- **Alert:** `AsicDatabaseNotReady`
- **Severity:** page
- **Protects:** Readiness: traffic reaches only processes whose database answers at the expected schema revision
- **Dashboard:** [`asic-api-health`](../../configs/observability/grafana/dashboards/asic-api-health.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

`asic_dependency_up{dependency="database"}` is 0 (unreachable) or 0.5 (answering at an unexpected schema revision).

## Impact

`/readyz` returns 503; load balancers stop routing to the process. All persistence-backed work stops.

## Diagnose

1. `GET /readyz` returns the dependency detail: `unreachable` or `schema_revision_mismatch`.
2. Unreachable: check database availability, connection limits and network policy.
3. Mismatch: a migration was not applied, or a newer schema was applied before the code that expects it.

## Mitigate

- Restore database connectivity.
- For a mismatch, apply the expected migration (`alembic upgrade head` with the migration role) or roll the code back to match the schema.

## Do not

- Do not bypass readiness to force traffic, and do not downgrade migrations that refuse to downgrade over existing history.
