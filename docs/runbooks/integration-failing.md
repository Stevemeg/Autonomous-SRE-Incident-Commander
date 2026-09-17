# Runbook: Integration calls failing

- **Alert:** `AsicIntegrationFailing`
- **Severity:** ticket
- **Protects:** Integration call success for each external system
- **Dashboard:** [`asic-tool-broker-integrations`](../../configs/observability/grafana/dashboards/asic-tool-broker-integrations.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

More than a quarter of calls to one integration (at least ten) failed over an hour.

## Impact

Investigations degrade (missing evidence domain), verification may be inconclusive, notifications may not arrive.

## Diagnose

1. *Integration failure classes*: `unauthorized`/`forbidden` point to credentials or connector scope; `rate_limited` to quota; `timeout`/`transient_unavailable` to the vendor or network; `scope_denied` to a revoked or unbound connector.
2. Logs: `event="tool.executed"` with the integration's tools.

## Mitigate

- Rotate or restore the credential behind the connector's credential reference.
- Re-bind or re-enable the connector through the administrative path.

## Do not

- Do not fall back to simulators or fixtures; live composition deliberately refuses mixed providers.
