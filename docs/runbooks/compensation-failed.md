# Runbook: Remediation rollback failed

- **Alert:** `AsicCompensationFailed`
- **Severity:** page
- **Protects:** Rollback integrity for R1/R2 actions
- **Dashboard:** [`asic-remediation-safety`](../../configs/observability/grafana/dashboards/asic-remediation-safety.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

An action that needed compensating (rollback) could not be rolled back; its status is `compensation_failed`.

## Impact

The target workload may be left in a changed or partially changed state.

## Diagnose

1. *Action status transitions by tier* shows the tier. Logs: `event="tool.executed"` for the rollback tool with its failure class.
2. Inspect the workload directly and compare with the action's recorded baseline.

## Mitigate

- A human restores the workload using the organisation's change process; record what was done on the incident.

## Do not

- Do not grant the broker broader Kubernetes permissions to make the rollback succeed.
