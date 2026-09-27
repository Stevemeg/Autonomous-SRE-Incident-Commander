# Runbook: Remediation left a partial effect

- **Alert:** `AsicRemediationPartialEffect`
- **Severity:** page
- **Protects:** Rollback integrity for R1/R2 actions
- **Dashboard:** [`asic-remediation-safety`](../../configs/observability/grafana/dashboards/asic-remediation-safety.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

A remediation action reached `failed_partial`: its effect was (or may have been) partly applied.
This includes an unknown outcome whose independent reconciliation read could not confirm the
target state. The executor escalated the incident and appended a `compensation.started` event.
That event is a **signal for a human**: automated compensation is deliberately not implemented
(FR-VRF-04 is partially satisfied), so nothing will roll the target back on its own.

This alert replaces `AsicCompensationFailed` (Phase 15, F-07), which watched a
`compensation_failed` status that no code path can set.

## Impact

The target workload may be left in a changed or partially changed state until a human acts.

## Diagnose

1. Open the incident: its timeline shows `execution.failed` and `compensation.started` with the
   action id. The action's recorded baseline (`remediation_baseline`) is the pre-change state.
2. Logs: `event="tool.executed"` for the action with its outcome and failure class; the tool
   execution record holds the broker's classification (never the vendor payload).
3. Inspect the workload directly (read-only) and compare it with the recorded baseline.

## Mitigate

- A human restores the workload through the organisation's change process and records what
  was done on the incident. Do not re-run the same remediation to "finish" it: an unknown or
  partial effect is reconciled, never retried blindly.

## Do not

- Do not grant the broker broader Kubernetes permissions to make a rollback succeed.
- Do not mark the incident resolved until an independent read confirms the target state.
