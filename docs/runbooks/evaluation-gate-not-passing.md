# Runbook: Evaluation gate not passing

- **Alert:** `AsicEvaluationGateNotPassing`
- **Severity:** ticket
- **Protects:** Evaluation gate: behaviour changes are released only after the suite passes
- **Dashboard:** [`asic-evaluation`](../../configs/observability/grafana/dashboards/asic-evaluation.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

A committed evaluation suite run finished `failed` or `errored`.

## Impact

The evaluated behaviour version must not be released.

## Diagnose

1. `GET /api/v1/evaluation/suite-runs/{id}` returns the sealed report; `report_verified` must be `true`.
2. `failed`: read `checks_failed`, `zero_tolerance_failures` and `comparison.new_failures`.
3. `errored`: read each scenario's `error` (tampered fixture, scenario changed without a version bump, missing replay fixture).

## Mitigate

- Fix the regression or the scenario definition (bump its version), then re-run the gate.

## Do not

- Do not edit stored results or recompute report digests, and do not release on a contested or errored run.
