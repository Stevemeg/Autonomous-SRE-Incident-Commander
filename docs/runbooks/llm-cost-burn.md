# Runbook: Model spend above the engineering threshold

- **Alert:** `AsicLlmCostBurn`
- **Severity:** ticket
- **Protects:** Cost control
- **Dashboard:** [`asic-llm-usage-cost`](../../configs/observability/grafana/dashboards/asic-llm-usage-cost.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

Committed model usage in the last hour exceeds 50 USD across the fleet (an INITIAL ENGINEERING TARGET).

## Impact

Budget exhaustion for tenants; runaway loops if a behaviour change broke termination.

## Diagnose

1. *Cost by model* and *Tokens by direction* identify the model.
2. *Planning iterations per run* and *Budget exhaustions* on the agent dashboard show whether runs are looping.

## Mitigate

- Roll back the behaviour change, or lower tenant budgets through configuration.

## Do not

- Do not disable per-run budgets; they are the enforcement, this alert is only the signal.
