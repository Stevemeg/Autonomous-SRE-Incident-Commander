# Runbook: Workflow runs failing

- **Alert:** `AsicWorkflowRunsFailing`
- **Severity:** page
- **Protects:** Workflow completion SLO: 99% of investigation and remediation runs finish without failing or dead-lettering
- **Dashboard:** [`asic-incident-operations`](../../configs/observability/grafana/dashboards/asic-incident-operations.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

Over the last hour more than 14.4% of finished runs (at least five) failed or were dead-lettered.

## Impact

Incidents stop being investigated or remediated automatically and fall back to humans.

## Diagnose

1. *Workflow runs started / finished* shows the failing status; *Runs terminated by reason* (agent dashboard) shows why runs ended.
2. Logs: `{service_name=~"asic.*"} | json | event=~"investigation.run.finished|remediation.run.finished"` and `event="tool.refused"`.
3. *Integration failure classes* - a failing Prometheus or Loki connector degrades evidence collection.
4. *Schema violations* rising after a model or prompt change indicates a behaviour regression; the [evaluation gate](./evaluation-gate-not-passing.md) should have caught it.

## Mitigate

- Roll back the behaviour version (code, prompts, model) that introduced the regression.
- Restore the failing integration; runs degrade rather than fail when a single evidence domain is missing, so a spike usually has a platform cause.

## Do not

- Do not raise budgets or iteration limits to make runs finish; budgets are safety bounds.
