# Runbook: Workflow run dead-lettered

- **Alert:** `AsicWorkflowRunDeadLettered`
- **Severity:** page
- **Protects:** Run recoverability: every run either completes, suspends resumably, or is surfaced for manual inspection
- **Dashboard:** [`asic-incident-operations`](../../configs/observability/grafana/dashboards/asic-incident-operations.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

A run could not checkpoint or reached an inconsistent state and was marked `dead_lettered`. It will not resume by itself.

## Impact

The incident it belongs to has no automated progress. If it was a remediation run, an action may be mid-flight.

## Diagnose

1. Logs around the time: `{service_name=~"asic.*"} | json | level="error"`.
2. Find the run via the API (`GET /api/v1/incidents/{incident_id}/trace`) and open its trace.
3. For a remediation run, read the action's status: `executing`, `unknown_outcome` or `reconciling` means the target system must be inspected before anything else.

## Mitigate

- Hand the incident to a human operator; reopen it deliberately if investigation should continue.
- For remediation: reconcile the target's actual state first (see [unknown outcome](./tool-unknown-outcome.md)).

## Do not

- Do not edit workflow or checkpoint rows to force a resume. Checkpoints and events are append-only history.
