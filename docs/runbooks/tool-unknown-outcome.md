# Runbook: Tool call ended with an unknown outcome

- **Alert:** `AsicToolUnknownOutcome`
- **Severity:** page
- **Protects:** No double application: an effect whose outcome is unknown is reconciled, never blindly retried
- **Dashboard:** [`asic-tool-broker-integrations`](../../configs/observability/grafana/dashboards/asic-tool-broker-integrations.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

An adapter could not tell whether its effect happened (for example a timeout after the request was sent). The broker recorded `unknown` and did not retry.

## Impact

For a write tool, the target may or may not have changed. For an external record (chat, page, ticket), a message may or may not have been delivered.

## Diagnose

1. The alert's `tool` label names the tool. Logs: `{service_name=~"asic.*"} | json | event="tool.executed" | outcome="unknown"` give the incident and correlation id.
2. For Kubernetes writes, read the deployment's current revision and replicas directly.
3. For notifications, check the destination (channel, PagerDuty, Jira) for the record.

## Mitigate

- If the effect did apply, let verification proceed or record the observed state for the operator.
- If it did not, a human decides whether to request the action again through the normal approval path.

## Do not

- Do not re-send, re-page or re-apply automatically. A duplicate rollback or page is the failure this alert exists to prevent.
