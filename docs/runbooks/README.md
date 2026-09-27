# Runbooks

One runbook per alert in [`configs/observability/prometheus/rules/asic-alerts.rules.yml`](../../configs/observability/prometheus/rules/asic-alerts.rules.yml). A test asserts every alert links to one of these files.

- [API availability error budget burning](./api-availability-burn.md) - `AsicApiAvailabilityFastBurn` / `AsicApiAvailabilitySlowBurn`
- [API latency objective burning](./api-latency-burn.md) - `AsicApiLatencyBurn`
- [Remediation left a partial effect](./remediation-partial-effect.md) - `AsicRemediationPartialEffect`
- [Database not ready](./database-not-ready.md) - `AsicDatabaseNotReady`
- [Evaluation gate not passing](./evaluation-gate-not-passing.md) - `AsicEvaluationGateNotPassing`
- [Integration calls failing](./integration-failing.md) - `AsicIntegrationFailing`
- [Model spend above the engineering threshold](./llm-cost-burn.md) - `AsicLlmCostBurn`
- [Metrics scrape failing](./metrics-scrape-failing.md) - `AsicMetricsScrapeFailing`
- [Tool call ended with an unknown outcome](./tool-unknown-outcome.md) - `AsicToolUnknownOutcome`
- [Remediation not verified](./verification-not-verified.md) - `AsicVerificationNotVerified`
- [Workflow run dead-lettered](./workflow-run-dead-lettered.md) - `AsicWorkflowRunDeadLettered`
- [Workflow runs failing](./workflow-runs-failing.md) - `AsicWorkflowRunsFailing`

## Operational runbooks (no alert fires them directly)

- [Migration failed or will not start](./operations/migration-failure.md)
- [Workflow run not progressing](./operations/stuck-workflow.md)
- [Model provider unavailable or misbehaving](./operations/model-provider-outage.md)
- [Identity provider or JWKS unavailable](./operations/identity-provider-outage.md)
- [Container or deployment failure](./operations/deployment-failure.md)
- [Rotating secrets and credentials](./operations/secret-rotation.md)
- [Tenant isolation or security alert](./operations/security-incident.md)

See also the [operator guide](../operations/OPERATOR_GUIDE.md) and
[troubleshooting guide](../operations/TROUBLESHOOTING.md).
