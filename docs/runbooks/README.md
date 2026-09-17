# Runbooks

One runbook per alert in [`configs/observability/prometheus/rules/asic-alerts.rules.yml`](../../configs/observability/prometheus/rules/asic-alerts.rules.yml). A test asserts every alert links to one of these files.

- [API availability error budget burning](./api-availability-burn.md) - `AsicApiAvailabilityFastBurn` / `AsicApiAvailabilitySlowBurn`
- [API latency objective burning](./api-latency-burn.md) - `AsicApiLatencyBurn`
- [Remediation rollback failed](./compensation-failed.md) - `AsicCompensationFailed`
- [Database not ready](./database-not-ready.md) - `AsicDatabaseNotReady`
- [Evaluation gate not passing](./evaluation-gate-not-passing.md) - `AsicEvaluationGateNotPassing`
- [Integration calls failing](./integration-failing.md) - `AsicIntegrationFailing`
- [Model spend above the engineering threshold](./llm-cost-burn.md) - `AsicLlmCostBurn`
- [Metrics scrape failing](./metrics-scrape-failing.md) - `AsicMetricsScrapeFailing`
- [Tool call ended with an unknown outcome](./tool-unknown-outcome.md) - `AsicToolUnknownOutcome`
- [Remediation not verified](./verification-not-verified.md) - `AsicVerificationNotVerified`
- [Workflow run dead-lettered](./workflow-run-dead-lettered.md) - `AsicWorkflowRunDeadLettered`
- [Workflow runs failing](./workflow-runs-failing.md) - `AsicWorkflowRunsFailing`
