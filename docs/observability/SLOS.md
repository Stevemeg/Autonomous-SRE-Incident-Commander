# Service Level Objectives

- **Status:** Implemented as Prometheus recording and alerting rules in Phase 12.
- **Rules:** [`asic-recording.rules.yml`](../../configs/observability/prometheus/rules/asic-recording.rules.yml) · [`asic-alerts.rules.yml`](../../configs/observability/prometheus/rules/asic-alerts.rules.yml) · [alert unit tests](../../configs/observability/prometheus/tests/asic-alerts.test.yml)
- **Runbooks:** [`../runbooks/`](../runbooks/README.md)

> **Every objective below is an INITIAL ENGINEERING TARGET.** None has been derived from
> measured traffic, because no production deployment exists. They encode the behaviour we
> intend to hold, so that alerting has a precise definition from day one. Each must be
> re-baselined against real traffic before anyone quotes it as a commitment. No latency,
> availability or cost figure in this repository is a measurement.

## Objectives and error budgets

All windows are rolling 30 days. Probe and scrape routes (`/livez`, `/healthz`, `/readyz`,
`/metrics`) are excluded from API SLIs.

| SLO | SLI (from exported metrics) | Objective | Error budget | Label |
|---|---|---|---|---|
| API availability | Non-5xx API requests / all API requests (`asic_api_requests_total`) | 99.5% | 0.5% of requests | INITIAL ENGINEERING TARGET |
| API latency | Requests completing within 2.5 s / all requests (`asic_api_request_duration_seconds`) | 99% | 1% of requests | INITIAL ENGINEERING TARGET |
| Workflow completion | Runs finishing `completed` / runs finishing (`asic_workflow_runs_finished_total`) | 99% | 1% of finished runs | INITIAL ENGINEERING TARGET |
| Integration calls | Non-failed calls per integration (`asic_integration_calls_total`) | 75% per hour before a ticket | 25% hourly failure ratio | INITIAL ENGINEERING TARGET |
| Readiness | Database dependency up at the expected schema revision (`asic_dependency_up`) | Up; alert after 2 min | none | INITIAL ENGINEERING TARGET |

The integration objective is deliberately loose: the external system's availability is not
ours to promise, and an investigation degrades rather than fails when one evidence domain is
missing. The alert exists to route a sustained outage to a human.

## Burn-rate alerting

Budget-based alerts use the multiwindow, multi-burn-rate pattern, so that a short spike does
not page and a slow leak is not missed:

| Alert | Long window | Short window | Burn rate | Budget spent before firing | Severity |
|---|---|---|---|---|---|
| `AsicApiAvailabilityFastBurn` | 1h | 5m | 14.4x | ~2% of the monthly budget | page |
| `AsicApiAvailabilitySlowBurn` | 6h | 30m | 6x | ~5% of the monthly budget | ticket |
| `AsicApiLatencyBurn` | 1h | 5m | 14.4x | ~2% | ticket |
| `AsicWorkflowRunsFailing` | 1h (min. 5 runs) | - | 14.4x | ~2% | page |

## Invariants are not SLOs

Some properties must not be expressed as a percentage with slack, because a tolerated rate
would license the failure. They alert on the **first** occurrence:

| Invariant | Alert |
|---|---|
| A run that cannot be resumed is surfaced, never silently lost | `AsicWorkflowRunDeadLettered` |
| An effect with an unknown outcome is reconciled, never retried | `AsicToolUnknownOutcome` |
| A rollback that fails is escalated immediately | `AsicCompensationFailed` |
| Success is claimed only with independent verification | `AsicVerificationNotVerified` |
| Unevaluated or regressed behaviour is not released | `AsicEvaluationGateNotPassing` |

Model cost has an engineering threshold (`AsicLlmCostBurn`, 50 USD per hour across the fleet,
INITIAL ENGINEERING TARGET) until live providers and tenant budgets give a principled value.

## What the metrics cannot tell you

Metrics carry no tenant, incident, run or user identifiers
([catalogue](../../src/asic/observability/catalogue.py)). A per-tenant SLO, or "which
incident", is answered from the tenant-isolated records and traces - a log line's `trace_id`
opens the trace, whose id is the `execution_trace.trace_id` that names the incident and, under
the harness, the evaluation run.

## Validation evidence

- `promtool check config` and `promtool test rules` against synthetic series (UNIT): alerts fire
  on the condition they name and stay silent on healthy or probe-only traffic.
- `tests/observability/test_config_artifacts.py` (UNIT): every queried series and label is
  catalogued; no identifier label; every alert has severity, summary, description and an
  existing runbook.
- `tests/observability/test_runtime_telemetry.py` (INTEGRATION / SIMULATOR): the exposition
  after real workflows respects the label policy.
