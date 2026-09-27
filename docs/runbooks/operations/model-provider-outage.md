# Runbook: Model provider unavailable or misbehaving

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Symptoms

`asic_llm_calls_total{outcome!="success"}` rising; investigations ending `failure` or
`insufficient_evidence` more often; `asic_budget_exhaustions_total{budget_kind="tokens"|"cost"}`
rising if the provider returns oversized output.

## What the system already does

Every model call is budgeted before it is made. Timeouts, errors, malformed or truncated output and
token-accounting violations end the step with a classified failure; the run terminates (failure,
uncertainty or escalation) and is **never** reported resolved. Well-formed output that claims
authority (approvals, tenants, tools, verification results) is ignored: authority comes only from
the registry, policy and humans (`tests/resilience/test_model_provider_failure.py`).

## Diagnose

1. Provider status page and the error classes in `asic_llm_calls_total` by `outcome`.
2. Whether usage is inside budget: `asic_llm_usage_tokens_total`, `asic_llm_usage_cost_usd_total`.

## Mitigate

* Nothing needs to be stopped: incidents fall back to human handling with the evidence gathered so
  far attached.
* After the provider recovers, reopen affected incidents for investigation if needed.

## Do not

* Do not raise budgets to "get through" an outage, and do not switch provider or model without
  passing the evaluation gate (a model change is a versioned behaviour change).

Note: the only provider wired today is the deterministic one (ADR-0016); this runbook describes the
behaviour a live provider inherits from the same port.
