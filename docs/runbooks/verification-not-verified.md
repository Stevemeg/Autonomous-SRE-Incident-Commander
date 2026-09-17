# Runbook: Remediation not verified

- **Alert:** `AsicVerificationNotVerified`
- **Severity:** ticket
- **Protects:** Independent verification: success is claimed only with a trusted baseline and post-action read
- **Dashboard:** [`asic-remediation-safety`](../../configs/observability/grafana/dashboards/asic-remediation-safety.json)

> Thresholds are INITIAL ENGINEERING TARGETS ([SLOs](../observability/SLOS.md)); they have not
> been calibrated against production traffic. If this alert is noisy or silent when it should
> not be, record that and adjust the target - do not silence it.

## What it means

An executed remediation was checked independently and the verdict was `not_verified` or `inconclusive`.

## Impact

The incident is not resolved by that action; it escalates to a human.

## Diagnose

1. *Verification verdicts* and the incident timeline show which action.
2. `inconclusive` usually means the post-action observation could not be read (integration failure) - see [integration failing](./integration-failing.md).

## Mitigate

- A human reviews the incident. If the symptom persists, investigate further; do not re-run the same action by default.

## Do not

- Do not mark the incident resolved or record verified memory without a verified verdict.
