# `configs/` — Configuration

[`observability/`](./observability/) holds reference Prometheus rules and rule tests, Grafana
dashboards and OpenTelemetry Collector configuration - validated by `scripts/check_observability.sh`
(`promtool check config`, `promtool test rules`, `otelcol-contrib validate`) but not deployed
([production gap register](../docs/PRODUCTION_GAP_REGISTER.md) GAP-22). Kubernetes workloads live
in `deploy/`, infrastructure prerequisites in `infra/terraform/`.

## What belongs here

- Environment-specific, non-secret application configuration.
- Declarative policy configuration (risk tiers, tool permission scopes, budget and
  iteration limits) once the tool registry and policy model are designed in Phase 2.
- Local development and simulator configuration.
- Example files (`*.example.*`) showing the shape of required settings.

## What must never be committed here

- Secrets, credentials, tokens, API keys, connection strings containing passwords,
  private keys, or `kubeconfig` files. These are excluded by `.gitignore` and checked by
  `scripts/check_repo_hygiene.py`, but the primary control is not committing them.
- Anything copied from a real production environment.

Secret material is supplied at runtime through a secret manager, per master
specification section 15. The design for that lives in
[`../docs/security/THREAT_MODEL.md`](../docs/security/THREAT_MODEL.md).

## `security/`

`security/supply-chain-policy.toml` - the dependency-lock policy enforced by
`scripts/check_dependency_lock.py` (lock locations, the reasoned prerelease allowlist, frontend
lockfile rules). The secret-scanning configuration is `.gitleaks.toml` at the repository root.
See `docs/security/SUPPLY_CHAIN.md`.
