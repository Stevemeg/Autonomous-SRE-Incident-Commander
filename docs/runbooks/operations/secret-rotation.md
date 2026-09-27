# Runbook: Rotating secrets and credentials

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

Procedures, by secret. None of these has been exercised in a production environment (GAP-25).

| Secret | Procedure | Restart needed |
|---|---|---|
| Connector credentials (`asic/read/...`, `asic/write/...`) | Update the value in the mounted secrets directory (`ASIC_SECRETS_DIR`) or secret manager; references in the database do not change | No: resolved per call |
| Runtime database password (`asic-runtime-database`) | Create the new password on the login, update the Secret, roll the API (`kubectl rollout restart deployment/asic-api`), then revoke the old password | Yes (rolling) |
| Migration database password (`asic-migration-database`) | Update before the next deployment; the Job reads it at start | No running component |
| Maintenance login (`asic-maintenance-database`) | Update the Secret; the next CronJob run uses it | No |
| OIDC signing keys | Rotate at the IdP, publishing the new key in JWKS before signing with it; the API picks it up within the 300 s cache TTL or on the first unknown `kid` | No |
| OTLP headers | Update the ConfigMap/Secret feeding `OTEL_EXPORTER_OTLP_HEADERS` and roll the API | Yes (rolling) |

After any rotation: run the post-rollout smoke (`scripts/deploy_release.py` does it automatically)
and confirm no authentication or database errors in the logs. If a secret may have leaked, treat it
as a [security incident](security-incident.md) first.

## Do not

Never put a secret in Git, a ConfigMap, a connector row, a ticket or a chat message. The repository's
hygiene scanner and gitleaks gate would block a committed one; nothing blocks the others.
