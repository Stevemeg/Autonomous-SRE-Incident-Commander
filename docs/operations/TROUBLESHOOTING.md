# Troubleshooting guide

Symptom first. Each entry says what the system is doing, why, and where to go next. Error bodies
carry a stable `code`; logs are JSON with `event`, and every request has a correlation id.

## API responses

| Symptom | Meaning | Next step |
|---|---|---|
| `401` `missing_token` / `signature_invalid` / `expired` | Token absent, forged or expired | Check the client's token source |
| `401` `lifetime_exceeded` | `exp − iat` exceeds `ASIC_JWT_MAX_LIFETIME_SECONDS` | Shorten token lifetime at the IdP |
| `401` `keys_unavailable` / `key_id_unknown` | JWKS unreachable beyond the stale bound, or a key not yet published | [identity-provider-outage](../runbooks/operations/identity-provider-outage.md) |
| `401` `unknown_principal` | Valid token, but no active user for that subject in that tenant | Provision the user and role assignment |
| `403` | Authenticated but not permitted (RBAC or environment scope); denials of state changes are audited | Check role assignments |
| `404` on an object you know exists | Tenant or environment scope: other tenants' objects are indistinguishable from missing | Check the token's tenant |
| `409` `idempotency_conflict` | The same `Idempotency-Key` was used for a different request | Use a new key per distinct request |
| `409` `concurrent_modification` | A concurrent update won an optimistic-lock race | Re-read and retry |
| `422` | Validation failure; the body names the field location, never echoes the input | Fix the request |
| `429` `rate_limited` | Per-principal (120/min) or failed-authentication (30/min per peer) limit; per process | Honour `Retry-After` |
| `503` `database_busy` / `database_timeout` / `database_contention` / `database_unavailable` | Classified database condition, with `Retry-After` | Transient: retry. Persistent: [database-not-ready](../runbooks/database-not-ready.md) |
| `503` `ingestion_busy` | Ingestion bulkhead full for 5 s | Sender retries; redeliveries are deduplicated |
| `500` | An unclassified defect — should not happen; fuzzing never produces one | Capture the correlation id and report it |

## Investigations

| Symptom | Meaning | Next step |
|---|---|---|
| Incident `uncertain` | Insufficient or contradictory evidence, or budget exhausted — a correct outcome, not a failure | Read the timeline and degraded domains |
| Incident `escalated` | An actionable cause was found and handed to a human, or a failure required escalation | Review hypotheses and evidence |
| A domain marked degraded | That evidence source failed (classified); the investigation continued without it | [integration-failing](../runbooks/integration-failing.md) |
| Evidence flagged `injection_flagged` | Hostile-looking text in telemetry or knowledge; recorded as a signal, never obeyed | [security-incident](../runbooks/operations/security-incident.md) if unexpected |
| Run not finishing | Lease held by a dead worker, or a human approval wait | [stuck-workflow](../runbooks/operations/stuck-workflow.md) |

## Remediation

| Symptom | Meaning | Next step |
|---|---|---|
| Action `awaiting_approval` | R2, or R1 in production, needs a human | `GET /api/v1/approvals/pending` |
| Approval refused as invalid | The action changed after approval (hash mismatch), expired, or the approver lacks authority | Review and re-approve the current version |
| `not_verified` | Independent verification did not confirm the effect; the incident is not resolved | [verification-not-verified](../runbooks/verification-not-verified.md) |
| Unknown outcome | A write may have happened; it is reconciled by query, never blindly retried | [tool-unknown-outcome](../runbooks/tool-unknown-outcome.md) |

## Deployment

See the troubleshooting section of [PHASE14_DEPLOYMENT.md](../deployment/PHASE14_DEPLOYMENT.md#troubleshooting)
and the [deployment-failure](../runbooks/operations/deployment-failure.md) and
[migration-failure](../runbooks/operations/migration-failure.md) runbooks.

## Local development

| Symptom | Next step |
|---|---|
| Tests skip with "needs PostgreSQL" | Set `ASIC_TEST_DATABASE_URL` to a migrated pgvector database |
| `alembic_version` missing | `ASIC_MIGRATION_DATABASE_URL=... alembic upgrade head` |
| Packaging tests skip "needs bash and jq" | Put `jq` on `PATH` |
| `python scripts/demo.py` cannot start PostgreSQL | Start Docker; or pass `--admin-url`/`--app-url` for an existing database |
