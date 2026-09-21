# Secrets policy

Implements NFR-SEC-06 and NFR-SEC-15 (Phase 13, ADR-0030). It records what exists, what the
guarantees are, and - because it is easy to overclaim - what is *not* guaranteed.

## 1. Inventory

| Secret | Where it may live | Where it must never appear |
|---|---|---|
| OIDC signing keys | the identity provider; only *public* keys reach us, through JWKS | any log, trace, response |
| Development signing secret (`ASIC_JWT_SECRET`) | an environment variable, non-production only, >= 32 characters | production (refused at startup), Git |
| Connector credentials (Prometheus, Loki, Kubernetes read/write, Slack/Teams webhooks, PagerDuty, Jira, Grafana) | an external secret store, resolved per call into a `SecretValue` | the database (only an `asic/...` *reference* is stored; a CHECK enforces the shape), `ToolExecution` arguments, prompts, traces, logs, metrics, API responses, evaluation fixtures, Git |
| Database DSNs (`ASIC_DATABASE_URL`, `ASIC_MIGRATION_DATABASE_URL`) | environment | Git, logs (a DSN is secret-shaped and redacted) |
| OTLP authentication (`OTEL_EXPORTER_OTLP_HEADERS`) | environment, read by the SDK | logs; the endpoint URL is validated and never echoed |
| Kubernetes / cloud credentials | mounted secret files or a secret manager (Phase 14) | as above |

The application and migration database roles are different on purpose: the application role has no
`INSERT` on the global catalogues and no DDL, so a deployment that pointed both at one role would
have given that away (`asic.db.session`).

## 2. Credential lifecycle

1. A connector row stores a reference (`asic/read/prometheus`), validated by a database CHECK and
   again in code (no traversal, no absolute path).
2. `EnvironmentCredentialProvider` resolves it *at the execution boundary, per call*, from a mounted
   secrets directory (`ASIC_SECRETS_DIR`, confined to that directory) or an environment variable.
   Rotation therefore takes effect without a restart.
3. The value exists only as a `SecretValue` inside the outbound request. Read and write credentials
   are distinct references (a CHECK forbids sharing) so an investigation credential is physically
   incapable of mutation.
4. Resolution fails closed (`CredentialUnavailable`). There is no fallback, and
   `StaticCredentialProvider` refuses to exist in a production deployment.
5. An external secret manager (Vault or a cloud KMS) and rotation schedules are deployment concerns
   for Phase 14; nothing here claims they exist.

## 3. Redaction: layered, and honest about its limits

Redaction is applied at emission (a log line, a span attribute, an audit payload, a persisted tool
argument), never on read. From strongest to weakest:

1. **Typed.** `SecretValue` derives from `NeverRender`; `redact_value` replaces any instance by
   type, at any depth, under any key. Its `repr`, `str`, `pickle` and `hash` are all refused or
   inert. Raw `bytes` are never rendered.
2. **Structural.** `HttpRequest` and `HttpResponse` exclude query, headers and body from `repr`;
   `describe()` renders method, origin and path only. Found in Phase 13: the dataclass `repr` of an
   `HttpRequest` printed its `Authorization` header and body into any message that formatted it.
3. **Name-based.** A key that *names* a secret is replaced whatever the value looks like: the
   database-column list plus suffix rules (`bot_token`, `db_password`, `*_webhook_url`,
   `authorization`, `cookie`, ...). Suffix, not substring, so `total_tokens` and `token_count`
   survive. Reference names (`credential_ref`) are kept on purpose.
4. **Shape-based (backup only).** A value that *looks* like a secret is replaced under an
   innocuous key: bearer tokens, JWTs, private keys, URL credentials, Slack and Teams webhook URLs,
   vendor tokens, and signed-URL query parameters (`sig=`, `access_token=`, `X-Amz-Signature=`).

**Not guaranteed.** A secret with no marker type, no telling key name and no known shape can still
be logged by code that formats it by hand. The primary rule, which the layers exist to back up, is:
**never pass a secret-bearing structure to a logger, span or audit payload at all.**
`tests/security/test_secrets_and_redaction.py` and the canary tests in
`tests/integrations/test_phase13_hardening.py` (a credential echoed by a vendor through 401/403/5xx
and malformed bodies) prove the layers; they do not prove detection is complete.

## 3a. Where secrets are checked in

`scripts/check_repo_hygiene.py` and gitleaks (`.gitleaks.toml`; full history and working tree) run
in the security gate. The single reviewed false positive (a token *count* argument in
`llm/accounting.py`) is allowed by exactly one rule, one file and one anchored matched text; a test
with the real scanner proves a genuine secret in that file, or appended to the allowed line, is
still caught. Test vectors that resemble secrets are assembled from fragments at runtime.

## 4. Encryption responsibility

| Layer | Who owns it | Status |
|---|---|---|
| In transit, inbound | TLS at the ingress / service mesh (Phase 14) | not implemented in the application |
| In transit, outbound | the application: HTTPS only (plain HTTP only to loopback, and only where composition allows it), certificate verification on, no redirects | **implemented** (`asic.integrations.transport`); OTLP and JWKS endpoints follow the same rule |
| At rest | the database and volume (PostgreSQL storage encryption, encrypted volumes, KMS) | **not implemented and not claimed**: PostgreSQL supporting it at deployment level is not an application control |
| Application-layer field encryption | none | no current datum requires it: secrets are references, not stored values |

No custom cryptography is implemented. Phase 14 must provide TLS termination, mutual TLS between
services where required, encrypted database storage and backups, and a key-management story.
