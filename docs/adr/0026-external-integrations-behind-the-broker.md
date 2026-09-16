# ADR-0026: External integrations are native adapters behind the broker, with server-side connector authority

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** Project owner (Phase 10 implementation)
- **Spec reference:** §6, §7, §11, §14, §15, §20
- **Supersedes / Superseded by:** none (implements ADR-0003 option C)

## Context

Phase 10 connects Prometheus, Loki, Kubernetes, Slack, Microsoft Teams, PagerDuty, Jira and
Grafana. Four decisions had to be made that no earlier ADR settled:

1. how an outbound call is authorised for a tenant, service and environment;
2. where secrets live and when they are resolved;
3. how a chat message, page, ticket or annotation is classified, given that the Phase 8
   risk model requires every non-read tool to declare a rollback;
4. whether to depend on vendor SDKs.

## Decision

**Connector authority.** A tenant's connector for one integration kind and environment is
an `integration_connector` row (endpoint and credential *references*). Whether it may serve
a service is a `connector_scope_binding` row - the same authority model already used for
inbound ingestion. The broker resolves both, inside the tenant-bound transaction, on every
call and before idempotent replay. The application role may only read both tables.

**Credentials.** Rows store references matching `^asic/...`. Secrets are resolved inside
the adapter immediately before the request, held as a `SecretValue` that cannot be
rendered or serialised, and placed only in an outbound header or body. Production uses
mounted secret files or environment variables and fails closed; a static test provider is
refused in production and by live composition. Kubernetes reads and writes use separate
references, enforced distinct by a check constraint.

**Effect classes.** `tool_effect_class` (`read`, `infrastructure_mutation`,
`external_record`) is added to `tool_definition` and `tool_execution`. An external record is
tier `r1`, declares no rollback (a message cannot be un-sent) and no retry, may execute only
without a remediation action and only when requested by the S2 notification service, and
is refused otherwise by both the broker and database check constraints. An execution's
class is derived by trigger from its definition and a disagreeing class is refused.

**Transport.** Standard-library `http.client`, no vendor SDKs. Connect, send and receive
failures are separated so a write knows whether its effect may have applied. Methods,
headers and paths are closed; endpoints are `https` (plain `http` only to loopback in
explicit test composition); redirects are never followed; responses are size-bounded;
vendor error bodies are never copied into persisted messages.

**Failure model.** `IntegrationFailureClass` normalises vendor failures. A write failure is
`failed_clean` only when the adapter positively establishes no effect (refused connection,
4xx, `ok=false`, missing credential); anything else is `unknown` and is never retried.
Reads retry transient failures with `Retry-After` capped at five seconds.

## Alternatives considered

- **Vendor SDKs (`kubernetes`, `slack_sdk`, `jira`)** - rejected: broad surfaces the model
  must never reach, harder failure-phase attribution, and new runtime dependencies. The
  phase-boundary validator continues to forbid these imports.
- **Collaboration outside the broker** (a direct notification client) - rejected: a second
  egress path without scope, audit, idempotency or trace.
- **Classifying messages as `RO`** - rejected: the broker treats `RO` timeouts as retryable
  pure reads, which would duplicate user-visible messages.
- **Inventing rollbacks** (e.g. "delete message") - rejected as dishonest about reversibility
  and not supported by every destination.

## Consequences

- **Security:** one enforcement point; revocation is immediate; secrets never persist.
- **Verification:** remediation verification profiles are versioned. Profile v2 adds the
  native Prometheus source; actions frozen under v1 are still judged by v1.
- **Limits:** inbound chat approval is not built (FR-CLB-03 remains satisfied by the
  authenticated approval API only); no trace backend adapter; no vendor compatibility has
  been demonstrated beyond local deterministic servers.

## Validation

`tests/integrations/` (transport, credentials, adapter contracts, broker integration under
the unprivileged role, whole remediation and notification workflows, non-vacuity), and
migration `0016_external_integrations` round-trip tests.
