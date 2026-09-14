# Phase 9 API and incident-command dashboard

Phase 9 adds an authenticated edge and a read-focused command-room dashboard. The edge
has five independently authorized surfaces: ingestion (connector binding remains deferred),
incident query/control, human approval, evaluation (deferred to Phase 11), and
administration. A signed JWT identifies a tenant and external subject; current active-user
role assignments, expiry and environment scope are reloaded from the platform catalogue.
JWT role claims and request tenant parameters never grant access.

All incident reads apply environment scope and return typed non-leaking errors. Mutations
require `Idempotency-Key`; lifecycle responses are durably recorded in
`api_idempotency_record` with a request digest, and changed requests under the same key
are rejected. Responses carry `X-Correlation-ID`. The bounded in-process rate limiter is
tested at the authenticated principal boundary; a distributed limiter is deferred.

The Next.js server-rendered dashboard reads the secure `asic_session` HttpOnly cookie
supplied by an identity proxy and presents incidents, evidence with provenance, hypotheses,
timeline, remediation actions, and exact approval/version context. It does not turn
displayed text into authority and has no external connector or replay implementation.

## Explicit boundary

Phase 10 external adapters and Phase 11 evaluation/replay execution are not implemented.
Their authenticated routes return typed `501 deferred` responses after authorization.
