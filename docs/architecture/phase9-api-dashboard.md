# Phase 9 API and incident-command dashboard

Phase 9 adds an authenticated edge and a read-focused command-room dashboard. The edge
has five independently authorized surfaces: ingestion (production connector adapters remain deferred),
incident query/control, human approval, evaluation (deferred to Phase 11), and
administration. A signed JWT identifies a tenant and external subject; current active-user
role assignments, expiry and environment scope are reloaded from the platform catalogue.
JWT role claims and request tenant parameters never grant access.

Environment-scoped permission checks always name the target environment; `None` is reserved
for an explicit tenant-wide role assignment. Administration reads require that tenant-wide
authority. Ingestion first resolves the signed connector service/environment against the
current catalogue and then checks `ingest.write` for that exact environment.

All incident reads apply environment scope and return typed non-leaking errors. Mutations
require `Idempotency-Key`; lifecycle responses are durably recorded in
`api_idempotency_record` with a request digest, and changed requests under the same key
are rejected. Current resource and environment authorization is performed before replay,
so a stored response cannot survive role or tenant-access revocation as authority.
Collection routes use opaque UUID cursors and a hard page cap; action relations are loaded
in batches. Responses carry `X-Correlation-ID`. Synchronous ingestion is isolated behind
FastAPI's worker-thread boundary. The bounded in-process rate limiter is
tested at the authenticated principal boundary; a distributed limiter is deferred.

The Next.js server-rendered dashboard reads the secure `asic_session` HttpOnly cookie
supplied by an identity proxy and presents incidents, evidence with provenance, hypotheses,
timeline, remediation actions, and exact approval/version context. It does not turn
displayed text into authority and has no external connector or replay implementation.

## Explicit boundary

Phase 10 external adapters and Phase 11 evaluation/replay execution are not implemented.
Evaluation routes return typed `501 deferred` responses after authorization. Incident
annotation and the documented administration GET surfaces for tools, policies, tenants,
services, knowledge and audit are implemented. Administrative mutation of those
catalogues is deliberately not exposed: connector/catalogue lifecycle configuration begins
with Phase 10 adapters and broader administration remains a later hardening phase.
