# ADR-0024: Authenticated API edge and server-rendered dashboard

## Status

Accepted — Phase 9

## Decision

Expose versioned FastAPI route groups with independently checked permissions. Resolve the
tenant only from a verified JWT and load current database-backed user role assignments,
including expiry and environment scope. Persist mutation replay responses with a request
digest. Use a Next.js server-rendered dashboard reading an HttpOnly session cookie from the
identity boundary.

## Consequences

Incident data has one authorization path and a bounded, replayable mutation surface. The
dashboard can present governed evidence without becoming an authority source. OAuth/IdP
deployment wiring, external alert adapters and evaluation/replay execution remain deferred
to their specified phases.
