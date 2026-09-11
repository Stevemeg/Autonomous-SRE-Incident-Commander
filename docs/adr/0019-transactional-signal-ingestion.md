# ADR-0019: Transactional signal ingestion and durable investigation requests

- **Status:** Proposed implementation decision for Phase 5 review
- **Date:** 2026-09-11
- **Spec reference:** Sections 12, 14, 15, 17

## Context

Alert occurrence identity already exists in Phase 3. Delivery identity does not: a firing
update and a resolution can share an occurrence. `AlertStatus` describes processing, not
the source state. Incidents cannot exist for invalid signals merely to host rejection events.
Phase 4 also commits run creation before its initial checkpoint, leaving a recovery gap.

## Decision

Keep the accepted occurrence key and processing vocabulary. Add a source-state projection
and an immutable signal receipt containing normalized data, provenance, delivery identity,
and the versioned correlation decision. Rejections retain hashes and reason codes, not raw
payloads. Incident effects continue through the existing event append/transition boundary.
Raw bodies are not retained. Normalized customer content remains untrusted tenant data.

Serialize ingestion with a PostgreSQL transaction advisory lock per tenant, under READ
COMMITTED, before reading delivery identities or correlation candidates. This deliberately
trades tenant throughput for a simple, auditable v1 guarantee across different fingerprints,
services and environments. Unique constraints remain the independent duplicate backstop.
Use statement timeouts; a timeout fails the transaction and requires caller retry.

Use service + environment + category + a fixed 15-minute occurrence-time window. Matching
multiple incidents creates a separate incident with an ambiguity explanation; no arbitrary
winner. Different services remain separate in v1. No automatic reopen or severity decrease.
Resolve-first signals are retained without creating incidents. Updates ordered by observed
time, source state (resolution wins ties), then canonical digest converge deterministically.
The identity scope of an occurrence cannot change through an update.

Insert an investigation request with the incident-opening event. A worker explicitly
dispatches it through the Phase 4 service. Link the request to its run and write the initial
checkpoint within the kernel's initial transaction. Lock request then incident; retries
discover the linked run, respect its lease, and resume rather than creating another run.
No broker, scheduler daemon, or external integration is introduced.

## Alternatives and consequences

In-memory locks fail across processes. Per-fingerprint locks do not serialize different
alerts creating the same incident. Environment locks offer more concurrency but require
additional delivery-lock ordering; defer until measured contention justifies that complexity.
Kafka and Temporal add infrastructure without removing database atomicity requirements.
Synchronous investigation inside the ingestion transaction holds locks across model/tool
work and cannot safely recover a post-commit failure. A durable request avoids that coupling.

This is at-least-once delivery with idempotent committed processing, never exactly-once
delivery. Receipt history explains decisions even after policy changes. Failed transactions
are not acknowledged; the caller must retry. Invalid content has a durable typed rejection
when the database is available. No production throughput or latency is claimed.

Revisit tenant-wide locking after measured contention; changing it requires race tests.
Reversal requires migrating retained receipts/requests, not deleting their history.
