# ADR-0019: Transactional signal ingestion and durable investigation requests

- **Status:** Accepted
- **Date:** 2026-09-11
- **Spec reference:** Sections 12, 14, 15, 17

## Context

Alert occurrence identity already exists in Phase 3. Delivery identity does not: firing and
resolution observations can share an occurrence. Phase 5 must survive at-least-once delivery,
concurrent workers and source-controlled text without weakening the accepted event log, RLS,
state machine, Tool Broker or Phase 4 read-only capability ceiling.

## Decision

Store an immutable signal receipt for every committed delivery outcome. A permanent content
failure consumes its delivery identity. Catalogue/environment failures, observations beyond the
allowed future-skew window, and correlation-candidate overflow use a typed `retryable` outcome
under a derived attempt key, leaving the canonical delivery key available. Repeating an unchanged
retryable attempt returns the same receipt; after the dependency or receiver clock changes, the
same source event can commit once under its canonical key. Database failure before commit produces
no receipt and the at-least-once caller retries.

Canonical timestamps use UTC and support `[2000-01-01, 2100-01-01)`. Policy
`signal-validation/2` allows observation time up to five minutes after the injected ingestion
clock, inclusive. The range prevents unsafe arithmetic at Python/PostgreSQL boundaries; the skew
covers ordinary connector/host clock drift without allowing a future observation to freeze the
source projection. A supported timestamp that is temporarily too far ahead is a durable retryable
outcome; when receiver time catches up, the same source event may commit exactly once. A timestamp
outside the supported absolute range remains a permanent typed rejection. Neither outcome alters
the alert projection.

Serialize ingestion under READ COMMITTED with PostgreSQL's two-int advisory-lock space. The
first key is the stable namespace hash for `asic.ingestion.tenant.v1`; the second is the tenant
hash. This domain separation prevents an unrelated future lock family from intentionally sharing
the same key. The tenant-wide scope remains a conservative v1 throughput trade-off. A
transaction-local 1,000 ms `lock_timeout` bounds lock acquisition separately from the 10,000 ms
statement timeout. Lock wait duration and acquired/failed/timeout outcome are emitted with only
namespace/outcome metric labels; trace spans may carry tenant and correlation identifiers.

Incident event sequencing and ingestion incident updates modify no primary/unique key. They use
`FOR NO KEY UPDATE`, which preserves serialization among writers and remains compatible with the
`KEY SHARE` lock PostgreSQL obtains when Phase 4 inserts incident child rows. Request/run locks
that protect row linkage continue to use `FOR UPDATE`.

Correlation policy `service-category-window/3` filters tenant, active state, environment,
service, category and the fixed 900-second occurrence window in SQL before applying the
256-candidate bound. More than 256 relevant candidates produces a durable `retryable` overflow
receipt and no selected correlation. Irrelevant services cannot consume this budget. If multiple
candidates match, rank the smallest absolute anchor-time delta, then the lexicographically
smallest incident UUID. Persist the ranking-time order separately from commit-time eligibility.
Lock and re-check candidates in that deterministic order; if the first-ranked incident terminated,
record why and try the next. Create a new incident only when no ranked candidate is still eligible.
The ranking-time winner and commit-time winner are both retained, while `tie_break.winner` always
names the incident actually attached. This deterministic rule makes repeated bridge alerts
converge instead of creating ambiguity anchors.

Order observations by `(observed_at, resolved_rank, severity_rank, content_digest)`. Resolution
wins a state tie, higher canonical severity wins a firing tie, and the digest is the final stable
tie-break. This projection order is independent of delivery retry state. An exact overflowed
observation may retry correlation without replaying its source-projection mutation; a stale or
different observation never inherits that permission. Multiple historical occurrence rows violate
an invariant and fail closed.

Do not reopen terminal incidents automatically. A later firing update for an occurrence already
attached to a terminal incident updates the source alert projection, leaves incident status and
severity unchanged, appends the observation/correlation decision, and creates or links one open
`incident_reopen_candidate` per tenant/incident/alert for human review. Equivalent later firings
do not create additional review obligations. It creates no investigation request. Resolution after
termination is retained without a candidate. Dispatching an unlinked request after its incident
is terminal records a permanent `terminal` dispatch status once; later calls do not increase
attempts. Once a workflow run has been linked, the dispatch is `completed`; replay returns the
linked run's outcome and cannot rewrite successful dispatch history as `terminal_incident`.

Persisted source text does not acquire authority. Phase 4 objectives now contain only generated
investigation intent, incident identity and catalogue-resolved structural scope. Alert title,
labels, annotations, correlation identifiers and metadata are loaded in bounded form through
`UntrustedBlock` for both real prompt renderers. They never enter SYSTEM provenance, tenant
binding, capability resolution or authorization.

## Alternatives and consequences

In-memory locks do not coordinate processes. Per-fingerprint locks cannot serialize different
alerts racing to create the same incident. Environment/service locks could improve concurrency
but require ordered multi-lock acquisition and new race analysis. Kafka or Temporal would not
remove the database atomicity requirement.

The current tenant lock can serialize unrelated ingestion bursts within one tenant. No throughput
or latency is claimed. Local deterministic contention probes have now observed the configured
one-second timeout: bursts of 8 and 16 were accepted, while one burst of 24 produced three
retry-required PostgreSQL `55P03` outcomes. This is not a production benchmark or throughput
claim; it demonstrates that bounded wait and at-least-once retry behavior occurs under real lock
contention. Revisit lock scope only after production-representative lock-wait histograms show
sustained contention and a proposed replacement passes duplicate, cross-service, resolution and
incident-creation race tests under the unprivileged application role.

The guarantee is at-least-once delivery plus idempotent committed processing and durable history,
never exactly-once delivery. Raw bodies are not retained. Reversal requires migrating retained
receipts, reopen candidates and dispatch terminal outcomes; downgrade refuses to erase them.
