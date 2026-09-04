# ADR-0014: Materialised incident status, reconciled against the event log

- **Status:** Accepted
- **Date:** 2026-09-04
- **Deciders:** Project owner (Phase 3 approved implementation)
- **Spec reference:** §12
- **Supersedes / Superseded by:** none

## Context

The data model states that the event log is the system of record and that incident status
is *derivable* from it (DM-2, INV-2). Phase 3 had to decide what that means physically.

Two things are in tension. Deriving status on every read is the honest expression of "the
log is the record", but the operator dashboard's primary query is "show me open incidents",
and answering it by folding every incident's event stream is unaffordable. Storing status
as a column is fast but reintroduces the possibility that the column and the log disagree —
which is precisely the class of bug the event-sourcing discipline exists to prevent.

## Decision

**Store `incident.status` as a materialised column, write it only through
`apply_transition()` in the same transaction as its `incident.state_changed` event, and
provide `recompute_incident_status()` / `assert_status_matches_log()` so the two can be
compared rather than assumed consistent.**

## Alternatives considered

### Option A — Materialised column with reconciliation (chosen)

- **Pros:** Indexable, so "open incidents for this tenant" is one index scan. Status and
  event are written in one transaction, so they cannot diverge through a partial failure.
  Divergence is *detectable*, and the test suite asserts its absence rather than hoping.
  Optimistic locking on the same row prevents two writers silently discarding a decision.
- **Cons:** Two representations of one fact. A writer that bypasses `apply_transition()`
  can still diverge them — mitigated by detection, not prevented.
- **Cost to adopt:** Low.

### Option B — Pure derivation, no stored status (rejected)

- **Pros:** One representation; divergence impossible by construction.
- **Cons:** Every list query folds every incident's event stream. Cannot index on status.
  "Show open incidents" becomes the most expensive query in the product, and it is the one
  the dashboard runs constantly.
- **Cost to adopt:** Low to build, high at runtime.

### Option C — Materialised view refreshed on write (rejected)

- **Pros:** Derivation stays declarative; the view cannot be hand-written.
- **Cons:** PostgreSQL materialised views refresh wholesale, not incrementally, so a
  refresh cost grows with total incident count rather than with the change. Refreshing
  inside the write transaction serialises unrelated incidents against each other.
- **Cost to adopt:** Moderate, with a scaling problem built in.

### Option D — Database trigger maintaining status from events (rejected)

- **Pros:** Impossible to write status without an event.
- **Cons:** Puts the state machine — including actor authority and termination-reason
  rules — into PL/pgSQL, where it is hard to test, hard to review, and duplicated from the
  Python implementation. Two state machines that must agree is worse than one plus a check.

## Rationale

The decisive factor is that **the risk Option A carries is detectable and the cost Option B
carries is not avoidable**. A divergence between column and log is a bug we can write a
test for, and have: `test_status_divergence_from_the_log_is_detected` deliberately writes
the column behind the service's back and asserts the reconciliation catches it. By
contrast, Option B's cost is structural and shows up as latency on the product's most
common query.

Option D was the closest rejected option and deserves the clearest reason: the state
machine is not just a transition table. It gates on *who* is acting (only a human may
approve into `REMEDIATING`) and demands a termination reason and a written justification on
specific edges. Expressing that in a trigger means either duplicating it or moving
authority logic into the database, and neither is better than one implementation plus a
reconciliation check.

`apply_transition()` being the only writer is the discipline that makes this work: it
validates against the state machine, writes the status, and appends the event, all in one
transaction. Nothing else writes the column.

## Consequences

- **Positive:** Fast status queries with a partial index on open incidents. Atomic
  status-and-event writes. Divergence detectable and tested. State machine stays in Python
  where it is unit-testable without a database.
- **Negative / accepted trade-offs:** Two representations of one fact; correctness depends
  on `apply_transition()` being the only writer, which is a convention backed by a test
  rather than a constraint.
- **Security and permissions:** Neutral.
- **Observability and evaluation:** Positive — the event stream remains the complete record
  for replay, unaffected by the materialisation.
- **Failure modes and recovery:** The database additionally enforces terminal consistency:
  `CHECK ((status IN terminal states) = (terminated_at IS NOT NULL))` and
  `CHECK (terminated_at IS NULL OR termination_reason IS NOT NULL)`, so raw SQL cannot
  leave an incident terminal without recording when and why.
- **Operational and cost impact:** Negligible.

## Reversal cost and revisit trigger

**Reversal cost: low.** Dropping to pure derivation means deleting a column and changing
the read path; the event log already holds everything needed.

Revisit if: reconciliation ever detects a divergence in a real environment (which would
mean a writer bypassed `apply_transition()` and the convention needs a stronger
enforcement); or if the status column acquires a second writer for a legitimate reason.

## Validation

| Test | Result |
|---|---|
| `test_a_transition_writes_status_and_event_together` | Passing |
| `test_status_divergence_from_the_log_is_detected` | Passing — the check fires on a deliberately divergent write |
| `test_an_illegal_transition_writes_nothing` | Passing — status and log both unchanged |
| `test_a_terminal_status_must_record_when_and_why` | Passing — raw SQL update refused |
| `TestGaplessSequencing` (4 tests) | Passing — including a test that the gap detector detects a planted gap |

## References

- Master specification §12
- [`../architecture/data-model-and-api.md`](../architecture/data-model-and-api.md) DM-2, INV-2
- `src/asic/db/projections.py`, `src/asic/domain/incident_state.py`
