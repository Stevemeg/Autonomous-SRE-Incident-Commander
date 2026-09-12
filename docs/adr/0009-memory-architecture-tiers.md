# ADR-0009: Memory architecture — five separated tiers with human-gated promotion

- **Status:** Accepted — T1–T3 implemented Phase 3–5; T4/T5 write governance (`MemoryGovernanceService`, `MemoryCategory`/`MemoryKind`) implemented Phase 6. See [`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md) §7 for what remains deferred (the G12 trigger, reranking)
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §8, §10
- **Supersedes / Superseded by:** none

## Context

Section 8 requires separating working incident state, short-term context, durable incident
history, operational knowledge and verified remediation outcomes, and requires that
historical incidents *"inform current investigation but never override current evidence."*
Section 10 adds that production behaviour must never be silently modified from a single
incident.

The tempting design is a single "memory" store with a relevance search over everything.
That is simpler and is what most agent systems do.

## Decision

**Implement five physically separated tiers (T1–T5) with distinct lifetimes, write
authorities and provenance labels, and require an explicit human-approved promotion for any
write into durable operational knowledge (T4) or verified outcomes (T5).**

Detail in [`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md) §1.

## Alternatives considered

### Option A — Five separated tiers with gated promotion (chosen)

- **Pros:** Each §8 concern has a home with the right lifetime and write authority.
  Provenance stays meaningful because a tier implies a trust level. Satisfies §10 by
  construction — there is no automatic path from "worked once" to "this is what we do".
  Contradiction between history and current evidence is representable rather than resolved
  silently.
- **Cons:** More stores and more transitions to implement. Promotion needs a human workflow,
  which is product surface. Some duplication between T3 and T5.
- **Cost to adopt:** Moderate.

### Option B — Single memory store with relevance search (rejected)

- **Pros:** Much simpler; one retrieval path; less code.
- **Cons:** Cannot express "verified" versus "suggested" — an unverified hypothesis retrieved
  next to a proven outcome looks identical to the model. **Makes §10 unimplementable**: with
  no promotion boundary, one incident's outcome immediately influences the next. Violates
  §8's explicit separation requirement.
- **Cost to adopt:** Low to build, high in correctness.

### Option C — Automatic learning from verified outcomes (rejected)

- **What it is:** Auto-promote to T5 whenever remediation verifies successfully.
- **Pros:** No human workflow; the system improves on its own; attractive demo.
- **Cons:** **Directly violates §10.** A verified remediation is evidence that an action
  worked *once, in one context*; promoting it to a general rule is over-generalisation, and
  memory poisoning becomes self-inflicted. A single unusual incident could durably skew all
  future investigations, with no human ever having reviewed the inference.
- **Cost to adopt:** Low to build, unacceptable in governance terms.

## Rationale

The decisive factor is that **§8 and §10 are jointly a statement about *authority*, not
storage.** The tiers differ in how much weight their content should carry, and merging them
erases exactly that distinction. Option B's single store cannot distinguish a proven outcome
from a discarded hypothesis, which is the difference between grounded advice and confident
noise.

Option C deserves the sharpest rejection because it is the most tempting: automatic learning
demonstrates well and feels like the point of the system. But §10's *"never silently modify
production behaviour from a single incident"* is unambiguous, and the failure it prevents is
severe — a single anomalous incident durably poisoning advice for every future one, with no
review and no obvious symptom.

The `support_count` field on `verified_outcome` operationalises this: a count of one is
never sufficient for promotion. Repetition across incidents is what turns an observation
into knowledge, and a human confirms the inference.

## Consequences

- **Positive:** Provenance is meaningful; §10 satisfied structurally; contradiction between
  history and current evidence is representable; memory poisoning requires defeating a human
  review; knowledge is versioned and auditable.
- **Negative / accepted trade-offs:** The system does not improve autonomously — deliberate.
  Promotion review is human work, and a backlog of unreviewed promotions is a real
  operational risk. More implementation surface.
- **Security and permissions:** Strongly positive — memory poisoning (T06) requires an
  approval record.
- **Observability and evaluation:** Positive — promotions are versioned events, so their
  effect on later replay runs is measurable.
- **Failure modes and recovery:** Positive — a bad promotion is a versioned change that can
  be reverted, not a diffuse contamination.
- **Operational and cost impact:** Adds a human review workflow.

## Reversal cost and revisit trigger

**Reversal cost: high.** Tier separation shapes the schema, retrieval and context assembly;
collapsing tiers later would mean re-labelling historical content whose provenance was never
recorded — likely impossible.

Revisit if: promotion review becomes a bottleneck (consider *assisted* review with batching
and a stronger `support_count` threshold — but **never** automatic promotion while §10
stands); or if measurement shows promoted knowledge has no effect on replay outcomes, which
would question the value of T5 rather than the gating.

## Validation

| Test | Passing criterion |
|---|---|
| No automatic promotion | Attempted memory write without an approval record is rejected (SI-12) |
| Single-incident guard | `support_count = 1` never auto-promotes |
| History does not override | Scenario 10 (stale, wrong runbook): current evidence wins |
| Provenance integrity | No tier transition upgrades a provenance label |
| Promotion effect | Measured change in replay outcomes after a promotion |

**None has been run.**

## References

- Master specification §8, §10
- [`../architecture/memory-and-rag.md`](../architecture/memory-and-rag.md)
- [`../architecture/data-model-and-api.md`](../architecture/data-model-and-api.md) §3.5
