# ADR-0022: Bounded reflection extends the hypothesis engine's output, not a new graph node

- **Status:** Accepted
- **Date:** 2026-09-13
- **Deciders:** Stevemeg
- **Spec reference:** 3, 4, 15
- **Supersedes / Superseded by:** none

## Context

Master specification section 3 requires a bounded reflection step between hypothesis
formation and termination: the ability to continue on a different gap, deliberately seek
counter-evidence, revise a hypothesis, or end the run - validated deterministically, never
an unrestricted recursive loop, and never a sixth, ambiguous way for a run to stop beyond
the five in `TerminationReason`.

`docs/architecture/orchestration-kernel.md` section 6.2 already named this gap explicitly:
"Not implemented, and deliberately - Phase 7 owns it." ADR-0001 approved a twelve-node
topology (plus two derived services) and Phase 4 implemented four of them. The question
this decision answers is where reflection's *own* decision point lives: as a thirteenth
node the approved topology did not name, or as an extension of a node that already exists
and already sits at exactly the right place in the graph.

## Decision

Bounded reflection is implemented as an extension of the G5 Hypothesis Engine's structured
output and the existing deterministic termination rule engine - **no new `NodeId`, no new
graph node, no new graph edge.** The hypothesis engine's model call is asked for an
optional `reflection` proposal alongside its hypotheses; `asic.orchestration.reflection`
validates that proposal exactly as `asic.orchestration.nodes.planner` already validates the
planner's own proposal ("the model's choice is a proposal, a deterministic guard can
override it"); and reflection's three terminal actions
(`terminate_success`/`terminate_uncertain`/`escalate`) are accepted as additional inputs to
`asic.orchestration.termination.decide`, the same function the planner's own `TERMINATE`
action already feeds.

## Alternatives considered

### Option A — A new G5b "Reflection" node (rejected)

- **What it is:** A thirteenth graph node, model-backed, sitting between the hypothesis
  engine and the terminator, with its own contract and its own model call.
- **Pros:** A one-to-one mapping from "the spec names a step" to "the graph has a node for
  it"; a clean, separately-testable contract boundary.
- **Cons:** A new node outside ADR-0001's approved twelve is itself a topology change and
  would need its own ADR to justify inflating the count for a step that has no capability
  of its own and calls no tool. It doubles the model calls per iteration (one for
  hypotheses, one for reflection) for no reasoning benefit reflection cannot already get
  from seeing the same evidence in the same call. It also requires a second termination
  authority to be invented for reflection's terminal actions, or an awkward round-trip
  through the existing one - exactly the risk the spec's "never a sixth outcome" warns
  against.
- **Cost to adopt:** A new contract, a new graph edge, a new routing function, doubled
  model-call budget accounting, and a second place the five termination categories would
  need to be re-derived correctly.

### Option B — Extend the hypothesis engine's output; validate through the existing termination rule engine (chosen)

- **What it is:** `HypothesisOutput.reflection` is an optional field on the same JSON
  response the hypothesis engine already produces. `reflection.py`'s guard chain mirrors
  `termination.py`'s and `planner.py`'s existing "propose, then a deterministic guard
  decides" pattern, reusing `termination.is_actionable` so a reflection-driven escalation
  clears exactly the same bar a planner-driven one does. Reflection's terminal proposals
  become an added field (`reflection_action`) on `TerminationInputs`; `termination.py`'s
  `R4`/`R5` predicates check `wants_to_stop` (planner OR reflection asking to end) rather
  than only the planner.
- **Pros:** No topology change, so ADR-0001 stands as accepted. One model call per
  iteration continues to cover both hypothesis formation and reflection - the same
  reasoning pass that concluded a hypothesis is exactly the pass that knows what would
  still need checking. Termination stays governed by one rule engine, so "never a sixth
  outcome" is true by construction rather than by cross-checking two authorities. The
  existing citation-integrity pattern (an id is trusted only if it resolves against this
  run's own persisted rows) extends naturally to `target_hypothesis_id`.
- **Cons:** The hypothesis engine's contract grows a second responsibility, and its prompt
  grows a second thing to ask for. A future need for reflection to reason over evidence the
  hypothesis engine's own prompt does not construct would strain this design.
- **Cost to adopt:** A minor-version contract bump (`1.0.0` → `1.1.0`) on `G5_HYPOTHESIS_
  ENGINE` and `G2_TERMINATOR`, one new `GraphState` key (`reflection_decision`), and a new,
  independently tested module (`reflection.py`). No schema migration: hypothesis revision
  reuses the `superseded_by_id`/`SUPERSEDED` columns and the `EvidenceRelation` counter-
  evidence columns Phase 4's schema already carries.

## Rationale

Option B wins because the two things reflection needs - the evidence-grounded judgement of
what the hypothesis engine already produces, and a termination decision bounded to exactly
five categories - already exist and are already correct. Building a second node would
duplicate both: a second model call reasoning over the same evidence a moment later, and a
second termination authority that would have to be proven equivalent to the first rather
than simply *being* the first. Master specification section 4's reuse principle ("do not
create artificial agents to inflate agent count") applies directly: reflection is a
decision, not an agent, and giving it a node would manufacture the second kind to satisfy
the first.

This is not a close call in the way ADR-0002 was: the existing "model proposes, deterministic
guard decides" pattern was already established by two other nodes before Phase 7 began, and
extending it a third time is the smaller, more consistent change.

## Consequences

- **Positive:** ADR-0001's twelve-node topology is unchanged. One termination authority
  remains the single source of truth for all five categories, from either the planner or
  reflection. No schema migration was required.
- **Negative / accepted trade-offs:** The hypothesis engine's prompt and contract carry two
  responsibilities rather than one; a future divergence in what each needs from the prompt
  would be the trigger to reconsider Option A.
- **Impact on security and permission boundaries:** None. G5 still declares no capabilities
  and calls no tools; reflection cannot reach anything a hypothesis could not already reach,
  and a reflection decision naming a hypothesis this run never persisted is rejected before
  any write, exactly as an unsupported evidence citation already is.
- **Impact on observability and evaluation:** Two new bounded-cardinality metrics
  (`asic.reflection.decisions`, `asic.hypothesis.revisions`); the hypothesis engine's trace
  span gains reflection fields. No new span kind was needed.
- **Impact on failure modes and recovery:** A missing or unparseable reflection proposal
  degrades to a deterministic default (continue on an open gap, or terminate uncertain) via
  the same guard chain a rejected proposal takes - it is never silently treated as
  "continue".
- **Operational and cost impact:** None measured; no new model call was added, so token and
  latency cost per iteration is unchanged from Phase 4's hypothesis step.

## Reversal cost and revisit trigger

- **How hard is this to undo?** Moderate. Splitting reflection into its own node later
  would mean a new contract, a new graph edge and moving the guard logic in `reflection.py`
  to be driven by a second model call instead of the existing one - a contained change, not
  a rearchitecture, because the deterministic guard chain itself would not need to change.
- **What would have to change for us to revisit it?** A measured need for reflection to
  reason over context the hypothesis prompt does not and should not carry (for example, a
  cross-incident view), or evidence from Phase 11's evaluation harness that combining the
  two responsibilities in one model call measurably degrades hypothesis quality.

## Validation

No live model provider is wired yet (ADR-0016), so no reasoning-quality claim is made here.
What is validated is structural: `tests/orchestration/test_reflection.py` asserts the guard
chain is total and each guard is non-vacuous (a mutation test disables the actionability
guard and confirms the outcome changes); `tests/orchestration/test_termination.py` asserts a
reflection-driven termination is governed by the identical rule set a planner-driven one is,
including precedence against budget exhaustion; and
`tests/orchestration/test_hypothesis.py::TestBoundedReflection` drives a fabricated
hypothesis-id revision attempt through the real kernel and the real database and asserts no
row was written for it.

## References

- `docs/architecture/orchestration-kernel.md` section 6.2 (the gap this ADR closes)
- `docs/architecture/bounded-reflection.md` (the resulting design, in full)
- ADR-0001 (topology), ADR-0016 (deterministic model provider)
