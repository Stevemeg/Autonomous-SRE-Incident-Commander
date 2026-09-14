# Bounded Reflection

- **Status:** **Implemented and tested** — Phase 7.
- **Master specification references:** Sections 3, 4, 5, 8, 15
- **Related:** [`orchestration-kernel.md`](./orchestration-kernel.md) §6, §7 ·
  [ADR-0022](../adr/0022-bounded-reflection-without-a-new-node.md) ·
  [`requirements-traceability.md`](./requirements-traceability.md)

This document describes what Phase 7 built: the explicit control loop over what the
hypothesis engine just formed, closing the gap `orchestration-kernel.md` §6.2 named as
deliberately deferred. It assumes that document's vocabulary (graph state, node contracts,
the termination rule engine) and does not repeat it.

---

## 1. What exists, and what does not

| | |
|---|---|
| **Exists** | An optional reflection proposal on the hypothesis engine's structured output · a deterministic guard chain that validates it (`asic.orchestration.reflection`) · hypothesis revision (supersede, never silent replacement) · counter-evidence-seeking as an explicit, named decision · a shared actionability gate between the planner's and reflection's terminal proposals · a `"RANK:<n>"`/`"LATEST"` sentinel so a fixture can name a hypothesis before its id exists |
| **Does not exist** | A second model call for reflection (it shares the hypothesis engine's) · a live model provider (unchanged from ADR-0016) · multi-hypothesis revision in one step · reflection over anything the hypothesis prompt does not already construct |
| **Not measured** | Whether reflection improves root-cause accuracy. No such claim appears anywhere in this document, because Phase 11's evaluation harness does not exist yet and a live model provider does not either. |

The read-only ceiling from `orchestration-kernel.md` is unchanged: reflection has no
capability of its own, calls no tool, and cannot widen what the run may reach. It is a
decision about what to do with evidence already gathered, nothing more.

---

## 2. Why reflection lives on the hypothesis engine

ADR-0022 is the full record. In outline: the hypothesis engine already makes the one model
call per iteration that reasons over the evidence gathered; reflection needs nothing that
call does not already have in front of it. A separate node would mean a second model call
reasoning over the same evidence a moment later, and a second termination authority that
would have to be proven equivalent to the one `termination.py` already provides. Neither
duplication earns anything, so there is no second node - `HypothesisOutput.reflection` is
simply an additional, optional field on the same response.

---

## 3. The vocabulary

`asic.domain.enums.ReflectionAction` - six members, closed, the same way
`asic.domain.enums.PlannerAction` is:

| Action | Meaning | Terminal? |
|---|---|---|
| `continue_with_gap` | Keep investigating; the named gap is the next one to close | No |
| `collect_counter_evidence` | Deliberately seek evidence that would *contradict* the leading hypothesis | No |
| `revise_hypothesis` | Supersede a named hypothesis with a better one formed this same step | No |
| `terminate_success` | Propose the leading hypothesis is sufficiently supported to stop on | Yes (via §5) |
| `terminate_uncertain` | Propose stopping because the evidence does not distinguish a cause | Yes (via §5) |
| `escalate` | Propose handing the investigation to a human now | Yes (via §5) |

A model proposing anything outside these six is a schema violation, handled exactly as an
invalid planner or hypothesis response is (§9 of `orchestration-kernel.md`): one repair
attempt, then a typed failure. There is no seventh, free-form action.

---

## 4. The guard chain

`asic.orchestration.reflection.decide_reflection` is a pure function - no model, no clock,
no database - mirroring `asic.orchestration.termination.decide`'s three properties:
**ordered** (the first matching guard wins), **total** (every input yields a verdict,
including a missing proposal), and **never claims more than the evidence supports**.

| Guard | Applies to | Rejects | Falls back to |
|---|---|---|---|
| G0 | Any | No proposal was made, or it failed to parse | Continue on an open gap, escalate, or terminate uncertain (whichever the run's own state supports) |
| G1 | `revise_hypothesis`, `collect_counter_evidence` | A target hypothesis id this run never persisted, or none given | Same three-way fallback |
| G2 | `revise_hypothesis` | No hypothesis newly formed this step to supersede onto; the target is the only new one; the target is already superseded | Same fallback |
| G3 | `continue_with_gap` | No gap proposed and none open | Same fallback |
| G4 | `terminate_success` | The evidence does not clear `termination.is_actionable` - confidence, support, contradiction and coverage, the same four conditions R4 checks | `terminate_uncertain` |
| G5 | `escalate` | No hypothesis exists to escalate at all | `terminate_uncertain` |
| G6 | Any | *(nothing left to reject)* | Accepted as proposed |

G1 is the same defence citation integrity already provides for evidence ids
(`orchestration-kernel.md` §8): a hypothesis id is trusted only after it is checked against
this run's own persisted rows, never taken from the model on faith. An id from another
run, an evidence id, or a fabricated string is rejected before anything is written - not
repaired, not partially trusted, exactly as an unsupported evidence citation is dropped
rather than scored down.

G4 is the same bar R4 in `orchestration-kernel.md` §7 already applies to the planner's own
`TERMINATE` proposal, called through the same function
(`asic.orchestration.termination.is_actionable`). A model cannot manufacture certainty by
choosing reflection's vocabulary instead of the planner's; both are held to one definition
of "actionable", not two.

### The fallback ladder

Every guard that rejects a proposal falls back to the same three-way decision, in order:

1. If an open gap exists, `continue_with_gap` on it.
2. Otherwise, if the evidence already clears the actionability bar, `escalate`.
3. Otherwise, `terminate_uncertain`.

A rejected proposal never silently becomes "continue" with no explanation: the verdict's
`overridden_reason` names what was rejected and why, exactly as the planner's
`PlannerDecisionRef.overridden_reason` already does.

---

## 5. Reflection does not terminate a run by itself

`terminate_success`, `terminate_uncertain` and `escalate` are **inputs**, not decisions.
`TerminationInputs.reflection_action` carries the validated action into
`asic.orchestration.termination.decide`, the same function the planner's own `TERMINATE`
proposal already feeds. `TerminationInputs.wants_to_stop` is true when *either* the planner
or reflection asked to end the run, and R4/R5 are evaluated identically regardless of which
one asked:

```text
R1  unrecoverable failure                          -> always outranks a stop request
R2  wall-clock exhausted                            -> always outranks a stop request
R3  any other budget exhausted or refused           -> always outranks a stop request
R4  (planner OR reflection asked to stop) AND actionable  -> human_escalation / escalated
R5  (planner OR reflection asked to stop), otherwise      -> insufficient_evidence / uncertain
R6  neither asked                                          -> continue
```

A run therefore still ends in exactly one of the five categories
`orchestration-kernel.md` §7 already documents. There is no sixth, reflection-only
outcome, and reflection cannot bypass a budget or wall-clock limit that would otherwise
have stopped the run - R1-R3 are checked first regardless of what reflection proposed.

`SUCCESS` remains unreachable from reflection for the same reason it is unreachable from
the planner: this deployment cannot remediate and therefore cannot verify a fix. A
`terminate_success` proposal that clears G4 is realised as `human_escalation`, never as
`SUCCESS`.

---

## 6. Hypothesis revision

`revise_hypothesis` is the one reflection action with a durable side effect, and it reuses
schema Phase 4 already carries - no migration was needed.

1. The target hypothesis's row is updated: `status = SUPERSEDED`,
   `superseded_by_id = <the new hypothesis's id>`. The database's own constraints
   (`no_self_supersede`, `superseded_names_successor`) make an inconsistent state
   unreachable independent of the guard chain above.
2. Graph state accumulates hypothesis references append-only
   (`orchestration-kernel.md` §3), so the target's earlier reference cannot be edited in
   place. A corrected reference - the same id, `status=superseded` - is appended after it.
3. `asic.orchestration.termination.best_hypothesis_of` (shared by the terminator and by
   reflection) deduplicates by id, keeping the **last** occurrence, so the corrected status
   always wins over the stale one for any subsequent decision in the same run.

A hypothesis supersedes at most one target per reflection step. Superseding several would
take several bounded-reflection steps, one per iteration - not a limitation anything has
needed yet, but named here rather than silently assumed away.

---

## 7. Counter-evidence as an explicit decision

`collect_counter_evidence` differs from `continue_with_gap` in intent, not mechanism: both
add a gap to `open_gaps` for the planner to act on next. The difference is that a
counter-evidence gap is deliberately framed as *"evidence that would contradict hypothesis
X"* rather than *"evidence that would support it"* - synthesised automatically
(`f"evidence that would contradict hypothesis {target_hypothesis_id}"`) when the model
does not supply its own framing, so the decision is never silently indistinguishable from
an ordinary continuation. This directly answers master specification section 3's
requirement to prefer seeking disconfirming evidence over accumulating only confirming
evidence.

---

## 8. Failure classification

`asic.domain.enums.EvidenceFailureCategory` adds a distinguishing vocabulary
(`NO_EVIDENCE_FOUND`, `EVIDENCE_COLLECTION_FAILED`, `EVIDENCE_UNAUTHORIZED`,
`INVESTIGATION_TIMEOUT`, `MODEL_FAILURE`, `TOOL_FAILURE`, `UNCERTAIN`) as an **additive**
field on `NodeFailureRef.category`, alongside the existing free-form `error_type` - never a
replacement for it, so nothing recorded before this field existed changes meaning. It is
populated at the evidence collector's and hypothesis engine's existing failure and
degradation call sites, classifying what already happens rather than changing when it
happens:

| Category | Where it is set |
|---|---|
| `EVIDENCE_UNAUTHORIZED` | The broker refused a request, or a knowledge manifest failed verification |
| `TOOL_FAILURE` | An adapter answered with a failure or a timeout |
| `MODEL_FAILURE` | The model provider failed, or its output could not be schema-validated after the one permitted repair attempt |
| `NO_EVIDENCE_FOUND`, `INVESTIGATION_TIMEOUT`, `UNCERTAIN` | Documented mappings onto existing mechanisms (an empty successful result, the wall-clock/budget rules, and `TerminationReason.INSUFFICIENT_EVIDENCE` respectively) rather than new code paths - these three describe outcomes the system already produces correctly by other means |

No failure is silently reported as "no evidence found" unless that is the actual
deterministic result: an adapter failure is `TOOL_FAILURE`, a refusal is
`EVIDENCE_UNAUTHORIZED`, and only a source that genuinely answered with nothing is
`NO_EVIDENCE_FOUND`.

---

## 9. Checkpoint and resume

`reflection_decision` is carried in the checkpoint's ephemeral remainder exactly as
`last_decision` already is (`orchestration-kernel.md` §10.3): serialised on write,
restored on `rehydrate()`. A resumed run sees the same validated reflection decision it had
before the interruption; it is not recomputed, and a revision already applied to the
database is not reapplied - the target row's `status` is read fresh from the database on
resume, the same as every other hypothesis.

---

## 10. Observability

Two new bounded-cardinality metrics:

| Metric | Dimensions | What it answers |
|---|---|---|
| `asic.reflection.decisions` | `action` (six values), `rule_id` (a small fixed set of guard ids) | How often each reflection action is proposed and validated, and which guard fires |
| `asic.hypothesis.revisions` | *(none)* | How often a hypothesis is actually superseded |

Neither carries incident text, a query, a tenant id or a hypothesis id - the same
bounded-cardinality discipline `orchestration-kernel.md` §12 already documents. The
hypothesis engine's trace span gains `reflection_action`, `reflection_rule_id`,
`reflection_overridden_reason` and `reflection_target` attributes (a hypothesis id, which
is not customer content and is already carried elsewhere on the span).

---

## 11. Security properties carried over unchanged

- **No new capability.** G5 declares none; reflection cannot reach anything a hypothesis
  could not already reach.
- **No new authority.** A reflection decision's `rationale` and `gap` fields are free text
  from the model, rendered nowhere but a trace attribute, a metric-free state string and an
  `open_gaps` entry a planner reads as data. Nothing parses them as instructions; hostile
  text asking for a capability grant, an approval bypass or a tenant switch has no mechanism
  to reach (`tests/orchestration/test_hypothesis.py::TestBoundedReflection::
  test_hostile_text_in_reflection_rationale_and_gap_is_inert`).
- **Tenant isolation is unchanged.** `target_hypothesis_id` is checked only against rows
  RLS already scoped to this run's tenant; a cross-tenant id cannot be named because it is
  never visible to resolve against in the first place.

---

## 12. Testing

| Category | File |
|---|---|
| Guard totality, precedence, non-vacuity | `tests/orchestration/test_reflection.py` |
| Reflection-driven termination through the shared rule set | `tests/orchestration/test_termination.py::TestReflectionDrivenTermination` |
| `best_hypothesis_of` dedup-by-latest | `tests/orchestration/test_termination.py::TestBestHypothesisOf` |
| Revision through the real kernel and database | `tests/orchestration/test_hypothesis.py::TestBoundedReflection` |
| Fabricated target id rejected before any write | same, `test_a_fabricated_reflection_target_is_rejected_through_the_real_kernel` |
| Unactionable `terminate_success` claim does not escalate | same, `test_an_unactionable_terminate_success_claim_does_not_escalate` |
| Hostile free text is inert | same, `test_hostile_text_in_reflection_rationale_and_gap_is_inert` |
| End-to-end scenario: counter-evidence changes the leading hypothesis | `SC-0012-counter-evidence-revises-hypothesis` (`tests/e2e/test_scenarios.py`, parametrised generically) |

The mutation test in `test_reflection.py`
(`test_disabling_the_actionability_guard_would_let_an_unsupported_success_through`) is
there for the same reason `docs/architecture/orchestration-kernel.md`'s testing
philosophy requires it: a guard that is never shown to fail when disabled is not evidence
that it works, only that it has not yet been shown not to.

---

## 13. Deferred and out of scope

Explicitly not built here, and not implied by anything above:

- A live model provider (ADR-0016 unchanged).
- Multi-hypothesis revision in a single step.
- Reflection reasoning over context the hypothesis prompt does not construct (a
  cross-incident view, for instance).
- Any remediation, approval, execution, verification or production write capability -
  unrelated to reflection and out of this phase's boundary entirely.
