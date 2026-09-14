# ADR-0023: Bounded remediation runs as a separate graph and kernel, entered only from a human-reopened investigation

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** Stevemeg
- **Spec reference:** 3, 6, 17
- **Supersedes / Superseded by:** none (implements the relaxation ADR-0017 deferred to Phase 8)

## Context

Master specification section 6 requires bounded remediation: a model proposes exactly one
registered action; a deterministic gate decides whether it may run autonomously, needs human
approval, or is denied outright; an approved action executes through the same Tool Broker
every read already goes through; and the result is independently verified rather than trusted
from the executor's own report. ADR-0017 named the trigger for this work explicitly: "Phase
8, and not before," and set out what would have to move deliberately when it arrived - the
resolver's risk ceiling, the registry's read-only assertion, and the documentation validator's
catalogue check, "all three."

Two questions had to be answered before any node code could be written, and both were already
settled by decisions Phases 3-7 made without remediation in view at the time:

1. **Does remediation extend investigation's graph, or is it a separate one?**
   `asic.domain.incident_state.TRANSITIONS` - the already-accepted, already-tested Phase 3
   state machine - permits `investigating -> awaiting_approval` and
   `investigating -> remediating`, but has **no edge from `escalated`** into either state.
   Investigation's own graph (ADR-0001's G1-G5, Phase 4-7) always terminates into either
   `resolved` or `escalated`; it never leaves an incident sitting in `investigating` on its
   own. The only path into a state remediation can start from is the existing, human-only
   `escalated -> investigating` transition - an operator deciding to reopen an incident and
   have the system attempt a fix, not an automatic continuation of the run that just
   escalated it.
2. **Does remediation reuse investigation's `ToolRegistry.read_only()` ceiling, or does the
   ceiling itself move?** ADR-0017's ceiling is a deliberate safety property of
   *investigation specifically* ("Phase 4-7's kernel can only ever read"). Relaxing it in
   place would mean every investigation run, for the rest of the project's life, trusts a
   ceiling that Phase 8 code elsewhere is allowed to have widened.

## Decision

**Bounded remediation is a second graph (`G6`-`G10`) and a second kernel
(`RemediationKernel`), sharing kernel-level abstractions with investigation's
(`RunContext`, `UnitOfWork`, `ToolBroker`, `AuditWriter`, `TraceRecorder`) but not its state
shape, its nodes, or its `ToolRegistry.read_only()` ceiling.** It is entered only through
`RemediationKernel.start()`, which refuses unless the target incident is currently
`investigating` with a live (`proposed`/`accepted`) hypothesis - the exact precondition the
`escalated -> investigating` human reopening already produces, and structurally unreachable
any other way.

The read-only ceiling is not loosened; a second one is added alongside it.
`ToolRegistry.remediation()` / `remediation_full()` are new classmethods returning a registry
built from `READ_ONLY_CATALOGUE | WRITE_CATALOGUE`; `ToolRegistry.read_only()` still builds
only from `READ_ONLY_CATALOGUE` and still applies `assert_no_write_capability`.
`CapabilityResolver.__init__` now refuses only `RiskTier.R3` (via a new `RiskTier.rank`
property: RO=0, R1=1, R2=2), rather than any non-RO tier - but a resolver built over the
*read-only* registry still only ever resolves RO descriptors, so investigation's own runtime
behaviour is provably unchanged; only remediation's resolver, built over the new registry, can
reach R1/R2.

## Alternatives considered

### Option A - Extend investigation's graph with remediation nodes (rejected)

- **What it is:** Add G6-G10 as further nodes in the existing twelve-node graph, reachable
  from the hypothesis engine or the terminator when a hypothesis is actionable.
- **Pros:** One graph, one kernel, one state shape; no new `RunContext`/`UnitOfWork` plumbing.
- **Cons:** Directly contradicts the accepted state machine: there is no
  `investigating -> awaiting_approval`/`remediating` edge reachable from anywhere inside
  investigation's own termination paths (`resolved`/`escalated` are both terminal in that
  graph). Making one reachable would mean either changing Phase 3's transition table - a
  historical, already-tested contract - or routing remediation through `escalated`, which
  every existing Phase 4-7 test and ADR treats as a human handoff point, not a continuation.
  It would also force every investigation run's `ToolRegistry` to be built with remediation's
  ceiling in view, undermining ADR-0017's guarantee for code that has nothing to do with
  remediation.
- **Cost to adopt:** A migration-adjacent change to accepted state-machine semantics, changes
  to every Phase 4-7 node contract to reason about a ceiling they never needed to, and
  re-validation of every existing investigation test against a widened registry.

### Option B - A separate graph/kernel, entered only from the human `escalated -> investigating` transition (chosen)

- **What it is:** As decided above.
- **Pros:** Investigation nodes and their registry remain read-only; the final full-suite
  validation exercises the earlier investigation behavior together with remediation. The state-machine boundary is
  structural, not policed by convention: `RemediationKernel.start()` raises `DomainError` for
  any incident not `investigating`, so there is no code path from an active investigation run
  straight into an autonomous write. `ToolRegistry.read_only()` remains literally unable to
  see a write descriptor, so ADR-0017's proof does not need re-verifying against Phase 8 code
  - it is architecturally impossible for it to regress.
- **Cons:** Some duplication at the kernel level - `RemediationKernel._drive` and
  `InvestigationKernel._drive` share a shape (drive the graph, checkpoint per node, suspend or
  finalise) without sharing code, because their state shapes and suspend semantics differ
  (remediation suspends on human approval or an unsettled tool effect; investigation does not
  have an analogous mid-run suspend). A remediation run that needs an approval decision
  suspends and resumes by *re-entering the graph from `START`* rather than from a LangGraph
  checkpoint (mirroring investigation's own no-attached-checkpointer design), which requires
  every remediation node to be independently idempotent on replay - a real cost, paid once, in
  G7/G8/G9's own "does the durable row already reflect this decision" guards.
- **Cost to adopt:** A new `contracts/remediation_state.py`, a new
  `orchestration/remediation/` package (context, graph, kernel, five nodes), a new
  `ToolRegistry.remediation_full()` classmethod, a new `RiskTier.rank` property, and one
  migration seeding the write catalogue - all additive; nothing in Phases 3-7 was modified to
  make this work.

## Rationale

Option B is not a stylistic preference; it is the only option consistent with the
already-accepted Phase 3 state machine without amending a historical contract mid-project.
Given that constraint, sharing kernel-level plumbing while keeping the state shape, the node
set, and the risk ceiling separate is what lets ADR-0017's read-only proof for Phase 4-7
continue to hold unconditionally rather than "until Phase 8 code is also considered." Master
specification section 4's reuse principle ("do not create artificial agents to inflate agent
count") is respected in the other direction here: G6-G10 are not artificial - they are the
five responsibilities section 6 actually names (propose, decide policy, decide approval,
execute, verify), each with its own capability surface and its own failure semantics, which is
exactly the case that principle exempts.

## Consequences

- **Positive:** ADR-0001's investigation topology and ADR-0017's read-only ceiling proof are
  both unconditionally unchanged. The state-machine boundary between investigation and
  remediation is enforced by a runtime precondition check, not by convention. A resumed
  remediation run's idempotency is enforced per-node (G6 retains the persisted action and
  uses `remediation_request_key`, G7 uses an
  existing-`PolicyDecision` check, G8 by reading the durable `Approval` row, G9 by the
  action's own terminal status plus the broker's durable pre-dispatch effect claim, and G10
  by re-checking the settling clock) rather than by a
  shared checkpoint mechanism neither kernel actually has.
- **Negative / accepted trade-offs:** Two kernels with a similar drive-loop shape and no
  shared implementation; a future kernel-level bug fix (for example, to lease handling) must
  be applied in both places. `RemediationKernel.resume()` re-executing G6-G8 on every resume
  (rather than resuming mid-graph) means a resumed run re-reads durable state at every node it
  passes through even when nothing changed - a deliberate cost for auditability and
  simplicity, not an oversight.
- **Impact on security and permission boundaries:** This is the central one. A second,
  additive `ToolRegistry.remediation_full()` is the only way R1/R2 tools become reachable at
  all; `CapabilityResolver`'s refusal narrows from "any non-RO tier" to "R3 only," but only
  resolvers built over the new registry can ever present a non-RO descriptor to narrow against
  - investigation's resolver, over the unchanged read-only registry, is unaffected in
  practice. `RiskTier.R3` remains permanently unreachable (SI-5): no descriptor may declare
  it, so `CapabilityResolver`'s R3 refusal is defensive, not a live code path.
- **Impact on observability and evaluation:** A new `TraceSpanKind`-tagged span tree per
  remediation run, its own `WorkflowRun` row (same table investigation uses, disambiguated by
  which graph's nodes appear in its trace), and the same `AuditWriter` and bounded-cardinality
  metric conventions Phase 4-7 established - no new observability primitive was introduced.
- **Impact on failure modes and recovery:** A remediation run that suspends (pending approval,
  or awaiting a tool's settling window) is durably `WorkflowRunStatus.SUSPENDED`, resumed by
  re-entering from `START`; every node's own idempotency guard is what makes that safe rather
  than merely convenient. A crash after a write is claimed cannot blindly re-dispatch the
  effect: the independently committed claim survives rollback of the node transaction and
  recovery escalates unless a fresh read can establish the exact intended effect (SI-8).
- **Operational and cost impact:** None measured; no live model or cloud provider is wired
  (ADR-0016), so no latency, cost, or success-rate claim is made here.

## Reversal cost and revisit trigger

- **How hard is this to undo?** Moderate, deliberately - the same rating ADR-0017 gave this
  exact relaxation in advance. Merging the two graphs later would require either adding the
  missing state-machine edges (a historical-contract change requiring its own ADR) or routing
  remediation through a state investigation already reaches unassisted, both of which are
  larger changes than anything this decision itself required.
- **What would have to change for us to revisit it?** A future phase's requirement for
  remediation to start *without* a human reopening the incident (fully autonomous
  investigation-to-remediation continuity) would need a new, explicitly reviewed state-machine
  edge - this ADR's position is that no such edge should be added implicitly as a side effect
  of wiring the graphs together.

## Validation

Structural, not a reasoning-quality claim (no live model provider is wired - ADR-0016):
`tests/orchestration/test_remediation.py` drives the real graph and kernel against a real
PostgreSQL database, starting every test from a real investigation run's escalation followed
by the real human-only `escalated -> investigating` transition (never a hand-constructed
shortcut around it), and covers: autonomous R1 execution and verification with no approval row
ever created; production R1 suspending for approval and resuming on a real decision through
`asic.remediation.approval_service.decide()`; R2 requiring approval even when otherwise clean
(the end-to-end proof of `tests/domain/test_policy.py`'s unit-level P3 case); a forged
self-approval attempt with no grant; a stale/tampered action hash refused both at
`approval_service.decide()` and, independently, at the executor's own SI-6 recomputation; and
a cross-tenant approval attempt finding nothing to decide. The final validation also covers
approval expiry and role revocation at dispatch, crash-window non-repetition, resume without
a fresh model proposal, strict effect comparison and empty verification evidence.

## References

- `docs/architecture/remediation-safety-policy.md` (the safety invariants and autonomy matrix
  this graph implements)
- `docs/architecture/tool-registry.md` (the write catalogue and capability model)
- `docs/architecture/bounded-remediation.md` (the resulting design, in full)
- ADR-0001 (investigation topology), ADR-0015 (domain-owned checkpointing, the pattern
  `RemediationKernel`'s suspend/resume mirrors), ADR-0017 (the read-only ceiling this phase
  was always the designated trigger to relax)
