# ADR-0017: A read-only capability ceiling enforced in three independent places

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** Project owner (Phase 4 approved implementation)
- **Spec reference:** §6, §7, §15
- **Supersedes / Superseded by:** none

## Context

Phase 4 was scoped as read-only and simulator-backed: no production mutation, no remediation
execution, no Kubernetes writes. The obvious implementation is to simply not write any code
that mutates anything, and to rely on that remaining true.

That is not good enough, for a reason worth naming. The remediation path — the policy gate,
the approval service, the executor — is Phase 8. Until it exists, a registered write tool
would be a capability with **nothing authorizing it**. Every safeguard the architecture
specifies for a write (SI-1 proposer ≠ authorizer, SI-6 approval binding, SI-7 precondition
re-validation) lives in components that have not been built. A write capability appearing in
the registry before them — through a well-meant commit, a copied descriptor, a seed migration
— would be authorized by nothing at all, and would look exactly like a capability that was
supposed to be there.

So the question was not "should Phase 4 write?" but "what makes a write structurally
impossible until the thing that authorizes it exists?"

## Decision

**The read-only ceiling is enforced in three independent places, each of which alone would
prevent a write.**

1. **At construction.** `ToolDescriptor` refuses risk tier `R3` outright (SI-5), and requires
   any non-`RO` tool to declare a rollback. `ToolRegistry.read_only()` calls
   `assert_no_write_capability` on the catalogue, so a write tool in the catalogue fails at
   **import**, not at first use.
2. **At resolution and again at dispatch.** `CapabilityResolver` refuses to be constructed
   with a ceiling above `RO`, and omits any non-`RO` tool from the resolved menu. The broker
   then re-checks the tier immediately before dispatch rather than trusting the menu — because
   checking once at menu time leaves a window in which a stale or mutated entry could reach
   an adapter.
3. **In the build.** `scripts/validate_docs.py` imports the catalogue and fails if any
   descriptor is not `RO`, if any capability falls outside the `read.*` prefix, or if any
   declares a rollback. It also forbids `subprocess`, `os.system`, `os.popen`, `shell=True`
   and `pty` anywhere in `src/` or `migrations/`, so an arbitrary-execution channel cannot
   arrive alongside one.

The database adds a fourth layer inherited from Phase 3: `ck_tool_definition_no_destructive_
tool_registered` refuses `R3` rows, and `INSERT`/`UPDATE`/`DELETE` on `tool_definition` are
revoked from the application role.

## Alternatives considered

### Option A — register write tools, disabled (rejected)

- **What it is:** seed the write catalogue now with `is_enabled = false`.
- **Pros:** the catalogue matches the architecture document sooner; enabling later is a flag.
- **Cons:** a boolean is one mistaken `UPDATE` away from an enabled capability that nothing
  authorizes. It also makes the registry describe capabilities the system cannot safely
  perform, so "what can this system do?" stops having an honest answer.
- **Decisive objection:** §7's whole argument is that a capability the system cannot express
  is safer than one it is told not to use. A disabled row is the second kind.

### Option B — a runtime feature flag (rejected)

- **Cons:** the ceiling becomes configuration, and configuration is the layer most likely to
  differ between environments and to be changed under pressure during an incident. A ceiling
  that can be raised by an environment variable is not a ceiling.

### Option C — three independent structural refusals (chosen)

- **Pros:** each layer alone suffices; two would have to fail silently and simultaneously for
  a write to become possible; and the build fails loudly rather than the runtime failing
  quietly. Removing the ceiling in Phase 8 is a deliberate, reviewable change to all three.
- **Cons:** more places to change when the ceiling legitimately moves. That is the intended
  cost: raising it should be conspicuous.

## Consequences

**What this rules out.** No tool this deployment can invoke changes anything. The credentials
the descriptors reference are read-only ones (SI-4), so even a defect in every one of our
layers is bounded by what the credential can do at the target system.

**A visible consequence in behaviour.** `IncidentStatus.RESOLVED` is not reachable. A run that
finds an actionable cause terminates as `escalated` with reason `human_escalation`, which is
one of §5's five categories. That is not a limitation working around a missing feature — it
is the honest report of what a system that cannot remediate or verify has actually achieved.

**Reversal cost.** Moderate, deliberately. Phase 8 must: relax the resolver's ceiling, extend
the validator's allowed prefixes, seed write descriptors with rollbacks and settling windows,
and — before any of that is safe — build the policy gate, the approval service and the
executor. The ordering is enforced by the fact that a write tool cannot be registered until
the ceiling moves, and moving the ceiling is three visible edits.

**When to revisit.** Phase 8, and not before. There is no partial adoption worth having: a
single write capability needs the entire authorization path.

## Evidence

- `tests/security/test_prompt_injection.py::TestStructuralProperties` — the catalogue is
  read-only, simulator-backed, and declares no free-form command argument.
- `tests/tools/test_broker.py::TestRiskCeiling` — the resolver refuses a higher ceiling; a
  write descriptor is refused at the risk boundary.
- `tests/tools/test_broker.py::TestRefusals` — a `mutate.*` request is refused before any
  adapter is reached, and audited as denied.
- `scripts/validate_docs.py` — negative-tested by planting a write tool, an `api/` package, a
  `subprocess` import, a `temporalio` import and a `.tsx` file; all were caught.
