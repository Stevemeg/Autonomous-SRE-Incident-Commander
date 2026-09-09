# ADR-0016: A deterministic model provider for Phase 4; no live provider yet

- **Status:** Accepted
- **Date:** 2026-09-07
- **Deciders:** Project owner (Phase 4 approved implementation)
- **Spec reference:** §9, §10, §11, §14, §20
- **Supersedes / Superseded by:** none

## Context

Phase 4 builds the orchestration kernel, and two of its five nodes are model-backed by the
approved topology. That forced a decision the phase could not avoid: does the first vertical
slice call a real language model, or a deterministic stand-in behind the same port?

The specification pulls in both directions. Section 13 names a multi-provider abstraction in
the baseline. Section 20 forbids fake integrations and placeholder production logic, while
permitting "mocks/simulators only as explicit test infrastructure". Section 9 forbids
reporting unmeasured results, and section 11 requires that important behaviour be
reproducible from fixtures and traces.

The deciding observation is that **nothing in this phase can evaluate a model's output**. The
evaluation harness is Phase 11. Without it, a live provider would produce reasoning whose
quality is unmeasured, unmeasurable and therefore unclaimable — while making every test
non-deterministic, every CI run cost money, and every failure ambiguous between a defect and
a bad sample.

## Decision

**Implement the model *port* now, and the only *adapter* is deterministic.**

1. `asic.llm.port.ModelProvider` is the thin internal interface ADR-0005 chose: one method,
   taking a rendered prompt, returning **text** plus provider, model id, token counts, cost
   and finish reason.
2. `asic.llm.deterministic.DeterministicModelProvider` replays per-node scripts from a
   scenario. It contains no model and no logic that inspects the incident.
3. No provider SDK is a dependency. `openai`, `anthropic` and `litellm` are in the Phase 4
   boundary validator's forbidden-import list, so one cannot arrive unnoticed.
4. Token counts and costs are **derived from text length using a stated approximation**, and
   the constants say so where they are defined. No figure produced by it is a measurement of
   any provider.

The port returning *text* rather than a parsed object is load-bearing. Model output is
untrusted until a node has parsed and validated it; a port returning a typed object would
have done that parsing somewhere invisible. Making the node parse the text is what makes
malformed output a case the tests can actually reach — and one scenario returns unparseable
output precisely to exercise it.

## Alternatives considered

### Option A — wire a live provider now (rejected)

- **Pros:** the reasoning path is exercised end to end against a real model; some qualitative
  signal about prompt shape arrives earlier.
- **Cons:** every test becomes non-deterministic, so the kernel's *deterministic* properties —
  routing, budgets, citation integrity, termination — could no longer be asserted without
  mocking the provider anyway; CI needs credentials and costs money per run; a failing test
  becomes ambiguous between a defect and an unlucky sample; and nothing in this phase can say
  whether the output was any good, so any claim about quality would be unmeasured.
- **Decisive objection:** it buys a signal we cannot read, at the cost of the properties we
  can prove.

### Option B — record-and-replay against a live provider (rejected for now)

- **What it is:** capture real responses once, replay them in tests.
- **Pros:** realistic outputs; deterministic replay.
- **Cons:** the cassettes are only as good as the prompts that produced them, and the prompts
  are the thing most likely to change in Phase 7 — so the fixtures would be stale before they
  were useful. It also still needs credentials to record.
- **When it becomes right:** Phase 7, once the prompts stabilise and Phase 11 can score the
  outputs. The port is unchanged by adopting it.

### Option C — deterministic provider behind the real port (chosen)

- **Pros:** every kernel property is deterministically testable; scenarios can script
  outputs that a real model would rarely produce but that the system must survive —
  unparseable JSON, a fabricated citation, a claim of certainty over one record, a domain
  outside the granted menu; no credentials, no cost, no flakiness; the seam that matters is
  built and exercised.
- **Cons:** reasoning quality is entirely unproven. This must be said plainly wherever the
  system is described, and it is.

## Consequences

**What is claimed.** The orchestration around a model is correct: bounded, typed, audited,
resumable, and unable to be talked out of its constraints. Adversarial scripts are refused
by code.

**What is not claimed.** That the system produces good root-cause analyses. Nothing in Phase
4 measures that, so nothing in Phase 4 asserts it.

**A related narrowing.** The evidence collector is implemented without a model call at all,
though the approved topology gives it model-assisted strategies. Collection and normalisation
are deterministic, so no model sits between a tool result and the evidence record derived
from it — the place a fabricated observation would be hardest to detect. Recorded on the node
contract as `model_backed=False`, with a test asserting the divergence from
`NodeId.uses_model` is deliberate rather than drift.

**Reversal cost.** Low. A live provider is a new class implementing `ModelProvider` plus a
dependency and a credential reference; no node changes, because nodes already treat model
output as untrusted text.

**When to revisit.** Phase 7, when the reasoning nodes are built for real and Phase 11 exists
to say whether they work.

## Evidence

- `tests/orchestration/test_planner.py` — schema rejection, ungranted-domain rejection,
  redundancy detection, budget bounds, and a planner emitting only rubbish still terminating.
- `tests/orchestration/test_hypothesis.py` — fabricated citations dropped, confidence ceiling
  applied, malformed output surviving as a typed failure.
- `tests/e2e/test_scenarios.py` — ten scenarios reaching their declared expectations,
  including insufficient evidence, contradiction and budget exhaustion.
