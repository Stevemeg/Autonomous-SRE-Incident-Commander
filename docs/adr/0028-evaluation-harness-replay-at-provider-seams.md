# ADR-0028: The evaluation harness replays at the provider seams and never lets a judge gate

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Project owner (Phase 11 implementation)
- **Spec reference:** §9, §10, §17, §18, §20
- **Supersedes / Superseded by:** resolves Architecture Package candidate decisions C2 (replay-fixture format) and, for now, C3 (judge strategy; calibration still open)

## Context

Phase 11 needs a harness that can run the same scenarios against the product, replay them
deterministically, compare versions and gate on the result, without a live model provider
(ADR-0016) and without a production deployment. Five decisions were open:

1. where to record and replay - inside the kernels, or at a boundary the kernels already use;
2. how a scenario and a recording are versioned so a changed target is never compared as if
   it were the same one;
3. what a result is evaluated from;
4. what authority an LLM judge has;
5. how the gate reports, and how its history is protected.

## Decision

**Replay at the provider seams.** A run's tool providers and model provider are wrapped in
recorders; the ordered answers - results, errors and timeouts alike - are sealed into a
fixture. Replay substitutes `ReplayToolProvider` and `ReplayModelProvider`, which serve
exactly those answers to the unchanged kernels, broker, persistence and tracing code. Replay
is strict: a request whose tool, version or non-scope arguments (or model node and prompt
version) differ from the next recorded entry raises, and a replay that leaves recorded
answers unused fails `replay.fully_consumed`. Scope arguments (tenant, environment, service,
namespace) are excluded from identity because a replay runs in a fresh world. Replay
providers declare the simulator family, so the broker's existing refusal to mix them with
native providers (ADR-0020) applies, and they refuse a production deployment. The governed
knowledge store is not recorded: RAG scenarios ingest versioned documents through the real
pipeline in every world, because knowledge evidence is only accepted with a manifest the
database verifies.

**Versioning by digest.** A scenario's digest covers its definition and the fingerprint of
the simulator fixtures it runs on. A stored scenario whose digest differs at the same version
errors the run ("changed without a version bump"). A replay fixture carries its scenario
digest, a format version and a content digest, and is refused if any differs. A baseline is
comparable only if the evaluator version and each scenario digest match; otherwise the
comparison says `not_comparable`.

**Evaluate the records, not the harness's memory.** Checks read incident, workflow run,
evidence, hypotheses and citation links, tool executions, trace spans, remediation action,
policy decision, approval, verification and audit rows under the application role and the
tenant's row-level security - the same records an operator would read.

**Judges score; they never gate.** A judge is an ordinary model call through the existing
port (node `e1_evaluation_judge`), with evidence fenced as untrusted data. Output that is not
the exact schema, or that cites evidence the run never gathered, is discarded. A panel below
its minimum is `insufficient`; disagreement beyond tolerance is `contested` and never
averaged; no configured judge is `not_measured`. Every result is `uncalibrated` until human
calibration exists. A contested run does not fail the gate, and no judge output feeds a
deterministic check or any product behaviour.

**A sealed, append-only, machine-readable gate.** `python -m asic.evaluation.gate` exits `0`
passed, `1` failed (any failed scenario, new failure or safety regression against the
baseline), `2` errored (no scenario, any errored scenario, or a refused input). The suite
report is stored with a digest that is re-verified when used as a baseline and when read
through the API. Result tables grant the application role SELECT and INSERT only; the
migration's downgrade is refused once history exists.

## Alternatives considered

- **Record inside each node.** Rejected: it would add evaluation code paths to the product
  and replay would not exercise the real broker, persistence or tracing.
- **HTTP-level recording (VCR style).** Rejected for now: simulator and deterministic model
  providers make no HTTP calls, so it would record nothing that Phase 11 runs; it remains
  possible for live-adapter replay later.
- **Lenient replay that serves the nearest answer.** Rejected: a replay that answers a
  different question is a fabrication, not a reproduction.
- **Averaging judges, or letting a judge fail a run.** Rejected: an uncalibrated judge is not
  an authority, and averaging hides the disagreement that is the signal.

## Consequences

- Positive: replay determinism is checked end to end, including after a process restart;
  tampering with a scenario, fixture or baseline is detected; results are bound to the
  workflow run and execution trace they describe.
- Negative: rows written in the same logical instant carry no sequence number, so the stored
  observation signature compares tool calls as a multiset; call order is enforced only
  during replay.
- Negative: no live model or judge provider has been evaluated; RCA figures from scripted
  runs validate the pipeline, not reasoning quality.
- Neutral: CI wiring of the gate is Phase 14.

## Validation

`tests/evaluation/` (UNIT: corpus coverage and digests, strict replay, judge panel,
comparison, gate decision, non-vacuous invariants; INTEGRATION/SIMULATOR/REPLAY: simulator
suite, replay after restart with identical signatures, trace binding, append-only grants,
cross-tenant isolation, tamper refusals, CLI exit codes, API), and
`tests/db/test_migration_history.py::TestUpgradePaths::test_phase11_evaluation_migration_round_trips_and_refuses_losing_history`.
