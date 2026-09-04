# ADR-0001: Agent topology — consolidate 19 candidate responsibilities into 12 nodes

- **Status:** Proposed
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §4, §5, §6, §15 of [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)
- **Supersedes / Superseded by:** none

## Context

Section 4 lists nineteen candidate agents/nodes and constrains their use in the same
paragraph: *"Do NOT build one giant LLM workflow. Use specialized agents/nodes only where
responsibility, tools, permissions, failure modes or evaluation criteria are meaningfully
different… Do not create agents merely to inflate the portfolio."*

This is a decision, not a specification. The list is a list of *responsibilities*; how many
nodes implement them is ours to determine and to defend.

Two failure modes are available. Building nineteen nodes inflates the portfolio, multiplies
prompt and evaluation surface, and — critically — implies that responsibilities like
"Risk/Policy Gate" and "Human Approval" should be LLM agents, which would violate §6 and
§15. Building one node contradicts §4 outright and destroys per-responsibility evaluation
and permission separation.

## Decision

**Implement twelve graph nodes plus two derived services**, covering all nineteen
responsibilities:

- **Seven LLM-backed reasoning nodes:** Investigation Planner, Evidence Collector,
  Hypothesis Engine, Remediation Planner, Verifier, Postmortem Author, Memory Curator.
- **One hybrid node:** Alert Correlator (deterministic core, model-assisted ranking).
- **Four deterministic nodes, explicitly not models:** Incident Coordinator, Policy Gate,
  Approval Service, Remediation Executor.
- **Two derived services:** Timeline projection, Notification service.

Six telemetry and knowledge responsibilities (metrics, logs, traces, deployments,
Kubernetes state, operational knowledge) collapse into the Evidence Collector as six
independently-evaluated **analyser strategies**.

The full per-candidate decision table is in
[`../architecture/agent-topology.md`](../architecture/agent-topology.md) §3.

## Alternatives considered

### Option A — Nineteen nodes, one per bullet (rejected)

- **What it is:** Literal implementation of the §4 list.
- **Pros:** Trivially defensible as "following the spec"; maximal apparent sophistication;
  each responsibility has an obvious home.
- **Cons:**
  - Five analysis nodes share permission scope, failure modes, recovery path and evaluation
    shape, differing only by adapter — five copies of one node with a parameter.
  - Five prompt surfaces and five golden-label sets to maintain for one behaviour.
  - **Implies the Policy Gate is an LLM agent.** A probabilistic authorizer cannot satisfy
    §6 or §15. This alone disqualifies the literal reading.
  - Directly contradicts §4's own instruction against inflating the portfolio.
- **Cost to adopt:** High and ongoing.

### Option B — Twelve nodes plus two services (chosen)

- **What it is:** Consolidation on a stated two-discriminator test, with reclassification of
  control responsibilities to deterministic components.
- **Pros:**
  - Every node earns its existence against a written test.
  - Per-domain evaluation is preserved at the strategy level.
  - Six responsibilities become deterministic — a **safety improvement**, not just fewer
    nodes.
  - Splitting a strategy into a node later is cheap; merging nodes later is expensive.
- **Cons:**
  - The Evidence Collector is the largest node and could accrete complexity.
  - "Twelve nodes" is a less impressive headline than "nineteen agents".
  - Requires explaining a deviation from a literal reading of the specification.
- **Cost to adopt:** Low.

### Option C — Three coarse nodes (investigate / decide / act) (rejected)

- **Pros:** Simplest graph; least prompt surface.
- **Cons:** Violates §4's separation requirement; loses per-responsibility evaluation;
  merges the proposer and the authorizer, destroying separation of duties.
- **Cost to adopt:** Low to build, high in lost safety and evaluability.

### Option D — Dynamic agent spawning (rejected)

- **What it is:** The planner creates specialised sub-agents on demand.
- **Pros:** Flexible; fashionable.
- **Cons:** Unbounded by construction — directly conflicts with §5's hard limits. Permission
  scope for a dynamically created agent is undefinable in advance, which is incompatible
  with §7 and §15. Unevaluable: the topology differs between runs, so replay and regression
  comparison lose meaning.
- **Cost to adopt:** Low to build, unacceptable in safety and evaluation terms.

## Rationale

The decisive factor is the **two-discriminator test applied honestly**: a node is justified
only if it differs meaningfully on at least two of §4's five discriminators, and at least
one must be *permissions* or *failure modes*, since those create genuine blast-radius
separation rather than tidy code.

The six analysis responsibilities fail this test — they differ only on responsibility
(narrowly) and evaluation criteria, sharing permission tier, failure modes and recovery
path. A strategy encapsulates exactly that difference.

The second, more important finding is that **§4's list mixes reasoning with control**.
"Risk/Policy Gate", "Human Approval" and "Remediation Executor" appear alongside "Log
Analysis", but implementing them as LLM agents would place authorization, human authority
and command execution inside a model — the exact thing §6 and §15 forbid. Reclassifying
them as deterministic components is not a deviation from the specification; it is what the
specification requires once §4 is read alongside §6 and §15.

Starting consolidated and splitting on evidence is also the cheaper error to correct.
Strategies already carry separate prompts, schemas and label sets, so promotion to a node is
mechanical. Merging two nodes that should never have been separate means unpicking two
permission scopes, two evaluation sets and two failure paths.

## Consequences

- **Positive:** Fewer prompt surfaces; one permission tier for all read paths; a smaller
  security-critical surface; six responsibilities made deterministic; per-domain evaluation
  retained; a graph small enough to reason about exhaustively.
- **Negative / accepted trade-offs:** The Evidence Collector needs disciplined internal
  structure to avoid becoming a god-object. The design requires explanation against a
  literal reading of §4 — hence this ADR. A less impressive node count.
- **Security and permissions:** **Strongly positive.** Authorization, approval and execution
  are deterministic; the proposer cannot authorize; read and write paths hold different
  credentials.
- **Observability and evaluation:** Neutral-to-positive. Strategy-level spans and labels
  preserve per-domain measurement; fewer nodes means a cleaner span tree.
- **Failure modes and recovery:** Positive. One read-path recovery policy instead of five
  near-identical ones.
- **Operational and cost impact:** Positive. Fewer model calls per investigation than a
  design that hands every domain to a separate agent.

## Reversal cost and revisit trigger

**Reversal cost: cheap in the split direction, expensive in the merge direction** — which is
why the design starts consolidated.

Revisit when any of these is observed:

- One strategy's evaluation metrics diverge persistently from the others, or it needs a
  different permission scope → split it into its own node.
- Correlation quality plateaus and needs a learned model with its own training lifecycle →
  promote the Alert Correlator to a separate service.
- Hypothesis quality requires parallel independent branches with cross-critique → split the
  Hypothesis Engine into generator and critic.
- The Evidence Collector exceeds a maintainable size or its strategies stop sharing a
  meaningful failure path.

## Validation

| Test | Passing criterion |
|---|---|
| Coverage | All nineteen §4 responsibilities have a disposition — checked mechanically by `scripts/validate_docs.py` |
| Per-strategy evaluation | Each of the six strategies produces independent metrics against its own labels |
| Separation of duties | No code path from Remediation Planner to Executor bypassing the Policy Gate |
| Determinism | Policy Gate, Approval Service and Executor contain no model call — static check |
| Graph reachability | Every node reaches a terminal state; no unbounded cycle |
| Tool-call efficiency | Compared against a naive one-node-per-domain baseline in evaluation |

**None has been run.** `Proposed` until they have.

## References

- Master specification §4, §5, §6, §15
- [`../architecture/agent-topology.md`](../architecture/agent-topology.md) — full decision table and node specifications
- [`../architecture/remediation-safety-policy.md`](../architecture/remediation-safety-policy.md) — the invariants requiring deterministic control components
