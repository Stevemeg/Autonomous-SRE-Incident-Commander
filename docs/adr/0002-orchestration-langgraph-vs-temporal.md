# ADR-0002: Orchestration and workflow durability — LangGraph checkpointing vs Temporal

- **Status:** Proposed
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §4, §12, §13 of [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)
- **Supersedes / Superseded by:** none

## Context

Section 12 requires incidents be modelled as long-running workflows with checkpointing,
resume-after-failure, idempotent actions, retries and backoff, timeouts, dead-letter states,
duplicate-event handling, partial tool failure, external API and model outage handling, and
**human-approval waiting states**. It then instructs: *"Compare LangGraph persistence with
Temporal or another workflow engine. Introduce a dedicated workflow engine only if
requirements justify it."*

The load-bearing requirement is the human-approval wait. An incident can sit awaiting a
human decision for minutes to hours, across process restarts and deployments, and must
resume without re-executing side effects. That is a durable-execution problem, not an
agent-framework problem, and it is what makes this a genuine decision rather than a default.

Expected scale, which materially affects the answer: tens to low hundreds of incidents per
day per tenant; a handful of tenants; single-digit concurrent active investigations;
approval waits measured in minutes to hours, not days.

## Decision

**Use LangGraph with a PostgreSQL checkpointer as the orchestration and durability layer for
v1. Do not adopt Temporal now.** Isolate the durability contract behind a narrow internal
interface so that Temporal can be adopted later without rewriting agent logic, and implement
the safety-critical durability guarantees — idempotency keys, precondition re-validation,
reconciliation of unknown outcomes, and the outbox for side effects — **in our own code,
independent of the engine**.

That last clause is the crux: the guarantees that matter most for safety are ones we must
own regardless of engine, so the engine choice is genuinely reversible.

## Alternatives considered

### Option A — LangGraph + PostgreSQL checkpointer (chosen)

- **What it is:** Agent graph and durable state in one framework. `interrupt()` suspends the
  graph awaiting external input; the checkpointer persists state to PostgreSQL; the graph
  resumes from the checkpoint.
- **Pros:**
  - One mental model and one repository for agent logic and durability; no split between
    "workflow code" and "agent code".
  - Native support for the interrupt/resume pattern that human approval requires.
  - Checkpoints live in the same PostgreSQL we already need — no new stateful service, no
    new backup/restore story, and workflow state can be joined to incident data in SQL.
  - Local reproducibility is trivial: PostgreSQL in Docker Compose, nothing else.
  - Directly matches the §13 baseline ("LangGraph or justified equivalent").
- **Cons:**
  - Weaker durable-timer semantics than a dedicated engine; long waits need our own
    scheduled sweeper.
  - No built-in versioning of in-flight workflows — a deployment changing the graph shape
    while incidents are mid-flight needs care.
  - Exactly-once side effects are **our** responsibility, not the framework's.
  - Retry/backoff and heartbeating are hand-rolled.
  - Framework churn: LangGraph's persistence APIs have moved faster than a workflow engine's.
- **Cost to adopt:** Low. Already in the baseline stack.

### Option B — Temporal (rejected for v1)

- **What it is:** A dedicated durable-execution engine. Workflows are deterministic
  functions; side effects are activities with automatic retry; the server owns state,
  timers, versioning and visibility.
- **Pros:**
  - Best-in-class durable timers — multi-day waits are trivial and reliable.
  - Automatic activity retry with configurable policy; heartbeating for long activities.
  - First-class in-flight workflow versioning, which LangGraph lacks.
  - Strong visibility, replay tooling and operational maturity.
  - Determinism enforcement catches a class of bug at development time.
- **Cons:**
  - A significant new stateful dependency: server, matching/history/frontend services, its
    own datastore, its own upgrade and backup story.
  - Two programming models: deterministic workflow code plus activities, alongside the agent
    graph. Agent logic ends up split across both, or Temporal merely wraps LangGraph and the
    duplication is obvious.
  - Local development requires the Temporal stack; heavier than "Postgres in Compose".
  - Determinism constraints are awkward for agent code, which is inherently
    non-deterministic — most agent work becomes an activity, reducing Temporal to a
    retry-and-timer layer.
  - Operational complexity that our expected scale does not require.
- **Cost to adopt:** Moderate–high. Days of infrastructure work plus ongoing operations.

### Option C — Custom state machine on PostgreSQL (rejected)

- **What it is:** Our own state machine, event log and scheduler on PostgreSQL.
- **Pros:** Total control; no framework dependency; the state model exactly matches our
  domain.
- **Cons:** Re-implements a solved problem. Every subtle durability bug — lease expiry,
  clock skew, at-least-once scheduling — becomes ours to discover in production. Zero
  portfolio value in a hand-rolled orchestrator.
- **Cost to adopt:** High, and high ongoing.

### Option D — LangGraph now, Temporal for remediation only (rejected for v1, kept in reserve)

- **What it is:** LangGraph for the investigation loop; Temporal only for the
  execute → verify → compensate saga.
- **Pros:** Puts the strongest durability where the risk is highest.
- **Cons:** Two engines to operate for one product; a distributed handoff at the most
  safety-critical boundary in the system, which is precisely where we least want a
  cross-process seam.
- **Note:** This is the natural first step *if* Option B's triggers fire.

## Evaluation against the required criteria

| Criterion | LangGraph + Postgres | Temporal | Assessment |
|---|---|---|---|
| **Long-running workflows** | Adequate — hours to days via checkpoints + sweeper | Excellent — arbitrary duration | Temporal wins; our need is hours, which LangGraph covers |
| **Human approval waits** | Native `interrupt()`, durable in Postgres | Native signals + durable timers | **Both adequate.** This was the decisive requirement and it does not discriminate |
| **Checkpointing** | Built-in, Postgres-backed | Built-in, server-owned | Even |
| **Retries** | Hand-rolled per operation class | Built-in per activity | Temporal wins — but see note below |
| **Idempotency** | Ours to implement | Ours to implement | **Even — neither engine solves this.** Idempotency is a domain concern |
| **Recovery** | Lease + reclaim + reconcile, ours | Automatic, server-driven | Temporal wins |
| **Versioning** | Weak; needs discipline for in-flight graphs | First-class | **Temporal wins clearly** |
| **Operational complexity** | Low — one database | High — a stateful cluster | **LangGraph wins clearly** |
| **Local reproducibility** | Excellent — Compose + Postgres | Moderate — full stack needed | **LangGraph wins**; §14 demands local determinism |
| **Portfolio / interview value** | Moderate | High keyword value | **Explicitly not a criterion** per §13 and §20. Recorded to show it was consciously discounted |
| **Expected project scale** | Comfortably sufficient | Substantially over-provisioned | **LangGraph wins** |

Score without the excluded criterion: Temporal wins on 3 (retries, versioning, recovery),
LangGraph wins on 3 (operational complexity, local reproducibility, scale fit), and 4 are
even. This is genuinely close, which is why the decision rests on a tiebreaker rather than
a tally.

**Note on retries.** Temporal's retry advantage is smaller here than it appears, because
§12's hard cases — C4 unknown outcomes, C5 semantic failures, precondition drift — must
*not* use automatic retry. Our classification in
[`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md) §1 is
domain logic that we would write identically under either engine. A generic retry policy
applied to a remediation action is a bug, not a feature.

## Rationale

The decisive factor is that **Temporal's genuine advantages — durable multi-day timers,
in-flight workflow versioning, automatic activity retry — address problems we do not yet
have**, while its cost — a stateful cluster, a second programming model, and degraded local
reproducibility — is paid immediately and conflicts with §14's requirement that nothing
depend on heavy live infrastructure.

Meanwhile, the durability guarantees that actually keep this system safe are ones **neither
engine provides**: business-keyed idempotency, precondition re-validation at execution time,
reconciliation instead of blind retry, and the approval-hash binding. Because we implement
those ourselves either way, the engine is not carrying the safety load, and choosing the
lighter engine does not weaken the safety story.

This is a close call, and it is recorded as close. If expected scale were tens of thousands
of concurrent long-running workflows, or if approvals routinely spanned days, the decision
would flip.

Section 12's own phrasing settles the tie: *"Introduce a dedicated workflow engine only if
requirements justify it."* At the stated scale, they do not — yet.

## Consequences

- **Positive:** One datastore; trivial local reproduction; workflow state joinable to
  incident data in SQL; one programming model; fastest path to a working durable loop.
- **Negative / accepted trade-offs:** We hand-roll lease management, heartbeating, the timer
  sweeper and retry policy. In-flight graph versioning needs an explicit discipline
  (drain-before-deploy for shape changes). We accept a framework whose persistence API has
  been less stable than a workflow engine's.
- **Security and permissions:** Neutral. Authorization lives in the policy gate and broker,
  not the orchestrator. Keeping everything in one process is mildly *positive*: no network
  hop between authorizer and executor.
- **Observability and evaluation:** Positive. Checkpoints in the same database as traces and
  evaluation runs make correlation straightforward.
- **Failure modes and recovery:** Mixed. Recovery is ours to get right, which is why
  [`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md)
  specifies lease reclaim, reconciliation and split-brain prevention explicitly rather than
  assuming the framework handles them.
- **Operational and cost impact:** Clearly positive — no additional stateful service.

## Reversal cost and revisit trigger

**Reversal cost: moderate**, and deliberately kept so. Mitigations:

1. Agent nodes are pure functions of state; they do not call orchestration APIs directly.
2. A narrow internal `DurableWorkflow` interface (start, checkpoint, interrupt, resume,
   schedule) is the only orchestration surface node code sees.
3. Idempotency, reconciliation, hash binding and the outbox are ours, so they survive an
   engine swap unchanged.

**Revisit if any of the following becomes observably true:**

- Approval waits routinely exceed 24 hours, or SLAs require multi-day durable timers.
- Sustained concurrent active incidents exceed ~500, or workflow state exceeds what a single
  PostgreSQL instance serves comfortably.
- In-flight workflow versioning causes a production incident, or blocks deployment more than
  twice.
- The remediation saga grows to span multiple external systems needing cross-system
  compensation.
- Hand-rolled lease/timer/retry code exceeds roughly 1,500 lines or becomes a recurring
  source of defects.

If one to two of these fire, adopt **Option D** (Temporal for the remediation saga only). If
three or more fire, adopt **Option B** wholesale.

## Validation

Per §9, only measured results may be reported. This decision is validated by:

| Test | Passing criterion |
|---|---|
| Kill-and-resume at every checkpoint | Resume with zero duplicated side effects |
| Approval durability | Restart and redeploy during `AwaitingApproval`; wait survives |
| Split-brain | Two workers, forced lease conflict; single execution |
| Sustained load | Target concurrency held without checkpoint-write saturation (Phase 15) |
| Checkpoint overhead | Measured p95 write latency within the step budget |
| Recovery time | Workflow resumes within the NFR-REL-09 budget of 60 s |

**None of these has been run.** The decision is `Proposed` until they have.

## References

- Master specification §4, §12, §13
- [`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md) — the durability requirements this must satisfy
- [`../architecture/agent-topology.md`](../architecture/agent-topology.md) — the graph being orchestrated
