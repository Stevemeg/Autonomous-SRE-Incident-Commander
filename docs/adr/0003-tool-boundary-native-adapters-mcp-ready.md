# ADR-0003: Tool boundary — native adapters behind an MCP-ready seam

- **Status:** Accepted — implemented in Phase 4. The broker depends on the `ToolProvider`
  protocol; the only implementation is the deterministic simulator. No MCP provider exists,
  and none of §5.4's adoption triggers has been met.
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §7, §13, §14, §15, §20 of [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)
- **Supersedes / Superseded by:** none

## Context

Section 7 requires a capability-based tool registry and states: *"Design an adapter boundary
where MCP can be introduced if it genuinely improves interoperability. Compare native
adapters vs MCP in an ADR; do not add MCP for résumé keywords. The model never receives
unrestricted infrastructure access."*

Section 13 lists MCP among technologies to *"evaluate rather than blindly add"*, and §20
forbids adopting technology solely for keyword value. The specification is unusually
explicit that this decision is a trap it expects us to avoid.

The nine integrations in §14 — Prometheus, Grafana, Loki/OpenSearch, OpenTelemetry,
Kubernetes, Slack, Teams, PagerDuty, Jira — are **all systems we integrate ourselves**, each
with a mature first-party client library.

## Decision

**Implement native, typed, in-process adapters for v1, behind a `ToolProvider` interface
whose descriptor shape is deliberately close to an MCP tool definition.** Do not adopt MCP
as a transport now. Treat any future MCP server as an *additional, untrusted tool provider*
mounted behind the same policy gate and credential broker.

## Alternatives considered

### Option A — Native adapters only, no seam (rejected)

- **What it is:** Typed adapters called directly by the broker; no provider abstraction.
- **Pros:** Simplest; least indirection; fastest.
- **Cons:** Adding any external tool source later means restructuring the broker and the
  registry. Ignores §7's explicit instruction to *design* the boundary.
- **Cost to adopt:** Lowest.

### Option B — MCP as the primary tool transport (rejected)

- **What it is:** Tools exposed via MCP servers; the orchestrator is an MCP client.
- **Pros:**
  - Standardised tool description and discovery.
  - Genuine interoperability with third-party MCP tooling.
  - High keyword value — **explicitly excluded as a reason** by §7 and §20.
- **Cons:**
  - An extra process and transport hop per tool call, for tools we wrote ourselves.
  - **A second trust boundary per server.** Each MCP server is a supply-chain dependency
    that can describe its own tools; a server that misdeclares a tool's effect is a
    privilege-escalation vector.
  - Credentials tend to live in the MCP server, outside our per-action scope resolution —
    directly weakening SEC-I1 and §7's "never unrestricted access".
  - New failure modes: server lifecycle, version skew, transport errors — none of which buy
    us anything at our current integration set.
  - Local reproducibility gets harder; §14 requires deterministic local simulators.
- **Cost to adopt:** Moderate–high, ongoing.

### Option C — Native adapters behind an MCP-ready boundary (chosen)

- **What it is:** Option A plus a `ToolProvider` interface (`list_tools`, `invoke`,
  `health`) with `NativeProvider` and `SimulatorProvider` in v1 and `McpProvider` possible
  later. Registry descriptors carry name, version, typed input/output schema and description
  — the fields an MCP tool definition carries.
- **Pros:**
  - All of Option A's simplicity and performance today.
  - The seam §7 asks for, at the cost of one interface.
  - The simulator becomes just another provider, which makes §14's deterministic local
    testing fall out naturally rather than being bolted on.
  - Future MCP adoption is an adapter task, not a redesign.
- **Cons:**
  - One layer of indirection with no immediate payoff beyond the simulator.
  - Risk of designing a seam for a future that never arrives.
- **Cost to adopt:** Low.

## Rationale

The decisive factor is that **MCP's value is interoperability with tools other people
wrote, and we currently have none.** Every §14 integration is ours. Adopting MCP as the
primary transport would purchase a process hop, a second trust boundary and a distributed
failure mode in exchange for interoperability we would not exercise.

The security argument is the stronger half. §7's non-negotiable is that *"the model never
receives unrestricted infrastructure access"*, and our answer is a four-layer restriction
culminating in **credentials the broker resolves per action and scopes narrowly**
([`../architecture/tool-registry.md`](../architecture/tool-registry.md) §1.2). MCP servers
conventionally hold their own credentials, which would move layer 4 outside our control and
replace a scoped, short-lived credential with a server that holds a broad one. That is a
material weakening for no compensating benefit.

Option C is chosen over Option A because the seam is nearly free and pays for itself
immediately: the deterministic simulators required by §14 become a `SimulatorProvider`
rather than a special case threaded through adapter code.

The seam is deliberately conservative. If MCP is adopted later, three rules preserve the
security model: a remote server's descriptors are **untrusted input** and are mapped into
our registry only after human review assigns capability, scope and risk tier; the policy
gate is unchanged; and credential resolution stays with our broker.

## Consequences

- **Positive:** Lowest latency; one trust boundary; credentials stay under per-action scope
  control; simulators fall out of the design; §7's boundary requirement satisfied.
- **Negative / accepted trade-offs:** One interface with no external consumer yet. We forgo
  a high-visibility keyword — consciously, and on the specification's own instruction.
- **Security and permissions:** **Strongly positive.** One enforcement point, one audit
  emission point, credentials never delegated.
- **Observability and evaluation:** Positive. In-process calls produce a clean span tree
  with no cross-process correlation to reconstruct.
- **Failure modes and recovery:** Positive. No transport or server-lifecycle failure modes.
- **Operational and cost impact:** Positive — no extra processes to run.

## Reversal cost and revisit trigger

**Reversal cost: low**, which is the point of the seam. Adopting MCP means implementing one
`McpProvider` plus a review workflow for imported descriptors; no node, gate or broker logic
changes.

Revisit when **any** of these becomes true:

- A maintained third-party MCP server exists for a system we need and would otherwise
  hand-write an adapter for.
- More than roughly three integrations are maintained outside this project.
- A customer requires bringing their own tools without our writing an adapter.
- MCP becomes the de-facto transport for the observability or Kubernetes tooling we depend
  on, such that native clients become the unusual choice.

## Validation

| Test | Passing criterion |
|---|---|
| Provider substitutability | Simulator and native providers are interchangeable with no node changes |
| Credential containment | No provider receives a credential; only the broker resolves them |
| Descriptor parity | Registry descriptors carry every field an MCP tool definition requires |
| Unregistered tool rejection | A proposal naming an unregistered tool is rejected, not repaired |
| Scope integrity | Provider-supplied arguments cannot widen resolved scope |

**None has been run.** `Proposed` until they have.

## References

- Master specification §7, §13, §14, §15, §20
- [`../architecture/tool-registry.md`](../architecture/tool-registry.md) §5 — full three-way comparison and the seam definition
- [`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md) — T15, malicious tool provider
