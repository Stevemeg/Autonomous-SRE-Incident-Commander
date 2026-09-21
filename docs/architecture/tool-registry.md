# Tool Registry and Capability Model

- **Status:** Authored — Architecture Package (V3 §23 G). Formalised as [ADR-0003](../adr/0003-tool-boundary-native-adapters-mcp-ready.md).
  **Implemented through Phase 8:** seven read capabilities remain isolated in the
  investigation registry; four typed R1/R2 simulator-backed Kubernetes actions are available
  only to the remediation executor through the policy and approval boundary
  ([`bounded-remediation.md`](./bounded-remediation.md)). R3 remains unregistrable.
  A write menu is selection input, not execution authority: the broker re-reads the current
  tenant/environment grant and global tool enabled state immediately before dispatch, and
  requires the action, immutable target and resolved scope to agree. Read menus may remain
  cached within one run because they cannot authorize writes.
  **Phase 10:** native adapters implement the read and Kubernetes write tools behind the
  same broker, and a third, separate catalogue registers six `external_record` tools for
  the S2 notification service. Every native call also requires a server-side connector and
  scope binding. Section 8's `notify.collaboration` / `write.ticketing` classes are
  registered as one capability per tool (`notify.slack_channel`, `write.jira_issue`, ...),
  because a capability menu admits one tool per capability. See
  [`integrations.md`](./integrations.md) and ADR-0026.
- **Master specification references:** Sections 6, 7, 15, 23(G)
- **Related:** [`remediation-safety-policy.md`](./remediation-safety-policy.md) · [`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md)

This document answers one question precisely: **how is the model prevented from receiving
unrestricted infrastructure access?** (§7)

---

## 1. The capability model

### 1.1 Capabilities, not endpoints

A **capability** is a permission to perform a *class* of operation on a *class* of resource.
Tools implement capabilities; actors hold capabilities; the registry maps between them.

```
capability := <verb>.<resource-class>.<risk-tier>
             e.g.  read.metrics.RO
                   read.k8s_workload.RO
                   mutate.k8s_deployment.R1
                   mutate.k8s_storage.R3
```

The model never names a capability it wishes to have. It selects from a list of *already
granted* capabilities that the registry resolved for the current incident, actor and
environment before the model was invoked. This inverts the usual arrangement — the model
does not request permission and receive a verdict; it is handed a bounded menu and can only
choose from it.

### 1.2 The four-layer restriction

The answer to "how is the model prevented from unrestricted access" is that four
independent layers must all agree before an effect occurs. No single layer is trusted.

| Layer | Enforces | Bypassable by a compromised model? |
|---|---|---|
| **1. Menu restriction** | The model is only shown capabilities already resolved for this context | No — it cannot invoke what it was never given |
| **2. Schema validation** | Tool arguments must satisfy a typed schema; free-form strings are not an argument type for write tools | No — invalid arguments are rejected before dispatch |
| **3. Policy gate** | Deterministic authorization of the typed proposal against tenant policy and risk tier | No — the gate reads no model output beyond the typed proposal |
| **4. Credential scope** | The credential the broker resolves is physically incapable of the forbidden operation | No — enforcement is at the target system, not in our code |

Layer 4 is the one that matters most and is most often skipped. A read-only Prometheus
token cannot write regardless of any bug in layers 1–3. **We assume layers 1–3 will
eventually contain a bug; layer 4 is what makes that survivable.**

---

## 2. Tool descriptor schema

Every tool declares the fields §7 requires. This is a conceptual schema, not an
implementation.

```yaml
# Conceptual descriptor — illustrative, not code
tool:
  name: k8s.deployment.rollback
  version: 1.2.0                  # semver; proposals bind to major.minor
  capability: mutate.k8s_deployment.R1

  description: >
    Roll a Deployment back to its immediately previous ReplicaSet revision.

  input_schema:                   # typed; no free-form command field exists
    tenant_id:   {type: uuid,   required: true}
    cluster:     {type: enum,   source: registered_clusters}
    namespace:   {type: string, pattern: "^[a-z0-9-]{1,63}$"}
    deployment:  {type: string, pattern: "^[a-z0-9-]{1,253}$"}
    to_revision: {type: int,    optional: true}
  output_schema:
    previous_revision: {type: int}
    new_revision:      {type: int}
    observed_state:    {type: object}

  permission_scope:
    tenants:      [from_incident_context]     # never widened by the caller
    environments: [staging, production]
    clusters:     from_tenant_registration
    namespaces:   from_service_ownership      # resolved, not supplied
    resource_kinds: [Deployment]
    forbidden_targets: [kube-system, istio-system]

  risk:
    tier: R1                       # reversible low-risk
    blast_radius: single_workload
    reversible: true
    rollback: k8s.deployment.rollback_to(previous_revision)
    data_loss_possible: false

  execution:
    timeout_seconds: 300
    idempotent: true
    idempotency_key: [tenant_id, cluster, namespace, deployment, to_revision]
    retry: {max_attempts: 2, backoff: exponential, retry_on: [transient_api_error]}
    unknown_outcome_policy: reconcile_by_query   # never blind-retry
    preconditions:
      - deployment_exists
      - previous_revision_available
      - no_other_rollout_in_progress
    settling_seconds: 60           # verification waits this long before judging

  audit:
    required_events: [execution.started, execution.completed, execution.failed]
    record_fields: [actor, incident_id, action_id, approval_id, arguments, observed_effect]
    retention_days: 2555           # 7 years; see data-retention policy

  approval:
    required_in: [production]
    required_role: sre_approver
    auto_allow_in: [staging]       # tenant-configurable, never model-configurable
```

### 2.1 Fields that are load-bearing

| Field | Why it exists |
|---|---|
| `permission_scope.namespaces: from_service_ownership` | The caller **cannot supply** the namespace scope. It is resolved from the incident's service ownership, so a model cannot broaden its own reach by naming a different namespace. |
| `input_schema` with no free-form field | FR-REM-06. There is no `command`, `script`, `patch` or `manifest` string field on any write tool. This is the structural answer to §6's "never execute arbitrary model-generated production commands". |
| `idempotency_key` | Composed of business identifiers, not a random UUID, so a duplicate proposal for the same effect collides rather than double-applying. |
| `unknown_outcome_policy` | The hardest real failure: a timeout where the operation may or may not have applied. Blind retry is how systems double-apply. Reconciliation queries actual state first. |
| `settling_seconds` | Fixed in the descriptor, so the verifier cannot be rushed into declaring premature success. |
| `rollback` | A write tool with no declared rollback cannot be tier R1. The rollback is declared *before* the action is ever proposed. |

---

## 3. Risk tiers

Section 6 mandates four tiers. Their operational meaning:

| Tier | Name | Examples | Autonomous? | Approval | Rollback |
|---|---|---|---|---|---|
| **RO** | Read-only investigation | Query metrics, logs, traces, K8s state, deployments, knowledge | Yes, always | None | N/A |
| **R1** | Reversible low-risk | Deployment rollback, HPA replica adjust within bounds, restart a pod, clear a cache key | In non-production only; production requires approval | Production: yes | Mandatory, declared |
| **R2** | High-risk | Scale a stateful workload, drain a node, modify a network policy, failover | **Never autonomous** | Always | Mandatory + tested |
| **R3** | Destructive / irreversible | Delete PVC, delete namespace, drop data, disable safety controls | **Never proposable by the system at all** | N/A — not in the autonomous catalogue | N/A |

### 3.1 R3 is not "approval-gated" — it is absent

A capability the system cannot express is safer than one it can express and is told not to
use. R3 operations are **not registered as agent-invocable tools**. They exist only as
human runbook steps outside this system. If a hypothesis implies an R3 action is needed, the
correct behaviour is to escalate to a human with the reasoning — not to propose the action
and rely on the gate.

This is the difference between a system that *is* safe and a system that is *asked* to be
safe.

### 3.2 Tier assignment is registry-owned

Tiers are assigned by a platform engineer (P2) in the registry, versioned in Git, reviewed
like code. Neither the model nor any runtime path can reclassify an action's tier.

---

## 4. Authorization flow

```mermaid
sequenceDiagram
    autonumber
    participant M as Remediation Planner (LLM)
    participant V as Schema validator
    participant R as Tool registry
    participant G as Policy gate (deterministic)
    participant A as Approval service
    participant B as Tool broker
    participant C as Credential resolver
    participant T as Target system
    participant AU as Audit log

    Note over M: Sees only capabilities pre-resolved for this incident
    M->>V: ActionProposal (typed)
    V->>V: Validate against tool input_schema
    alt schema invalid or tool unregistered
        V-->>M: REJECT (no repair for unregistered tools)
        V->>AU: remediation.rejected_unregistered
    end
    V->>R: Resolve descriptor + version
    R->>G: descriptor + proposal + tenant policy + actor
    G->>G: Deterministic rule evaluation
    G->>AU: policy.evaluated (always, with rule ID)

    alt DENY
        G-->>M: denied + rule ID
    else REQUIRE_APPROVAL
        G->>A: approval request bound to action_version_hash
        A->>A: Durable interrupt; workflow may restart safely
        A-->>G: approved | rejected | expired
        alt not approved
            G->>AU: approval.rejected or approval.expired
        end
    end

    G->>B: authorized action + approval_id
    B->>B: Re-validate preconditions against live state
    alt preconditions drifted
        B-->>G: FAIL CLOSED (no execution)
        B->>AU: execution.failed (precondition_drift)
    end
    B->>C: Resolve narrowest credential for scope
    C-->>B: Short-lived scoped credential
    B->>T: Execute with idempotency key
    T-->>B: Result
    B->>AU: execution.completed (actor, action, effect)
```

### 4.1 Non-obvious properties of this flow

- **Step 4 rejects rather than repairs** for unregistered tools. Repair loops teach the
  planner to negotiate; rejection teaches it the catalogue is fixed.
- **`policy.evaluated` is emitted on every path**, including allow. An audit log that only
  records denials cannot prove what was permitted.
- **Preconditions are re-validated at the broker**, after approval. An approval granted
  ninety seconds ago against state that has since changed must not execute (FR-REM-09).
- **Credentials are resolved after authorization**, are short-lived, and are scoped to this
  action. There is no long-lived ambient credential in the process.

---

## 5. Native adapters vs MCP

Required comparison (§7). Decision recorded in
[ADR-0003](../adr/0003-tool-boundary-native-adapters-mcp-ready.md).

### 5.1 The three options

| | **A. Native adapters only** | **B. MCP as primary transport** | **C. Native adapters behind an MCP-ready boundary** |
|---|---|---|---|
| **What it is** | Typed Python adapters called in-process by the broker | Tools exposed via MCP servers; the agent is an MCP client | Native adapters now, with the registry descriptor and broker interface designed so an MCP server can be mounted as an additional tool *provider* |
| **Authorization** | Fully ours, in-process, one enforcement point | Split: our gate plus whatever the MCP server enforces | Fully ours; an MCP provider is treated as an untrusted upstream behind the same gate |
| **Latency** | In-process call | Extra process/transport hop per call | In-process today |
| **Interop value** | None — we own every integration | High if third-party tools exist that we want | Realised only when a genuine third-party tool appears |
| **Trust boundary** | One | One per MCP server, each a new supply-chain dependency | One today; explicit and reviewed when a provider is added |
| **Credential handling** | Broker resolves scoped, short-lived credentials | Credentials often live in the MCP server, outside our scope resolution | Broker retains credential authority |
| **Failure modes** | Adapter errors | Adapter errors + transport + server lifecycle + version skew | Adapter errors |
| **Cost to adopt** | Low | Moderate–high | Low (plus a modest interface discipline) |
| **Résumé keyword value** | Low | High | Moderate — *and explicitly not a reason* (§7, §20) |

### 5.2 Recommendation: Option C

**Native adapters now, behind an MCP-ready boundary.**

The decisive factor is that **every integration in §14 is one we implement ourselves.**
Prometheus, Loki, Kubernetes, Slack, Teams, PagerDuty and Jira all have first-class client
libraries. MCP's genuine value is interoperability with tools *other people* wrote; we
currently have none. Adopting MCP as the primary transport today would buy an extra process
hop, a second trust boundary and a distributed-systems failure mode, in exchange for
interoperability we would not use.

Section 7 anticipates exactly this trap: *"do not add MCP for résumé keywords."*

What we *do* take from MCP is the discipline. The registry descriptor in §2 is deliberately
close to an MCP tool definition — name, version, typed input/output schema, description —
so that mounting an MCP server later is an adapter-implementation task, not a redesign.

### 5.3 The seam, concretely

The broker depends on a `ToolProvider` interface, not on adapter classes:

```
ToolProvider
  ├─ list_tools()            -> [ToolDescriptor]
  ├─ invoke(name, args, ctx) -> ToolResult
  └─ health()                -> ProviderHealth

  NativeProvider   — in-process typed adapters              (v1)
  SimulatorProvider — deterministic fixtures, test-only     (v1)
  McpProvider      — mounts an external MCP server          (future)
```

Three rules keep the seam honest and prevent MCP from becoming a security hole later:

1. **An MCP provider's tool descriptors are untrusted input.** They are mapped into our
   registry only after a human reviews and assigns capability, scope and risk tier. A remote
   server cannot declare its own risk tier.
2. **The policy gate is unchanged.** MCP tools pass the same gate as native ones.
3. **Credentials stay with our broker.** We do not delegate credential resolution to a
   remote server.

### 5.4 When Option B becomes justified

Concrete triggers, not vibes:

- A third-party MCP server exists for a system we need and would otherwise hand-write.
- More than roughly three integrations are maintained by parties outside this project.
- A customer requires bringing their own tools without our writing an adapter.

Until one of those is true, Option C is strictly better.

---

## 6. Untrusted content handling

Any content originating outside our trust boundary — log lines, runbook text, ticket bodies,
alert annotations, deployment messages, and **model output itself** — is untrusted.

### 6.1 Provenance labels

| Label | Origin | Can influence authorization? | Can be cited as fact? |
|---|---|---|---|
| `SYSTEM` | Our own policy and configuration | **Yes** | Yes |
| `HUMAN` | An authenticated human decision | **Yes** | Yes |
| `VERIFIED_FACT` | Tool broker result, with query + timestamp | No | Yes |
| `RETRIEVED` | Knowledge base, tickets, runbooks | **No** | Only with citation, as retrieved content |
| `MODEL_CLAIM` | Model generation | **No** | No — must be grounded before use |

**Authority flows only from `SYSTEM` and `HUMAN`.** This is the single rule that satisfies
§15's "retrieved text must never override system policy or tool authorization", and it is
enforced structurally: the policy gate's input type accepts only a validated
`ActionProposal` plus `SYSTEM`-labelled policy. There is no field on the gate's input that
can carry `RETRIEVED` or `MODEL_CLAIM` content.

### 6.2 Handling at ingestion and at use

- Untrusted content is stored with its label and never re-labelled upward.
- It is delimited and marked as data when placed in a prompt, never concatenated into an
  instruction position.
- Known injection patterns are detected, flagged and recorded (`content.injection_flagged`)
  — but detection is a *signal*, not the defence. The defence is that the content is
  structurally incapable of reaching the authorization path.
- Model output is untrusted until schema-validated; a hypothesis citing a non-existent
  evidence ID is dropped in code, not scored down in a prompt.

---

## 7. Audit requirements

Every tool invocation emits an immutable audit record. The broker is the sole egress, so
"unaudited action" is unreachable rather than merely discouraged.

| Field | Purpose |
|---|---|
| `audit_id`, `occurred_at` | Identity and ordering |
| `tenant_id`, `actor` (human or node + version) | Who, in which tenant |
| `incident_id`, `action_id`, `correlation_id` | Links to the incident and its trace |
| `tool_name`, `tool_version`, `capability`, `risk_tier` | What was invoked |
| `arguments_redacted` | Inputs with secrets and PII redacted |
| `policy_decision`, `policy_rule_id`, `approval_id` | Why it was permitted |
| `outcome`, `observed_effect`, `duration_ms` | What happened |

Audit records are append-only, tenant-scoped, retained per the data-retention policy, and
never contain secret material (NFR-SEC-06, NFR-OBS-05).

---

## 8. Initial capability catalogue

The v1 registry. Everything not listed here is, by definition, not something the system can
do.

| Capability | Tier | Tools | Notes |
|---|---|---|---|
| `read.metrics` | RO | `metrics.query`, `metrics.range` | PromQL built from typed parameters |
| `read.logs` | RO | `logs.query` | Result size capped; scoped by service/time |
| `read.traces` | RO | `traces.query`, `traces.get` | |
| `read.k8s_workload` | RO | `k8s.get`, `k8s.list`, `k8s.events`, `k8s.logs` | Read-only service account |
| `read.deploy` | RO | `deploy.list`, `deploy.diff` | |
| `read.topology` | RO | `topology.dependencies` | |
| `read.knowledge` | RO | `knowledge.search` | ACL-filtered pre-search |
| `mutate.k8s_deployment` | R1 | `k8s.deployment.rollback`, `k8s.deployment.restart` | Rollback declared; approval in production |
| `mutate.k8s_scale` | R1 | `k8s.hpa.adjust` | Bounded by registered min/max |
| `mutate.k8s_pod` | R1 | `k8s.pod.delete` | Recreated by controller; blast radius one pod |
| `mutate.k8s_node` | R2 | `k8s.node.cordon`, `k8s.node.drain` | Never autonomous. *Phase 8 implemented cordon/uncordon (drain is not registered). Node-scoped, **not** service-scoped: authority is the frozen tenant/environment target, the node identity bound into the approved action hash, R2 and a current human approval on every dispatch (Phase 13, F-08; `AUTHORIZATION.md` section 5)* |
| `mutate.k8s_network` | R2 | `k8s.networkpolicy.apply` | Never autonomous; from a registered template |
| `notify.collaboration` | R1 | `slack.post`, `teams.post` | Outbound only. *Phase 10 registers these as `notify.slack_channel` / `notify.teams_channel`, effect class `external_record`* |
| `write.ticketing` | R1 | `jira.create`, `jira.update`, `pagerduty.update` | *Phase 10: `write.jira_issue`, `write.jira_comment`, `write.pagerduty_event`, plus `write.grafana_annotation`; external records, no rollback, never retried* |

Deliberately absent: anything deleting persistent state, anything modifying RBAC or
policy, anything executing an arbitrary command or applying an arbitrary manifest.

---

## 9. Evaluation of the tool layer

| Property | How it is tested |
|---|---|
| Model cannot invoke an unregistered tool | Adversarial suite; every attempt must be rejected and audited |
| Scope cannot be widened by argument injection | Property tests over namespace/cluster/tenant arguments |
| Retrieved content cannot reach authorization | Injection corpus in runbooks, tickets and log lines; gate input type inspected |
| Idempotency holds | Duplicate delivery and concurrent-execution tests per write tool |
| Unknown-outcome reconciliation | Fault injection: timeout after the target applied the change |
| Fail-closed on policy unavailability | Policy store outage must produce deny, never allow |
| Audit completeness | Every executed action has a matching audit record — reconciliation test, target 100% |
