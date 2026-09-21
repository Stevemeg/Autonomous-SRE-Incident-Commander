# Authorization: roles, permissions, scope and authority types

Implements NFR-SEC-01, NFR-SEC-02, NFR-SEC-04, NFR-SEC-05 (Phase 13, ADR-0030). The single
source of truth is `src/asic/domain/permissions.py`; the tests in
`tests/security/test_rbac_matrix.py` compute every expectation below from it and assert it equals
the migrated database.

## 1. Three authorities that are never conflated

| Authority | Held by | Established by | Checked |
|---|---|---|---|
| **Human RBAC** | a person | a role assignment row (tenant, role, optional environment, optional expiry) | on **every** request, reloaded from the database |
| **Human approval** | a person, for one exact action | a recorded decision bound to the action-version hash | at decision time **and again at dispatch**, against *current* RBAC |
| **Connector authority** | a machine (a connector identity) | a `ConnectorScopeBinding` (connector, source, service, environment) and a registered connector | on every ingestion and on every outbound call |

Consequences that the tests attack:

- Token claims identify a subject and a tenant. `role`, `permissions`, `is_admin`, `scope` and
  `environment_id` claims confer nothing (`test_forged_authority_claims_confer_nothing`).
- No historical success substitutes for current authority: revocation and expiry apply to the very
  next request, idempotent replays included (`TestCurrentAuthorityNotHistoricalSuccess`, and the
  Phase 9 replay-revocation tests).
- Model output is none of these. It can propose; it cannot hold, grant or widen anything.
- A connector binding never satisfies a human permission, and a human permission never satisfies a
  connector binding.

## 2. Scope: which tenant, which environment

Every grant is per tenant. A role assignment may be narrowed to one environment (`environment_id`)
or left tenant-wide (`NULL`). Each permission has a scope rule:

- **environment** - honoured for the environment(s) the assignment names; a tenant-wide assignment
  covers all of them. A role in environment A grants nothing in environment B, and resources in
  another environment answer as not-found rather than forbidden.
- **tenant-wide** - the resource is not environment-owned (configuration, evaluation history, the
  audit stream, memory and knowledge governance). **Only a tenant-wide assignment satisfies it**:
  an environment-scoped role must not become a window onto tenant-wide data.

## 3. The matrix (generated from the vocabulary)

| Permission | Scope rule | `viewer` | `responder` | `sre_approver` | `senior_approver` | `platform_admin` | `security_auditor` | `system_operator` |
|---|---|---|---|---|---|---|---|---|
| `incident.read` | environment | yes | yes | yes | yes | yes | yes | yes |
| `incident.control` | environment | - | yes | yes | yes | yes | - | - |
| `ingestion.write` | environment | - | - | - | - | - | - | yes |
| `remediation.approve` | environment | - | - | yes | yes | yes | - | - |
| `evaluation.read` | tenant-wide | - | - | - | - | - | - | yes |
| `administration.read` | tenant-wide | - | - | - | - | yes | - | - |
| `audit.read` | tenant-wide | - | - | - | - | yes | yes | - |
| `memory.promotion.decide` | tenant-wide | - | - | - | - | - | - | - |
| `knowledge.source.access.manage` | tenant-wide | - | - | - | - | - | - | - |
| `knowledge.source.lifecycle.manage` | tenant-wide | - | - | - | - | yes | - | - |

Two permissions are held by **no** system role: `memory.promotion.decide` and
`knowledge.source.access.manage`. Authority to govern memory and to change knowledge-source access
is not granted by default; a deployment provisions a dedicated role (roles are platform-owned rows
the runtime cannot write). This is recorded in code (`UNASSIGNED_BY_DEFAULT`) so it is a decision,
not an accident.

`remediation.approve` carries a risk-tier ceiling (`r2`) in the permission catalogue; the approval
service compares it with the action's tier. **Every holder may therefore decide through R2.** The
earlier threat model implied `sre_approver` could not approve R2; that was never implemented and
the Phase 9 role description ("through risk tier R2") was the truth. Separating R1 and R2
approvers needs distinct permission tiers and is listed under future improvements (ADR-0030).

## 4. Where authority is checked

| Action | Check | Current at |
|---|---|---|
| Read incidents, evidence, timeline, actions, trace | `incident.read` in the incident's environment | each request |
| Escalate, cancel, annotate | `incident.control` in the incident's environment | each request, and again on idempotent replay |
| List / read / decide approvals | `remediation.approve` in the action's environment | each request; **again at dispatch** (`is_authorized_approver`) |
| Ingest alerts and webhooks | `ingestion.write` **and** a current binding for the signed connector, source, service and environment | each request |
| Evaluation history | `evaluation.read`, tenant-wide | each request |
| Tools, policies, tenant, services, knowledge sources | `administration.read`, tenant-wide | each request |
| Audit stream | `audit.read`, tenant-wide | each request |
| Knowledge lifecycle / access | `knowledge.source.*.manage`, tenant-wide | each operation |
| Memory promotion decision | `memory.promotion.decide`, tenant-wide | each decision |
| Outbound connector use | enabled, unrevoked connector **and** binding for tenant/environment/service | each call, no cache |
| Remediation write dispatch | frozen target, action-version hash, policy decision, current human approval, current approver RBAC | immediately before dispatch |

## 5. Tool and capability authority

Every registered capability is reviewed mechanically (`tests/security/test_capability_authority.py`):
an explicit namespace (`read`, `mutate`, `write`, `notify`) consistent with its effect class and
risk tier; tenant and environment resolved by the broker and never supplied; no argument able to
carry a command or a secret; every effectful tool audited, idempotent, single-attempt and bounded;
every mutation with a declared rollback and preconditions; and a reviewed, closed list of the only
free-text arguments (each bounded and rendered as inert data). No model-supplied name creates a
capability, `ToolDescriptor`/`ToolRegistry` are constructed only in the catalogue and registry
modules, and no module invokes a provider except the broker.

### Node-scoped actions (F-08)

`k8s.node.cordon` and `k8s.node.uncordon` (capability `mutate.k8s_node`) are **not** service-scoped:
a node is shared infrastructure and has no service label to check. Earlier documentation implied
every Kubernetes mutation checks a service label; that is true of deployment and HPA mutations and
was never true of nodes. The node authority model is instead:

1. tenant and environment come from the immutable remediation target, never from the model;
2. the node identity is the `node` argument, frozen into the action and covered by the
   action-version hash the human approval is bound to - a different node is a different action;
3. the tier is R2 and **policy alone can never admit it**: dispatch demands a current, scoped human
   approval every time, and a node the cluster read does not show is refused by the SI-7
   precondition (`tests/orchestration/test_node_authority.py`).

## 6. Audit of authority decisions

Denied state changes and denied tenant-wide reads (administration, audit, evaluation, approvals) are
durable `authorization.denied` records: tenant-bound, attributed to the user, carrying the
correlation id, the permission, the route template and the authority source, and never a token or a
request body. Ordinary denied reads are logged, not audited: a durable row per failed `GET` would
let a caller fill the trail (volume is bounded by the per-principal limiter regardless). Failed
authentication happens before a tenant is known, so it is a structured log event with a closed reason
code, not a tenant-bound row. All audit rows are append-only for the application role.
