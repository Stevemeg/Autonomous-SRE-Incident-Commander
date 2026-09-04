# ADR-0011: Authentication, authorization and tenancy model

- **Status:** Proposed
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §15, §23(L)
- **Supersedes / Superseded by:** none

## Context

Section 15 mandates authentication, OAuth2/JWT where appropriate, RBAC, tenant isolation,
least privilege and scoped tool permissions. Two properties make this harder than a
conventional web application:

1. **Authority is per tenant, per environment and per risk tier.** "Can approve" is not a
   global role — an `sre_approver` in staging is not one in production.
2. **Non-human principals act.** Agent nodes take actions, and their authority must be
   representable, auditable and narrower than any human's.

## Decision

**OAuth2/OIDC with the organisation's IdP for human authentication; short-lived JWTs
carrying tenant and role claims; RBAC evaluated per (tenant, environment, risk tier); shared
schema multi-tenancy with PostgreSQL row-level security as the isolation backstop; and
per-action, short-lived, scoped credentials for all outbound infrastructure access.**

Agent nodes are **not** principals with credentials. They act only through the tool broker,
under the incident's resolved scope, and the audit record names the node and its version as
the actor.

## Alternatives considered

### Tenancy isolation

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **A. Shared schema + RLS** | One database; simple ops and migrations; the database enforces isolation independently of application correctness | A bug in RLS policy affects all tenants; noisy-neighbour effects | **Chosen** |
| B. Schema per tenant | Stronger separation; per-tenant backup | Migration complexity multiplies; connection/schema management; still one instance | Reserve — for a tenant requiring it |
| C. Database per tenant | Strongest isolation; per-tenant tuning | Heavy operations; expensive at small tenant counts; cross-tenant evaluation becomes hard | Only on regulatory demand |

### Agent authority

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **A. Nodes are not principals; act via broker under incident scope** | No credential for a node to leak; one enforcement point; audit names node + version | Requires the broker chokepoint (already the design) | **Chosen** |
| B. Each node is a service principal with its own credentials | Familiar; granular | **Creates credentials a compromised or injected model could try to use.** More secrets to rotate; authorization spreads across nodes | Rejected |

## Rationale

**RLS is chosen because application-layer scoping alone means one forgotten `WHERE` clause
is a cross-tenant breach.** Defence in depth requires a layer that does not depend on every
query being written correctly, and the database is the only place that can provide it. The
`tenant_id`-on-every-table discipline (DM-1) exists to make RLS possible.

**Nodes are deliberately not principals.** The intuitive design gives each node a service
account, but that creates exactly what §7 forbids: credentials sitting in the model's
execution context. If a node holds a credential, a successful prompt injection has something
to steal. If authority exists only as a resolved scope inside the broker — outside the
reasoning path — there is nothing in the model's reach to take. This is the same reasoning
that makes the broker the sole egress point.

Per-action, short-lived credentials follow from SEC-I1: a long-lived broad credential in
process memory is a standing risk, and narrowing it later is hard once callers depend on it.

## Consequences

- **Positive:** Isolation enforced by the database independent of application correctness;
  no credentials in the reasoning path; authority is explicit and auditable per tier and
  environment; standard IdP integration.
- **Negative / accepted trade-offs:** RLS adds query-planning complexity and a session-context
  mechanism that must never be omitted. Per-action credential resolution adds latency to
  every tool call. The role matrix is more complex than a flat RBAC model.
- **Security and permissions:** The core of the security architecture (SEC-I1, I2, I9, I10).
- **Observability and evaluation:** Positive — the audit actor is unambiguous, so the safety
  dashboard is meaningful.
- **Failure modes and recovery:** Identity or secret-manager unavailability **fails closed**
  (SEC-I8), which is correct and does mean an outage stops remediation.
- **Operational and cost impact:** Requires a secret manager and IdP integration from Phase 2.

## Reversal cost and revisit trigger

**Reversal cost: very high.** Tenancy touches every table, query, index and cache key.
Retrofitting isolation is close to a rewrite — which is why it is decided now rather than in
Phase 13, and why assumption AS-01 needs owner confirmation before Phase 3 begins.

Revisit if: a regulated tenant requires physical separation (move that tenant to Option B or
C rather than changing the model globally); RLS causes a measured query-planning problem;
or a genuine multi-org federation requirement appears.

## Validation

| Test | Passing criterion |
|---|---|
| Cross-tenant access | Property tests at API, repository, retrieval and cache layers: **zero** leakage |
| RLS backstop | With application scoping deliberately removed, RLS still blocks access |
| Role matrix | Every (role, tenant, environment, tier) combination behaves per the matrix |
| Self-approval | An actor cannot approve their own proposal |
| Credential scope | Investigation credential attempts a write; denied *by the target* |
| Fail-closed | IdP and secret-manager outage denies rather than allows |

**None has been run.**

## References

- Master specification §15
- [`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md) §5
- [`../architecture/data-model-and-api.md`](../architecture/data-model-and-api.md) §6
