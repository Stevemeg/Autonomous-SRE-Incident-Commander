# ADR-0010: Observability and evaluation tooling — OpenTelemetry-native, not LangSmith or Phoenix

- **Status:** Proposed
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §9, §10, §11, §13
- **Supersedes / Superseded by:** none

## Context

Section 11 mandates OpenTelemetry across the incident lifecycle, agents, model calls, tools,
retrieval, database operations, integrations, approvals, remediation and verification.
Section 13 lists LangSmith and Arize Phoenix among technologies to evaluate rather than
blindly add.

Our trace requirement is unusual: per
[`../architecture/observability.md`](../architecture/observability.md) §1, **the trace is a
system of record shared by operations, replay and evaluation**, carrying a domain-specific
schema (incident, action, approval, evidence, behaviour version) and subject to tenant
isolation and retention policy.

## Decision

**Instrument natively with OpenTelemetry, store traces in PostgreSQL alongside incident
data, and use Prometheus/Grafana/Loki for metrics, dashboards and logs.** Do not adopt
LangSmith or Arize Phoenix in v1. Follow OTel GenAI semantic conventions for model spans so
that adopting Phoenix later is a collector configuration change, not re-instrumentation.

## Alternatives considered

### Option A — OpenTelemetry-native (chosen)

- **Pros:** §11 and §13 already require the OTel/Prometheus/Grafana/Loki stack, so this adds
  no new dependency. Full control over the domain schema — `action_id`, `approval_id`,
  `behaviour_version` are first-class span attributes, not shoehorned metadata. Traces are
  joinable to incident and evaluation rows in SQL (ADR-0004). **No tenant telemetry leaves
  our boundary**, which persona P4 will ask about. Retention is ours to enforce.
- **Cons:** We build the evaluation and trace-inspection UI. Judge-calibration tooling is
  ours. Slower to a nice visualisation than a hosted product.
- **Cost to adopt:** Low for emission; moderate for the UI.

### Option B — LangSmith (rejected)

- **Pros:** Excellent LLM tracing, dataset management and evaluation UI out of the box;
  fast to value; mature judge tooling.
- **Cons:** Hosted SaaS holding **customer incident telemetry, log excerpts and runbook
  content** — a hard conversation with security review, and a data-residency question for
  regulated tenants. Would duplicate the OTel pipeline §11 requires us to build anyway.
  Its data model is LLM-call-centric, not incident-centric; our domain joins would be
  awkward. Vendor lock-in on the evaluation system of record.
- **Cost to adopt:** Low technically, high in data governance.

### Option C — Arize Phoenix (rejected for v1, kept in reserve)

- **Pros:** Self-hostable, so the data-residency objection largely disappears. OTel-native,
  which aligns with our emission layer. Strong evaluation and trace-analysis UI — genuinely
  the tooling we would otherwise build. Open source.
- **Cons:** Another service to run and secure. Its evaluation model is generic and would not
  express our domain labels (RCA class, remediation safety, verification verdict) without
  adaptation. Adds a dependency before we know how much evaluation UI we actually need.
- **Cost to adopt:** Moderate. **This is the closest alternative.**

## Rationale

The decisive factor is that **our trace is a domain artifact, not a generic LLM trace.** The
join that makes this system explicable — evidence → tool execution → action → policy
decision → approval → verification, all under one `behaviour_version` — is not something a
general LLM-observability product models. We would end up storing the domain relationships
in PostgreSQL anyway and using the vendor for a partial view of model calls, which means
maintaining two trace stores that must agree.

The second factor is data governance. Incident telemetry contains customer log excerpts and
runbook content. Sending that to a hosted third party is a genuine obstacle with persona P4
and a plausible deal-blocker in fintech and healthcare (§3 target sectors). Phoenix's
self-hostability removes this objection, which is why it is the reserve option rather than
rejected outright.

Following OTel GenAI semantic conventions costs nothing now and keeps Option C cheap later.
That is the hedge, and it is deliberate: this decision is reversible by design.

## Consequences

- **Positive:** One emission standard; traces joinable to domain data; no vendor dependency
  on the evaluation system of record; no tenant data egress; retention under our control.
- **Negative / accepted trade-offs:** We build trace-inspection and evaluation-comparison
  UI. Judge-calibration tooling is ours. This is the main risk and it is quantified in the
  revisit trigger below.
- **Security and permissions:** Strongly positive — no third party holds tenant telemetry.
- **Observability and evaluation:** The whole point; enables the one-trace-three-consumers
  property (PR-5).
- **Failure modes and recovery:** Neutral; the collector is a standard component.
- **Operational and cost impact:** Positive — no SaaS spend; PostgreSQL carries trace volume,
  addressed by time partitioning.

## Reversal cost and revisit trigger

**Reversal cost: low for adding a consumer, moderate for moving the system of record.**
Because emission is OTel-standard, Phoenix can be added as an additional exporter without
re-instrumenting.

**Adopt Phoenix (Option C) if:** building evaluation visualisation and trace analysis
exceeds roughly two weeks of effort; or judge calibration tooling becomes a project of its
own; or trace volume in PostgreSQL forces a dedicated trace store regardless.

**Reconsider LangSmith only if** the data-governance objection is resolved — which for the
target sectors is unlikely.

## Validation

| Test | Passing criterion |
|---|---|
| Trace completeness | ≥99.9% of incidents have a complete span chain |
| Replay fidelity | A stored trace + fixtures reproduces routing exactly (L2) |
| Evaluation reuse | A production incident becomes an evaluation case with no transformation |
| Redaction | No secret material in any span, log or trace |
| Volume | Trace storage and query stay within budget at target load (Phase 15) |

**None has been run.**

## References

- Master specification §9, §10, §11, §13
- [`../architecture/observability.md`](../architecture/observability.md) §9
- [`../evaluation/EVALUATION_ARCHITECTURE.md`](../evaluation/EVALUATION_ARCHITECTURE.md)
