# ADR-0005: Multi-provider LLM abstraction — thin internal interface, not LiteLLM

- **Status:** Accepted — implemented in Phase 4 as `asic.llm.port.ModelProvider`. The only
  adapter is deterministic; no provider SDK is a dependency
  ([ADR-0016](./0016-deterministic-model-provider.md)).
- **Date:** 2026-09-04
- **Deciders:** Project owner (pending approval)
- **Spec reference:** §9, §10, §11, §13
- **Supersedes / Superseded by:** none

## Context

Section 13 requires a *"multi-provider LLM abstraction (OpenAI/Anthropic/local where
appropriate)"* and lists LiteLLM among technologies to evaluate rather than blindly add.

Our requirements are more specific than "call a model": every call must record provider,
model ID, prompt version, token counts and cost onto a span (FR-OBS-01); the model ID is
part of the `behaviour_version` tuple that gates releases (FR-EVL-09); outputs must be
schema-validated and treated as `MODEL_CLAIM` until grounded; and provider failover must be
recorded as a behaviour-affecting event (§7.1 of failure-and-recovery).

## Decision

**Implement a thin internal `ModelClient` interface over official provider SDKs.** Do not
adopt LiteLLM or a similar routing library in v1. The interface owns structured output
validation, token and cost accounting, span emission, retry classification, and failover.

## Alternatives considered

### Option A — Thin internal interface over official SDKs (chosen)

- **Pros:** Full control over the cross-cutting concerns we actually need — span
  attributes, cost accounting, behaviour versioning, schema validation, retry
  classification. No dependency on a fast-moving third party for a boundary this central.
  Official SDKs expose provider-specific features (structured outputs, prompt caching)
  without waiting for a wrapper to support them.
- **Cons:** We write and maintain the adapter per provider. Adding a provider is our work.
- **Cost to adopt:** Low — the interface is small.

### Option B — LiteLLM (rejected for v1)

- **Pros:** Many providers immediately; unified interface; built-in routing, fallback and
  budget features; less code for us.
- **Cons:** We would still wrap it to add behaviour versioning, span attributes and schema
  validation — so the abstraction count goes from one to two. Its retry and fallback
  behaviour is generic, whereas our C1–C6 retry classification is domain-specific and must
  not be overridden by a library's defaults. Version churn on a critical path. Provider
  feature lag.
- **Cost to adopt:** Low to install, moderate in indirection.

### Option C — Single provider, no abstraction (rejected)

- **Pros:** Simplest.
- **Cons:** Violates §13. Leaves no failover path for T13 (provider outage), which
  failure-and-recovery §7.1 requires. Makes model comparison in evaluation impossible.

## Rationale

The decisive factor is that **the abstraction we need is not "call any model" — it is "make
every model call an evaluable, versioned, cost-accounted, schema-validated event."** That is
domain logic. LiteLLM solves the part that is already easy (provider API differences) and
does not solve the part that is hard (behaviour versioning, span semantics, retry
classification). Adopting it would leave us writing our own wrapper anyway, over a
dependency we do not control, on the most central path in the system.

Two providers (one primary, one failover) plus optional local models satisfy §13. The
marginal value of a library that supports a hundred providers is near zero when we
deliberately use two.

## Consequences

- **Positive:** Uniform span attributes and cost accounting by construction; retry
  classification stays domain-correct; provider features available immediately; one
  abstraction layer rather than two.
- **Negative / accepted trade-offs:** Per-provider adapter maintenance; adding a third
  provider is a small task rather than a config line.
- **Security and permissions:** Positive — prompt assembly has no access to the credential
  resolver, and provider credentials stay in the secret manager.
- **Observability and evaluation:** Strongly positive — this is the reason for the decision.
- **Failure modes and recovery:** Positive — failover is ours, recorded as a behaviour event
  so evaluation knows which model produced a run.
- **Operational and cost impact:** Neutral; cost accounting is more accurate because it is
  first-class.

## Reversal cost and revisit trigger

**Reversal cost: low.** `ModelClient` could be reimplemented over LiteLLM without touching
node code.

Revisit if: we need more than three providers; local model serving requires routing we do
not want to build; or per-provider adapter maintenance becomes a recurring cost.

## Validation

| Test | Passing criterion |
|---|---|
| Failover | Primary outage triggers secondary; switch recorded on the span |
| Cost accounting | Token and cost totals reconcile against provider billing |
| Schema validation | Malformed output triggers one repair, then a typed failure |
| Behaviour versioning | Model ID change produces a new `behaviour_version` and forces re-evaluation |

**None has been run.**

## References

- Master specification §9, §10, §11, §13
- [`../architecture/observability.md`](../architecture/observability.md) §3
- [`../architecture/failure-and-recovery.md`](../architecture/failure-and-recovery.md) §7.1
