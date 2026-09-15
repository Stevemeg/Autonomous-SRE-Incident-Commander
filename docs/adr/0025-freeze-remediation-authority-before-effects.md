# ADR-0025: Freeze remediation authority before operational effects

## Status

Accepted — Phase 6–9 audit correction

## Context

An action-version hash bound parameters and approval, but the selected service and
investigation hypothesis could be reconstructed from mutable incident alerts on resume.
Planning-time capability menus could also outlive a grant, and model-authored comparison
thresholds were treated as verification policy. Separately, API replay and unscoped RBAC
checks could be evaluated before current resource authority.

These are one architectural problem: observations and proposals were retained durably, but
some authority inputs were not frozen or revalidated at the last responsible boundary.

## Decision

Create an append-only `remediation_target` before G6. It binds the remediation workflow to
the incident, investigation run, hypothesis, service, environment and resolved permission
scope. Resume rehydrates the objective from this row, never from the current alert set. The
action references the target, and final broker authorization requires the action, resolved
broker scope and target to agree.

The model may select only a server-defined, tool-specific verification profile. G10 runs
before policy and execution to persist an independent baseline, then runs after the
settling interval to obtain fresh evidence and deterministically compare baseline and
observation. Executor output is not an input to the verdict.

Write dispatch always re-resolves the enabled tool and tenant/environment grant. API
authorization resolves current resource/environment authority before consulting an
idempotency record. Tenant-wide operations require an explicit tenant-wide grant; an
environment grant is never interpreted as tenant-wide authority.

Model providers must expose a conservative per-request token and cost bound. A call whose
bound does not fit the remaining hard budget is refused before provider invocation, and
actual usage is checked against the declared bound.

## Alternatives considered

- **Reconstruct targets from current alerts.** Rejected because alert membership is mutable
  while approval is pending.
- **Include more target fields only in the action hash.** Rejected because a first-class
  foreign-keyed target is inspectable before an action exists and survives a crash before
  G6.
- **Cache write menus for a workflow lease.** Rejected because a lease is not current
  authorization and cannot make revocation immediate.
- **Allow model thresholds inside broad numeric bounds.** Rejected because choosing an
  easy threshold is still choosing the authoritative success condition.
- **Replay before authorization to reduce database work.** Rejected because idempotency is
  effect deduplication, not authority.

## Consequences

The remediation graph adds a pre-execution G10 baseline pass and one append-only target
row. Write dispatch and protected API replay perform additional current database reads.
These costs are bounded and occur at security boundaries. Read capability menus may still
be cached within a run; they do not authorize writes.

The deterministic provider is the only model adapter today. Live adapters must provide
honest bounded estimates or refuse hard-budget calls. Cross-process reservation accounting
for future asynchronous/streaming providers remains a prerequisite of introducing such a
provider; no live provider is claimed by this decision.

## Evidence

Migration `0013_audit_corrections`; `tests/orchestration/test_remediation_security.py`;
`tests/domain/test_verification_policy.py`; `tests/domain/test_budget.py`;
`tests/api/test_auth.py`; and `tests/knowledge/test_ingestion_db.py`.
