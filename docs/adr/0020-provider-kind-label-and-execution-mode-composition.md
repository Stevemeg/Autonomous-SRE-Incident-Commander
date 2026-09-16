# ADR-0020: `provider_kind` is a catalogue label; execution mode decides providers

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** Project owner (Phase 10 implementation)
- **Spec reference:** §7, §14, §20
- **Supersedes / Superseded by:** none

## Context

The Phase 6 correction reserved this number for a known defect: every read descriptor
declares `provider_kind = simulator`, and migration `0005` derives its seed rows from the
live catalogue module. Changing the label in code would change what a historical migration
does on a fresh database (ADR-0018), so the label was left stale and the broker selected
providers by `supports()`.

Phase 10 adds native adapters for tools whose seeded label says `simulator`. The question
is what, if anything, the label should decide, and what guarantees that a simulator can
never answer for a live system.

## Decision

1. **`tool_definition.provider_kind` is descriptive catalogue metadata only.** It is still
   compared for drift, and new Phase 10 rows (external records) are seeded `native`, but no
   runtime decision reads it. Historical rows are not rewritten.
2. **An explicit execution mode chooses the provider set** (`ExecutionMode`: `live`,
   `simulator`, `replay`), in `asic.integrations.composition`:
   - `live` contains only native providers and a production credential provider; a test
     credential provider, a loopback endpoint or any non-native provider is refused;
   - `simulator` contains the scenario simulator, which already refuses production;
   - local integration tests use a separately named composition that is refused in
     production and labelled `is_test_infrastructure`.
3. **The broker refuses to be constructed** with a live external-integration provider and
   any non-native provider together, so no configuration mistake can put a simulator next
   to a live adapter.
4. The broker never tries a second provider after a failure: a failing live call is a
   typed failure.

## Alternatives considered

### Option A — rewrite the label with a data migration (rejected)
Updating `provider_kind` rows to `native` would make the label truthful for a live
deployment and false for every simulator run using the same database. A single global
row cannot describe a per-deployment choice.

### Option B — two descriptors per tool, one per provider family (rejected)
Doubles the catalogue, splits grants and idempotency keys across two tool identities for
one operation, and reintroduces a selection rule the registry deliberately refuses.

### Option C — label is metadata; composition decides; broker forbids mixing (chosen)

## Consequences

- A deployment's provider set is visible in one function call and one returned object.
- The stale label stays documented rather than silently repaired.
- `traces.query` has no native adapter; in a live composition it is refused at capability
  resolution (`UnregisteredCapability`) rather than simulated.

## Validation

`tests/integrations/test_transport_and_credentials.py::TestComposition`,
`tests/integrations/test_broker_integration.py::TestNoSimulatedFallback`.
