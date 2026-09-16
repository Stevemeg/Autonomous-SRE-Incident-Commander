# ADR-0027: Loki is the log backend adapter; Elasticsearch/OpenSearch is not built

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** Project owner (Phase 10 implementation)
- **Spec reference:** §13, §14
- **Supersedes / Superseded by:** resolves Architecture Package candidate decision C1

## Context

Section 14 lists "Loki and/or Elasticsearch/OpenSearch"; section 13's baseline stack names
OpenTelemetry + Prometheus + Grafana + Loki, and lists OpenSearch/Elasticsearch among
technologies to evaluate rather than add.

## Decision

Implement one log adapter, for Loki's `query_range` API, with a typed selector (service,
environment, optional closed severity set, literal line filter). Do not implement
Elasticsearch/OpenSearch.

## Alternatives considered

- **Both** - rejected: a second adapter for the same `read.logs` capability requires a
  selection policy the registry refuses, and adds a query language (Query DSL) to bound for
  no product gain today.
- **OpenSearch only** - rejected: diverges from the baseline stack, and its query surface is
  broader to constrain than a label selector with a literal filter.

## Consequences

Tenants whose logs live in Elasticsearch/OpenSearch need a later adapter. Revisit if a
customer requirement names one; the capability contract (`logs.query`) would not change.
