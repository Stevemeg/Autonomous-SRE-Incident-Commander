# ADR-0029: Bounded telemetry: catalogued labels, committed-record metrics, one trace id

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Project owner (Phase 12 implementation)
- **Spec reference:** §11, §13, §15, §20
- **Supersedes / Superseded by:** refines ADR-0010 (OpenTelemetry-native observability) and corrects `docs/architecture/observability.md` §4

## Context

Phase 12 completes observability. The Architecture Package's metrics catalogue said every
instrument would be "dimensioned by `tenant_id`, `environment` and `behaviour_version`", and
`observability/metrics.py` shipped a helper building exactly those labels (never called).
Four problems had to be settled before exporting anything:

1. Tenant, incident, run and user identifiers as labels make series count grow with traffic,
   and a tenant identifier on an unauthenticated scrape endpoint discloses tenancy.
2. Several lifecycle facts (a verified remediation, an approval, a model's cost) are only facts
   once a transaction commits; counting at the call site counts work a rollback undid.
3. The OpenTelemetry spans used SDK-random trace ids and were never parented, so an exported
   trace could not be joined to its `execution_trace` row, incident or evaluation.
4. Structured logging, readiness and alerting needed a label and redaction policy that holds
   at emission, not in a collector.

## Decision

**A metric catalogue enforced by the SDK.** `asic.observability.catalogue` lists every
instrument, its unit, buckets and the only labels it may carry. `configure_telemetry` builds
one OpenTelemetry view per entry with `attribute_keys` set to that allowlist, so an
uncatalogued label is dropped by the SDK rather than exported. A final wildcard view with a
drop aggregation matches every instrument, so an instrument missing from the catalogue is not
exported at all (the SDK's default view, which keeps every attribute, applies only to
instruments no view matches). Label *values* a caller controls are closed too: the API reports
an unrecognised HTTP method as `OTHER` and an unmatched path as `unmatched`. Identifier-shaped
keys are forbidden outright. Tests assert the catalogue equals the instruments created in code, the
exposition after real workflows carries no identifier-shaped label value, and every series
and label used by a rule or dashboard is catalogued. Per-tenant questions are answered from
tenant-isolated records and traces.

**Lifecycle metrics from committed records.** `asic.observability.lifecycle` registers
SQLAlchemy session listeners that collect facts from rows as they flush, attach them to the
(sub)transaction that wrote them, merge them into the parent when a savepoint is released,
discard them on any rollback (a confirmed commit is required), and emit them only when the
outermost transaction commits. One mechanism covers kernels, API, ingestion and the harness.

**One trace id.** `TraceRecorder` parents its root spans on a remote span context carrying the
derived trace id and makes each span current while it runs, so exported spans nest, share the
`execution_trace.trace_id`, and logs and library spans inside them correlate. Evaluation
suite and scenario spans record the trace id of the run they scored; the evaluation API
returns it too.

**Exporters and endpoints.** The official OpenTelemetry Prometheus reader renders this
process's `/metrics` (off unless `ASIC_METRICS_ENABLED`), separate from the Phase 10 Prometheus
adapter that queries a tenant's Prometheus. Traces export over OTLP/HTTP only when
`ASIC_OTEL_TRACES_EXPORTER=otlp`. Logs are one redacted JSON object per line with trace
correlation; Loki streams are labelled only by service and environment. `/livez` touches
nothing external; `/readyz` requires the database to answer at the expected schema revision.

**SLOs as initial engineering targets.** Objectives, burn-rate alerts and runbooks ship as
Prometheus rules validated with `promtool` unit tests; none is presented as measured.

## Alternatives considered

- **Keep tenant labels and rely on relabelling in Prometheus.** Rejected: the identifier has
  already left the process, and a scrape configuration mistake exposes it.
- **Count at call sites.** Rejected for lifecycle facts: it reports rolled-back work.
- **Collector-side redaction.** Rejected: fails open on a new field name (observability §6).
- **SDK-generated trace ids with a link attribute only.** Rejected: operators search by trace
  id; a second id to translate is where incident investigation loses time.

## Consequences

- Positive: bounded cardinality is enforced, not conventional; dashboards and alerts cannot
  drift from the code silently; a trace, a log line, an incident and an evaluation share one id.
- Negative: metrics cannot answer per-tenant questions; that is deliberate.
- Negative: model usage is derived from spans carrying model-call metadata; deterministic
  providers report their configured token and cost figures, not vendor invoices.
- Neutral: Prometheus, Grafana, Loki, Tempo and collector deployment are Phase 14; the shipped
  configurations are validated references.

## Validation

`tests/observability/` (UNIT: catalogue, views, logging redaction, span safety, config
artifacts; LOCAL SERVICE: OTLP/HTTP export decoded from protobuf; INTEGRATION/SIMULATOR:
committed-only facts across commit, rollback and savepoints, readiness and degradation,
exposition label policy after real workflows, trace-to-incident-to-evaluation linkage), plus
`promtool check config`, `promtool test rules` and `otelcol-contrib validate` (LOCAL SERVICE).
