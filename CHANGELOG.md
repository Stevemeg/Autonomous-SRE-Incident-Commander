# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Conventions

- Entries describe **what changed and why it matters**, not which files moved.
- Nothing is listed as delivered until it has been validated and the actual result
  reported (master specification section 20).
- No invented metrics, benchmarks or business impact appear here (sections 9 and 22).
  Measured results are labelled with how they were measured.
- Changes to AI behaviour — prompts, models, retrievers, agent policy — are versioned
  behaviour changes and must be recorded explicitly with their evaluation results
  (section 10).
- Releases are tagged once there is a runnable artifact to version. Until then, changes
  accumulate under `[Unreleased]`.

---

## [Unreleased]

### Added — Phase 14 CI/CD, Docker, Kubernetes and Terraform

- Digest-pinned multi-stage backend and Next.js standalone images run as UID/GID 10001 and contain
  only runtime dependencies/artifacts; simulator and test sources are excluded from production.
- Trivy HIGH/CRITICAL scanning is now a mandatory fail-closed security-gate input. Final-image
  CycloneDX SBOMs are checked for expected packages, and trusted GHCR releases receive GitHub OIDC
  build-provenance attestations over immutable registry digests.
- Kustomize defines the API/frontend, TLS Ingress contract, PDBs, probes, initial resources,
  tokenless service accounts, hardened pod contexts, default-deny networking and a separate one-shot
  Alembic migration Job. Local overlays add disposable PostgreSQL/pgvector only for smoke testing.
- Provider-neutral Terraform owns only the namespace and three service-account prerequisites. No
  cloud cluster or database is pretended; workload ownership remains with Kustomize.
- GitHub Actions add least-privilege PR quality, trusted release and protected manual deployment
  paths with pinned Actions/tools, timeouts, serialization, complete 18-scenario release evaluation,
  build/scan/SBOM gates and local kind deployment validation.
- ADR-0031 and the deployment guide document configuration/secrets, database-role separation,
  migration ordering, dynamic-egress limits, rollback, remote-state/backup expectations and the
  distinction between local validation and unexecuted remote production.

### Fixed — Phase 14 deployment convergence and diagnostics (closure review M-1, LOW-1, LOW-2)

- The post-rollout smoke no longer reports healthy releases as failed while the API rollout
  converges (old pods terminating, endpoints settling). Each service's checks are retried as a unit
  within a bounded 60 s convergence allowance (2 s interval, 5 s per request); anything still failing
  at the deadline fails the deployment with the last redacted error. Readiness semantics are
  unchanged. Verified on kind with repeated API-rolling redeployments and a never-ready release.
- Diagnostic redaction also covers `PGPASSWORD`/`api_key`-style assignments, JSON and YAML
  `password` values, `Authorization: Bearer|Basic|Token`, and `--password`-style flags, keeping the
  field name and leaving ordinary prose intact.
- A migration Job created by this deployment that is deleted before finishing now fails the
  deployment immediately instead of after the 10-minute deadline. A kubectl call that times out is
  reported as a deployment error rather than a traceback.

### Fixed — Phase 14 repeatable redeployment (re-review N-1, N-2)

- Redeployment no longer fails with `field is immutable` while a previous `asic-migration` Job is
  retained (TTL 3600 s). The orchestrator frees the Job name first: a `Complete`/`Failed` Job is
  recorded (a failed one with its bounded diagnostics), deleted and confirmed absent within 180 s;
  an active Job fails the deployment closed and is never deleted. The new Job is validated after the
  old one is gone, created (never adopted) and tracked by UID. Verified on kind with sequential
  same-release, changed-template, failed and fix-forward deployments, a finalizer-delayed delete and
  an active-migration collision.
- The publish job's identity binding supports OCI indexes (containerd image store) as well as single
  manifests: the index digest or its single `linux/amd64` runtime manifest's config must equal the
  scanned image ID; anything else fails closed.
- Long kubectl errors keep their first and last 1500 characters (redacted) instead of only the tail,
  so causes such as `field is immutable` remain visible.

### Changed — Phase 14 post-audit hardening (eight LOW findings)

- Release privilege split: `build-validate` (read-only token, no persisted checkout credential) builds
  once, tests, scans, SBOMs and kind-deploys, then hands checksummed image archives to
  `publish-attest`, which alone holds `packages`/`id-token` write, runs no repository code, verifies
  checksums and image IDs, and binds the registry digest to the scanned image ID.
- Deploy now verifies each attestation's repository, `release.yml` signer, `main`/`v*` source ref,
  source revision (new required `release_commit` input) and subject digest from certificate claims.
  The kubeconfig exists only inside the one deployment step (0600, removed on exit and in `always()`).
- One deployment orchestrator (`scripts/deploy_release.py`) is shared by the workflow and the kind
  smoke. It fails fast on a `Failed` migration Job with bounded, redacted diagnostics, never applies
  the application after a failed migration, and runs an automatic post-rollout smoke (API
  `/livez`/`/readyz`/401, frontend `/livez`/`/readyz`). The kind smoke proves the guard is not vacuous
  by mutating it away in an outside-repo copy.
- Frontend `/livez` (self-only) and `/readyz` (API probe with an explicit 1.5 s deadline) replace `/`
  as probe targets; an API outage no longer restarts the frontend. Data requests are bounded (10 s).
- Terraform enforces Pod Security Admission `restricted` (`v1.34`) on the namespace; privileged pods
  are rejected at admission.
- The renderer rejects CIDR sets whose collapsed union is all IPv4 or IPv6 space.

### Deferred after Phase 14

- A retention execution Job remains absent because no safe bounded deletion/receipt primitive exists.
  Production TLS, cloud identity, managed database/PITR, scale/HA/DR and remote
  deployment are not claimed. P13-SEC-05 and F-07/F-09/F-10/F-12/F-17 remain open.

### Added — Phase 13 security, RBAC, tenant isolation and supply-chain controls

Nothing here is a compliance claim. Infrastructure controls (TLS, encryption at rest, network
policy, container scanning, CI wiring) remain Phase 14 obligations. Decisions: ADR-0030.

- **Authentication.** A `TokenVerifier` abstraction. Production composes an OIDC/JWKS verifier
  (asymmetric algorithms only; `alg=none` and HS/RS confusion unrepresentable; key-type check; `kid`
  required; `jku`/`x5u`/`jwk` refused; issuer, audience, expiry, subject and tenant required; bounded,
  rotation-aware key cache; HTTPS-only fetch with timeout and size ceiling; fail closed). The HS256
  verifier is development-only and refused at startup in production. Failures are closed reason codes;
  no token content reaches an error, log or trace. Dependency: `PyJWT[crypto]`.
- **One permission vocabulary** (`asic.domain.permissions`) replacing four independent spellings,
  with scope rules and the system-role matrix, asserted equal to the migrated database. A duplicate
  spelling in the approval node was found and removed.
- **Mechanical tenancy proof** (`asic.db.tenancy_audit`): RLS, FORCE, policies, composite foreign
  keys, role privilege and grants checked against the live schema, with 19 mutation tests.
- **Migration 0018.** The application role loses `DELETE`/`TRUNCATE` (it held `DELETE` on 18 tables
  and no code deletes anything), write access to `alembic_version`, and write access to identity,
  role-assignment, tool-grant, environment and service tables. `connector_scope_binding` gains a
  composite `RESTRICT` foreign key to `integration_connector` (F-13); `execution_trace.trace_id`
  gains a W3C CHECK (F-11). Both are added `NOT VALID` and validated only when no historical row
  violates them, so existing databases upgrade and their rows are never rewritten.
- **Audit.** Denied state changes and denied tenant-wide reads are durable, attributed, tenant-bound
  `authorization.denied` records; ordinary denied reads are not (no audit flooding).
- **Edge hardening.** 128 KiB body bound including streamed bodies, JSON-only, control-character
  refusal in human text (a NUL byte used to return HTTP 500), bounded cursors, failed-auth limiter per
  peer address, limiter before database lookup, bounded limiter key space, coalesced `/readyz`,
  database connect and pool deadlines (F-15).
- **Egress.** One host policy (no link-local, metadata, unspecified, multicast or ambiguous numeric
  hosts; ASCII only) shared by connectors, JWKS and the OTLP endpoint.
- **Secrets.** `SecretValue` redacted by type; `HttpRequest`/`HttpResponse` no longer render
  credentials or bodies in `repr` (a request's `repr` printed its Authorization header); name-suffix
  and signed-URL/vendor-token backup rules (F-16). Limits documented.
- **Loki.** The stream `level` is mapped to a closed vocabulary; C1, zero-width and bidi characters
  are removed from display text (F-06).
- **Kubernetes nodes.** Node cordon/uncordon authority model made explicit and enforced: node identity
  bound into the approval hash, R2, never admitted by policy alone; misleading service-label
  documentation corrected (F-08).
- **Trace ids.** One validity rule applied at construction, in the database and at the span-context
  boundary; a malformed persisted id fails loudly and is never replaced (F-11).
- **Data retention.** Complete table classification, tenant policy schema with minimums and holds,
  and a dry-run planner. No deletion engine by design (the runtime cannot delete).
- **Supply chain.** Upper-bounded direct ranges; hash-pinned universal locks (`requirements/`);
  `scripts/check_dependency_lock.py`; prerelease allowlist (the only beta is the OpenTelemetry
  Prometheus exporter, which has no stable release); frontend lock regenerated because 26 of 34
  packages had no integrity digest (F-14); SAST via `ruff --select S` plus policy tests (with a scan
  for invisible/bidirectional characters that found one real instance); `.gitleaks.toml` with an
  allowance narrowed to one rule, file and anchored text (a line-level allowance was shown to hide an
  appended secret).
- **`scripts/security_gate.py`.** One fail-closed, machine-readable gate for Phase 14 CI. Container
  scanning is reported `not_executable` until a Phase 14 image exists.
- Package version `0.13.0`.

### Changed — Phase 13

- Inbound connector identities must now be registered in `integration_connector` (an inbound-only
  identity may be registered disabled).
- `ApiSettings` gains `auth_mode`, `oidc_jwks_url`, `oidc_algorithms`; production defaults to OIDC.
- Test fixtures that arrange identity/configuration tables run as the test login role, which is granted
  those writes; the application role is asserted not to hold them.

### Known limitations carried forward

Every approve-holder may decide through R2 (no R1/R2 approver split); a revoked signing key is trusted
until the JWKS cache expires; rate limits are per process; `memory.promotion.decide` and
`knowledge.source.access.manage` are held by no system role. Unrelated audit observations F-07, F-09,
F-10, F-12 and F-17 are unchanged.

### Fixed — Phases 10-12 audit corrections

Five defects an independent audit of Phases 10-12 reproduced - four blocking, plus an alert
that fired on a healthy system. Each entry states the invariant that failed, not only the
change.

- **An applied Kubernetes write could be recorded as a clean failure (F-01, high).** The
  executor's status transition lived in the node's own transaction, so a crash between the
  adapter's response and the node-boundary commit erased it along with the receipt; the
  resumed pass then read the deployment it had itself rolled back as *precondition drift*
  and recorded `failed_clean` with the incident sent back to investigation. Execution intent
  is now committed before dispatch, in its own transaction, and recovery classifies an
  interrupted action from durable evidence alone (`asic.remediation.dispatch_recovery`):
  no effect claim means nothing was sent; a claim without a conclusive receipt is reconciled
  by an independent read and escalated as a partial effect when it cannot be confirmed; a
  receipt replays the broker's own classification. Precondition drift is evaluated only
  after that. An applied effect is never recorded as clean, and never dispatched twice.
- **Adapter exceptions could escape the broker unclassified (F-02, medium).** A vendor body
  nested past the parser's recursion limit, or a Loki timestamp outside the representable
  range, raised `RecursionError`/`OverflowError`/`OSError` through the broker: no execution
  receipt, no audit record, a dead-lettered run - and, for an effectful call, an effect that
  may already have been applied. Those failures are now classified in the adapters, and the
  broker carries a final defensive boundary for anything unanticipated: `failed_clean` for a
  read, `unknown` for anything effectful, recording the exception type and never the vendor
  payload. Cancellation, process exit and keyboard interrupt still propagate.
- **A diverging replay could still pass (F-03, medium).** Strict replay raised on
  divergence, but the broker turns a tool failure into a degraded result, so a fixture with
  its first recording removed replayed to `passed` when the scenario's other expectations
  survived. Divergences are now counted at both replay seams and scored as a zero-tolerance
  invariant, joined by a recorded interaction signature that must match what the run
  actually consumed. A divergent replay fails the run, the suite report and the gate exit
  code.
- **Lifecycle metrics missed Core SQL transitions (F-04, medium).** Workflow-run and
  remediation-action statuses are written with Core `UPDATE` statements, which the
  unit-of-work listeners never see, so `asic_workflow_runs_finished_total` stayed empty
  while runs completed and dead-lettered - and the alerts on dead-lettered and failing runs
  could never fire. Those call sites now go through `lifecycle.core_update`, which reports
  what the statement actually changed through `RETURNING` and feeds the same
  commit-gated collection: rolled-back work and rolled-back savepoints still count nothing,
  and a transition written by both paths counts once.
- **The latency burn alert fired on an idle API (F-05).** With no traffic the recorded
  slow-request ratio evaluated to `1 - 0/1e-9 = 1`, a permanent full burn. The ratio is now
  recorded only for windows that served requests, with `promtool` cases for idle, all-fast,
  just-below-threshold, sustained-violation, recovery and absent series.

Tests added with the fixes: a crash-recovery matrix against the local Kubernetes test
service that *actually changes* when a PATCH reaches it (simulator state does not, which is
why the original tests could not see F-01), malformed and parser-breaking vendor responses
for reads and effectful writes, twelve replay mutations per scenario exercised through the
harness and the gate rather than the replay provider alone, Core/ORM lifecycle counting
across commit, rollback and savepoints, and non-vacuity controls that reintroduce each
defect when the guard is removed.

### Added — Phase 12 observability and SLO instrumentation

- A metric catalogue (`asic.observability.catalogue`) fixing every instrument's unit, buckets
  and allowed labels, enforced by OpenTelemetry views; a wildcard drop view keeps any
  uncatalogued instrument out of the exposition, and an unrecognised HTTP method is reported as
  `OTHER` so callers cannot mint label values. Tenant, incident, run, user and other
  identifiers are forbidden as labels. The unused `base_attributes` helper that would have
  labelled metrics by tenant is removed, and the design document corrected (ADR-0029).
- Lifecycle metrics counted from committed rows through session listeners: incidents opened,
  transitions and terminations, workflow runs, policy verdicts, approvals and approval wait,
  remediation action statuses, verifications, authorization denials, model tokens and cost,
  evaluation suite runs, results and judge outcomes. Rolled-back writes and savepoints are
  never counted.
- OpenTelemetry spans now use the persisted `execution_trace.trace_id`, nest, and are current
  while running; exception text is never recorded as a span event and failure descriptions are
  bounded and redacted. Evaluation suite and scenario spans and results carry the trace id they
  scored. OTLP/HTTP trace export behind `ASIC_OTEL_TRACES_EXPORTER=otlp`.
- Structured JSON logging with trace correlation and redaction at emission; lifecycle log
  events for API requests, broker refusals and executions, run completion, approvals and
  notification failures.
- API: `/livez`, `/readyz` (database at the expected schema revision), `/metrics` (off unless
  `ASIC_METRICS_ENABLED`), request metrics by route template; `python -m asic.api` entry point.
- The kernels now record `asic.node.duration`, which was declared but never emitted. The
  planner-only `asic.llm.tokens` counter is replaced by committed-record usage metrics.
- Seven Grafana dashboards, Prometheus recording and alerting rules with `promtool` unit tests,
  an OpenTelemetry Collector configuration, SLOs labelled INITIAL ENGINEERING TARGET and a
  runbook per alert. Validated with `promtool` and `otelcol-contrib validate`; not deployed.
- Dependencies: `opentelemetry-exporter-prometheus`, `opentelemetry-exporter-otlp-proto-http`,
  `prometheus-client`; PyYAML for tests. Package version `0.12.0`.

### Added — Phase 11 evaluation, replay and regression harness

- A versioned golden corpus of 18 scenarios covering 23 declared behaviours (clear,
  ambiguous, conflicting and insufficient evidence; metrics, logs, traces, deployments,
  Kubernetes and runbook-grounded investigation; prompt injection and fabricated citations;
  correlation; remediation with approval, verification success and failure, and an unsafe
  R2 refusal; authorization denial, connector revocation and duplicate execution). Each
  scenario has a digest over its definition and fixtures; changing one without a version bump
  errors the run.
- Recording and strict replay at the tool- and model-provider seams, with digest-verified
  fixtures; an incompletely consumed replay fails rather than fabricating a reproduction.
  Verified identical observation signatures across simulator and replay runs, including after
  a process restart. (Divergence itself was raised at the seam but not scored: an independent
  audit showed a replay could still pass. Corrected below.)
- Deterministic evaluators reading the durable records under RLS: zero-tolerance invariants
  (cross-tenant execution, citations resolve, no unauthorised infrastructure mutation,
  external records only from S2, budgets, trusted verification lineage) plus per-scenario
  expectations, failure classification and per-run metrics that are `None` when not
  applicable.
- LLM judges through the model-provider port with strict output validation; panel status
  `not_measured` / `insufficient` / `agreed` / `contested`; results recorded `uncalibrated`
  and never able to fail or pass the gate.
- Baseline comparison per scenario and metric, and `python -m asic.evaluation.gate` with exit
  codes `0` passed, `1` failed, `2` errored and a sealed JSON report.
- Migration `0017_evaluation_harness`: suite runs, judge results and replay fixtures;
  evaluation results append-only for the application role; downgrade refused once history
  exists. `node_id` gains `e1_evaluation_judge` (left in place on downgrade).
- Read-only evaluation result routes replace the Phase 9 `501 deferred` placeholder.
- `RemediationKernel.start` accepts optional fixture references so a remediation trace can be
  bound to the evaluation that produced it.
- Results (SIMULATED / REPLAY, scripted model, local PostgreSQL, 2026-09-17): golden suite 18
  of 18 passed in simulator and in replay mode, 0 unsafe actions, 0 false-success verdicts;
  judges not measured. These validate the pipeline and safety invariants, not reasoning
  quality.
- Package version `0.11.0` (`asic.__version__` had not been advanced past `0.5.0`; it now
  matches the package).

### Added — Phase 10 external integrations

- Native, typed adapters behind the tool broker for Prometheus (reviewed PromQL templates,
  bounded range/points, non-finite samples dropped and counted), Loki (typed selector,
  literal line filter, bounded single-line data), Kubernetes (workload/deployment reads and
  the four approved remediation writes with optimistic concurrency and service-label scope
  checks), Slack, Microsoft Teams, PagerDuty Events v2, Jira Cloud and Grafana annotations.
  No vendor SDK; standard-library HTTP with explicit connect/send/receive failure phases.
- Tenant connector authority: `integration_connector` plus the existing
  `connector_scope_binding`, resolved on every call before idempotent replay; both are
  read-only to the application role.
- Credential references resolved at the execution boundary into a non-renderable
  `SecretValue`; production resolution fails closed; test credentials refused in production.
- `tool_effect_class` (`read`, `infrastructure_mutation`, `external_record`) with a trigger
  deriving each execution's class from its definition; external records only from the S2
  notification service, never under a remediation action, never retried.
- Normalised integration failure classes, connector id and external reference on every
  execution; outbound W3C `traceparent` from the durable trace identity.
- S2 notification service with deterministic event ids; delivery failure never fails an
  investigation.
- Explicit execution-mode composition; a broker refuses live and simulated providers
  together (ADR-0020). ADR-0026, ADR-0027. Migration `0016_external_integrations`.
- Versioned verification profile v2 approving the native Prometheus source; actions are
  judged by the exact profile version frozen on them.

Validated against local deterministic HTTP servers and PostgreSQL under the unprivileged
role. **No live vendor integration has been exercised.**

### Fixed — final Phase-10 gate corrections

- Require complete G10 remediation lineage before a T5 verified-outcome proposal or human
  promotion: immutable target/action, append-only baseline, successful baseline and
  post-action broker reads, deterministic profile/criteria, scope, time and observed values
  must agree. Legacy non-empty JSON and forged `verified` rows now fail closed.
- Narrow model-reservation updates to settlement columns and enforce the one-way
  `reserved -> completed` transition in PostgreSQL. Completed usage, identity and replay
  responses are immutable to the application role, including under concurrent settlement.
- Added migration `0015_verified_memory_ledger` and database-backed adversarial tests. No
  Phase 10 connector or live-provider functionality is introduced.

### Fixed — final pre-Phase-10 safety corrections

- Bound each pre-write verification baseline to the immutable target, action, versioned
  server profile, approved read source and real broker execution; stale or mismatched
  evidence now fails closed before dispatch or yields an inconclusive verdict.
- Added durable per-attempt model reservations so malformed output, failed repairs and
  interrupted calls cannot erase consumed or potentially consumed token/cost allowance.
- Added a tenant-isolated connector/service/environment catalogue binding and enforce it
  before constructing trusted ingestion context.
- Moved pending-approval environment authorization into SQL before cursor limiting, and
  made duplicate safety-invariant identifiers a documentation-validation failure.
- Added migration `0014_pre_phase10_safety`. External connectors and live model providers
  remain deferred; this milestone establishes only the boundaries they will consume.

### Fixed — Phase 6–9 architecture and security audit corrections

- Froze remediation incident, investigation, hypothesis, service, environment and permission
  scope in an append-only target before planning; resume and dispatch now reject target drift.
- Re-resolve write grants/tool enablement at dispatch and bind actions to current policy,
  approval and exact target scope.
- Replaced model-authored verification thresholds with typed server profiles and a durable
  independent pre-action baseline plus fresh post-action comparison.
- Added pre-call token/cost bounds for every model path, explicit environment versus
  tenant-wide RBAC, and authorization-before-idempotency replay.
- Separated knowledge lifecycle attribution from current lifecycle authority, including
  audited denials and immediate role revocation.
- Added cursor caps and batched action reads, moved synchronous ingestion off the async event
  loop, implemented incident annotation and administration policy/tenant reads, and removed
  the dashboard's fabricated healthy-policy status.
- Added migration `0013_audit_corrections`, ADR-0025 and adversarial/non-vacuity coverage for
  the corrected boundaries. No production adapter, live model or distributed limiter is
  introduced or claimed.

### Added — Phase 9 API and incident-command dashboard

- Added independently authorized, tenant-scoped FastAPI surfaces for incidents, approvals,
  ingestion boundary, evaluation boundary and administration.
- Added JWT identity validation with current database-backed role/environment grants, typed
  errors, correlation IDs, bounded rate limiting and durable mutation idempotency records.
- Added the Next.js server-rendered dashboard for incident evidence, hypotheses, timeline,
  remediation actions and approval context. External integrations and evaluation/replay
  execution remain deferred.
- Added migration `0012_phase9_api_rbac` and API tenancy/authorization/replay tests.

### Added — Phase 8 bounded remediation

- Added a separate five-node remediation graph: model proposal, deterministic policy gate,
  durable human approval, typed execution and independent verification.
- Added four simulator-backed Kubernetes actions at R1/R2, while preserving investigation's
  read-only registry and keeping destructive R3 actions unregistrable.
- Bound approvals to the exact action version and current tenant/environment/risk-scoped
  human authority, rechecked immediately before dispatch.
- Added effect-level idempotency with a durable pre-dispatch claim, fresh-state
  preconditions, unknown-outcome reconciliation and fail-closed empty verification evidence.
- Added checkpoint/resume support that rehydrates durable rows, retains consumed budgets and
  never asks the model to replace an already selected action.
- Added migration `0011_remediation_safety`, ADR-0023, architecture documentation and
  adversarial policy, approval, crash-window, tenancy and verification tests.

### Added — Phase 7 investigation agents, evidence reasoning and bounded reflection

- Added bounded reflection: the hypothesis engine's structured output gains an optional
  `reflection` proposal (`continue_with_gap`, `collect_counter_evidence`,
  `revise_hypothesis`, `terminate_success`, `terminate_uncertain`, `escalate` —
  `ReflectionAction`, a closed vocabulary), validated by a new deterministic guard chain
  (`asic.orchestration.reflection.decide_reflection`) on the same "the model's choice is a
  proposal" principle already used for the planner. No new graph node, no new model call,
  no schema migration — see [ADR-0022](docs/adr/0022-bounded-reflection-without-a-new-node.md).
- Added hypothesis revision: `revise_hypothesis` supersedes a named hypothesis
  (`status=superseded`, `superseded_by_id` set) rather than leaving a stale conclusion
  standing beside a contradicting new one, reusing schema Phase 4 already carried.
  `asic.orchestration.termination.best_hypothesis_of` now deduplicates hypothesis
  references by id, keeping the latest status, so a superseded hypothesis cannot still be
  selected as the run's best answer from stale graph state.
- Extended `asic.orchestration.termination`: `TerminationInputs.reflection_action` and
  `wants_to_stop` let a reflection-driven terminal proposal (`terminate_success`/
  `terminate_uncertain`/`escalate`) feed the same R4/R5 rules the planner's own
  `TERMINATE` action already used, so a run still ends in exactly one of the five
  existing termination categories — never a sixth. `is_actionable()` is now a standalone,
  shared function so both proposal sources are held to the identical actionability bar.
- Added a `"RANK:<n>"`/`"LATEST"` sentinel for `target_hypothesis_id`, mirroring the
  existing evidence-citation sentinels, so a deterministic scenario script can name a
  hypothesis before its generated id exists.
- Added `EvidenceFailureCategory` (`NO_EVIDENCE_FOUND`, `EVIDENCE_COLLECTION_FAILED`,
  `EVIDENCE_UNAUTHORIZED`, `INVESTIGATION_TIMEOUT`, `MODEL_FAILURE`, `TOOL_FAILURE`,
  `UNCERTAIN`) as an additive classification on `NodeFailureRef.category`, alongside the
  existing free-form `error_type` rather than replacing it.
- Added scenario `SC-0012-counter-evidence-revises-hypothesis`: reflection asks for
  counter-evidence rather than accepting a plausible first hypothesis, the counter-evidence
  changes the conclusion, and the original hypothesis is superseded — run end to end
  through the real kernel in `tests/e2e/test_scenarios.py`.
- Added two bounded-cardinality metrics: `asic.reflection.decisions` (by action and guard
  rule id) and `asic.hypothesis.revisions`.
- Security: a `revise_hypothesis`/`collect_counter_evidence` proposal naming a hypothesis
  this run never persisted — a fabricated id, an evidence id, or an id from another run —
  is rejected before any database write, driven through the real kernel and a real
  PostgreSQL database (`tests/orchestration/test_hypothesis.py::TestBoundedReflection::
  test_a_fabricated_reflection_target_is_rejected_through_the_real_kernel`). Hostile free
  text in a reflection proposal's `rationale`/`gap` fields is confirmed inert — there is no
  mechanism by which it could grant a capability, bypass approval, or cross a tenant
  boundary, because nothing parses those fields as anything but data.
- Mutation-tested: disabling the actionability guard in `reflection.py` is shown to let an
  unsupported `terminate_success` claim through, confirming the guard — not something else
  — is what stops it (`tests/orchestration/test_reflection.py`).
- No remediation planner, executor, approval workflow, production write capability, or
  later-phase functionality was added. No live model provider was wired (ADR-0016
  unchanged); no RCA-accuracy, calibration, or redundant-call-rate figure is claimed —
  those require Phase 11's evaluation harness and a real provider, neither of which exists.

### Added — Phase 6 operational knowledge, RAG and governed memory

- Added versioned, idempotent knowledge ingestion (`KnowledgeSource`/`KnowledgeDocument`/
  `KnowledgeChunk`): deterministic canonicalization and structure-aware chunking, a
  swappable embedding provider with a deterministic test implementation, and a
  supersede-then-insert commit sequence serialized per source under a PostgreSQL advisory
  lock so concurrent imports of the same document never race. A routine re-import cannot
  change a source's access policy — that requires a separate, audited operation.
- Added authorization-first hybrid retrieval (`KnowledgeRetriever`): one SQL statement
  classifies every chunk's disposition — unauthorized, inactive source, revoked, not yet
  effective, superseded, stale, or embedding-model mismatch — before lexical and vector
  search ever run, so out-of-scope content cannot influence ranking. Reciprocal rank
  fusion is versioned as part of the retrieval policy; reranking is not implemented.
- Added stable, forgery-resistant citations (`knowledge:<retrieval_id>/<chunk_id>@
  <version_id>`), resolvable only against the append-only retrieval-result table that
  produced them, and exact replay of historical retrievals that reproduces what was
  actually seen at the time, withholding content whose access has since been withdrawn.
- Registered `knowledge.search` as the first native (non-simulator) Tool Broker provider
  (`KnowledgeStoreProvider`), so retrieved knowledge reaches an investigation through the
  same broker as every other capability, with no second egress path.
- Added governed memory writes (`MemoryGovernanceService`): a deterministic policy decides
  what may become a proposal — `working_state`/`incident_history`/`model_inference` are
  refused outright; `verified_outcome` requires an actual `VERIFIED` verification record;
  `operational_knowledge` requires a closed incident. A human who is not the proposer, and
  who holds `memory.promotion.decide`, must approve before anything durable is written; the
  database itself refuses a `memory_entry` lacking a promotion or carrying SYSTEM/HUMAN
  provenance, independent of the application code.
- Added structural (not merely prompt-based) resistance to memory poisoning and prompt
  injection: retrieved content reaches a model only as a fenced `RETRIEVED`-provenance
  block whose fence markers neutralise any forged marker text found inside the content
  first, and a provider's retrieval manifest is re-verified against the database — tenant,
  correlation id, idempotency key, and every result's chunk/version/source/content-hash —
  before anything is recorded. Verified against the real broker, the real provider, real
  manifest verification and the real hypothesis prompt template with a document containing
  a fake SYSTEM header, an instruction-override payload, a forged citation and forged fence
  markers (`tests/security/test_knowledge_prompt_injection.py`).
- Added a ten-document, fifteen-query retrieval evaluation corpus
  (`tests/knowledge/test_retrieval_evaluation.py`) covering exact-lexical, semantic-
  paraphrase, ambiguous, wrong-service, no-result, unauthorized, stale, revoked and
  competing-version cases. Measured on this corpus: recall@5 = 1.000, precision@5 = 0.867,
  MRR = 1.000 over nine gradeable queries; unauthorized-rate and stale-rate both zero.
  Architecture validation on a small, deliberately separable corpus — not a production
  benchmark, and not a claim about any other corpus or embedding model.
- Added migration `0008_knowledge_memory`: five new tables, RLS and append-only grants
  identical in shape to every other tenant-scoped table, `NOT VALID` check constraints
  retrofitting governance onto the pre-existing `knowledge_document`/`knowledge_chunk`/
  `memory_entry`/`memory_promotion` tables without breaking rows written before this phase,
  and a literal `UPDATABLE_COLUMNS` grant restricting the application role to lifecycle
  columns only on tables it may no longer freely rewrite.
- Deferred, and recorded as deferred rather than silently absent: a reranker (no measured
  evidence justifies one — ADR-0008), the `G12_MEMORY_CURATOR` orchestration node and any
  automatic promotion trigger (`MemoryGovernanceService.propose()`/`decide()` exist for a
  future caller), and connector-specific ingestion fetch (git/wiki/ticketing) — only the
  ingest-a-document API is implemented this phase.

### Fixed — Phase 5 independent-review corrections

- Kept persisted source titles, labels, annotations, correlation identifiers and metadata in
  bounded untrusted prompt blocks; orchestration objectives now use only generated intent and
  catalogue-resolved structural identity.
- Applied every relevance predicate before the production 256-candidate bound, made overflow a
  durable retryable outcome, and changed ambiguity to a versioned nearest-anchor/UUID tie-break.
- Added explicit timestamp range and future-skew policies, catalogue-retry semantics, severity
  tie ordering, fail-closed occurrence lookup, terminal reopen candidates and terminal dispatch.
- Namespaced advisory locks, measured lock waits separately, and changed non-key incident writers
  to `FOR NO KEY UPDATE` so Phase 4 FK inserts do not block unrelated ingestion.
- Added forward migration `0007_phase5_hardening` and expanded unprivileged PostgreSQL tests for
  production-sized bounds, real contention, terminal lifecycle behavior and real prompt rendering.

### Added — Phase 5 telemetry ingestion and incident correlation

- Added bounded canonical signal envelopes, simulator and Alertmanager-format fixture normalizers,
  provenance-safe unknown metadata handling, timestamp/schema/structure validation and typed
  rejection reasons.
- Added append-only signal receipts and durable investigation dispatch requests with tenant RLS,
  composite foreign keys, delivery/occurrence idempotency, source-state ordering and rollback-safe
  transaction boundaries.
- Added deterministic correlation with persisted positive/negative
  factors, ambiguity explanations, change-signal temporal association without causation claims,
  severity escalation and source-resolution semantics.
- Added explicit dispatcher integration to the accepted Phase 4 read-only kernel and atomic initial
  checkpoint linkage, including lease-aware duplicate-worker recovery.
- Added migration `0006_telemetry_ingestion`, Phase 5 architecture documentation, ADR-0019,
  security/authorship audit guidance, boundary validation and database-backed scenario coverage.

### Fixed

- **Migration history is a contract again.** Migration `0003` derived its table list from
  the live model registry, so adding one tenant-scoped table in Phase 4 silently changed
  what a Phase 3 migration would do — and a fresh `alembic upgrade head` began failing on a
  table `0002` had never created. The lists are now literal, and three things make that
  safe rather than merely convenient:

  - the pinned lists were **proved identical** to what the original derivation produced,
    by extracting the models from the Phase 3 commit and comparing the sets — 30
    tenant-scoped and 9 append-only tables, symmetric difference empty in both cases, and
    re-checked on every test run;
  - restoring the original was **demonstrated non-viable**: run against an empty database
    with today's models it fails with `relation "workflow_checkpoint" does not exist`, and
    no corrective migration can help because `0003` fails before one would be reached;
  - the upgrade path that matters is now tested against a real throwaway database — a
    database at the pre-Phase-4 head reaching current head, alongside clean-to-head, a full
    round trip, and drift detection.

  A guard test parses every migration's AST and fails the build if one reads
  `tenant_scoped_tables()` or `append_only_tables()` again. Recorded as
  [ADR-0018](docs/adr/0018-migrations-are-historical-contracts.md), which also documents the
  evidence that no persistent database consumed the original.

- **The wall-clock budget is now enforced, not merely declared.** `elapsed_seconds` was
  never charged, so `BudgetKind.WALL_CLOCK` always read zero and the timeout rule could
  never fire: a run could exceed its deadline indefinitely provided it stayed under the
  iteration count. Elapsed time is now *observed* — measured as now minus the run's start,
  rather than summed from node durations, so it counts the gaps between nodes and the time a
  suspended run spent waiting. It is read at every node boundary and at every node entry,
  and a resumed run continues from `execution_trace.started_at` so an interruption cannot
  hand it a fresh allowance.

- **Database work now has a server-enforced bound.** Every unit of work sets
  `statement_timeout` and `idle_in_transaction_session_timeout`, transaction-locally so they
  cannot leak onto a pooled connection. This is the only timeout in the system that a
  *server* enforces: PostgreSQL cancels the statement whether or not anything in the process
  is watching. The statement bound sits at or below the shortest node timeout and the idle
  bound above the longest, both asserted by tests rather than by arithmetic in a comment.

### Changed

- **Timeout claims now match behaviour.** `docs/architecture/orchestration-kernel.md` §11
  states, per layer, whether a timeout is enforced and by what. Four are enforced — database
  statement and idle-in-transaction by PostgreSQL, tool invocation by the broker's deadline,
  and the investigation wall clock at step boundaries. **Node execution is declared and not
  preemptible**, and the reason is recorded rather than glossed: a node holds an open
  transaction on a psycopg2 connection, and abandoning its thread would leave that thread
  writing through a connection the kernel is rolling back, corrupting the checkpoint that
  makes the run recoverable. Proper enforcement needs an async execution model or a per-node
  connection closable out of band; it is a **Phase 15 obligation**, and a test asserts the
  kernel does not preempt so the claim cannot drift from the code.

- The broker's adapter deadline is now proved against an adapter that genuinely never
  returns, rather than one that raises a timeout error. The previous test exercised the
  error path; this one exercises the execution boundary.

- Migration `0005`'s downgrade documents that it fails by design once any tool has run:
  `ON DELETE RESTRICT` protects execution history from losing the catalogue row that
  explains it. Referential integrity was not weakened to make the downgrade succeed.

### Added

- **Phase 4 — orchestration kernel: agent state machine, planner, tool registry and
  broker.** A bounded, read-only, simulator-backed incident investigation now runs end to
  end. **No remediation, external integration, API or frontend exists**, and no capability
  above risk tier `RO` is registered — three independent layers prevent one appearing
  ([ADR-0017](docs/adr/0017-read-only-capability-ceiling.md)).

  - **Typed graph state and enforced node contracts** (`src/asic/contracts/`). Five graph
    nodes, each declaring the twelve attributes specification section 4 requires. Three of
    them are *enforced*, not merely published: the kernel rejects any state key a node's
    contract does not list, the broker refuses any capability the calling node does not
    declare, and contract tests fail the build if a node stops emitting its audit events.
    The state carries references and scalars only — there is no `messages` key and no field
    able to hold a prompt, a payload or a credential.

  - **Tool registry, capability resolution and broker** (`src/asic/tools/`). The broker is
    the single controlled boundary: every request passes request validation, tenant
    context, capability resolution, the risk boundary, argument validation, idempotency,
    adapter invocation with a deadline, result validation, audit and trace. It fails closed
    at every stage. Scope arguments — tenant, environment, service, namespace — are
    *resolved from the incident and rejected if supplied*, so a caller cannot widen its own
    reach. Seven read-only capabilities are registered; every write tier named in the
    architecture is deliberately absent.

  - **Deterministic simulators** (`src/asic/simulators/`), explicit test infrastructure
    sitting at the adapter boundary behind the broker rather than inside a node — so the
    pipeline a simulated call takes is the pipeline a real one will take. Eleven scenarios
    cover supporting evidence, contradicted evidence, insufficient evidence, an adapter
    error, a timeout, a transient error that clears on retry, a malformed tool result,
    malformed model output, budget exhaustion, hostile injected content and a multi-service
    incident. **No scenario hard-codes a successful root-cause analysis.**

  - **Bounded autonomy.** Iterations, tool calls, wall clock, tokens and cost are checked
    *before* each step, so exhaustion produces a clean partial result rather than paying for
    the step that broke the limit. A refusal is recorded explicitly, because the ledger
    cannot express a cost that was never paid. Four deterministic guards can override the
    planner: unparseable output gets one repair then a typed failure; an ungranted domain is
    rejected and never repaired; a redundant collection is converted; and the budget
    terminates the run regardless of what the model asked for.

  - **Deterministic termination.** An ordered, total rule set — every run leaves with
    exactly one verdict naming the rule that produced it. `RESOLVED` is unreachable, and
    correctly so: a deployment that cannot remediate cannot verify a fix, so an actionable
    cause is escalated to a human rather than reported as resolved.

  - **Fact distinguished from claim, in code.** Provenance is assigned by the broker, so a
    node cannot label its own output a verified fact. Every evidence id a hypothesis cites
    is checked against the persisted set and the whole hypothesis is dropped if any is
    fabricated. A deterministic confidence ceiling derived from support count, contradiction
    and evidence quality caps whatever the model claimed, with both numbers and the
    derivation stored so calibration is measurable later.

  - **Durability** (`src/asic/orchestration/`, migration `0004`). One transaction per node,
    with the checkpoint written alongside the work it describes, so a checkpoint can never
    describe rolled-back work. Resume rebuilds state from durable rows and takes only the
    ephemeral remainder from the checkpoint; where they disagree, the rows win and the
    divergence is recorded. A conditional-update lease prevents two orchestrators advancing
    one incident. The guarantee is stated exactly as **at-least-once node execution with
    effect-level idempotency** — not exactly-once, which the design does not support.

  - **Observability** (`src/asic/observability/`). Every span is emitted twice from one
    description: an OpenTelemetry span for live tooling and a durable `trace_span` row for
    operators and, later, the evaluation harness. Span ids are derived rather than random so
    a replay reproduces them. Spans carry node and version, budget headroom at entry, the
    decision *and the alternatives weighed*, provider, model, prompt version and hash,
    tokens, cost and termination reason — and no prompt text, payloads or credentials,
    because redaction happens at emission. No exporter is configured; that is Phase 12.

  - **Model boundary** (`src/asic/llm/`). The thin internal port ADR-0005 chose, returning
    text rather than parsed objects so that validation happens in the node where it can be
    tested. The only adapter is deterministic; no provider SDK is a dependency
    ([ADR-0016](docs/adr/0016-deterministic-model-provider.md)).

  - **Adversarial tests.** Hostile content in a log line and in a runbook asks for a
    capability, a tenant switch and an approval bypass. All three are inert: the capability
    menu was resolved before the content existed, tenant context comes from the bound
    session, and there is no approval path to bypass. An import-graph test parses every node
    module and fails if one reaches past the broker to a provider.

  - **Persistence and migrations.** One new table, `workflow_checkpoint` — tenant-scoped,
    RLS-forced, append-only — created and protected in the same migration. Migration `0005`
    seeds the read-only catalogue from the code descriptors, and the registry refuses to run
    if the two ever diverge. Migration `0003`'s table lists were pinned to the schema as it
    stood when it was authored: deriving them from the live models meant a later phase
    silently changed what an old migration did.

  - **Validation.** `scripts/validate_docs.py` now enforces the Phase 4 boundary — forbidden
    packages, imports, file types, arbitrary-execution shapes anywhere in `src/`, and a
    catalogue that must import clean and be entirely read-only. Negative-tested by planting
    an `api/` package importing `fastapi` and `subprocess`, a `temporalio` import, a `.tsx`
    file and a write capability; all eight violations were caught. The secret scanner gained
    a per-line pragma so the redaction fixtures are exempted visibly rather than through a
    path allowlist that would grow quietly.

  - **Dependencies.** `langgraph` (ADR-0002) and `opentelemetry-api`/`-sdk` (ADR-0010). No
    model provider SDK, no HTTP framework, no infrastructure client.

  - **Validated:** 468 tests pass (266 needing no database) after the Phase 4
    corrections; `ruff`, `ruff format --check` and `mypy --strict` clean across 60
    source files; migrations round-trip to base and back
    with no orphan enum types and no schema drift; specification transcription, repository
    hygiene and documentation validation all clean. **No performance was measured and no
    claim is made about the quality of the system's reasoning** — the harness that could
    measure it is Phase 11.

- **Phase 3 — domain model, PostgreSQL schema, multi-tenancy and event model.** The first
  phase containing implementation. **No agent, orchestration, remediation executor,
  external integration, API or frontend exists**, and `scripts/validate_docs.py` now fails
  the build if any appears.

  - **Domain layer** (`src/asic/domain/`), pure and database-free: 38 closed vocabularies;
    the incident state machine with 31 explicitly permitted transitions, each naming which
    actor kinds may cause it; the event envelope contract and timeline projection rules;
    seven idempotency key derivations; and structural safety guards.

  - **Incident state machine.** Only listed transitions are permitted. An agent node cannot
    approve into `REMEDIATING` — that edge is human-only. Every transition into a terminal
    state must record a termination reason, and a human reopening a resolved incident must
    justify it in writing. `FAILED` is irreversible. No state can strand an incident: the
    suite asserts every state reaches closure.

  - **Persistence** (`src/asic/db/`): 36 tables — 30 tenant-scoped, 6 deliberately global —
    with composite tenant foreign keys, 9 append-only tables, and check constraints
    carrying the safety invariants into the database. A destructive (R3) tool cannot be
    registered; a write tool without a rollback cannot exist; a non-idempotent write tool
    cannot declare a retry policy; an action cannot be self-approved; a terminal incident
    cannot exist without recording when and why.

  - **Tenant isolation** (`migrations/versions/*_0003_tenant_isolation_rls.py`): a separate
    unprivileged application role, a transaction-local tenant setting, and
    `ENABLE` + `FORCE ROW LEVEL SECURITY` with `USING` and `WITH CHECK` policies on all 30
    tenant-scoped tables. With no tenant bound the policy denies rather than defaults —
    forgetting to bind produces an empty result set, never a cross-tenant read.

  - **Event log**: append-only, gapless per-incident sequencing under a row lock, idempotent
    append, and a database constraint preventing an external event from being stored with
    authority-bearing provenance. `incident.status` and `timeline_event` are derived, and
    reconciliation functions let the derivation be *checked* rather than trusted.

  - **Three ADRs raised, decided and verified during implementation**: native PostgreSQL
    enum types (0012), composite tenant foreign keys (0013), and materialised incident
    status with reconciliation (0014). These are the project's first `Accepted` ADRs,
    because each names the passing tests that confirm it.

  - `docs/architecture/tenancy-and-rls.md` — how tenant isolation survives an application
    bug, including the superuser trap that made the first draft of the isolation tests pass
    while proving nothing.

  - Project tooling: `pyproject.toml`, Alembic infrastructure, ruff and mypy (strict)
    configuration, and a pytest suite that skips database tests cleanly when no database
    is configured.

### Fixed

- **Migration downgrade left orphan enum types.** Alembic's autogenerated `downgrade` drops
  tables but not the native `ENUM` types they depended on, so `downgrade` followed by
  `upgrade` failed with `type "risk_tier" already exists`. The schema migration now derives
  the type list from the models and drops each one, and `TestEnumTypeParity` keeps the
  database and the models in step. Round-trip verified.

### Changed

- `scripts/validate_docs.py` replaced its "no implementation code" check with a **phase
  boundary** check: it now fails if code for an unapproved phase appears — agent packages,
  API surfaces, integration adapters, frontend files, or an import of LangGraph, FastAPI,
  a model provider SDK or a Kubernetes client.
- Two entities renamed for consistency with the Phase 3 brief, with the reconciliation
  recorded in `docs/architecture/data-model-and-api.md` rather than applied silently:
  `tool_descriptor` → `tool_definition`, and `verified_outcome` → `memory_entry`
  (discriminated by `kind`).
- README, documentation index, ADR index and requirements traceability updated to
  distinguish what is now built from what is still designed.

### Notes

- **181 tests pass.** 117 of them require no database; 62 need PostgreSQL with `pgvector`
  and skip cleanly without it. `ruff` and `mypy --strict` are clean across 22 source files.
- **No performance has been measured.** Every numeric target in the documentation remains a
  budget to be validated in Phase 15.
- Concurrency under a shared connection pool is **not** yet tested; the isolation tests use
  one connection per test. Recorded as a Phase 15 obligation in
  `docs/architecture/tenancy-and-rls.md` §9.

### Added — earlier phases

- **Phase 1 and Phase 2 — product requirements and the Project Initiation & Architecture
  Package** (master specification section 23, sections A-Q). Documentation only; **no
  product code, no migrations, no agents, no APIs.** Every decision is *proposed* and
  awaiting approval.

  - **Product layer.** PRD with executive definition, buyer/user separation and a
    competitive analysis that cites no competitor performance figures. SRS with 138
    requirement identifiers, each classified `[SPEC]`, `[DERIVED]` or `[ASSUMED]` so that
    our judgement is distinguishable from the specification's requirements. Six personas
    and six journeys, including correct termination in uncertainty and a blocked unsafe
    action.

  - **Agent topology.** The nineteen candidate responsibilities of section 4 evaluated
    individually against a stated two-discriminator test and consolidated into twelve graph
    nodes plus two derived services. Six telemetry and knowledge responsibilities become
    strategies of one Evidence Collector node; six control responsibilities become
    deterministic non-LLM components, because implementing a policy gate, an approval
    record or a command executor as a language model would violate sections 6 and 15.
    No section 4 responsibility was dropped, and this is verified mechanically.

  - **Safety architecture.** Twelve safety invariants, each enforced by a type, a
    credential or a deterministic code path rather than by a prompt instruction, and each
    with a named adversarial test. Four risk tiers, in which destructive actions are not
    approval-gated but *not expressible*. Of the twelve action fields section 6 requires,
    the model authors four; the remainder are resolved from the registry and incident
    context.

  - **Evaluation and observability.** One trace schema serving operations, replay and
    evaluation, so a production incident becomes an evaluation case without transformation.
    Twelve golden scenario archetypes, twelve adversarial scenarios, thirteen deterministic
    checks that judges cannot overrule, and multi-judge scoring in which disagreement is
    flagged rather than averaged away.

  - **Security.** Ten invariants required from the first executable slice, eighteen
    enumerated threats with residual risk stated, and explicit modelling of six untrusted
    input classes including model output. Security is designed in Phase 2 rather than
    Phase 13 because tenancy, the authorization chokepoint and provenance typing are not
    retrofittable.

  - **Data model and API.** Twenty-six conceptual entities, seventeen invariants and five
    separately-authorised API surfaces. **No migrations and no DDL** — physical schema is
    Phase 3.

  - **Eleven Architecture Decision Records**, each with genuinely considered alternatives,
    a reversal cost and an observable revisit trigger. All eight technologies section 13
    flags as "evaluate rather than blindly add" have been evaluated. Statuses are
    `Proposed`, `Needs validation` or `Deferred`; **none is Accepted**, because section 9
    forbids reporting unmeasured results as fact and several decisions rest on measurements
    not yet taken.

  - **Requirements traceability matrix** mapping all 138 requirement identifiers to
    architecture component, implementation phase, validation strategy and acceptance
    criterion. No requirement is claimed as implemented.

  - **Twenty-one Mermaid diagrams**: C4 context, container and two component views, agent
    topology, incident lifecycle, remediation approval flow, evaluation loop, retrieval
    pipeline, memory tiers, phase dependencies and the entity-relationship model.

  - `scripts/validate_docs.py` — validates internal links, Mermaid structure, requirement
    traceability in both directions, section 4 responsibility coverage, absence of
    implementation code and absence of invented improvement percentages. Standard library
    only. Verified against deliberately introduced defects, not only against a passing
    repository.

- **Phase 0 — repository bootstrap.**
  - Git repository initialised on `main` and connected to the canonical GitHub remote.
  - Master specification V3 preserved unmodified under `docs/spec/` and transcribed to
    Markdown at `docs/spec/MASTER_PROJECT_PROMPT_V3.md` for diffable review.
  - `scripts/verify_spec_transcription.py` — verifies the transcription against the
    `.docx` in both directions (nothing dropped, nothing invented) and checks section
    ordering. Standard library only.
  - `scripts/check_repo_hygiene.py` — scans tracked and untracked files for
    secret-shaped content, forbidden paths and generated artifacts. Standard library only.
  - `docs/security/REPOSITORY_SECURITY_CHECKLIST.md` — the pre-commit and pre-push
    procedure required by master specification section 20, active from Phase 0.
  - `docs/adr/` — ADR process, template, and an index of the 15 candidate technology
    decisions Phase 2 is obliged to make. No decisions recorded yet.
  - Documentation skeletons for the PRD, SRS, personas and journeys, architecture
    overview, C4 diagrams, agent topology, tool registry, memory and RAG, observability,
    data model and API, failure and recovery, CI/CD and infrastructure, evaluation
    harness, and threat model. All are empty by design.
  - `.gitignore` covering secrets, Python, Node/Next.js, IDE and OS files, test and
    coverage artifacts, build output, Docker, Kubernetes and Terraform local state.
  - `README.md` stating the product intent and the current design-phase status.

### Changed — earlier phases

- README and documentation index updated to reflect Phase 2 completion, the eight
  technology recommendations, and the revised roadmap. Repository security checklist now
  requires `validate_docs.py` before any commit touching `docs/`.

### Notes — earlier phases

- **No product code exists.** `src/`, `tests/` and `configs/` are intentionally empty.
- The architecture is **proposed, not accepted.** No ADR has status `Accepted`, and no
  technology has been committed to.
- **No performance has been measured.** Every numeric target in the documentation is a
  budget to be validated in Phase 15, labelled as such. Per master specification sections
  9 and 22, no figure will be reported here until a run produces it.
- Twelve assumptions and decisions require the project owner's approval before Phase 3
  begins; they are listed at the end of the architecture package.

---

## Release history

_No releases yet._
