# Requirements Traceability Matrix

## Final status (Phase 16 closure correction)

The authoritative closing status of every SRS requirement, recomputed requirement by requirement
in the Phase 16 closure correction (the previous counts were not carried forward). Status values:
**SATISFIED** (built and verified by a named test or run; the limit, if any, is stated),
**PARTIAL** (built, but part of the requirement's wording is not met), **UNSATISFIED** (not built)
and **EXTERNAL PREREQUISITE** (needs infrastructure outside this repository). No mandatory
requirement is marked "deferred". `GAP-nn` refers to the
[production gap register](../PRODUCTION_GAP_REGISTER.md). Performance figures are LOCAL benchmarks
([docs/testing](../testing/README.md)).

| Status | Count |
|---|---:|
| SATISFIED | 112 |
| PARTIAL | 19 |
| UNSATISFIED | 0 |
| EXTERNAL PREREQUISITE | 0 |
| **Total** | **131** |

| Req | Status | Evidence and limit |
|---|---|---|
| FR-API-01 | SATISFIED | Five independently authorized surfaces; Phase 16 adds remediation requests and human resolution (incident control) and postmortem reads (incident read), each in the RBAC matrix and fuzz campaign |
| FR-API-02 | SATISFIED | Tenant from signed claim + RLS; schema-wide tenant campaign |
| FR-API-03 | SATISFIED | Next.js dashboard renders incidents, evidence, hypotheses, timeline, actions and approvals |
| FR-API-04 | SATISFIED | Administration permissions separate from operational ones (no step-up authentication) |
| FR-APR-01 | SATISFIED | Autonomy matrix: no autonomous R2, no production R1 without approval; only R1 in non-production executes without a human (P6). The responder who requested a remediation cannot approve it |
| FR-APR-02 | SATISFIED | Durable approval wait survives restart (crash matrix); a crash between approval and dispatch fails closed and asks again (GAP-20) |
| FR-APR-03 | SATISFIED | Expiry escalates; never executes |
| FR-APR-04 | SATISFIED | Immutable approver, decision, justification and time |
| FR-APR-05 | SATISFIED | Action-version hash binding; replay/wrong-hash attacks refused |
| FR-CLB-01 | PARTIAL | Slack, Teams, PagerDuty, Jira and Grafana outbound adapters and the notification service exist and are tested against local servers only (GAP-16); the deployed worker does not compose the notification service, so a deployed incident announces nothing (GAP-38) |
| FR-CLB-02 | SATISFIED | Deterministic event ids and effect claims; delivery failure never fails the incident |
| FR-CLB-03 | PARTIAL | The invariant holds - chat identity grants nothing, because no collaboration channel reaches the approval service and approvals are accepted only through the authenticated RBAC API - but the inbound collaboration approval path this requirement governs is not built (GAP-12); not claimed as satisfied vacuously |
| FR-COR-01 | SATISFIED | Deterministic correlation v2; alert-storm tests; event-storm campaign (one incident per group) |
| FR-COR-02 | SATISFIED | Pure deterministic correlation; import-boundary test excludes model reasoning |
| FR-COR-03 | SATISFIED | Persisted factors, exclusions and tie-break decisions |
| FR-COR-04 | SATISFIED | Late occurrence joins by start-time anchor; out-of-order storms converge |
| FR-EVD-01 | SATISFIED | Broker-assigned provenance (`VERIFIED_FACT` for query results, `RETRIEVED` for knowledge) distinct from hypotheses and `MODEL_CLAIM` |
| FR-EVD-02 | SATISFIED | Citations carry the re-derivation query; citation replay |
| FR-EVD-03 | SATISFIED | Every retrieved chunk carries a resolvable citation (Phase 6 evaluation) |
| FR-EVD-04 | PARTIAL | Historical knowledge enters only as fenced `RETRIEVED` content with no authority; historical-incident retrieval (T3 -> T2) does not exist (GAP-33); no scenario proves a contradicting stale runbook is outranked (GAP-18) |
| FR-EVL-01 | SATISFIED | Own data model, read-only API and executable gate |
| FR-EVL-02 | SATISFIED | 18 versioned golden/adversarial scenarios plus strict replay; no production-incident replay case |
| FR-EVL-03 | SATISFIED | Zero-tolerance invariants with non-vacuity tests |
| FR-EVL-04 | PARTIAL | Multi-judge panel with disagreement recorded; calibration against human labels and live judges not performed (GAP-09) |
| FR-EVL-05 | SATISFIED | Per-scenario, per-metric comparison; never silently omits scenarios or metrics (F-09) |
| FR-EVL-06 | PARTIAL | Most §9 metrics computed; latency to first hypothesis, redundant-call rate and calibration error are not (GAP-27) |
| FR-EVL-07 | SATISFIED | Every report labelled simulated/replay; unmeasured judges `not_measured`; docs validator checks unmeasured claims |
| FR-EVL-08 | PARTIAL | Every loop stage has tooling (replay, trace, evaluation, failure classes, regression tests); no recorded walkthrough on a real model regression (GAP-27) |
| FR-EVL-09 | SATISFIED | Behaviour version on every run; digests force re-baselining |
| FR-EVL-10 | SATISFIED | Release workflow runs the full 18-scenario gate before publishing; executed locally, remote CI run not verified (GAP-01) |
| FR-EVL-11 | SATISFIED | Results bind to the workflow run and trace they evaluate; shown for harness runs (no production incident recorded) |
| FR-INC-01 | SATISFIED | Durable LangGraph workflow with explicit states and append-only transitions, driven in deployment by the worker (`python -m asic.worker`) |
| FR-INC-02 | SATISFIED | Checkpoint/resume; crash matrix at every node boundary with zero duplicated effects (`test_crash_resume_matrix.py`); a worker killed mid-run is recovered by another without repeating an effect (`tests/worker`, demo) |
| FR-INC-03 | SATISFIED | Five terminal categories; deterministic termination tests |
| FR-INC-04 | SATISFIED | Append-only incident events; status equals the event-log projection (asserted in E2E and storms) |
| FR-INC-05 | SATISFIED | Deterministic evidence-backed timeline projection; E2E scenario A |
| FR-INC-06 | SATISFIED | Timeline entries trace to source events/evidence; determinism tests |
| FR-ING-01 | SATISFIED | Authenticated connector-scoped ingestion API; `tests/ingestion`, `tests/api`, event-storm and pool-deadlock suites |
| FR-ING-02 | PARTIAL | Metrics, logs, Kubernetes state and deployment history through native adapters (local servers); traces are simulator-only and configuration-change history has no dedicated adapter (GAP-17) |
| FR-ING-03 | SATISFIED | Delivery/occurrence identities and idempotency ledger; redelivery and retry storms over HTTP (`tests/resilience/test_event_storms.py`) |
| FR-ING-04 | SATISFIED | Canonical versioned envelope with tenant/service/environment from the signed connector |
| FR-ING-05 | SATISFIED | Durable typed rejection receipts; no silent drop |
| FR-INT-01 | PARTIAL | Prometheus, Loki, Kubernetes, Slack, Teams, PagerDuty, Jira, Grafana adapters; OpenTelemetry context propagated; no trace-store adapter (GAP-17) |
| FR-INT-02 | SATISFIED | Deterministic simulators and recorded replay fixtures |
| FR-INT-03 | SATISFIED | Entire suite runs against local servers and PostgreSQL only |
| FR-INT-04 | SATISFIED | Live composition refuses simulators/test credentials; production image excludes simulator and test sources |
| FR-INV-01 | SATISFIED | Planner selects from declared gaps |
| FR-INV-02 | SATISFIED | Hypothesise/gather/critique/revise/stop observable in the trace (SC-0012, E2E scenario C) |
| FR-INV-03 | SATISFIED | Five budget limits each terminate the run; budget-exhaustion scenario |
| FR-INV-04 | SATISFIED | Limit exhaustion yields a partial result, never a stall |
| FR-INV-05 | PARTIAL | Six evidence domains reachable; traces simulator-only (GAP-17); per-domain analysis is deterministic; a multi-service incident collects evidence for the first service only (GAP-32) |
| FR-INV-06 | SATISFIED | Read-only registry ceiling for investigation; tool-abuse campaign refuses writes before any adapter call |
| FR-INV-07 | SATISFIED | Every step persisted with rationale, tool, inputs, outputs and cost; strict replay |
| FR-INV-08 | PARTIAL | Gap tracking drives selection; the redundant-call-rate baseline metric is not computed (GAP-27) |
| FR-KNW-01 | SATISFIED | Governed ingestion, structure-aware chunking and metadata for runbooks, service docs, known errors and postmortems as imported text; no connector-specific fetch |
| FR-KNW-02 | SATISFIED | Scope filters applied as query predicates before ranking |
| FR-KNW-03 | SATISFIED | ACL in the pre-ranking CTE; zero unauthorized hits; mutation-tested |
| FR-KNW-04 | SATISFIED | Hybrid lexical+vector (RRF) shipped; no reranker because no measurement justified one (ADR-0008) |
| FR-KNW-05 | SATISFIED | Supersede-not-overwrite versioning (INV-14) |
| FR-KNW-06 | SATISFIED | Retrieval evaluation on a 12-document golden corpus (recall@5, precision@5, MRR); small corpus, not a production benchmark |
| FR-KNW-07 | SATISFIED | Injection corpus across every vector; zero authorization effect (`test_injection_campaign.py`) |
| FR-MEM-01 | SATISFIED | Five tiers with distinct write authority |
| FR-MEM-02 | SATISFIED | Database rejects ungoverned memory writes. Nothing in the deployed product proposes a promotion yet (no G12 step, GAP-31), so the governed path is exercised by tests, not by incidents |
| FR-MEM-03 | SATISFIED | No auto-promotion path; every promotion needs a human decision |
| FR-MEM-04 | SATISFIED | Human, not-the-proposer decision; versioned; lineage re-evaluated |
| FR-OBS-01 | PARTIAL | Workflow, node, planner, tool, integration, API, ingestion, knowledge, evaluation, worker and postmortem spans; model calls are attributes; no database-operation spans (GAP-28) |
| FR-OBS-02 | SATISFIED | Catalogued metrics, seven dashboards and SLO rules (validated, not deployed) |
| FR-OBS-03 | SATISFIED | Exported trace ids equal persisted ones; strict replay reproduces routing |
| FR-OBS-04 | SATISFIED | Trace id joins incident, workflow run, evidence, actions and evaluation |
| FR-OBS-05 | SATISFIED | Secret-leak campaign finds no canary in any sink |
| FR-PMT-01 | SATISFIED | G11 postmortem author (`src/asic/postmortem`) drafts a postmortem for every resolved incident; the deployed worker triggers it (`WorkKind.POSTMORTEM`). Golden and negative-control suite `tests/postmortem`, worker flow `tests/worker`, demo product path and kind acceptance. Prose is scripted until a live model exists (GAP-08, GAP-37) |
| FR-PMT-02 | SATISFIED | Every non-structural claim cites incident events, evidence or other persisted records by handle, resolved to row ids and re-checked against the database in tests, the demo and kind; a deterministic validator removes uncited, foreign-cited, flagged-only, unsupported-causal and unsupported-figure claims into a labelled uncertainty list. Drafts are `draft` + `review_required`, enforced by a check constraint and append-only grants (migration 0020); no review or publication workflow exists (GAP-30) |
| FR-POL-01 | SATISFIED | Deterministic gate, sole authorization path, no model call |
| FR-POL-02 | SATISFIED | Gate input type cannot carry retrieved or model content |
| FR-POL-03 | SATISFIED | Exactly one policy decision per action |
| FR-RCA-01 | SATISFIED | Ranked hypotheses with evidence, confidence and counter-evidence; simulated RCA@1/@3 = 1.0 with the deterministic provider only (reasoning quality with a live model not measured) |
| FR-RCA-02 | SATISFIED | Fabricated evidence/hypothesis ids dropped before ranking (SC-0015) |
| FR-RCA-03 | SATISFIED | Deterministic confidence ceiling with its basis (count, strength, contradiction); calibration error not computed |
| FR-RCA-04 | SATISFIED | No discoverable cause ends in uncertainty (SC-0002, E2E scenario C) |
| FR-REM-01 | SATISFIED | Separate proposal/gate/approval/executor/verifier graph; no bypass path |
| FR-REM-02 | SATISFIED | Typed proposal with the twelve §6 fields |
| FR-REM-03 | SATISFIED | Registry-assigned tiers; not model-settable |
| FR-REM-04 | SATISFIED | Ambiguity conditions force approval or denial |
| FR-REM-05 | SATISFIED | No free-form command/script/manifest field on any write tool |
| FR-REM-06 | SATISFIED | Unregistered tools rejected, never repaired (tool-abuse campaign) |
| FR-REM-07 | SATISFIED | Scope resolved from context; arguments cannot widen it |
| FR-REM-08 | SATISFIED | Effect-key claim before dispatch; duplicate/crash-window tests; E2E scenario F (exactly one patch) |
| FR-REM-09 | SATISFIED | Fresh precondition reads; stale state fails closed |
| FR-VRF-01 | SATISFIED | Every executed action independently verified (E2E scenarios B, H) |
| FR-VRF-02 | SATISFIED | Executor output absent from the verdict input |
| FR-VRF-03 | SATISFIED | Criteria frozen at proposal |
| FR-VRF-04 | PARTIAL | Verification failure escalates and is never marked resolved (E2E scenario H, partial-effect alert and runbook); rollback tools are registered but no path proposes or triggers compensation (GAP-11) |
| NFR-MNT-01 | SATISFIED | 31 ADRs (0001-0032; 0021 reserved) with alternatives and trade-offs |
| NFR-MNT-02 | SATISFIED | Each technology justified in an ADR against the specification |
| NFR-MNT-03 | SATISFIED | Quality workflow gates all listed categories; executed locally, remote runs not verified (GAP-01) |
| NFR-MNT-04 | SATISFIED | Hygiene scanner, reproducible clean install, linear authored history |
| NFR-OBS-06 | SATISFIED | Observable, testable, replayable, evaluable, interruptible, recoverable, permission-aware, reproducible — each with tests |
| NFR-PRF-01 | PARTIAL | LOCAL (final image): ingestion p95 72 ms at 8 alerts/s; at 50 alerts/s offered most alerts cannot be sent within 1 s (Phase 15: p95 6.4 s), so the budget holds only below ingestion capacity |
| NFR-PRF-02 | PARTIAL | LOCAL (final image): investigation run p95 3.1 s with the deterministic provider; a live model is not measured |
| NFR-PRF-03 | SATISFIED | Budget exhaustion is a clean terminating state |
| NFR-PRF-04 | PARTIAL | LOCAL (final image): ≈ 21 successful alerts/s per 2-CPU API process with 56 % of the offered 50/s dropped before sending (Phase 15: ≈ 12/s including rejections); below the assumed 50/s (GAP-23) |
| NFR-PRF-05 | SATISFIED | Tokens and cost recorded per run and in evaluation reports |
| NFR-PRT-01 | SATISFIED | Docker images (non-root, digest-addressed); Kubernetes deployment of database, migration, API, frontend and the **worker** on kind + Cilium; Terraform apply / no-drift re-plan / destroy of the namespace, Pod Security Admission and service accounts. Kind acceptance drives alert -> worker -> investigation -> remediation -> verification -> postmortem through the API. Limit: the production worker profile refuses to start until a live model exists (GAP-08); on kind the worker runs the final image plus a test-only simulator layer |
| NFR-PRT-02 | SATISFIED | Local demo and full suite with simulators and no live infrastructure |
| NFR-REL-01 | SATISFIED | Crash matrix: resume with zero duplicated side effects |
| NFR-REL-02 | SATISFIED | Effect-level idempotency for every write tool |
| NFR-REL-03 | SATISFIED | Retries only for transient reads, jittered and capped; unknown outcomes reconciled |
| NFR-REL-04 | SATISFIED | Node, tool, model and workflow deadlines; statement timeouts enforced by the server |
| NFR-REL-05 | SATISFIED | Dead-letter/error states for input and steps |
| NFR-REL-06 | SATISFIED | Duplicate classes absorbed; HTTP storms |
| NFR-REL-07 | SATISFIED | Partial tool failure degrades (dependency fault matrix, E2E scenario E) |
| NFR-REL-08 | SATISFIED | Provider/API outages end in escalation or uncertainty, never destructive (model-provider suite, chaos) |
| NFR-REL-09 | PARTIAL | Resume is proven and the deployed worker recovers crashed runs, but only after the 15-minute lease expires, so the assumed 60 s budget is not met (GAP-26) |
| NFR-SEC-01 | SATISFIED | OIDC/JWKS verifier with bounded lifetime; development HS256 refused in production; no live-IdP interop test |
| NFR-SEC-02 | SATISFIED | RBAC matrix over every route, including approval |
| NFR-SEC-03 | SATISFIED | RLS backstop with mechanical schema audit; tenant campaign |
| NFR-SEC-04 | SATISFIED | Least-privilege roles (runtime, migration, auditor, maintenance) and per-connector credentials |
| NFR-SEC-05 | SATISFIED | Model cannot invoke, widen or authorize outside its menu (tool-abuse and model-failure suites) |
| NFR-SEC-06 | SATISFIED | Typed secrets, redaction at emission, gitleaks history/tree, canary campaign |
| NFR-SEC-07 | PARTIAL | In transit: outbound HTTPS verified; a production process refuses any database URL that is not `sslmode=verify-full` with a mounted CA and a TCP host, enforced by the API, worker, migration and retention entry points before connecting (`asic.db.tls`, `tests/security/test_database_tls.py`, final image). Not verified against a TLS-serving managed database; ingress TLS and pod-to-pod mTLS are platform (GAP-02, GAP-29). At rest: managed-database encryption not deployed (GAP-03) |
| NFR-SEC-08 | SATISFIED | Executions, decisions and denials audited |
| NFR-SEC-09 | SATISFIED | Bounded validated input; seeded fuzz campaign over every route never yields a 500 |
| NFR-SEC-10 | SATISFIED | Injection corpus; zero authorization effect; detection recorded as signal |
| NFR-SEC-11 | SATISFIED | Log lines, runbooks, tickets and titles reach the model only fenced as untrusted data with no authority; log query results carry `VERIFIED_FACT` provenance (the query happened) while their text stays untrusted |
| NFR-SEC-12 | PARTIAL | Per-principal and failed-auth limiters plus an ingestion bulkhead, per process only (GAP-13) |
| NFR-SEC-13 | SATISFIED | `security_gate.py --strict --require-container-scan` executed locally 11/11; remote CI run not verified (GAP-01) |
| NFR-SEC-14 | PARTIAL | Classification, holds, dry-run planner and an executor for the idempotency cache only (ADR-0032); other classes deferred (GAP-15) |
| NFR-SEC-15 | SATISFIED | Per-tenant connector credentials with composite RESTRICT binding |
| NFR-TST-01 | SATISFIED | All fifteen §17 categories present, including load, resilience and deployment smoke |
| NFR-TST-02 | SATISFIED | Failure-path, adversarial, chaos and fault suites gate completion |
| NFR-TST-03 | SATISFIED | SI-1..SI-15 (remediation-safety-policy.md §1) each attacked: proposer/executor separation, command-field refusal, gate input type, read-only credentials, R3 absence, hash-mismatch, drift, duplicate delivery, executor-claim, immutable target, dispatch re-resolution, deterministic verifier, audit reconciliation, fail-closed, ungated memory write |


## Phase 16 closure correction evidence

| Requirement | Implemented evidence and limits |
|---|---|
| FR-PMT-01, FR-PMT-02 | G11 author and grounding validator (`src/asic/postmortem`), migration 0020 (versioned, append-only, drafts-only), API `GET /incidents/{id}/postmortems`, `tests/postmortem` (golden resolved incident; unsupported causal claim, malicious publish instruction, cross-tenant access, ineligible incident, replay/resume), worker trigger, demo and kind acceptance |
| NFR-PRT-01, FR-INC-01, FR-INC-02 | Worker (`src/asic/worker`: PostgreSQL discovery, advisory-lock claims over kernel leases, bounded concurrency, SIGTERM drain, probes), `deploy/kubernetes/base/worker-deployment.yaml`, `tests/worker` (full flow, two-worker race, crash recovery, shutdown, outage, configuration), kind acceptance with two replicas |
| NFR-SEC-07 | `asic.db.tls` production transport policy; migration and maintenance Jobs mark the production profile; optional database CA Secret mounted by every backend workload |
| FR-CLB-03, FR-CLB-01 | Re-evaluated: no vacuous satisfaction (GAP-12, GAP-38) |

## Phase 15 implementation evidence

Load, resilience, chaos, adversarial security and end-to-end validation
([docs/testing](../testing/README.md), [ADR-0032](../adr/0032-bounded-retention-executor.md)).
Every measured figure is LOCAL.

| Requirement | Implemented evidence and limits |
|---|---|
| NFR-PRF-01, NFR-PRF-02, NFR-PRF-04 | Load harness profiles and measured results in [LOAD_AND_PERFORMANCE.md](../testing/LOAD_AND_PERFORMANCE.md); the assumed 50 alerts/s is not sustained locally |
| NFR-REL-01, NFR-REL-07, NFR-REL-08 | Crash/resume matrix, dependency fault matrix, model-provider failure, database stress and six declared chaos experiments on kind ([RESILIENCE_AND_CHAOS.md](../testing/RESILIENCE_AND_CHAOS.md)) |
| NFR-SEC-09, NFR-SEC-10, NFR-SEC-12 | API fuzz and abuse-cost, injection corpus, rate-limit and ingestion bulkhead ([SECURITY_HARDENING.md](../testing/SECURITY_HARDENING.md)) |
| NFR-SEC-01 | P13-SEC-05 closed: `iat` required, bounded token lifetime in both verifiers |
| NFR-SEC-14 | Retention executor for the idempotency cache under `asic_maintenance`, immutable receipts, suspended dry-run CronJob |
| NFR-TST-01 | Load/performance, resilience/fault-injection and E2E categories added; 2,472 tests pass after the Phase 16 closure correction ([PHASE16_CLOSURE_RESULTS.md](../testing/PHASE16_CLOSURE_RESULTS.md)) |

## Phase 5 implementation evidence

[Telemetry ingestion](./telemetry-ingestion.md) and `tests/ingestion` implement the
deterministic ingestion/correlation/application portion of the following requirements.
This does not claim that future transport authentication or production adapters exist.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-ING-01 | Connector-bound tenant/service/environment; spoofing tests. HTTP authentication remains Phase 9/10 |
| FR-ING-03 | Delivery/occurrence identities, permanent vs retryable receipts, committed duplicate and real-contention tests |
| FR-ING-04 | Canonical versioned envelope, simulator and Alertmanager-format fixture normalizers; future production sources deferred |
| FR-ING-05 | Durable typed rejection/overflow receipts; unsafe timestamps cannot poison source state; append/DB failure propagates |
| FR-COR-01 | Twelve-alert storm and repeated ambiguous bridges converge under deterministic v2 |
| FR-COR-02 | Pure deterministic correlation with an import-boundary test excluding model reasoning |
| FR-COR-03 | SQL relevance before bound; versioned factors, candidate exclusions and persisted tie-break decisions |
| FR-COR-04 | Late occurrence joins by start-time anchor; source resolution does not terminate investigation |
| FR-INC-04 | Incident events remain append-only; terminal updates create human reopen candidates without lifecycle mutation |

Additional coverage: application-role RLS and composite foreign keys, atomic rollback,
source-state ordering, persisted source text through real prompt renderers without authority,
terminal dispatch, read-only trigger deduplication,
pre-drive crash recovery, trace redaction and migration clean/accepted-head/round-trip/drift.
No production scale or performance result is implied.

## Phase 13 implementation evidence

Security, RBAC, tenant isolation and supply-chain controls
([ADR-0030](../adr/0030-security-boundary-consolidation.md),
[security architecture](../security/SECURITY_ARCHITECTURE.md)). Nothing here is a compliance claim;
infrastructure controls (TLS, at-rest encryption, network policy, container scanning, CI wiring)
are Phase 14 obligations and are stated as such.

| Requirement | Implemented evidence and limits |
|---|---|
| NFR-SEC-01 | `TokenVerifier`: OIDC/JWKS (asymmetric only, `kid`, claims, bounded rotation-aware cache) for production; HS256 development verifier refused in production (`tests/security/test_authentication.py`). No live-IdP interop test; normal revocation lag is up to the 300 s TTL, while issuer outage can extend last-known-good key service to the 600 s stale bound, after which authentication fails closed |
| NFR-SEC-02 | One permission vocabulary and scope rules, equal to the migrated catalogue; every (role, assignment scope, route) cell tested; revocation, expiry, disabled users, forged claims and wrong tenant/environment attacked (`test_rbac_matrix.py`). Every approve-holder may decide through R2 (no R1/R2 approver split) |
| NFR-SEC-03 | Mechanical tenancy audit of the live schema: exact one-policy canonical RLS model, complete model-derived tenant-FK inventory including actions and referenced uniqueness, role and grants; live mutation proofs include permissive-policy widening and missing required FKs; migration 0018 (`tests/security/test_tenancy_and_grants.py`, `tests/db/test_security_migration.py`) |
| NFR-SEC-04 | Application role loses `DELETE`/`TRUNCATE`, write on `alembic_version` and on identity/authority/configuration tables; node authority model (F-08); capability inventory reviewed mechanically (`test_capability_authority.py`, `test_node_authority.py`) |
| NFR-SEC-05 | No dynamic capability creation, no provider invoked outside the broker, reviewed closed set of free-text arguments |
| NFR-SEC-06 | `SecretValue` typed redaction, credential-free request/response `repr`, name/shape backup, secret scanning of history and tree (`test_secrets_and_redaction.py`, `test_security_gate.py`). Redaction is not complete detection |
| NFR-SEC-07 | Outbound TLS verified and HTTPS-only; Phase 14 supplies a TLS Ingress contract. Actual termination and encryption at rest remain platform responsibilities and are not claimed executed |
| NFR-SEC-08 | Denied state changes and tenant-wide reads are durable, attributed, tenant-bound audit records; authentication failures are structured logs (`test_security_audit.py`) |
| NFR-SEC-09 | 128 KiB streamed body bound, JSON-only, control-character refusal (a NUL was a 500), bounded pagination/cursors, egress host policy, Loki level vocabulary, trace-id rule (`test_api_bounds.py`, `test_phase13_hardening.py`) |
| NFR-SEC-10, NFR-SEC-11 | Adversarial payload set through the fence renderer and a live adapter/broker; menu, tenant, scope, tier, approvals, policy unchanged (`test_prompt_injection_phase13.py`) |
| NFR-SEC-12 | Bounded per-principal and failed-auth limiters, limiter before database lookup, coalesced readiness, connect deadlines. Per-process only; shared limiter deferred to Phase 14/15 |
| NFR-SEC-13 | `scripts/security_gate.py`: dependency/SAST/secret controls plus Phase 14 fail-closed Trivy scans of both built images; `--require-container-scan` is mandatory in release CI |
| NFR-SEC-14 | Complete table classification, holds and dry-run planner; Phase 14 intentionally deploys no owner Job because a safe bounded deletion/receipt primitive does not exist |
| NFR-SEC-15 | Connector binding composite `RESTRICT` FK; credential references only; per-call resolution; separate read/write credentials |

## Phase 12 implementation evidence

[`observability.md` §10](./observability.md#10-phase-12-implementation-status),
[SLOs](../observability/SLOS.md), [ADR-0029](../adr/0029-bounded-telemetry-from-committed-records.md),
`src/asic/observability`, `configs/observability` and `tests/observability`. Evidence is
**UNIT + INTEGRATION + SIMULATOR + LOCAL SERVICE** (local OTLP receiver, `promtool`,
`otelcol-contrib`); nothing was deployed and no SLO value was measured.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-OBS-01 | Exported span kinds: `workflow.phase`, `node.execute` (including the policy gate, approval, executor and verifier nodes), `planner.step`, `tool.invoke`, `integration.call`, plus `api.request`, `ingestion.*`, `knowledge.*` and `evaluation.*` spans. Not emitted as distinct kinds: `incident`, `correlation`, `llm.call` (model calls are attributes of the calling span), `retrieval.query` (covered by `knowledge.*`), `db.operation`, `policy.evaluate`, `approval.wait`, `remediation.execute`, `verification.check`, `evaluation.score` |
| FR-OBS-02 | Seven dashboards and SLO/SLI rules over catalogued metrics; every query checked against the catalogue. Tenant-health dashboard intentionally not built (no tenant labels) |
| FR-OBS-03 | Exported trace ids equal persisted trace ids; routing reproduction is the Phase 11 strict replay |
| FR-OBS-04 | Trace id joins execution trace, workflow run, incident and evaluation result (span attribute, report field and API) |
| FR-OBS-05 | Redaction at emission for spans and logs; tests assert no secret-shaped value, prompt body or injected content in exported spans, and no identifier-shaped metric label value |
| NFR-OBS-06 | Observable (metrics, logs, traces), replayable and evaluable (Phase 11), interruptible and recoverable (dead-letter and readiness alerts); availability of a deployment is not demonstrated |

## Phase 11 implementation evidence

[`EVALUATION_ARCHITECTURE.md` §11](../evaluation/EVALUATION_ARCHITECTURE.md#11-phase-11-implementation-status),
[ADR-0028](../adr/0028-evaluation-harness-replay-at-provider-seams.md), `src/asic/evaluation`
and `tests/evaluation` implement the harness. Evidence is **UNIT + INTEGRATION + SIMULATOR +
REPLAY** with a deterministic scripted model provider under the unprivileged application
role; no live model, live judge or production incident was evaluated.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-EVL-01 | Own data model (suite run, run, judge result, replay fixture, scenario), read-only API routes and an executable gate with machine-readable exit codes. CI wiring is Phase 14 |
| FR-EVL-02 | 18 versioned scenarios covering 23 declared categories (golden and adversarial); replay of recorded harness runs. No production-incident replay case exists |
| FR-EVL-03 | Zero-tolerance invariants and expectations, each shown to fail on its target defect by non-vacuity tests. Forbidden-evidence, schema-validity and audit-completeness checks are not re-checked by the harness (stated in §11.2) |
| FR-EVL-04 | Multi-judge panel with disagreement recorded as `contested`, never averaged; malformed or fabricated-citation output discarded. **Calibration against human labels not performed**; judges not measured in the gate runs |
| FR-EVL-05 | Per-scenario, per-metric deltas against a digest-verified baseline; not comparable when scenario digest or evaluator version changes |
| FR-EVL-06 | Investigation, RCA @1/@3, unsupported-claim rate, evidence recall/precision, tool efficiency, remediation correctness, verification success, false success, unsafe actions, escalation, tokens, cost and regression rate computed per run; `None` where not applicable. Redundant-call rate, latency to first hypothesis and confidence calibration error are not computed |
| FR-EVL-07 | Every report carries `SIMULATED / REPLAY EVALUATION - not production results`; unmeasured judges reported `not_measured` |
| FR-EVL-09 | Behaviour version recorded on every suite run and result; scenario digests force re-baselining |
| FR-EVL-11 | Results bind to the workflow run and execution trace they evaluate; a production incident has not been recorded, so the no-transformation round trip is shown only for harness runs |

## Phase 10 implementation evidence

[`integrations.md`](./integrations.md), `src/asic/integrations`, `src/asic/notifications`
and `tests/integrations` implement native adapters behind the broker. Evidence is
**INTEGRATION + LOCAL SERVICE** (deterministic local HTTP servers under the unprivileged
application role); no live vendor system was exercised.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-INT-01 | Prometheus, Loki, Kubernetes, Slack, Teams, PagerDuty, Jira and Grafana adapters behind `NativeIntegrationProvider`; OpenTelemetry trace context propagated on outbound calls. No trace-store adapter and no Elasticsearch/OpenSearch (ADR-0027) |
| FR-INT-02 | Existing deterministic simulators unchanged; adapter contract tests use deterministic local servers. Recorded replay fixtures were added in Phase 11 |
| FR-INT-03 | The whole suite runs against local servers and PostgreSQL only |
| FR-INT-04 | Live composition refuses test credentials, loopback endpoints and non-native providers; the broker refuses mixed live/simulated providers (ADR-0020). Build-level exclusion remains Phase 14 |
| FR-CLB-01 | S2 notification service delivers typed records to Slack, Teams, PagerDuty, Jira and Grafana through the broker |
| FR-CLB-02 | Deterministic event ids and durable effect claims; unknown outcomes never re-sent; a failing destination or notification infrastructure never fails the investigation |
| FR-CLB-03 | No inbound chat approval path exists; approval authority remains the authenticated approval API |
| NFR-SEC-04 | Per-tenant connector references, separate Kubernetes read/write credentials, per-call resolution with fail-closed production provider |

## Phase 9 implementation evidence

[`phase9-api-dashboard.md`](./phase9-api-dashboard.md), `src/asic/api`, `frontend/`, and
`tests/api` implement the authenticated API and incident-command dashboard boundary.
Tests exercise tenant isolation, environment scope, independently authorized surfaces,
idempotent lifecycle control and typed deferred boundaries. The dashboard consumes an
identity-proxy-provided HttpOnly session cookie; no provider or external connector is
claimed.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-API-01 | Versioned ingestion, incident, approval, evaluation and administration routers with separate permissions; evaluation routes became read-only result reporting in Phase 11 |
| FR-API-02 | Signed tenant claim plus current database assignment lookup; API tests prove cross-tenant reads return 404 |
| FR-API-03 | Dashboard renders evidence, hypotheses, timeline and actions/approval state |
| FR-API-04 | Independent administration/audit/incident/approval grants; viewer isolation is tested |
| NFR-SEC-01 | JWT edge contract with explicit production key-management boundary |
| NFR-SEC-02 | Current role, expiry and environment grants; claims do not widen authority |
| NFR-SEC-03 | RLS-bound sessions and explicit tenant predicates |
| NFR-SEC-09 | Bounded Pydantic models, UUID validation, typed errors and correlation IDs |
| NFR-SEC-12 | Causal authenticated-principal rate-limit test; distributed limiter deferred |
| NFR-REL-06 | Durable idempotency response ledger with digest conflict detection and advisory-key serialization |

## Phase 6 implementation evidence

[`memory-and-rag.md`](./memory-and-rag.md) and `tests/knowledge`, `tests/memory`,
`tests/security/test_knowledge_prompt_injection.py` implement the operational-knowledge,
retrieval and governed-memory portion of the following requirements. Ranking quality,
reranking, and semantic-similarity strength are architecture-validation measurements
against a twelve-document golden corpus (P6-09 reconciled this figure with
`tests/knowledge/test_retrieval_evaluation.py`, the authoritative source - the corpus and
this count previously drifted apart), not production benchmarks.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-KNW-01 | `KnowledgeIngestionService`: canonicalize → structure-aware chunk → deterministic embed → transactional commit; idempotent re-ingestion (identical content re-import writes nothing); typed rejection for oversized/invalid/empty documents. Lifecycle attribution is separate from current `knowledge.source.lifecycle.manage` authority and denial/success are audited. One source type (imported document text) is exercised; connector-specific fetch is out of scope for Phase 6 |
| FR-KNW-02 | `KnowledgeRetriever`'s single disposition CTE filters by service/environment/document-type *before* ranking; `tests/knowledge/test_retrieval_db.py::TestScopeAndAuthorization` proves wrong-service and wrong-environment scope yield zero results, not a wrong one |
| FR-KNW-03 | ACL evaluated in the same pre-ranking CTE; `test_acl_label_hides_the_document_without_the_clearance` and the golden-corpus unauthorized-rate test (`TestUnauthorizedAndStaleRatesAreZero`, measured 0 unauthorized hits across the probe set) confirm zero out-of-scope exposure; mutation-tested (see completion report) — forcing the ACL predicate to `TRUE` makes both tests fail |
| FR-KNW-04 | [ADR-0008](../adr/0008-rag-retrieval-strategy.md) status raised to Accepted on this evidence: hybrid (lexical + vector, versioned RRF fusion) is the only mode shipped; no reranker exists in the codebase — there is nothing to have "enabled only on a measured improvement" because no measurement has shown a need |
| FR-KNW-05 | Supersede-then-insert under a per-source advisory lock plus a partial unique index (`uq_knowledge_document_current_source`) enforce INV-14; `TestVersioning` in `test_ingestion_db.py` proves old chunk text survives supersession and content returning to an earlier state creates a new version rather than reusing one; retrieval and replay both prefer current and can reproduce a historical version exactly |
| FR-KNW-06 | `tests/knowledge/test_retrieval_evaluation.py`: twelve-document, eighteen-query golden corpus (P6-09 added a lexical-only holdout, a hard-negative distractor and an out-of-vocabulary paraphrase holdout). Measured this run: recall@5 = 1.000, precision@5 = 0.730, MRR = 0.933 over the ten gradeable queries (ambiguous, the hard-negative distractor and the out-of-vocabulary holdout excluded from the average by design, each with its own dedicated test instead). The out-of-vocabulary holdout is measured and asserted to miss - the deterministic embedding is a hashed bag of tokens and a fixed concept table, not a semantic model, and this suite says so rather than omitting the case. These are architecture-validation numbers on a small corpus that now deliberately includes a hard negative — not a claim about any other corpus or a production benchmark |
| FR-KNW-07 | `tests/security/test_knowledge_prompt_injection.py` ingests a document containing fake SYSTEM headers, an "ignore all previous instructions" payload, a forged citation, and forged `<<<UNTRUSTED_DATA...UNTRUSTED_DATA>>>` fence markers, then runs it through the real broker → real manifest verification → real `HYPOTHESIS_PROMPT.render()`. Confirmed: the hostile text is retrievable (detection is a signal, never a filter) and confined to the untrusted section; the forged fence markers are neutralised so exactly one real fence renders; the forged citation does not resolve |
| FR-MEM-01 | `MemoryCategory` (five values) enforced by `asic.memory.policy.evaluate()`: `working_state`/`incident_history`/`model_inference` are refused outright (T1/T2/T3 are not writable through this path at all — T3 already has its own append-only path); only `operational_knowledge` and `verified_outcome` can become a proposal, each requiring a different reference shape |
| FR-MEM-02 | `MemoryEntry.promotion_id` is NOT NULL under the `governed_entry` check constraint (NOT VALID, applies to new rows); `TestMemoryIsNotDirectlyWritable` proves a direct INSERT bypassing `MemoryGovernanceService.decide()` is rejected by the database itself, not merely by application code |
| FR-MEM-03 | `support_count()` counts independent incidents; the policy and the entry-construction code do not special-case `support_count == 1` into automatic promotion — every promotion, single-incident or not, still requires the same human decision. No auto-promotion path exists to guard against |
| FR-MEM-04 | `MemoryGovernanceService.decide()`: human-only, not-the-proposer, permission-checked (`memory.promotion.decide`, seeded by migration `0008`), re-evaluates policy and the complete G10 baseline/post-read lineage at decision time; every decision — approve, decline, and every rejection at propose time — is recorded in the append-only `memory_write_decision` table. Mutation-tested: bypassing trusted-lineage resolution makes a forged legacy `VERIFIED` row promotable, while the intact guard rejects it |

## Phase 7 implementation evidence

[`bounded-reflection.md`](./bounded-reflection.md) and `tests/orchestration/
test_reflection.py`, `test_termination.py::TestReflectionDrivenTermination`,
`test_hypothesis.py::TestBoundedReflection` implement the bounded-reflection portion of the
following requirements. No live model provider exists (ADR-0016 unchanged) and no
evaluation harness exists (Phase 11), so no accuracy, calibration or redundant-call-rate
figure is claimed here even where a row below names one as its eventual validation.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-INV-01 | Unchanged from Phase 4: the planner selects from declared gaps. Phase 7 adds that a gap can now originate from a bounded-reflection decision (`continue_with_gap`, `collect_counter_evidence`) as well as from the planner's own analysis - both are ordinary `open_gaps` entries to the planner, no new selection mechanism |
| FR-INV-02 | Hypothesise → gather → critique → revise → stop is now observable in the trace: the hypothesis engine's span carries `reflection_action`, `reflection_rule_id` and `reflection_overridden_reason`; `SC-0012-counter-evidence-revises-hypothesis` exercises the full cycle end to end. "Critique" and "revise" are code, not a second model call - see [ADR-0022](../adr/0022-bounded-reflection-without-a-new-node.md) |
| FR-INV-04 | Unchanged mechanism (budget exhaustion still yields a partial result via R2/R3); reflection cannot bypass it because R1-R3 in `termination.py` are checked before `wants_to_stop` regardless of what reflection proposed |
| FR-RCA-02 | Extended to hypothesis ids: `revise_hypothesis`/`collect_counter_evidence` naming a hypothesis this run never persisted is rejected by `reflection.py`'s G1 guard before any write, the same principle INV-5 already applies to evidence citations. `test_a_fabricated_reflection_target_is_rejected_through_the_real_kernel` proves no row is touched |
| FR-RCA-04 | Extended: a `terminate_success`/`escalate` proposal is held to the identical actionability bar (`termination.is_actionable`) the planner's own `TERMINATE` already was, so reflection cannot manufacture certainty the planner could not. `test_an_unactionable_terminate_success_claim_does_not_escalate` is the direct test |

**Not addressed by Phase 7, and not implied by the rows above:** FR-RCA-01 (accuracy
against labels - needs Phase 11 and a real provider), FR-RCA-03 (calibration curve - same),
FR-INV-05 (per-domain analyser strategies in G4 - untouched), FR-INV-07/08 (already
partially true from Phase 4's step persistence; the redundant-call-rate *baseline* is
explicitly a Phase 11 artefact), FR-EVD-01/02/04 (unchanged from Phase 4/6).

## Phase 8 implementation evidence

[`bounded-remediation.md`](./bounded-remediation.md), `tests/domain/test_policy.py`,
`tests/domain/test_remediation_observations.py`, `tests/orchestration/test_remediation.py`
and `test_remediation_security.py` implement the simulator-backed remediation boundary.
They cover deterministic risk classification, exact-effect approval, dispatch-time role and
expiry checks, typed broker-only execution, crash-window effect claims, resume without a new
model proposal, strict preconditions and independent fail-closed verification. No live model,
production adapter, remediation-quality score or automated compensation is claimed.

| Requirement | Implemented evidence and limits |
|---|---|
| FR-REM-01..07 | Separate G6/G7/G8/G9/G10 contracts and graph; append-only target binds incident/investigation/hypothesis/service/environment/scope before G6; the proposal has no capability; policy and broker independently refuse unauthorized writes |
| FR-REM-08..09 | Effect-key claim precedes dispatch; duplicate and crash-window tests; every declared precondition is checked against fresh explicit state |
| FR-APR-01..05 | Autonomy matrix, durable wait, expiry, tenant/environment/risk-scoped role authority, immutable decision evidence and action-version binding |
| FR-VRF-01..03 | Tool-specific deterministic profile, independent baseline before execution, settling wait and fresh broker read; empty/unrelated/stale evidence is inconclusive and executor output is absent from the verdict input |
| FR-VRF-04 | Partially implemented: failure returns to investigation or escalates; automated compensation remains deferred |
| NFR-SEC-01..02 | Tool Broker remains the sole provider boundary; write grant/tool enablement and target/action/policy/approval authority are recomputed immediately before dispatch |
| NFR-REL-06 | Checkpoints retain the original run identity, wall clock and consumed budget; the immutable target and durable remediation rows are re-read on resume. Every current synchronous model adapter must publish a conservative token/cost bound and calls that cannot fit are refused before invocation; live/asynchronous providers remain deferred |

- **Status:** The per-area tables below are the Architecture Package's planned mapping (component, phase, validation, acceptance). Closing status: [Final status](#final-status-phase-16-closure-correction).
- **Requirement definitions:** [`../prd/SRS.md`](../prd/SRS.md)
- **Master specification:** [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)

Every requirement identifier defined in the SRS appears here exactly once, mapped to the
architecture component that will satisfy it, the phase in which it is built, how it will be
validated, and the acceptance criterion.

> **Historical note (Phases 3–10).** The closing status of every requirement is the
> [Final status](#final-status-phase-16-closure-correction) table at the top of this document; the note below records
> how status was tracked while Phases 3 through 10 were in progress.
> Rather than repeat a status column 138 times, the rule is: a requirement is
> implemented **only** where a passing test is named in the Validation column *and* that
> test exists and passes today.
>
> **From Phase 3** — the *schema and constraints* that make a requirement enforceable, but
> not the behaviour that uses them: the persistence-layer half of FR-INC-04, FR-ING-03,
> FR-ING-05, FR-REM-03, FR-REM-05, FR-REM-08, FR-POL-03, FR-APR-04, FR-APR-05, FR-VRF-03,
> FR-MEM-02, FR-MEM-04, FR-EVL-09, FR-API-02, NFR-SEC-03 and NFR-REL-06.
>
> **From Phase 4** — behaviour, exercised end to end against deterministic simulators and
> covered by named tests ([`orchestration-kernel.md`](./orchestration-kernel.md)):
>
> | Requirement area | What is built | What is not |
> |---|---|---|
> | Investigation planning and bounds (FR-INC-01..03, FR-EVD-01..02) | The bounded loop, gap declaration, the capability menu, budgets checked before each step, deterministic termination | Model-assisted per-domain analysis; multi-service strategy |
> | Tool authorization (FR-REM-06, NFR-SEC-01..02) | Registry, capability resolution, the broker chokepoint, refusals audited on every path | Anything above risk tier `RO`, which has no policy gate yet |
> | Evidence provenance and citation (FR-EVD-02, FR-RCA-02..03) | Broker-assigned provenance, citation integrity enforced before ranking, a deterministic confidence ceiling | Retrieval quality, reranking, knowledge ingestion |
> | Durability (NFR-REL-01..03, NFR-REL-07) | Per-node transactions, checkpointing, resume with reconciliation, leasing, degradation on partial failure | Unknown-outcome reconciliation for writes; approval waits |
> | Observability (FR-OBS-01..04) | One trace model, spans persisted with the work they describe, correlation identifiers, redaction at emission | Exporters, dashboards, SLOs — added in Phase 12 (see its evidence section) |
> | Prompt-injection resistance (NFR-SEC-07) | Structural: the menu precedes the content, scope is resolved not supplied, fenced untrusted regions | Nothing further is claimed; detection is a signal, not the defence |
>
> **The behaviour a row describes must exist before that row is called implemented.** No
> requirement is marked complete on the strength of a schema alone, and none on the
> strength of a simulator alone where the requirement names a real integration.

Coverage is enforced by `scripts/validate_docs.py`, which fails if any SRS identifier is
missing here or if an identifier appears here that the SRS does not define.

**Component key:** G1–G12 and S1–S2 are nodes and services from
[`agent-topology.md`](./agent-topology.md). Others: `EDGE` API service · `NORM` normaliser ·
`ORCH` orchestrator · `REG` tool registry · `GATE` policy gate · `BROKER` tool broker ·
`KNOW` knowledge service · `MEM` memory services · `HARN` evaluation harness ·
`OTEL` observability · `DB` PostgreSQL · `UI` dashboard · `CI` pipeline · `PROC` project process.

---

## 1. Ingestion and correlation

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-ING-01 | EDGE, NORM | 5 | API + contract tests | Authenticated ingestion accepts valid alerts, rejects unauthenticated |
| FR-ING-02 | BROKER, adapters | 5, 10 | Adapter contract tests vs simulators | All six evidence domains reachable through typed adapters |
| FR-ING-03 | NORM, DB | 5 | Duplicate-delivery test | Redelivered alert creates no second incident |
| FR-ING-04 | NORM | 5 | Schema tests per source | Every source maps to canonical `Alert` with tenant/service/environment resolved |
| FR-ING-05 | NORM, DB | 5 | Fault injection with malformed payloads | Every rejected alert is in the dead-letter store with a reason; zero silent drops |
| FR-COR-01 | G1 | 5 | Scenario 7 (alert storm) | 12 related alerts produce 1 incident |
| FR-COR-02 | G1 | 5 | Ablation: model assist disabled | Correlation still functions deterministically; model never creates a group alone |
| FR-COR-03 | G1, DB | 5 | Audit inspection | Every correlation decision records its signals and is replayable |
| FR-COR-04 | G1, ORCH | 5 | Late-alert test | Late alert joins the open incident and emits `incident.joined` |

## 2. Incident lifecycle

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-INC-01 | ORCH | 4 | State-machine conformance tests | Every state and transition matches `failure-and-recovery.md` §2 |
| FR-INC-02 | ORCH, DB | 4 | Kill-and-resume at every checkpoint | Resume with zero duplicated side effects |
| FR-INC-03 | G2, ORCH | 4 | Reachability analysis + scenario suite | Every run reaches exactly one of the five terminal states |
| FR-INC-04 | ORCH, DB | 3, 4 | Projection test | Incident status equals the projection of its events (INV-2) |
| FR-INC-05 | S1 | 5 | Scenario suite | Timeline produced for every incident |
| FR-INC-06 | S1, DB | 5 | Determinism + FK test | Identical events yield an identical timeline; every entry cites a source (INV-3) |

## 3. Investigation and reasoning

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-INV-01 | G3 | 7 | Tool-call efficiency vs a fixed-script baseline | Planner selects steps from declared gaps, not a fixed order |
| FR-INV-02 | G3, G5 | 7 | Trace inspection on scenarios | Hypothesise → gather → critique → revise → stop is observable in the trace |
| FR-INV-03 | ORCH budget supervisor | 4 | Budget-exhaustion tests for each of the five limits | Each limit independently terminates the run |
| FR-INV-04 | G3, ORCH | 4, 7 | Non-convergence scenario | Limit exhaustion yields a partial result, never a stall |
| FR-INV-05 | G4 (6 strategies) | 7 | Per-strategy evaluation | All six domains produce evidence against golden labels |
| FR-INV-06 | BROKER, REG | 4 | Credential test: investigation attempts a write | Denied *by the target system*, not only by our code (SI-4) |
| FR-INV-07 | G3, DB | 7 | Replay test | Every step persisted with rationale, tool, IO and cost; decision replayable |
| FR-INV-08 | G3 | 7 | Redundant-call-rate metric | Redundant calls below the baseline established in Phase 11 |
| FR-EVD-01 | G4, BROKER | 4, 7 | Type inspection + provenance tests | `VERIFIED_FACT`, `RETRIEVED`, `MODEL_CLAIM` are distinct persisted types |
| FR-EVD-02 | BROKER, G4 | 7 | Citation re-derivation test | A human can re-run any citation and obtain the same evidence |
| FR-EVD-03 | KNOW, G4 | 6 | Citation validity metric | 100% of retrieved evidence carries a resolvable citation |
| FR-EVD-04 | G5, MEM | 6, 7 | Scenario 10 (stale wrong runbook) | Current evidence outranks contradicting history |
| FR-RCA-01 | G5 | 7 | RCA accuracy @1/@3 vs labels | Ranked hypotheses with evidence, confidence and counter-evidence |
| FR-RCA-02 | G5, DB | 7 | Fabricated-ID test (A7) | A hypothesis citing a non-existent evidence ID is dropped before ranking (INV-5) |
| FR-RCA-03 | G5 | 7 | Confidence calibration curve | Confidence reported with its basis; calibration error measured |
| FR-RCA-04 | G5, G3 | 7 | Scenario 8 (no discoverable cause) | Terminates in uncertainty rather than asserting a cause |

## 4. Knowledge and memory

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-KNW-01 | KNOW | 6 | Ingestion pipeline tests | Four source types ingested, chunked and indexed with metadata |
| FR-KNW-02 | KNOW | 6 | Scope-filter tests | Retrieval scoped by service and environment as query predicates |
| FR-KNW-03 | KNOW | 6 | ACL property tests (A12) | Zero out-of-scope chunks returned; filter applied pre-search |
| FR-KNW-04 | KNOW | 6, 11 | Retrieval A/B ([ADR-0008](../adr/0008-rag-retrieval-strategy.md)) | Reranking enabled only on a measured improvement |
| FR-KNW-05 | KNOW, DB | 6 | Versioning tests | Documents superseded not overwritten (INV-14); staleness visible to consumers |
| FR-KNW-06 | HARN | 6, 11 | Retrieval evaluation set | Recall@k, Precision@k, nDCG measured and reported |
| FR-KNW-07 | GATE, KNOW | 4 | Injection corpus A1–A4 | Zero authorization effect from retrieved content (SI-3) |
| FR-MEM-01 | MEM, DB | 6 | Schema and lifetime tests | Five tiers physically separated with distinct write authority |
| FR-MEM-02 | G12, MEM | 6 | Ungated-write test (SI-15) | Memory write without an approval record is rejected |
| FR-MEM-03 | G12, HARN | 6, 11 | Single-incident guard | `support_count = 1` never auto-promotes |
| FR-MEM-04 | G12, G10, DB | 6, 8 | Real G10 promotion + forged-lineage tests | Every promotion has human approval and creates a version (INV-15); T5 verified outcomes also resolve an action-bound baseline and independent post-read provenance |

## 5. Remediation, policy, approval, verification

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-REM-01 | G6, G9 | 8 | Static analysis | No code path from proposer to executor bypassing the gate (SI-1) |
| FR-REM-02 | G6, REG | 8 | Schema tests | All twelve §6 fields present or the proposal is invalid |
| FR-REM-03 | REG, GATE | 4, 8 | Registry lint + tier tests | Every action carries a registry-assigned tier; tiers are not model-settable |
| FR-REM-04 | GATE | 8 | Ambiguity-trigger tests | Each of the five ambiguity conditions forces approval or denial |
| FR-REM-05 | REG, GATE | 4 | Static check (SI-2) | No write tool exposes a free-form command/script/manifest field |
| FR-REM-06 | REG, G6 | 8 | Unregistered-tool test (A5) | Rejected, never repaired |
| FR-REM-07 | BROKER | 4, 8 | Scope-widening test (A6) | Scope resolved from context; arguments cannot widen it |
| FR-REM-08 | BROKER, DB | 8 | Duplicate/concurrent delivery (A9) | Single application; unique idempotency key per tenant (INV-12) |
| FR-REM-09 | BROKER | 8 | State-drift test (SI-7) | Action approved against stale state fails closed |
| FR-POL-01 | GATE | 4 | Static check + adversarial suite | Gate is the sole authorization path and contains no model call |
| FR-POL-02 | GATE | 4 | Type inspection + A1–A4 | Gate input type cannot carry `RETRIEVED` or `MODEL_CLAIM` content |
| FR-POL-03 | GATE, DB | 4 | Audit reconciliation | Exactly one `policy_decision` per action, including allows (INV-6) |
| FR-APR-01 | GATE, G8 | 8 | Autonomy matrix tests | No R2 autonomous; no production R1 without approval |
| FR-APR-02 | G8, ORCH | 8 | Restart-during-wait test | Approval wait survives restart and redeployment |
| FR-APR-03 | G8 | 8 | Expiry test | Expiry escalates; never executes, never hangs |
| FR-APR-04 | G8, DB | 8 | Audit inspection | Approver, decision, justification, timestamp recorded immutably |
| FR-APR-05 | G8, BROKER | 8 | Post-approval mutation (A8) | Hash mismatch invalidates the approval (SI-6, INV-9) |
| FR-VRF-01 | G10 | 8 | Verification accuracy vs labels | Every executed action is independently verified |
| FR-VRF-02 | G10 | 8 | False-claim test (A11) | Verifier verdict unchanged by an executor success claim (SI-9) |
| FR-VRF-03 | G6, G10, DB | 8 | Criteria-hash test | Criteria frozen at proposal; mismatch rejected (INV-11) |
| FR-VRF-04 | G9, G10, ORCH | 8 | Scenario 12 | Verification failure triggers compensation then escalation |

## 6. Collaboration, postmortem, integrations

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-CLB-01 | S2, BROKER | 10 | Adapter contract tests vs simulators | Slack, Teams, PagerDuty, Jira operate through typed adapters |
| FR-CLB-02 | S2 | 10 | Delivery-failure injection | Notification failure never fails the incident; no duplicate user-visible messages |
| FR-CLB-03 | G8, EDGE | 10 | Spoofed-approval test (T08) | Chat identity must resolve to an RBAC principal before carrying authority |
| FR-PMT-01 | G11 | 16 | Scenario suite | Postmortem drafted for every resolved incident |
| FR-PMT-02 | G11 | 16 | Citation-validity metric | Uncited claims stripped; draft never auto-published |
| FR-INT-01 | BROKER, adapters | 10 | Contract tests per integration | All nine §14 integrations behind adapter interfaces |
| FR-INT-02 | Simulators | 4, 10 | Determinism tests | Every adapter has a simulator producing identical output for identical fixtures |
| FR-INT-03 | HARN, CI | 11, 14 | CI runs with network egress disabled | Full suite passes with no live infrastructure |
| FR-INT-04 | CI, config | 14 | Build inspection | Simulator providers unreachable in a production build (PR-7) |

## 7. Evaluation

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-EVL-01 | HARN | 2, 4, 11 | Architecture review + API tests | Evaluation has its own API, data model and CI gate |
| FR-EVL-02 | HARN | 4, 11 | Corpus review | Twelve golden archetypes + replay + adversarial, all labelled |
| FR-EVL-03 | HARN | 4, 11 | Self-test on known-bad traces | All thirteen deterministic checks detect their target defect |
| FR-EVL-04 | HARN | 11 | Judge calibration vs human labels | Multi-judge with disagreement flagged, never averaged away |
| FR-EVL-05 | HARN, OTEL | 11 | Version-comparison test | Per-scenario, per-metric deltas produced against a baseline |
| FR-EVL-06 | HARN | 11 | Metric self-tests | All 12 metrics §9 names computed and reported, within the 19-metric catalogue |
| FR-EVL-07 | PROC, HARN | All | Documentation review + reporting rules | No unmeasured figure appears in any artifact |
| FR-EVL-08 | HARN, PROC | 11 | Loop walkthrough on a real regression | All seven loop stages executed and recorded |
| FR-EVL-09 | HARN, DB | 4, 11 | Behaviour-version test | Any element of the version tuple changing forces re-evaluation |
| FR-EVL-10 | CI | 14 | Gate test with a deliberately regressed build | Release blocked on safety-metric regression |
| FR-EVL-11 | OTEL, HARN | 4 | Round-trip test | A production incident becomes an evaluation case with no transformation |

## 8. Observability

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-OBS-01 | OTEL | 4, 12 | Span-coverage test | All fifteen span types emitted across the ten §11 areas |
| FR-OBS-02 | OTEL, Grafana | 12 | Dashboard review | All §11 exposures present with SLO/SLI dashboards |
| FR-OBS-03 | OTEL, HARN | 4, 12 | L2 replay test | Trace + fixtures + seeds reproduce routing exactly |
| FR-OBS-04 | OTEL, DB | 4 | Join test | One identifier chain links incident, trace, evidence, action, evaluation |
| FR-OBS-05 | OTEL | 4 | Secret-scan over traces and logs | Zero secret material in any telemetry (SEC-I6) |

## 9. API and administration

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| FR-API-01 | EDGE | 9 | Authorization tests per surface | Five surfaces with independent authorization |
| FR-API-02 | EDGE, DB | 3, 9 | Cross-tenant property tests | Zero cross-tenant data on any endpoint; tenant never from a parameter |
| FR-API-03 | UI | 9 | E2E tests | Dashboard shows incidents, evidence, hypotheses, timeline, actions, approvals |
| FR-API-04 | EDGE | 9 | Role-matrix tests | Admin surfaces require step-up auth and separate roles |

## 10. Security (non-functional)

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| NFR-SEC-01 | EDGE | 2, 13 | AuthN tests per surface | No non-public surface reachable unauthenticated |
| NFR-SEC-02 | EDGE, GATE | 2, 13 | Role-matrix tests | RBAC governs all operations including approval |
| NFR-SEC-03 | DB, KNOW, EDGE | 3, 13 | RLS backstop test | With app scoping removed, RLS still blocks cross-tenant access |
| NFR-SEC-04 | BROKER | 4, 13 | Credential-scope tests | Every credential is the narrowest that works; none ambient |
| NFR-SEC-05 | REG, GATE, BROKER | 4 | Four-layer restriction tests | Model cannot invoke, widen, or authorize outside its menu |
| NFR-SEC-06 | BROKER, OTEL, CI | 2, 13 | Secret scanning in repo, traces, prompts, DB | Zero secret material anywhere outside the secret manager |
| NFR-SEC-07 | Infra, DB | 13, 14 | Config audit | TLS 1.3 external, mTLS internal, encryption at rest |
| NFR-SEC-08 | BROKER, DB | 4, 13 | Audit reconciliation | 100% of executions and authorization decisions audited (SI-13) |
| NFR-SEC-09 | EDGE, NORM, KNOW | 5, 13 | Fuzz and schema tests | All external input validated and size-capped |
| NFR-SEC-10 | GATE, KNOW | 4, 13 | Injection corpus A1–A4 | Zero authorization effect; detection recorded as signal |
| NFR-SEC-11 | KNOW, G4 | 4, 6 | Provenance tests | Logs, runbooks and tickets always labelled `RETRIEVED` |
| NFR-SEC-12 | EDGE | 13, 15 | Flood tests | Rate limits enforced per tenant, source and user |
| NFR-SEC-13 | CI | 14 | Pipeline verification | Dependency, SAST and container scanning gate the build |
| NFR-SEC-14 | DB, PROC | 13 | Retention job tests | Each data class expires per the documented policy |
| NFR-SEC-15 | BROKER, secret manager | 13 | Credential isolation tests | Connector credentials scoped per tenant, never shared |

## 11. Reliability, performance, quality (non-functional)

| Req | Component | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| NFR-REL-01 | ORCH, DB | 4 | Kill-and-resume at every checkpoint | Zero duplicated side effects on resume |
| NFR-REL-02 | BROKER | 8 | Idempotency tests per write tool | Duplicate execution applies once |
| NFR-REL-03 | ORCH, BROKER | 4 | Retry-classification tests (C1–C6) | Only C1/C2 retried; C4 reconciles; C5/C6 never retried |
| NFR-REL-04 | ORCH | 4 | Timeout-layer tests | Each of the six timeout scopes fires before its parent |
| NFR-REL-05 | NORM, ORCH, BROKER | 4, 5 | Dead-letter tests | All four dead-letter stores capture with reason and are replayable |
| NFR-REL-06 | NORM, DB | 5 | Duplicate tests across six duplicate classes | Each absorbed without side effect |
| NFR-REL-07 | G4, G3 | 7 | Adapter-outage injection | Investigation degrades and records the limitation; does not abort |
| NFR-REL-08 | ORCH, G4 | 7 | Provider and API outage injection | Pause, failover or escalate; never destructive failure |
| NFR-REL-09 | ORCH | 15 | Recovery-time measurement | Workflow resumes within 60 s of orchestrator recovery *(budget, AS-04)* |
| NFR-PRF-01 | EDGE, G1 | 15 | Load test | p95 ingestion-to-correlation under 5 s *(budget)* |
| NFR-PRF-02 | ORCH, G3, G4, G5 | 15 | Scenario timing | p95 to first hypothesis under 3 min on golden scenarios *(budget)* |
| NFR-PRF-03 | ORCH budget supervisor | 4, 15 | Budget tests | No run exceeds its configured budget; exhaustion terminates cleanly |
| NFR-PRF-04 | EDGE, DB | 15 | Sustained-load test | 50 alerts/second without queue-depth growth *(budget)* |
| NFR-PRF-05 | OTEL | 4, 12 | Cost-reconciliation test | Token and cost measured and reported per run |
| NFR-OBS-06 | OTEL, HARN, ORCH | 4, 12 | Property review + tests | All eight §11 harness properties demonstrable |
| NFR-MNT-01 | PROC, ADRs | 2 onward | ADR review | Every major choice has an ADR with alternatives and trade-offs |
| NFR-MNT-02 | PROC | All | ADR review | No technology adopted without a stated non-keyword justification |
| NFR-MNT-03 | CI | 14 | Pipeline verification | All nine §18 gates enforced |
| NFR-MNT-04 | PROC, repo | 0 onward | `scripts/check_repo_hygiene.py`, review | Clean structure, reproducible setup, clean history |
| NFR-PRT-01 | Infra | 14 | Deployment smoke tests | Docker build, Kubernetes deploy, Terraform apply all succeed |
| NFR-PRT-02 | Simulators, Compose | 4, 14 | Offline run | Full stack runs locally with no live infrastructure and no egress |
| NFR-TST-01 | CI | 17 areas, phases 4–15 | Coverage review | All fifteen §17 test categories present and running |
| NFR-TST-02 | PROC, CI | All | Gate review | Release requires failure-path and adversarial suites, not only happy path |
| NFR-TST-03 | CI | 4 onward | Suite review | Every safety invariant SI-1…SI-15 has an adversarial test |

## 12. Constraints

| Constraint | Enforced by | Phase | Validation | Acceptance criterion |
|---|---|---|---|---|
| CON-01 | PROC | All | Phase-gate review | No major implementation begins before its architecture is approved |
| CON-02 | PROC, CI | All | Code review + `check_repo_hygiene.py` | No fake integrations, metrics, hard-coded success paths or placeholder logic |
| CON-03 | CI, config | 14 | Build inspection | Simulators unreachable outside test configuration |
| CON-04 | ADR-0001 | 2, 4 | Topology review | Every node justified against the two-discriminator test |
| CON-05 | ADRs 0002–0011 | 2 | ADR review | Baseline stack adopted or deviation justified in an ADR |
| CON-06 | ADRs 0002, 0003, 0005, 0006, 0007, 0010 | 2 | ADR review | All eight named technologies evaluated, not assumed |
| CON-07 | PROC, roadmap | All | Phase-plan review | Security, observability, evaluation and failure handling ship with features |

---

## 13. Master specification section coverage

Confirmation that no numbered section stating a product requirement is unrepresented.

| §  | Topic | Traced via |
|---:|---|---|
| 2 | Product definition | FR-ING, FR-COR, FR-INV, FR-RCA, FR-REM, FR-VRF, FR-PMT |
| 3 | Problem and use cases | FR-COR-01, FR-INV-05, FR-RCA-01, FR-KNW-01, FR-INC-05, FR-REM-03, FR-APR-01, FR-REM-07, FR-VRF-01, FR-CLB-01, FR-INT-02, FR-MEM-02 |
| 4 | Agentic architecture | CON-04, ADR-0001, all node requirements |
| 5 | Planning and bounded reflection | FR-INV-01…04, FR-INC-03, FR-RCA-04 |
| 6 | Safety-first remediation | FR-REM-01…09, FR-POL-01…03, FR-APR-01 |
| 7 | Tool registry and MCP boundary | FR-REM-06, FR-REM-07, NFR-SEC-05, ADR-0003 |
| 8 | Memory and RAG | FR-KNW-01…07, FR-MEM-01, FR-EVD-01, FR-EVD-04 |
| 9 | Evaluation harness | FR-EVL-01…07 |
| 10 | Evaluation-driven improvement | FR-EVL-08, FR-EVL-09, FR-MEM-03 |
| 11 | Observability and harness | FR-OBS-01…05, NFR-OBS-06 |
| 12 | Durable workflows and resilience | FR-INC-01, FR-INC-02, NFR-REL-01…08, ADR-0002 |
| 13 | Baseline tech stack | CON-05, CON-06, ADRs 0002–0011 |
| 14 | Integrations | FR-INT-01…04, FR-CLB-01 |
| 15 | Security and governance | NFR-SEC-01…15, FR-KNW-07 |
| 16 | Required documentation | This package; see [`../README.md`](../README.md) |
| 17 | Testing | NFR-TST-01…03 |
| 18 | CI/CD quality gates | NFR-MNT-03, FR-EVL-10 |
| 19 | Implementation roadmap | Phase column throughout; deviations justified in the package §O |
| 20 | Working rules | CON-01, CON-02, CON-03, CON-07, NFR-MNT-02, NFR-MNT-04 |
| 21 | Per-feature output | PROC — required for every feature from Phase 3 |
| 22 | Portfolio positioning | FR-EVL-07, PRD §D.5 |
| 23 | This package | Delivered by the Architecture Package |
| 24 | Final quality bar | Definition of Done, package §Q |

Sections 1 and 24 are role and quality-bar statements governing how the project is run; they
are traced to process rather than to product components.

## Phase 14 delivery evidence mapping

| V3 boundary | Implementation | Acceptance evidence |
|---|---|---|
| Sections 13, 18: reproducible builds | Root/frontend Dockerfiles, hash locks, standalone Next.js | Actual image builds; UID/runtime checks; Trivy final-image scans and bound SBOMs |
| Sections 15, 18: release security | `scripts/security_gate.py`, pinned Actions/tools, unprivileged build vs minimal publish/attest jobs, checksummed artifact hand-off, `scripts/verify_release_attestation.py`, step-scoped kubeconfig | Required container scan; malformed/missing/wrong-image mutation tests; workflow trust-graph tests; attestation policy tests (repo/workflow/ref/revision/digest, real `gh` 2.98 JSON); publish identity binding executed against manifest/OCI-index fixtures and a real registry; repository security suite |
| Sections 11, 12, 18: deployment | Kustomize base/local overlays, migration Job, probes, network policies, Terraform PSA `restricted`, CIDR-union validation, `scripts/deploy_release.py` | Disposable kind: PSA rejection, fail-fast migration through the shared orchestrator with guard-mutation control, sequential redeployments (same release, changed Job template, failed then fix-forward, finalizer-delayed delete, active-migration refusal), automatic post-rollout smoke, API-outage frontend probe behavior, failed-rollout recovery; Cilium allow/deny probes; frontend health contract |
| Sections 16, 19: infrastructure ownership | Terraform namespace and tokenless identities; ADR-0031 | fmt/init/validate and local apply; no cloud or raw-secret state claims |
| Sections 17, 18: quality/evaluation | Reusable quality workflow plus trusted release | Full pytest; golden 18-scenario simulator and strict replay; frontend and observability checks |
| Sections 20, 24: truthful operating boundary | Deployment guide and CI/CD architecture | Remote production, TLS, cloud capacity and disaster recovery remain unmeasured |
