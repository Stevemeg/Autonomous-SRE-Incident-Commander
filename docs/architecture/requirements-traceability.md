# Requirements Traceability Matrix

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
| FR-KNW-01 | `KnowledgeIngestionService`: canonicalize → structure-aware chunk → deterministic embed → transactional commit; idempotent re-ingestion (identical content re-import writes nothing); typed rejection for oversized/invalid/empty documents. One source type (imported document text) is exercised; connector-specific fetch is out of scope for Phase 6 |
| FR-KNW-02 | `KnowledgeRetriever`'s single disposition CTE filters by service/environment/document-type *before* ranking; `tests/knowledge/test_retrieval_db.py::TestScopeAndAuthorization` proves wrong-service and wrong-environment scope yield zero results, not a wrong one |
| FR-KNW-03 | ACL evaluated in the same pre-ranking CTE; `test_acl_label_hides_the_document_without_the_clearance` and the golden-corpus unauthorized-rate test (`TestUnauthorizedAndStaleRatesAreZero`, measured 0 unauthorized hits across the probe set) confirm zero out-of-scope exposure; mutation-tested (see completion report) — forcing the ACL predicate to `TRUE` makes both tests fail |
| FR-KNW-04 | [ADR-0008](../adr/0008-rag-retrieval-strategy.md) status raised to Accepted on this evidence: hybrid (lexical + vector, versioned RRF fusion) is the only mode shipped; no reranker exists in the codebase — there is nothing to have "enabled only on a measured improvement" because no measurement has shown a need |
| FR-KNW-05 | Supersede-then-insert under a per-source advisory lock plus a partial unique index (`uq_knowledge_document_current_source`) enforce INV-14; `TestVersioning` in `test_ingestion_db.py` proves old chunk text survives supersession and content returning to an earlier state creates a new version rather than reusing one; retrieval and replay both prefer current and can reproduce a historical version exactly |
| FR-KNW-06 | `tests/knowledge/test_retrieval_evaluation.py`: twelve-document, eighteen-query golden corpus (P6-09 added a lexical-only holdout, a hard-negative distractor and an out-of-vocabulary paraphrase holdout). Measured this run: recall@5 = 1.000, precision@5 = 0.730, MRR = 0.933 over the ten gradeable queries (ambiguous, the hard-negative distractor and the out-of-vocabulary holdout excluded from the average by design, each with its own dedicated test instead). The out-of-vocabulary holdout is measured and asserted to miss - the deterministic embedding is a hashed bag of tokens and a fixed concept table, not a semantic model, and this suite says so rather than omitting the case. These are architecture-validation numbers on a small corpus that now deliberately includes a hard negative — not a claim about any other corpus or a production benchmark |
| FR-KNW-07 | `tests/security/test_knowledge_prompt_injection.py` ingests a document containing fake SYSTEM headers, an "ignore all previous instructions" payload, a forged citation, and forged `<<<UNTRUSTED_DATA...UNTRUSTED_DATA>>>` fence markers, then runs it through the real broker → real manifest verification → real `HYPOTHESIS_PROMPT.render()`. Confirmed: the hostile text is retrievable (detection is a signal, never a filter) and confined to the untrusted section; the forged fence markers are neutralised so exactly one real fence renders; the forged citation does not resolve |
| FR-MEM-01 | `MemoryCategory` (five values) enforced by `asic.memory.policy.evaluate()`: `working_state`/`incident_history`/`model_inference` are refused outright (T1/T2/T3 are not writable through this path at all — T3 already has its own append-only path); only `operational_knowledge` and `verified_outcome` can become a proposal, each requiring a different reference shape |
| FR-MEM-02 | `MemoryEntry.promotion_id` is NOT NULL under the `governed_entry` check constraint (NOT VALID, applies to new rows); `TestMemoryIsNotDirectlyWritable` proves a direct INSERT bypassing `MemoryGovernanceService.decide()` is rejected by the database itself, not merely by application code |
| FR-MEM-03 | `support_count()` counts independent incidents; the policy and the entry-construction code do not special-case `support_count == 1` into automatic promotion — every promotion, single-incident or not, still requires the same human decision. No auto-promotion path exists to guard against |
| FR-MEM-04 | `MemoryGovernanceService.decide()`: human-only, not-the-proposer, permission-checked (`memory.promotion.decide`, seeded by migration `0008`), re-evaluates the policy at decision time; every decision — approve, decline, and every rejection at propose time — is recorded in the append-only `memory_write_decision` table. Mutation-tested: disabling the VERIFIED-verdict requirement in `evaluate()` makes `test_only_a_verified_verdict_counts` fail for both `not_verified` and `inconclusive` |

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

- **Status:** Authored — Architecture Package. **Most requirements below are not implemented**; the note beneath says exactly which are, and on what evidence.
- **Requirement definitions:** [`../prd/SRS.md`](../prd/SRS.md)
- **Master specification:** [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)

Every requirement identifier defined in the SRS appears here exactly once, mapped to the
architecture component that will satisfy it, the phase in which it is built, how it will be
validated, and the acceptance criterion.

> **Implementation status.** Phases 3 and 4 are complete; every other phase is not
> started. Rather than repeat a status column 138 times, the rule is: a requirement is
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
> | Observability (FR-OBS-01..04) | One trace model, spans persisted with the work they describe, correlation identifiers, redaction at emission | Exporters, dashboards, SLOs — Phase 12 |
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
| FR-MEM-02 | G12, MEM | 6 | Ungated-write test (SI-12) | Memory write without an approval record is rejected |
| FR-MEM-03 | G12, HARN | 6, 11 | Single-incident guard | `support_count = 1` never auto-promotes |
| FR-MEM-04 | G12, DB | 6 | Promotion workflow test | Every promotion has an approval and creates a version (INV-15) |

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
| NFR-SEC-08 | BROKER, DB | 4, 13 | Audit reconciliation | 100% of executions and authorization decisions audited (SI-10) |
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
| NFR-TST-03 | CI | 4 onward | Suite review | Every safety invariant SI-1…SI-12 has an adversarial test |

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
