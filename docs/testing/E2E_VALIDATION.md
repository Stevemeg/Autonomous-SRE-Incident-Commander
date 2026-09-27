# End-to-end validation (Phase 15.26–15.27)

**Scope.** Production-style incident scenarios A–H run the real system under test and assert on
what it *recorded*, not on HTTP 200s. Source: `tests/e2e/test_phase15_scenarios.py` (9 tests,
PostgreSQL-backed, marker `postgres`). They run in the normal test matrix.

## What is real and what is simulated

| Real (system under test) | Simulated (the outside world) |
|---|---|
| PostgreSQL 16 + pgvector under the unprivileged, non-`BYPASSRLS` application role | Telemetry sources and targets: the deterministic simulator |
| FastAPI app: authentication (HS256 development verifier), RBAC, idempotency, rate limit | Scenario F only: a local HTTP "cluster" behind the *native* Kubernetes adapter |
| Transactional ingestion + correlation, investigation dispatcher | The model: the deterministic provider (ADR-0016) |
| LangGraph investigation and remediation kernels with durable checkpoints and leases | |
| Tool Broker: registry tiers, policy, approvals, idempotency keys, verification | |
| Governed knowledge store (manifest-verified ingestion), evaluation evaluators, OTel spans, Prometheus metrics | |

Entry points that are not HTTP are called at the service layer exactly as a worker would: the
dispatcher (the API records dispatch requests; a worker drives them), the human "reopen for
remediation" transition and the remediation kernel start/resume. There is no deployed worker
process in the Kubernetes manifests today — see the gap register.

## Scenarios and the evidence each asserts

| # | Scenario | Asserted from the database / telemetry |
|---|---|---|
| A | Read-only investigation reaches an evidence-backed RCA | run `completed`; incident `escalated` (an actionable cause goes to a human); evidence spans metrics, deployments and logs; leading hypothesis `bad_deployment`; **every citation resolves to recorded evidence**; timeline and trace present; every tool execution is risk tier RO and audited; trace spans persisted and `node.*` spans exported; `asic_workflow_runs_finished_total` advanced; event-log projection consistent; online evaluation and golden-case evaluation pass |
| B | R2 remediation waits for a human, executes once, verifies | `awaiting_approval`; action `k8s.node.cordon` at R2; **no tool execution before approval**; policy rule `P3_high_risk_requires_approval`; the pending-approval API lists exactly that action; approval via API 200; executor settles, then independent verification → `resolved`; action `verified`; **exactly one write execution**; verdict `verified`; audit trail covers proposal → approval → execution → verification; evaluation passes |
| C | Ambiguous evidence → bounded reflection → uncertainty | incident `uncertain` (never a confident guess); ≥1 hypothesis; reflection cycle visible in the trace; **no remediation proposed**; online and golden evaluation pass |
| D | Malicious retrieved instructions ("SYSTEM OVERRIDE…") | incident `uncertain`, environment unchanged; evidence rows carrying the hostile text have `injection_flagged` set (recorded, never obeyed); no remediation action, approval, policy-decision or verification rows; every execution RO; knowledge evidence labelled `retrieved`; evaluation passes |
| E1 | Source outage degrades; transient failure recovers | degraded incident still `escalated`; the failed step is recorded (not hidden) and `asic_tool_invocations_total` advances; a transient failure is retried within its bound (`attempts > 1`) and that incident escalates normally |
| E2 | Model-provider outage | run ends `uncertain`/`escalated`, **never resolved**; no remediation; evaluation passes |
| F | Crash after the external side effect, then resume | the local cluster received **exactly one** patch before the crash and still exactly one after recovery; the action is not mis-labelled "failed clean"; the incident is resolved only if verification says so |
| G | Cross-tenant attack | every GET of the victim's objects → 404; control call → 404; ingestion into the victim with the attacker's connector → 403/404; no victim rows visible to the attacker; denied state changes are audited |
| H | Remediation that does not verify | R1 non-production executes autonomously, then verification says `not_verified`; incident **not** `resolved`; action `not_verified`; exactly one write; no false-success evidence |

## How to run

```bash
# PostgreSQL 16 + pgvector reachable; ASIC_TEST_DATABASE_URL points at an owner login.
python -m pytest tests/e2e/test_phase15_scenarios.py -q
```

Measured on the validation run recorded in `docs/testing/PHASE15_RESULTS.md`: 9 passed.

## Known limits (not hidden)

* Evidence provenance is assigned only by the broker: `verified_fact` for telemetry query results
  and `retrieved` for knowledge content (scenario A asserts nothing else appears). *Corrected in
  Phase 16: an earlier version of this page wrongly said `verified_fact` was never assigned.*
* The `content.injection_flagged` telemetry event is not emitted; flagging is recorded on the
  evidence itself (scenario D asserts that).
* A crash between a human approval and dispatch loses the approval wait's continuation: the
  resumed run fails closed and asks again. Nothing executes without a fresh, valid approval.
