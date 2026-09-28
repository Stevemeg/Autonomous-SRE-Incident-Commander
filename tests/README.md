# `tests/` — Test suites

2,472 tests after the Phase 16 closure correction, all passing on a fresh database with no skips
([PHASE16_CLOSURE_RESULTS.md](../docs/testing/PHASE16_CLOSURE_RESULTS.md)). Master specification section 17's
fifteen categories map onto the directories below; section 20's rule — a working happy path is
not completion — is why most suites attack the system rather than exercise it.

| Directory | What it proves | Needs |
|---|---|---|
| `domain/`, `contracts/` | Pure rules: state machine, budgets, idempotency keys, node contracts | nothing |
| `db/` | Schema contracts, RLS, append-only history, migration history and upgrade paths | PostgreSQL |
| `tools/` | Broker pipeline: registry, capability resolution, refusals, provenance, audit | PostgreSQL |
| `orchestration/` | Kernel, checkpoint/resume, planner bounds, reflection, termination, remediation graph | PostgreSQL |
| `ingestion/` | Normalisation, correlation, durable receipts, dispatch | PostgreSQL |
| `knowledge/`, `memory/` | Governed ingestion, retrieval scope/ACL, evaluation corpus, promotion governance | PostgreSQL |
| `api/` | Authentication, RBAC, tenant scoping, idempotency, bounds | PostgreSQL |
| `integrations/` | Native adapters against deterministic local HTTP servers, crash recovery | PostgreSQL |
| `evaluation/` | Harness, evaluators, comparison, gate, replay | PostgreSQL |
| `observability/` | Metric catalogue, tracing, config artifacts, alert/runbook links | some: PostgreSQL |
| `security/` | Phase 13 controls and Phase 15 campaigns: injection, tool abuse, tenant, auth, SSRF, fuzz, secret leak, redaction, retention | PostgreSQL |
| `resilience/` | Database stress, dependency faults, model failure, crash/resume, event storms, retries/bulkhead, resource bounds, pool deadlocks | PostgreSQL |
| `e2e/` | Every scenario against its expectation; Phase 15 scenarios A–H | PostgreSQL |
| `worker/` | Phase 16 closure: the deployed worker - alert-to-postmortem flow through the API, two-worker race, crash recovery, SIGTERM drain, database outage, probes, configuration refusals, separation of duties, import without the simulator package | PostgreSQL |
| `postmortem/` | Phase 16 closure: G11 golden resolved incident and negative controls (unsupported claims, injected publish instruction, cross-tenant, ineligible, replay/versioning, model failure, database draft-only enforcement) | PostgreSQL |
| `packaging/` | Images, manifests, workflows, deploy orchestrator, renderer, chaos-suite contract | some: `bash`, `jq` |

Run everything:

```bash
export ASIC_TEST_DATABASE_URL=postgresql+psycopg2://<owner>:<password>@localhost:55432/asic  # migrated to head
python -m pytest
```

Database-backed tests skip cleanly without `ASIC_TEST_DATABASE_URL`. Deployment smoke, chaos and
load are scripts rather than pytest suites because they need Docker and minutes of wall clock:
`scripts/deployment_smoke.py --chaos`, `scripts/load_harness.py`, `scripts/demo.py`.
