# Resume evidence

Bullet points that the repository can defend line by line, each with the evidence a reviewer can
open. Wording is deliberately factual: no user counts, revenue, uptime or "production" claims,
because none exist. Every performance figure is labelled local.

## Suggested bullets

- Designed and built an agentic SRE incident commander (Python, FastAPI, LangGraph, PostgreSQL +
  pgvector, Next.js) in which the model investigates through a permission-scoped tool broker but
  every action passes a deterministic policy gate, a hash-bound human approval and an independent
  verifier. *Evidence:* [remediation safety policy](../architecture/remediation-safety-policy.md),
  E2E scenarios B/F/H.
- Enforced multi-tenant isolation at the database with row-level security, composite tenant
  foreign keys and a least-privilege application role, verified by a schema-wide adversarial
  campaign against every tenant-scoped table. *Evidence:* `tests/security/test_tenant_campaign.py`.
- Built durable, bounded workflows with checkpointing, leases and effect-level idempotency; a crash
  matrix over 11 kill points shows no side effect is ever repeated. *Evidence:*
  `tests/resilience/test_crash_resume_matrix.py`.
- Wrote a load harness and fault-injection suites that exposed two connection-pool deadlocks
  (96 % client timeouts under a 96-client burst); fixed both with regression tests and added an
  ingestion bulkhead, after which the same burst completed with 0 timeouts (local benchmark).
  *Evidence:* [LOAD_AND_PERFORMANCE.md](../testing/LOAD_AND_PERFORMANCE.md).
- Shipped a supply-chain-gated delivery path: digest-pinned non-root images, Trivy and gitleaks
  gates, CycloneDX SBOMs, OIDC provenance attestation, Kustomize + Terraform, and a kind-based
  deployment smoke with six declared chaos experiments, including a live proof that migrations
  never overlap. *Evidence:* [RESILIENCE_AND_CHAOS.md](../testing/RESILIENCE_AND_CHAOS.md).
- Built an evaluation harness (18 versioned golden scenarios, strict replay, regression gate) and
  kept every reported number labelled as simulated. *Evidence:*
  [evaluation architecture](../evaluation/EVALUATION_ARCHITECTURE.md).
- Hardened against prompt injection with a 40-case versioned corpus planted in every input vector;
  hostile text never changed tools, tenants, tiers or approvals. *Evidence:*
  `tests/security/test_injection_campaign.py`.

## Numbers you may quote, and how to qualify them

| Number | Qualifier to say out loud |
|---|---|
| 2,422 automated tests | "all passing on a fresh database" |
| 131 requirements, 112 satisfied | "the rest partially satisfied, deferred or external, each with a reason" |
| 18/18 evaluation scenarios | "with a deterministic model — it validates the pipeline and safety, not reasoning quality" |
| 0 timeouts in a 96-client burst | "local benchmark, one 2-CPU container, after fixing two deadlocks" |
| ≈ 12 alerts/s ingestion | "per process locally; below the 50/s target I had assumed" |

## Do not claim

Production deployment, real customers or incidents, a live LLM's accuracy, high availability,
compliance certifications, or scale beyond the local benchmarks.
