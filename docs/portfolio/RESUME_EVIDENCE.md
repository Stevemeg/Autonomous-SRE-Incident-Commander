# Resume evidence

Bullet points that the repository can defend line by line, each with the evidence a reviewer can
open. Wording is deliberately factual: no user counts, revenue, uptime or "production" claims,
because none exist. Every performance figure is labelled local, with the commit and image it was
measured on.

## Suggested bullets

- Designed and built an agentic SRE incident commander (Python, FastAPI, LangGraph, PostgreSQL +
  pgvector, Next.js) in which the model investigates only through a permission-scoped tool broker
  and every write passes a deterministic policy gate and an independent verifier; high-risk actions
  and any action in production require a human approval bound to the exact action version, and only
  low-risk reversible (R1) actions in non-production may execute autonomously under the same
  deterministic policy. *Evidence:* [remediation safety policy](../architecture/remediation-safety-policy.md)
  (autonomy matrix, rule P6), E2E scenarios B/F/H.
- Shipped the deployed execution path: a PostgreSQL-backed worker (advisory-lock claims over
  kernel leases, bounded concurrency, graceful SIGTERM drain, probes) that drives an alert through
  investigation, a human-approved remediation, independent verification and an evidence-grounded
  postmortem draft on Kubernetes, with two replicas proving one logical execution per item.
  *Evidence:* `tests/worker/`, kind acceptance in
  [PHASE16_CLOSURE_RESULTS.md](../testing/PHASE16_CLOSURE_RESULTS.md).
- Built a draft-only postmortem author whose facts are assembled from persisted records and whose
  model prose must cite them; a deterministic validator removes uncited, foreign-cited,
  injection-only, unsupported-causal and invented-figure claims, and the database refuses anything
  but an unreviewed draft. *Evidence:* `src/asic/postmortem/`, `tests/postmortem/`.
- Enforced multi-tenant isolation at the database with row-level security, composite tenant
  foreign keys and a least-privilege application role, verified by a schema-wide adversarial
  campaign against every tenant-scoped table. *Evidence:* `tests/security/test_tenant_campaign.py`.
- Built durable, bounded workflows with checkpointing, leases and effect-level idempotency; a crash
  matrix over 11 kill points, and a worker killed mid-run in the demo, show no side effect is ever
  repeated. *Evidence:* `tests/resilience/test_crash_resume_matrix.py`, `tests/worker/`.
- Wrote a load harness and fault-injection suites that exposed two connection-pool deadlocks
  (96 % client timeouts under a 96-client burst); fixed both with regression tests and added an
  ingestion bulkhead, after which the same burst completed with 0 timeouts (local benchmark,
  measured in Phase 15; re-measured on the final image in Phase 16). *Evidence:*
  [LOAD_AND_PERFORMANCE.md](../testing/LOAD_AND_PERFORMANCE.md).
- Built a supply-chain-gated delivery path: digest-pinned non-root images, Trivy and gitleaks
  gates, CycloneDX SBOMs bound to image IDs, Kustomize + Terraform, a GitHub OIDC
  provenance-attestation workflow whose policy and verification script are validated locally
  (never yet run on GitHub), production database TLS enforced at startup, and a kind + Cilium
  deployment smoke with six declared chaos experiments. *Evidence:*
  [RESILIENCE_AND_CHAOS.md](../testing/RESILIENCE_AND_CHAOS.md),
  [SUPPLY_CHAIN.md](../security/SUPPLY_CHAIN.md).
- Built an evaluation harness (18 versioned golden scenarios, strict replay, regression gate) and
  kept every reported number labelled as simulated. *Evidence:*
  [evaluation architecture](../evaluation/EVALUATION_ARCHITECTURE.md).
- Hardened against prompt injection with a 40-case versioned corpus planted in every input vector;
  hostile text never changed tools, tenants, tiers, approvals or a postmortem's draft status.
  *Evidence:* `tests/security/test_injection_campaign.py`, `tests/postmortem/`.

## Numbers you may quote, and how to qualify them

| Number | Qualifier to say out loud |
|---|---|
| 2,472 automated tests | "all passing on a fresh PostgreSQL 16 database, 0 skipped" |
| 131 requirements: 112 satisfied, 19 partial | "each status recomputed against the requirement's wording; the partial ones name what is missing" |
| 10 LangGraph nodes, 4 model-calling components | "the design had 12 nodes; G12 is not built and G11 runs as a post-incident stage" |
| 18/18 evaluation scenarios | "with a deterministic model — it validates the pipeline and safety, not reasoning quality" |
| 0 timeouts in a 96-client burst | "local benchmark, one 2-CPU container, after fixing two deadlocks" |
| ingestion capacity | "a few alerts per second per 2-CPU process locally, well below the 50/s I had assumed" (see the load doc for the measured figures) |

## Do not claim

Production deployment, real customers or incidents, a live LLM's accuracy, a remote CI run or a
verified GHCR attestation, high availability, zero-downtime migrations, compliance certifications,
or scale beyond the local benchmarks. Do not say "every action is human-approved": R1 in
non-production is autonomous by design.
