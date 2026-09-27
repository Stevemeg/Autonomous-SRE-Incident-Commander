# Production gap register

The single list of everything this repository does **not** do, or has not verified, that a real
production deployment would need. Other documents link here instead of keeping their own lists.
Each gap has one class, the evidence for its current state, and what would close it.

**Classes**

- **EXTERNAL PREREQUISITE** — needs infrastructure, accounts or people outside this repository.
- **INTENTIONALLY DEFERRED** — a product capability deliberately not built, with the reason.
- **NOT VERIFIED** — built, but only local evidence exists; it may work, it is not proven.
- **KNOWN LIMITATION** — a property of the current design that operators must plan around.

| ID | Gap | Class | Current state and evidence | What closes it |
|---|---|---|---|---|
| GAP-01 | Remote CI/CD execution (GitHub Actions, GHCR publish, OIDC attestation) | NOT VERIFIED | Workflows are pinned and statically validated (actionlint, workflow trust-graph tests); every gate they run was executed locally (security gate 11/11, 18/18 evaluation, kind smoke) but never on GitHub-hosted runners | Run `quality.yml` and `release.yml` on the real repository; verify an attestation with `scripts/verify_release_attestation.py` |
| GAP-02 | TLS termination, certificates, ingress controller | EXTERNAL PREREQUISITE | TLS Ingress contract rendered; the local overlay removes the production edge | Cluster ingress controller and certificate management |
| GAP-03 | Managed PostgreSQL, encryption at rest, backups, PITR, restore drills | EXTERNAL PREREQUISITE | Disposable local pgvector only; no backup has been taken or restored | Managed database with PITR and a restore drill proving RPO/RTO |
| GAP-04 | High availability | NOT VERIFIED | Base manifests: 2 replicas, PodDisruptionBudgets, `maxUnavailable: 0`. Kind runs 1 replica on 1 node; the measured API pod-kill outage was ≈ 5.8 s ([RESILIENCE_AND_CHAOS.md](testing/RESILIENCE_AND_CHAOS.md)) | Multi-node, multi-zone cluster; repeat the chaos suite with ≥ 2 replicas and measure availability |
| GAP-05 | Disaster recovery | EXTERNAL PREREQUISITE | None | Region/cluster recovery plan with documented RTO/RPO, exercised |
| GAP-06 | Zero-downtime schema migrations | KNOWN LIMITATION | Migrations run before rollout (fail-closed ordering, overlap-safe Job replacement); not every revision is reviewed as expand/contract | Per-migration overlap review; drain or constrain rollouts where overlap cannot be established |
| GAP-07 | Orchestration worker deployment | INTENTIONALLY DEFERRED | The API records investigation dispatch requests; `InvestigationDispatcher` drives them in-process (tests, E2E, load harness, demo). No worker Deployment ships (ADR-0031) | A durable worker entry point with leases, graceful shutdown and probes, then a Deployment |
| GAP-08 | Live LLM provider | INTENTIONALLY DEFERRED | Only the deterministic provider is wired (ADR-0016); reasoning quality is not measured | A provider adapter behind the existing budgeted port, then measured evaluations through the gate |
| GAP-09 | LLM-as-judge calibration (FR-EVL-04) | EXTERNAL PREREQUISITE | Multi-judge panel with disagreement handling exists; no calibration against human labels, no live judge | A human-labelled set, live judges, agreement and calibration measurement |
| GAP-10 | Postmortem generation (FR-PMT-01/02, node G11) | INTENTIONALLY DEFERRED | Postmortems are ingested as knowledge; no generator exists | A draft generator citing incident events and evidence, marked draft, human-reviewed |
| GAP-11 | Automated compensation after failed verification (FR-VRF-04) | INTENTIONALLY DEFERRED | Failed or partial verification is never marked resolved and escalates (`AsicRemediationPartialEffect`, runbook) | Per-action compensation designs, each with its own approval and verification |
| GAP-12 | Inbound chat approvals (FR-CLB-03) | INTENTIONALLY DEFERRED | Outbound Slack/Teams/PagerDuty/Jira only; approvals only through the RBAC API | Signed inbound callbacks mapped to RBAC principals |
| GAP-13 | Distributed rate limiting | KNOWN LIMITATION | Per-principal and failed-auth limiters and the ingestion bulkhead are per process; N replicas multiply the limits | Edge or gateway limiter in front of the API |
| GAP-14 | DNS rebinding / DNS-aware egress | EXTERNAL PREREQUISITE | The application validates names, not resolutions (a test pins this limitation); NetworkPolicy cannot authorize names | Egress gateway with DNS-aware policy |
| GAP-15 | Retention of classes other than the idempotency cache | INTENTIONALLY DEFERRED | Executor deletes only expired idempotency records (ADR-0032) | Lineage-aware cascades, backup/PITR coordination, legal-hold integration |
| GAP-16 | Live vendor systems | NOT VERIFIED | Prometheus, Loki, Kubernetes, Slack, Teams, PagerDuty, Jira and Grafana adapters validated against local deterministic servers only | Sandbox accounts and contract tests against each live API |
| GAP-17 | Trace store and configuration-change evidence | INTENTIONALLY DEFERRED | Trace evidence is simulator-only; no dedicated configuration-change adapter (FR-ING-02, FR-INV-05, FR-INT-01) | Tempo/Jaeger and change-source adapters behind the broker |
| GAP-18 | Stale history vs current evidence (FR-EVD-04) | KNOWN LIMITATION | Historical incidents and runbooks enter only as fenced `RETRIEVED` content with no authority; no scenario proves a contradicting stale runbook is outranked | A golden scenario with a stale, contradicting runbook and a ranking assertion |
| GAP-19 | `content.injection_flagged` telemetry event | KNOWN LIMITATION | The flag is stored on evidence rows (asserted in E2E scenario D); the event is not emitted | Emit the event from the evidence write path |
| GAP-20 | Crash between approval and dispatch | KNOWN LIMITATION | The resumed run fails closed and asks again; nothing executes without a fresh approval | A durable approval-continuation record |
| GAP-21 | OTLP shutdown drain | KNOWN LIMITATION | During a collector outage a stopping pod may spend its grace period exporting and lose spans | Lower `OTEL_EXPORTER_OTLP_TIMEOUT`; accept span loss |
| GAP-22 | Observability backends and alert routing | EXTERNAL PREREQUISITE | Prometheus rules, dashboards and collector config validated with `promtool`/`otelcol-contrib`; nothing deployed | Deployed backends and routing to on-call |
| GAP-23 | Capacity and cost at production scale | NOT VERIFIED | LOCAL BENCHMARK only; ingestion ≈ 12 alerts/s per 2-CPU process, below the assumed 50/s ([LOAD_AND_PERFORMANCE.md](testing/LOAD_AND_PERFORMANCE.md)) | Multi-process scaling test, correlation-lock profiling, production-like load |
| GAP-24 | Independent penetration test | EXTERNAL PREREQUISITE | Automated adversarial campaigns only | Third-party assessment |
| GAP-25 | Secret manager and rotation in production | EXTERNAL PREREQUISITE | Secrets referenced from Kubernetes Secrets; per-call credential resolution makes rotation effective without restart ([SECRETS_POLICY.md](security/SECRETS_POLICY.md)) | Platform secret manager and a rotation drill |
| GAP-26 | Resume latency after an unclean death (NFR-REL-09) | KNOWN LIMITATION | A new worker takes over only when the 15-minute lease expires; the assumed 60 s budget is not met | Shorter leases with heartbeat renewal, or fencing-token takeover |
| GAP-27 | Unmeasured evaluation metrics (FR-EVL-06/08, FR-INV-08) | INTENTIONALLY DEFERRED | Latency to first hypothesis, redundant-call rate and calibration error are not computed; no recorded improvement-loop walkthrough on a real model regression | Needs GAP-08 (a live model) to be meaningful |
| GAP-28 | Database-operation spans (FR-OBS-01) | KNOWN LIMITATION | Database work is inside node and request spans but not its own span kind | SQLAlchemy instrumentation with the same redaction rules |
| GAP-29 | Encryption in transit inside the cluster (NFR-SEC-07) | EXTERNAL PREREQUISITE | Outbound HTTPS is verified; pod-to-pod mTLS and database TLS are platform choices | Service mesh or database TLS enforcement |
