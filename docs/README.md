# Documentation Index

This directory holds every non-code artifact required by the master specification
(section 16, "REQUIRED ARCHITECTURE/DOCUMENTATION").

> **Current project stage: Phase 11 complete - evaluation, replay and regression harness.** Bounded,
> tenant-aware investigation and safety-gated remediation run through one capability broker.
> Phase 10 adds native Prometheus, Loki, Kubernetes, Slack, Microsoft Teams, PagerDuty, Jira
> and Grafana adapters behind that broker, with server-side connector authority, credential
> references resolved only at the execution boundary, normalised failure classes and a
> deterministic notification service. These adapters are validated against **local
> deterministic HTTP servers only**; no live vendor system has been exercised. Phase 11 adds a
> versioned golden corpus, strict replay, regression comparison and an executable gate; its
> results are simulator/replay runs with a scripted model provider, not reasoning
> measurements. Observability completion (Phase 12) is not yet built. No metric
> anywhere in this directory is a measurement beyond what is explicitly labelled as measured
> on a stated corpus.

## Start here

**[`architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](./architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md)**
— the master specification §23 package, sections A–Q. It is the spine: it summarises every
area and points to the document that owns the detail.

## Contents

| Directory | Contents | Stage |
|---|---|---|
| [`spec/`](./spec/) | The authoritative master specification (`.docx`) and its verified Markdown transcription | Complete |
| [`prd/`](./prd/) | PRD (§A, B, D), SRS (§C, 138 requirement IDs), personas, journeys, incident lifecycle | **Authored** |
| [`architecture/`](./architecture/) | A–Q package spine, architecture overview, C4, agent topology, tool registry, safety policy, memory/RAG, observability, data model/API, failure & recovery, traceability, CI/CD | **Authored** |
| [`architecture/tenancy-and-rls.md`](./architecture/tenancy-and-rls.md) | How tenant isolation survives an application bug | **Implemented and tested** |
| [`architecture/orchestration-kernel.md`](./architecture/orchestration-kernel.md) | The graph, node contracts, tool broker, budgets, checkpointing and trace model | **Implemented and tested** |
| [`architecture/bounded-reflection.md`](./architecture/bounded-reflection.md) | The reflection decision loop: vocabulary, deterministic guards, hypothesis revision, failure handling | **Implemented and tested** |
| [`architecture/integrations.md`](./architecture/integrations.md) | Native external adapters, connector authority, credentials, failure model | **Implemented; tested against local servers only** |
| [`adr/`](./adr/) | Architecture Decision Records | See the ADR index for current status |
| [`security/`](./security/) | Threat model (§L) and the active repository security checklist | **Authored** |
| [`evaluation/`](./evaluation/) | Evaluation harness architecture (§I) and Phase 11 implementation status | **Implemented (simulator/replay) and tested** |

## Reading order for a new reviewer

1. [`spec/MASTER_PROJECT_PROMPT_V3.md`](./spec/MASTER_PROJECT_PROMPT_V3.md) — what the product must be.
2. [`architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](./architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md) — the whole package, A–Q.
3. [`prd/PRD.md`](./prd/PRD.md) and [`prd/SRS.md`](./prd/SRS.md) — what we are building and for whom.
4. [`architecture/ARCHITECTURE_OVERVIEW.md`](./architecture/ARCHITECTURE_OVERVIEW.md) — how it fits together.
5. [`architecture/agent-topology.md`](./architecture/agent-topology.md) — the most consequential decision in the package.
6. [`adr/README.md`](./adr/README.md) — why each major choice was made, and what would reverse it.
7. [`architecture/tenancy-and-rls.md`](./architecture/tenancy-and-rls.md) — how tenant isolation survives a bug.
8. [`architecture/orchestration-kernel.md`](./architecture/orchestration-kernel.md) — what
   Phase 4 built, what it deliberately did not, and what remains unmeasured.
9. [`architecture/telemetry-ingestion.md`](./architecture/telemetry-ingestion.md) — normalized
   signals, durable receipts, correlation explanations and the recoverable investigation handoff.
10. [`architecture/bounded-reflection.md`](./architecture/bounded-reflection.md) — the
    reflection decision loop Phase 7 added: vocabulary, deterministic guards, hypothesis
    revision and how it stays inside the existing five-category termination model.

### If you are reviewing for security

[`security/THREAT_MODEL.md`](./security/THREAT_MODEL.md) →
[`architecture/remediation-safety-policy.md`](./architecture/remediation-safety-policy.md) →
[`architecture/tool-registry.md`](./architecture/tool-registry.md) §1 (how the model is
prevented from unrestricted infrastructure access) →
[`architecture/orchestration-kernel.md`](./architecture/orchestration-kernel.md) §12 (which
of those invariants are enforced in code today, and by which adversarial test).

## Document ownership

To keep the set internally consistent, each area has exactly one authoritative document.
Where a summary and a detail document disagree, **the detail document wins** and the summary
is the defect.

| Area | Authoritative document |
|---|---|
| Requirements | [`prd/SRS.md`](./prd/SRS.md) |
| Node inventory and consolidation | [`architecture/agent-topology.md`](./architecture/agent-topology.md) |
| Tools, capabilities, permissions | [`architecture/tool-registry.md`](./architecture/tool-registry.md) |
| Risk tiers, approval, execution safety | [`architecture/remediation-safety-policy.md`](./architecture/remediation-safety-policy.md) |
| Memory tiers, RAG, provenance | [`architecture/memory-and-rag.md`](./architecture/memory-and-rag.md) |
| Trace model, metrics, SLOs | [`architecture/observability.md`](./architecture/observability.md) |
| State machine, retries, recovery | [`architecture/failure-and-recovery.md`](./architecture/failure-and-recovery.md) |
| Entities, invariants, API boundaries | [`architecture/data-model-and-api.md`](./architecture/data-model-and-api.md) |
| Tenancy, RLS, composite keys | [`architecture/tenancy-and-rls.md`](./architecture/tenancy-and-rls.md) |
| Graph, node contracts, broker, budgets, checkpointing | [`architecture/orchestration-kernel.md`](./architecture/orchestration-kernel.md) |
| Bounded reflection: vocabulary, guards, hypothesis revision | [`architecture/bounded-reflection.md`](./architecture/bounded-reflection.md) |
| Threats and security invariants | [`security/THREAT_MODEL.md`](./security/THREAT_MODEL.md) |
| Scenarios, judges, metrics, regression | [`evaluation/EVALUATION_ARCHITECTURE.md`](./evaluation/EVALUATION_ARCHITECTURE.md) |
| Technology decisions | [`adr/`](./adr/) |

## Rules for this directory

- The `.docx` in `spec/` is authoritative. The Markdown transcription is verified by
  `scripts/verify_spec_transcription.py` and must never drift from it.
- Documents state **decisions and rationale**, not aspirations. A document that
  describes behaviour the code does not have is a defect.
- Every major technology choice gets an ADR with alternatives and trade-offs
  (master specification section 13).
- No invented metrics, benchmarks, customers or business impact
  (master specification sections 9 and 22).
- `scripts/validate_docs.py` enforces the mechanical half of these rules: link integrity,
  Mermaid structure, requirement traceability in both directions, that no §4 responsibility
  has silently disappeared, and that no later-phase capability has entered the repository.
