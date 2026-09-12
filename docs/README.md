# Documentation Index

This directory holds every non-code artifact required by the master specification
(section 16, "REQUIRED ARCHITECTURE/DOCUMENTATION").

> **Current project stage: Phase 6 complete — operational knowledge, RAG and governed
> memory.** A bounded, read-only, simulator-backed incident investigation runs end to end
> through a typed graph with a capability broker, durable checkpointing and structured
> traces, and can now retrieve versioned operational knowledge — authorization-first,
> citation-backed — through the same broker as every other capability. A governed memory
> write path lets a human, never a model and never storage alone, promote a verified
> outcome or an operational fact into durable memory.
> **No remediation, no external integration, no API and no frontend exists**, and no
> capability above risk tier `RO` is registered. No metric anywhere in this directory is a
> measurement beyond what is explicitly labelled as measured on a stated corpus.

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
| [`adr/`](./adr/) | 19 Architecture Decision Records | **11 Accepted**; the remainder proposed, deferred or awaiting later evidence |
| [`security/`](./security/) | Threat model (§L) and the active repository security checklist | **Authored** |
| [`evaluation/`](./evaluation/) | Evaluation harness architecture (§I) | **Authored** |

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
