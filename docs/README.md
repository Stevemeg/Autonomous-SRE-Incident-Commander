# Documentation Index

This directory holds every non-code artifact required by the master specification
(section 16, "REQUIRED ARCHITECTURE/DOCUMENTATION").

> **Current project stage: Phase 0 complete — repository bootstrap.**
> Everything below except `spec/` is an empty skeleton. No architecture has been
> authored and no implementation exists.

| Directory | Contents | Stage authored |
|---|---|---|
| [`spec/`](./spec/) | The authoritative master specification (`.docx`) and its verified Markdown transcription | **Complete** |
| [`prd/`](./prd/) | PRD, SRS, personas, user journeys, incident lifecycle | Phase 1 |
| [`architecture/`](./architecture/) | Architecture overview, C4 diagrams, agent topology, tool registry, memory/RAG, observability, data model/API, failure & recovery, CI/CD & infrastructure | Phase 2 |
| [`adr/`](./adr/) | Architecture Decision Records for every major technology choice | Phase 2 onward |
| [`security/`](./security/) | Threat model and repository security checklist | Phase 2 (threat model); checklist active now |
| [`evaluation/`](./evaluation/) | Evaluation harness architecture, metrics definitions, golden-scenario design | Phase 2 (design), Phase 11 (build) |

## Reading order for a new reviewer

1. [`spec/MASTER_PROJECT_PROMPT_V3.md`](./spec/MASTER_PROJECT_PROMPT_V3.md) — what the product must be.
2. [`prd/PRD.md`](./prd/PRD.md) — what we are building and for whom.
3. [`architecture/ARCHITECTURE_OVERVIEW.md`](./architecture/ARCHITECTURE_OVERVIEW.md) — how it fits together.
4. [`adr/README.md`](./adr/README.md) — why each major choice was made.

## Rules for this directory

- The `.docx` in `spec/` is authoritative. The Markdown transcription is verified by
  `scripts/verify_spec_transcription.py` and must never drift from it.
- Documents state **decisions and rationale**, not aspirations. A document that
  describes behaviour the code does not have is a defect.
- Every major technology choice gets an ADR with alternatives and trade-offs
  (master specification section 13).
- No invented metrics, benchmarks, customers or business impact
  (master specification sections 9 and 22).
