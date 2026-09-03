# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Conventions

- Entries describe **what changed and why it matters**, not which files moved.
- Nothing is listed as delivered until it has been validated and the actual result
  reported (master specification section 20).
- No invented metrics, benchmarks or business impact appear here (sections 9 and 22).
  Measured results are labelled with how they were measured.
- Changes to AI behaviour — prompts, models, retrievers, agent policy — are versioned
  behaviour changes and must be recorded explicitly with their evaluation results
  (section 10).
- Releases are tagged once there is a runnable artifact to version. Until then, changes
  accumulate under `[Unreleased]`.

---

## [Unreleased]

### Added

- **Phase 0 — repository bootstrap.**
  - Git repository initialised on `main` and connected to the canonical GitHub remote.
  - Master specification V3 preserved unmodified under `docs/spec/` and transcribed to
    Markdown at `docs/spec/MASTER_PROJECT_PROMPT_V3.md` for diffable review.
  - `scripts/verify_spec_transcription.py` — verifies the transcription against the
    `.docx` in both directions (nothing dropped, nothing invented) and checks section
    ordering. Standard library only.
  - `scripts/check_repo_hygiene.py` — scans tracked and untracked files for
    secret-shaped content, forbidden paths and generated artifacts. Standard library only.
  - `docs/security/REPOSITORY_SECURITY_CHECKLIST.md` — the pre-commit and pre-push
    procedure required by master specification section 20, active from Phase 0.
  - `docs/adr/` — ADR process, template, and an index of the 15 candidate technology
    decisions Phase 2 is obliged to make. No decisions recorded yet.
  - Documentation skeletons for the PRD, SRS, personas and journeys, architecture
    overview, C4 diagrams, agent topology, tool registry, memory and RAG, observability,
    data model and API, failure and recovery, CI/CD and infrastructure, evaluation
    harness, and threat model. All are empty by design.
  - `.gitignore` covering secrets, Python, Node/Next.js, IDE and OS files, test and
    coverage artifacts, build output, Docker, Kubernetes and Terraform local state.
  - `README.md` stating the product intent and the current design-phase status.

### Notes

- **No product code exists.** `src/`, `tests/` and `configs/` are intentionally empty.
- No architecture has been authored and no technology has been committed to; the
  baseline stack in the specification remains a proposal pending ADRs.

---

## Release history

_No releases yet._
