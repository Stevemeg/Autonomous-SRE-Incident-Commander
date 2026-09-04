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

- **Phase 1 and Phase 2 — product requirements and the Project Initiation & Architecture
  Package** (master specification section 23, sections A-Q). Documentation only; **no
  product code, no migrations, no agents, no APIs.** Every decision is *proposed* and
  awaiting approval.

  - **Product layer.** PRD with executive definition, buyer/user separation and a
    competitive analysis that cites no competitor performance figures. SRS with 138
    requirement identifiers, each classified `[SPEC]`, `[DERIVED]` or `[ASSUMED]` so that
    our judgement is distinguishable from the specification's requirements. Six personas
    and six journeys, including correct termination in uncertainty and a blocked unsafe
    action.

  - **Agent topology.** The nineteen candidate responsibilities of section 4 evaluated
    individually against a stated two-discriminator test and consolidated into twelve graph
    nodes plus two derived services. Six telemetry and knowledge responsibilities become
    strategies of one Evidence Collector node; six control responsibilities become
    deterministic non-LLM components, because implementing a policy gate, an approval
    record or a command executor as a language model would violate sections 6 and 15.
    No section 4 responsibility was dropped, and this is verified mechanically.

  - **Safety architecture.** Twelve safety invariants, each enforced by a type, a
    credential or a deterministic code path rather than by a prompt instruction, and each
    with a named adversarial test. Four risk tiers, in which destructive actions are not
    approval-gated but *not expressible*. Of the twelve action fields section 6 requires,
    the model authors four; the remainder are resolved from the registry and incident
    context.

  - **Evaluation and observability.** One trace schema serving operations, replay and
    evaluation, so a production incident becomes an evaluation case without transformation.
    Twelve golden scenario archetypes, twelve adversarial scenarios, thirteen deterministic
    checks that judges cannot overrule, and multi-judge scoring in which disagreement is
    flagged rather than averaged away.

  - **Security.** Ten invariants required from the first executable slice, eighteen
    enumerated threats with residual risk stated, and explicit modelling of six untrusted
    input classes including model output. Security is designed in Phase 2 rather than
    Phase 13 because tenancy, the authorization chokepoint and provenance typing are not
    retrofittable.

  - **Data model and API.** Twenty-six conceptual entities, seventeen invariants and five
    separately-authorised API surfaces. **No migrations and no DDL** — physical schema is
    Phase 3.

  - **Eleven Architecture Decision Records**, each with genuinely considered alternatives,
    a reversal cost and an observable revisit trigger. All eight technologies section 13
    flags as "evaluate rather than blindly add" have been evaluated. Statuses are
    `Proposed`, `Needs validation` or `Deferred`; **none is Accepted**, because section 9
    forbids reporting unmeasured results as fact and several decisions rest on measurements
    not yet taken.

  - **Requirements traceability matrix** mapping all 138 requirement identifiers to
    architecture component, implementation phase, validation strategy and acceptance
    criterion. No requirement is claimed as implemented.

  - **Twenty-one Mermaid diagrams**: C4 context, container and two component views, agent
    topology, incident lifecycle, remediation approval flow, evaluation loop, retrieval
    pipeline, memory tiers, phase dependencies and the entity-relationship model.

  - `scripts/validate_docs.py` — validates internal links, Mermaid structure, requirement
    traceability in both directions, section 4 responsibility coverage, absence of
    implementation code and absence of invented improvement percentages. Standard library
    only. Verified against deliberately introduced defects, not only against a passing
    repository.

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

### Changed

- README and documentation index updated to reflect Phase 2 completion, the eight
  technology recommendations, and the revised roadmap. Repository security checklist now
  requires `validate_docs.py` before any commit touching `docs/`.

### Notes

- **No product code exists.** `src/`, `tests/` and `configs/` are intentionally empty.
- The architecture is **proposed, not accepted.** No ADR has status `Accepted`, and no
  technology has been committed to.
- **No performance has been measured.** Every numeric target in the documentation is a
  budget to be validated in Phase 15, labelled as such. Per master specification sections
  9 and 22, no figure will be reported here until a run produces it.
- Twelve assumptions and decisions require the project owner's approval before Phase 3
  begins; they are listed at the end of the architecture package.

---

## Release history

_No releases yet._
