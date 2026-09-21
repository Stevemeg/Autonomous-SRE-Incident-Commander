# Repository Quality and Security Checklist

Before committing or pushing, inspect Git authors/committers and attribution trailers,
AUTHORS/CONTRIBUTORS files, README credits and package author metadata. The human owner is
the sole project contributor; implementation tools receive no author, committer or
co-author credit. Correct local/unpushed attribution while preserving the owner's identity.
Report attribution in shared history and obtain explicit approval before rewriting it.
Preserve dependency licenses and factual provider references.

> **Status: ACTIVE from Phase 0.** Unlike the other documents in this directory, this
> checklist is in force now and applies to every commit and push.

Master specification section 20 requires: *"Before commits/pushes, inspect for secrets,
credentials, generated junk and sensitive data"* and *"Maintain professional repository
structure, README, reproducible setup and clean Git history."* This document is how that
rule is operationalised.

A partially automated version of the mechanical checks is available:

```bash
python scripts/check_repo_hygiene.py
```

The script is an aid, not the control. It reduces the chance of a mistake; it does not
replace looking at the diff.

---

## 1. Before every commit

### 1.1 Inspect the change, not just the summary

- [ ] `git status` reviewed — no unexpected files staged.
- [ ] `git diff --staged` read in full. Every hunk is intentional.
- [ ] No file staged that you cannot explain the purpose of.
- [ ] Binary files justified. Binary blobs are effectively permanent in Git history.

### 1.2 Secrets and credentials

- [ ] No API keys, tokens, passwords, or session cookies.
- [ ] No private keys or certificates (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`).
- [ ] No cloud credentials (`.aws/`, `.azure/`, service-account JSON).
- [ ] No `kubeconfig` or cluster credentials.
- [ ] No `.env` file. Only `.env.example` with placeholder values may be committed.
- [ ] No database connection strings containing real credentials.
- [ ] No webhook URLs with embedded tokens (Slack, Teams, PagerDuty).
- [ ] No credentials inside documentation, diagrams, comments or test fixtures.
- [ ] `python scripts/check_repo_hygiene.py` reports no findings, or every finding is
      reviewed and confirmed a false positive.

> **If a secret was ever committed, rotating it is mandatory even after the commit is
> amended or the branch is rewritten.** Assume any secret that reached a commit object is
> compromised, and assume anything pushed to GitHub is public forever.

### 1.3 Sensitive and personal data

- [ ] No real customer, employee or user data.
- [ ] No real production hostnames, internal IP ranges, or account identifiers.
- [ ] No real incident content, log excerpts, or ticket contents from a real organisation.
- [ ] Personal data limited to the repository owner's own Git identity.
- [ ] Test fixtures are synthetic. Master specification section 20 permits simulators and
      mocks **only as explicit test infrastructure**, and section 14 forbids depending on
      live production infrastructure.

### 1.4 Generated and junk files

- [ ] No `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/`.
- [ ] No `node_modules/`, `.next/`, `dist/`, `build/`, `out/`, `*.tsbuildinfo`.
- [ ] No virtual environments (`.venv/`, `venv/`, `env/`).
- [ ] No coverage or test output (`.coverage`, `htmlcov/`, `junit*.xml`).
- [ ] No Terraform state or plans (`*.tfstate*`, `.terraform/`, `tfplan`).
- [ ] No OS junk (`.DS_Store`, `Thumbs.db`, `Desktop.ini`).
- [ ] No editor state (`.idea/`, `.vscode/` beyond shared config).
- [ ] No Office lock files (`~$*.docx`).
- [ ] No local agent or assistant scratch directories.

### 1.5 Correctness of the change itself

- [ ] No implementation code added that the current project phase does not authorise.
- [ ] No fake integrations, fabricated metrics, hard-coded success paths or placeholder
      production logic (master specification section 20).
- [ ] No invented business impact, benchmark figures or customer claims
      (master specification sections 9 and 22).
- [ ] Documentation describes what exists, not what is intended. Aspirational
      documentation written in the present tense is a defect.
- [ ] `.gitignore` updated if the change introduces a new class of generated file.

### 1.6 Validation

- [ ] Relevant validation actually executed and **actual** results reported — not assumed
      (master specification section 20).
- [ ] `python scripts/verify_spec_transcription.py` passes if anything under `docs/spec/`
      changed.
- [ ] `python scripts/validate_docs.py` passes if anything under `docs/` changed — internal
      links resolve, Mermaid diagrams are structurally valid, every requirement is traced in
      both directions, and no master specification section 4 responsibility has silently
      disappeared.
- [ ] Commit message describes the milestone, uses a conventional-commit type, and does
      not overstate what was delivered.

---

## 2. Before every push

- [ ] Commits are milestone-level, not noise (master specification section 20).
- [ ] Author identity on every commit is the repository owner. Verify with
      `git log --format='%an <%ae>' -n 10`.
- [ ] Branch is `main` or an intentional feature branch.
- [ ] Full history scanned for secrets if history was rewritten.
- [ ] No force-push to `main` without a deliberate, stated reason.

---

## 3. Per-phase security gates

These become active as the corresponding phase begins. They are listed now so the
obligation is visible from the start, not discovered late.

| From phase | Gate |
|---|---|
| 3 — domain model / schema | Tenant isolation enforced in the data layer and covered by tests |
| 4 — tool registry / orchestration | Tool authorization checked server-side; retrieved content tainted as untrusted; trace emission in place |
| 6 — RAG and memory | Access-control filtering applied at retrieval time, not after; prompt-injection defenses on retrieved content |
| 8 — remediation | Risk tiers enforced; human approval required for high-risk and irreversible actions; no execution of arbitrary model-generated commands |
| 13 — security hardening | Authn/authz, RBAC, rate limiting, encryption, audit logging, data-retention controls |
| 14 — CI/CD | Dependency scanning, SAST and container scanning wired as blocking gates |

---

## 4. Automated enforcement roadmap

Currently manual, plus `scripts/check_repo_hygiene.py`. As the repository grows, these
checks move into automation so that compliance does not depend on discipline:

| Control | Status |
|---|---|
| `.gitignore` covering secrets, environments, build output and IaC state | **In place** (Phase 0) |
| Manual pre-commit checklist (this document) | **In place** (Phase 0) |
| `scripts/check_repo_hygiene.py` secret and junk scan | **In place** (Phase 0) |
| `scripts/validate_docs.py` documentation and traceability validation | **In place** (Phase 2) |
| `pre-commit` hooks (formatting, linting, secret scan) | Planned — Phase 3, with the first code |
| Secret scanning (gitleaks over history and tree) | **Executable locally (Phase 13)** via `scripts/security_gate.py`; CI wiring Phase 14 |
| Dependency vulnerability scanning (`pip-audit`, `npm audit`) | **Executable locally (Phase 13)**; CI wiring Phase 14 |
| SAST (`ruff --select S` plus policy tests) | **Executable locally (Phase 13)**; CI wiring Phase 14 |
| Container image scanning | **Not executable until a Phase 14 image exists** (the gate reports `not_executable`, never a pass) |
| Branch protection on `main` | Planned — when collaboration begins |

---

## 5. If a secret is exposed

1. **Rotate the credential immediately.** This is the first step, not the last.
2. Revoke any sessions or tokens derived from it.
3. Remove it from the working tree and from history (`git filter-repo`), then force-push.
4. Assume the value is permanently compromised regardless of cleanup — GitHub caches
   unreachable objects, forks retain them, and mirrors may exist.
5. Record what happened and add the pattern to `scripts/check_repo_hygiene.py`.
