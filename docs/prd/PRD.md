# Product Requirements Document (PRD)

- **Status:** Authored — Architecture Package (V3 §23 A, B, D). Requirements themselves live in [`SRS.md`](./SRS.md).
- **Authoritative source of requirements:** [`../spec/MASTER_PROJECT_PROMPT_V3.md`](../spec/MASTER_PROJECT_PROMPT_V3.md)
- **Master specification references:** Sections 2, 3, 21, 22, 23(A–D)

> **Nothing in this document is implemented.** Every metric named here is a *target to be
> measured*, never an achievement. Master specification section 22 forbids fabricated
> business impact; section 9 forbids invented improvement percentages. Targets become
> results only when the evaluation harness or a load test produces them.

---

## A. Executive product definition

### A.1 One-sentence definition

The **Autonomous SRE Incident Commander** is a multi-agent incident-response system that
ingests alerts and telemetry from cloud-native environments, correlates them into coherent
incidents, conducts bounded autonomous investigation across logs, metrics, traces,
Kubernetes state and deployment history, produces evidence-backed and ranked root-cause
hypotheses, plans risk-classified remediation that a human approves before anything
irreversible happens, executes only permission-scoped tools, independently verifies the
outcome, and preserves the result as governed operational memory.

### A.2 What it is not

Master specification section 2 defines the product negatively, and those exclusions are
binding architectural constraints rather than marketing copy:

| It is not | The constraint this imposes on us |
|---|---|
| A chatbot | The primary interface is an incident workflow with state, not a conversation. Chat is an integration surface (Slack/Teams), not the product. |
| An incident summarizer | Summaries are a by-product. The deliverable is an *evidence-backed causal hypothesis* with citations and counter-evidence. |
| A generic RAG demo | Retrieval is one evidence source among six, subject to the same provenance and citation rules as a Prometheus query. |
| A single-agent toy | Responsibilities with different permissions, failure modes and evaluation criteria are separated into distinct nodes ([`../architecture/agent-topology.md`](../architecture/agent-topology.md)). |
| A hackathon project | Durable workflows, recovery, tenant isolation, audit and evaluation exist from the first executable slice, not at the end. |
| An academic prototype | Deterministic simulators and replay fixtures make behaviour reproducible; no live-infrastructure dependency. |
| An LLM API wrapper | The model never receives unrestricted infrastructure access. Authorization is deterministic and sits outside the model. |

### A.3 The product thesis

On-call engineering is expensive because the *investigation* is repetitive while the
*judgement* is not. An experienced SRE responding to "checkout latency p99 breached" runs a
largely predictable evidence-gathering sequence — check recent deploys, check dependency
latency, check pod restarts, check error-log deltas, check the runbook — and then applies
scarce judgement to the small residue that the evidence does not explain.

This product automates the predictable evidence-gathering under hard bounds, presents the
residue to a human with the evidence already assembled and cited, and refuses to take
irreversible action on its own authority. The value is not that a model "solves" the
incident; it is that the human's first minute of involvement starts from assembled,
attributable evidence rather than from a blank terminal.

Two design consequences follow directly, and they shape the whole architecture:

1. **Bounded autonomy is the product, not a safety tax.** An investigation that cannot
   terminate is worse than no investigation, because it consumes budget and trust while
   producing nothing an operator can act on.
2. **Attribution beats fluency.** A confident wrong hypothesis is a negative-value output.
   The system must distinguish verified facts, hypotheses and model-generated claims
   (master specification section 8) and must be measured on unsupported-claim rate
   (section 9).

### A.4 Scope boundaries for v1

| In scope | Out of scope for v1 (and why) |
|---|---|
| Alert ingestion, correlation, incident lifecycle | Alert *routing/paging policy* — PagerDuty already owns this well |
| Read-only investigation across six evidence domains | Autonomous capacity planning or cost optimisation — different problem, different data |
| Ranked RCA hypotheses with evidence and counter-evidence | Automated code-level fault localisation in source — needs repository context we do not model |
| Risk-classified remediation planning + human approval | Fully autonomous high-risk remediation — explicitly forbidden by section 6 |
| Bounded reversible remediation execution + verification | Arbitrary model-generated production commands — explicitly forbidden by section 6 |
| Operational RAG over runbooks, docs, known errors, postmortems | General enterprise knowledge search — out of domain |
| Postmortem drafting and governed memory | Automated policy/SLO authoring |
| Evaluation harness, replay, regression | Multi-region active-active deployment — a scale problem, not a v1 problem |

---

## B. Users, buyers and personas

Detailed persona narratives and end-to-end journeys are in
[`personas-and-journeys.md`](./personas-and-journeys.md). This section fixes *who decides*
and *who is harmed if we get it wrong*.

### B.1 Target organizations

Per master specification section 3: SaaS, enterprise platform teams, fintech, healthcare,
e-commerce, MSPs, and Kubernetes/cloud-native operators.

The common qualifying characteristics — these are the assumptions we design against:

- Kubernetes-based or otherwise cloud-native workloads with a service/environment taxonomy.
- An existing observability stack (Prometheus-compatible metrics, centralised logs, and
  ideally distributed tracing). **We integrate with observability; we do not replace it.**
- A formal on-call rotation, which implies incidents have owners and approval has meaning.
- Enough incident volume that repetitive investigation is a real cost.

### B.2 Buyer vs user

Distinguishing these matters because they judge the product on different axes, and the
architecture must produce evidence for both.

| | **Economic buyer** | **Primary user** | **Blocking approver** |
|---|---|---|---|
| Role | Director/VP of Engineering, Head of Platform, or SRE Manager | On-call SRE / Platform Engineer | Security and Compliance |
| Judges the product on | Reduced toil, faster triage, retained operational knowledge, defensible spend | Does it save me time at 03:00 without lying to me? | Can it be given production credentials at all? |
| Kills the deal by saying | "This is a nice demo but I can't measure it" | "I don't trust it, I check everything it says anyway" | "It gives an LLM cluster write access" |
| Architectural obligation it creates | Measured evaluation metrics and SLO dashboards (§9, §11) | Evidence citations, confidence, counter-evidence, low unsupported-claim rate (§8, §9) | Deterministic policy gate, scoped tools, tenant isolation, audit log (§6, §7, §15) |

The security approver is the most common silent blocker for this product category and is
therefore treated as a first-class persona, not a compliance checkbox. This is why the
threat model and the policy gate are designed in Phase 2 rather than Phase 13 — see
[`../architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md`](../architecture/PROJECT_INITIATION_AND_ARCHITECTURE_PACKAGE.md)
section O for the justified roadmap deviation.

### B.3 Persona summary

| ID | Persona | Core need | Primary failure that loses them |
|---|---|---|---|
| P1 | **On-call SRE** | Start from assembled evidence, not a blank terminal | A confident, uncited, wrong hypothesis |
| P2 | **Platform/DevOps Engineer** | Safe, auditable, scoped automation of routine remediation | An unscoped action that touches the wrong namespace |
| P3 | **Engineering Manager / Buyer** | Defensible evidence that the system reduces toil | Unmeasurable claims; no regression protection |
| P4 | **Security / Compliance Architect** | Proof the model cannot escalate privilege | Retrieved text influencing tool authorization |
| P5 | **Service Owner / Developer** | A trustworthy timeline and postmortem for their service | Timeline that cannot be traced back to raw evidence |
| P6 | **Operator of this system** | Observe, replay, evaluate and roll back agent behaviour | Silent behaviour change with no regression signal |

Persona P6 is deliberately included: master specification section 11 requires the harness
itself be observable, replayable and evaluable, which means the system has an operator
distinct from its users.

---

## C. Requirements

Functional and non-functional requirements carry stable identifiers and live in
[`SRS.md`](./SRS.md). They are traced to architecture, phase, validation strategy and
acceptance criteria in
[`../architecture/requirements-traceability.md`](../architecture/requirements-traceability.md).

Requirements are **not** restated here, to avoid the two documents drifting.

---

## D. Competitive landscape and differentiation

### D.1 Honest framing

This is a portfolio-grade product built to enterprise standards, not a funded company. The
purpose of this section is to demonstrate that the design choices are made *knowingly*
against a real market, and to prevent building something whose differentiation is
imaginary. **No competitor's performance figures are cited, because we have not measured
them.** Capability statements below describe publicly documented product categories and
are labelled as assessment, not benchmark.

### D.2 Category map

| Category | Representative products | What they do well | Gap this product targets |
|---|---|---|---|
| **Incident response / paging** | PagerDuty, Opsgenie, incident.io | Routing, escalation, on-call scheduling, comms, postmortem workflow | They coordinate *humans*. They do not investigate telemetry or produce evidence-backed RCA. |
| **Observability platforms with AI assist** | Datadog, New Relic, Grafana, Dynatrace | Data collection, anomaly detection, correlation within their own data | Investigation is confined to their own telemetry silo, and output is typically a summary or anomaly, not a bounded, auditable, approval-gated remediation plan. |
| **AIOps / event correlation** | BigPanda, Moogsoft | Alert noise reduction and correlation at scale | Correlation is the endpoint. Little causal reasoning, little remediation safety modelling, weak evidence attribution. |
| **Runbook automation** | Rundeck, Ansible AWX, Shoreline | Reliable, safe, scoped execution of *predefined* actions | Requires a human to have already decided *what* to run. No investigation, no hypothesis formation. |
| **LLM SRE assistants / copilots** | Various vendor copilots and OSS agents | Fast natural-language access to telemetry | Typically single-agent, unbounded, weak permission modelling, no independent verification, no evaluation harness, often no durable state. |

### D.3 Differentiation

The defensible position is the **seam between AIOps correlation and runbook automation**:
the part where investigation becomes a *justified, risk-classified, approved* action. The
five differentiators below are the ones the architecture is actually built to support, and
each maps to a measurable evaluation metric rather than a claim.

| # | Differentiator | Why it is defensible | How it is measured (§9) |
|---|---|---|---|
| D1 | **Evidence-grounded, attributed reasoning** | Every claim carries provenance and citations; verified facts, hypotheses and model claims are structurally distinct types, not prose conventions | Unsupported-claim rate; evidence precision/recall; citation validity |
| D2 | **Bounded autonomy with deterministic termination** | Hard limits on iterations, tool calls, wall-clock, tokens and cost; every run ends in success, uncertainty, timeout, failure or escalation | Termination-reason distribution; loop count; tool-call efficiency |
| D3 | **Safety architecture outside the model** | A deterministic, non-LLM policy gate is the only path to any write action; the model cannot widen its own scope | Unsafe-action rate (target: zero by construction, verified by adversarial tests) |
| D4 | **Independent verification** | Verification is a separate node that re-derives system state rather than trusting the executor's claim of success | Verification success rate; false-success rate |
| D5 | **Evaluation as a product subsystem** | Golden scenarios, replay, judge calibration and regression gates in CI; behaviour changes are versioned | Regression rate; RCA accuracy across versions |

### D.4 Where we are deliberately weaker

Stating this honestly is part of the engineering position, and it prevents scope creep:

- **Data scale.** Datadog-class ingestion is not a goal. We query existing backends through
  adapters rather than storing telemetry ourselves.
- **Breadth of integrations.** Nine integrations (section 14) done well and simulated
  deterministically, rather than a hundred done shallowly.
- **Detection.** We do not compete on anomaly detection or alerting quality. We consume
  alerts; upstream systems generate them.
- **Turnkey deployment.** This targets teams with an existing observability stack and a
  service taxonomy, not greenfield operations.

### D.5 Portfolio positioning (§22)

The completed system is intended to support AI Engineer, AI Platform Engineer, Agentic AI
Engineer, LLMOps/AI Infrastructure, Software Engineer–AI Systems, and SRE/DevOps-with-AI
roles. The evidence for each of those claims is an artifact in this repository — a
topology decision, a policy gate, an evaluation harness, a trace model — not a bullet on a
résumé. Per section 22, any metric quoted from this project must originate in a recorded
replay, benchmark or load-test run and be labelled with the conditions under which it was
measured.

---

## Open questions requiring stakeholder decision

These are recorded rather than silently assumed; they are listed for review in the
Architecture Package completion report.

| # | Question | Current working assumption | Impact if wrong |
|---|---|---|---|
| Q1 | Is multi-tenancy a real requirement, or single-org with environment separation? | Multi-tenant from day one, enforced in the database | Retrofitting tenancy later is expensive and touches every table and query |
| Q2 | Is v1 expected to *execute* remediation, or only recommend it? | Execute, restricted to reversible low-risk tiers, always after approval | Determines whether the executor and verifier are v1 or v2 scope |
| Q3 | Do we target a specific cloud, or stay cloud-agnostic via Kubernetes? | Kubernetes-native, cloud-agnostic | Cloud-specific adapters (EKS/GKE/AKS control planes) would expand scope materially |
