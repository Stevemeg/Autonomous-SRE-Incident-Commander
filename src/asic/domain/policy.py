"""The deterministic policy gate: G7's rule engine.

``docs/architecture/remediation-safety-policy.md`` section 3 is the specification this
module implements exactly. Nothing here reads a model, retrieved content, or anything not
listed on :class:`PolicyInputs` - SI-3 requires that authority flow only from ``SYSTEM`` and
``HUMAN`` provenance, and every field here is one of those two.

The autonomy matrix (section 3), stated as a decision procedure rather than a table:

* **R2 is never autonomous.** It always requires approval, unless ambiguity or a
  concurrent overlapping incident is present, in which case it is denied outright and
  escalated - R2 does not get a chance to ask a human for something the gate itself will
  not authorise attempting.
* **R1 is autonomous only in non-production, with no ambiguity signal and no concurrent
  overlapping incident.** Anything else about an R1 proposal requires approval; R1 is never
  denied outright, because a reversible low-risk action with a human available to look at
  it is exactly the case approval exists for.
* **RO is always autonomous.** In practice a remediation *action* is never RO - RO is
  investigation, not remediation - but the rule is stated for totality rather than assumed.

Ambiguity (section 3.1) is defined **deterministically**, never from the model's own stated
confidence. "The model says it's sure" is not one of the five signals below.
"""

from __future__ import annotations

from dataclasses import dataclass

from asic.domain.enums import PolicyVerdict, RiskTier
from asic.domain.errors import PolicyEvaluationFailed

#: Default confidence floor below which a hypothesis cannot justify autonomous action.
#: Tenant-configurable in a later phase; this is the platform default.
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.6


@dataclass(frozen=True, slots=True)
class PolicyInputs:
    """Everything the gate's decision depends on. No other state may influence it.

    Every field is ``SYSTEM`` provenance: computed by deterministic code from durable rows
    (the hypothesis, the incident, the tenant's grant), never from model prose and never
    from retrieved content. There is no field here a runbook or a log line could populate.
    """

    risk_tier: RiskTier
    is_production: bool
    hypothesis_confidence: float
    supporting_evidence_count: int
    contradicting_evidence_count: int
    #: Two or more hypotheses within this incident propose materially different actions
    #: and are within the configured confidence margin of each other.
    competing_hypotheses_conflict: bool
    #: The hypothesis has an evidence gap the model itself declared unresolved (a
    #: counter-evidence item with no accompanying explanation).
    unexplained_counter_evidence: bool
    #: The evidence supporting the action is older than the action's declared staleness
    #: window.
    evidence_stale: bool
    #: Another open incident already holds a write action against the same service or
    #: namespace in this environment.
    concurrent_incident_same_scope: bool
    #: Tenant grant narrowing: forces approval even where the platform default would not
    #: require it. ``None`` or ``False`` defers to the platform default; this field can
    #: only add an approval requirement, never remove one the default would apply.
    tenant_requires_approval_override: bool | None = None
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD


@dataclass(frozen=True, slots=True)
class PolicyVerdictResult:
    """The gate's decision, with the rule that produced it and why."""

    verdict: PolicyVerdict
    rule_id: str
    rationale: str
    ambiguity_signals: tuple[str, ...] = ()


def detect_ambiguity(inputs: PolicyInputs) -> tuple[str, ...]:
    """The five deterministic ambiguity signals of section 3.1, evaluated independently.

    Every signal that fires is returned, not just the first - the approver (or the audit
    record, for a denial) sees the whole picture rather than one arbitrarily chosen reason.
    """
    signals: list[str] = []
    if inputs.hypothesis_confidence < inputs.confidence_threshold:
        signals.append("confidence_below_threshold")
    if inputs.competing_hypotheses_conflict:
        signals.append("competing_hypotheses_conflict")
    if inputs.unexplained_counter_evidence or inputs.contradicting_evidence_count > 0:
        signals.append("unexplained_counter_evidence")
    if inputs.evidence_stale:
        signals.append("evidence_stale")
    if inputs.concurrent_incident_same_scope:
        signals.append("concurrent_incident_same_scope")
    return tuple(signals)


def evaluate_policy(inputs: PolicyInputs) -> PolicyVerdictResult:
    """Apply the autonomy matrix. Always returns a verdict naming the rule that produced it.

    Raises:
        PolicyEvaluationFailed: if asked to evaluate a tier that cannot reach this gate at
            all (R3 is never registered - SI-5 - so seeing one here is a programming
            error, not a policy question, and the honest response is to refuse rather than
            invent a verdict for an input the system should never produce).
    """
    if inputs.risk_tier is RiskTier.R3:
        raise PolicyEvaluationFailed(
            "risk tier r3 reached the policy gate; r3 capabilities are not registered "
            "(SI-5) and this input should be structurally unreachable"
        )

    ambiguity = detect_ambiguity(inputs)
    forced_approval = bool(inputs.tenant_requires_approval_override)

    if inputs.risk_tier is RiskTier.RO:
        return PolicyVerdictResult(
            verdict=PolicyVerdict.ALLOW,
            rule_id="P0_read_only_always_autonomous",
            rationale="read-only actions require no authorisation beyond the tool broker",
        )

    if inputs.risk_tier is RiskTier.R2:
        if ambiguity or inputs.concurrent_incident_same_scope:
            return PolicyVerdictResult(
                verdict=PolicyVerdict.DENY,
                rule_id="P4_high_risk_ambiguous_denied",
                rationale=(
                    "r2 is high-risk and never autonomous; with an ambiguity signal or an "
                    "overlapping concurrent incident present, it is denied outright and "
                    "escalated rather than offered for approval"
                ),
                ambiguity_signals=ambiguity,
            )
        return PolicyVerdictResult(
            verdict=PolicyVerdict.REQUIRE_APPROVAL,
            rule_id="P3_high_risk_requires_approval",
            rationale="r2 (high-risk) requires human approval in every environment, always",
        )

    # R1: reversible low-risk.
    if forced_approval:
        return PolicyVerdictResult(
            verdict=PolicyVerdict.REQUIRE_APPROVAL,
            rule_id="P5_tenant_requires_approval",
            rationale="the tenant's grant requires approval for this tool beyond the platform default",
            ambiguity_signals=ambiguity,
        )
    if ambiguity:
        return PolicyVerdictResult(
            verdict=PolicyVerdict.REQUIRE_APPROVAL,
            rule_id="P2_reversible_ambiguous_requires_approval",
            rationale=(
                "r1 is reversible, so ambiguous evidence requires a human to look rather "
                "than being denied outright"
            ),
            ambiguity_signals=ambiguity,
        )
    if inputs.is_production:
        return PolicyVerdictResult(
            verdict=PolicyVerdict.REQUIRE_APPROVAL,
            rule_id="P1_reversible_production_requires_approval",
            rationale="r1 in production requires approval; only non-production r1 is autonomous",
        )
    return PolicyVerdictResult(
        verdict=PolicyVerdict.ALLOW,
        rule_id="P6_reversible_non_production_autonomous",
        rationale="r1 in non-production, with no ambiguity and no concurrent overlap, is autonomous",
    )


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "PolicyInputs",
    "PolicyVerdictResult",
    "detect_ambiguity",
    "evaluate_policy",
]
