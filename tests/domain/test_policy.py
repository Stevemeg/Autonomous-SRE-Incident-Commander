"""The deterministic policy gate (G7's rule engine), tested directly against pure inputs.

No database, no graph, no broker: ``asic.domain.policy.evaluate_policy`` is SYSTEM-provenance
arithmetic over :class:`~asic.domain.policy.PolicyInputs`, and the autonomy matrix it
implements (``docs/architecture/remediation-safety-policy.md`` section 3) is provable from
that function alone. Several tests here are deliberately *mutation-style*: they do not just
assert a guard exists, they flip exactly one input the guard is supposed to key off and prove
the verdict actually changes - a guard that fires regardless of that input would pass a naive
"the DENY case denies" test and still be worthless.
"""

from __future__ import annotations

import pytest

from asic.domain.enums import PolicyVerdict, RiskTier
from asic.domain.errors import PolicyEvaluationFailed
from asic.domain.policy import PolicyInputs, detect_ambiguity, evaluate_policy


def _inputs(**overrides: object) -> PolicyInputs:
    base: dict[str, object] = {
        "risk_tier": RiskTier.R1,
        "is_production": False,
        "hypothesis_confidence": 0.9,
        "supporting_evidence_count": 3,
        "contradicting_evidence_count": 0,
        "competing_hypotheses_conflict": False,
        "unexplained_counter_evidence": False,
        "evidence_stale": False,
        "concurrent_incident_same_scope": False,
    }
    base.update(overrides)
    return PolicyInputs(**base)  # type: ignore[arg-type]


class TestReadOnly:
    def test_ro_is_always_autonomous(self) -> None:
        result = evaluate_policy(_inputs(risk_tier=RiskTier.RO, is_production=True))
        assert result.verdict is PolicyVerdict.ALLOW
        assert result.rule_id == "P0_read_only_always_autonomous"


class TestR3Unreachable:
    def test_r3_is_refused_rather_than_evaluated(self) -> None:
        """R3 is never registered (SI-5): seeing one here is a programming error, and the
        honest response is to refuse outright, never to invent a verdict for it."""
        with pytest.raises(PolicyEvaluationFailed):
            evaluate_policy(_inputs(risk_tier=RiskTier.R3))


class TestHighRiskR2:
    def test_r2_requires_approval_even_when_completely_unambiguous(self) -> None:
        """R2 never gets an autonomous ALLOW, no matter how clean the evidence is - the
        mutation this proves: an R1 input with every ambiguity signal cleared is ALLOW
        (see TestReversibleR1 below), but the *same* clean inputs at R2 are not."""
        result = evaluate_policy(_inputs(risk_tier=RiskTier.R2, is_production=False))
        assert result.verdict is PolicyVerdict.REQUIRE_APPROVAL
        assert result.rule_id == "P3_high_risk_requires_approval"

    def test_r2_with_ambiguity_is_denied_not_offered_for_approval(self) -> None:
        result = evaluate_policy(_inputs(risk_tier=RiskTier.R2, hypothesis_confidence=0.1))
        assert result.verdict is PolicyVerdict.DENY
        assert result.rule_id == "P4_high_risk_ambiguous_denied"

    def test_r2_with_a_concurrent_overlapping_incident_is_denied(self) -> None:
        result = evaluate_policy(
            _inputs(risk_tier=RiskTier.R2, concurrent_incident_same_scope=True)
        )
        assert result.verdict is PolicyVerdict.DENY
        assert result.rule_id == "P4_high_risk_ambiguous_denied"


class TestReversibleR1:
    def test_r1_non_production_unambiguous_is_autonomous(self) -> None:
        result = evaluate_policy(_inputs(risk_tier=RiskTier.R1, is_production=False))
        assert result.verdict is PolicyVerdict.ALLOW
        assert result.rule_id == "P6_reversible_non_production_autonomous"

    def test_flipping_only_is_production_changes_the_verdict(self) -> None:
        """The mutation proof for P1: every other input held fixed, production alone
        moves R1 from autonomous to requiring approval - proving the gate actually keys
        off ``is_production`` rather than defaulting to ALLOW regardless of it."""
        non_prod = evaluate_policy(_inputs(risk_tier=RiskTier.R1, is_production=False))
        prod = evaluate_policy(_inputs(risk_tier=RiskTier.R1, is_production=True))
        assert non_prod.verdict is PolicyVerdict.ALLOW
        assert prod.verdict is PolicyVerdict.REQUIRE_APPROVAL
        assert prod.rule_id == "P1_reversible_production_requires_approval"

    def test_r1_is_never_denied_outright(self) -> None:
        """Reversible + a human available is exactly what approval exists for; R1 either
        proceeds or waits for a human, but this gate never denies it outright."""
        result = evaluate_policy(
            _inputs(
                risk_tier=RiskTier.R1,
                is_production=True,
                hypothesis_confidence=0.05,
                competing_hypotheses_conflict=True,
                contradicting_evidence_count=5,
                evidence_stale=True,
                concurrent_incident_same_scope=True,
            )
        )
        assert result.verdict is PolicyVerdict.REQUIRE_APPROVAL

    @pytest.mark.parametrize(
        "field,value",
        [
            ("hypothesis_confidence", 0.1),
            ("competing_hypotheses_conflict", True),
            ("contradicting_evidence_count", 1),
            ("evidence_stale", True),
            ("concurrent_incident_same_scope", True),
        ],
    )
    def test_each_ambiguity_signal_alone_forces_approval(self, field: str, value: object) -> None:
        """Each of the five signals, in isolation (all others clean), is independently
        sufficient to move R1 off the autonomous path - a guard that only fired when every
        signal was present at once would leave four of these five cases silently autonomous."""
        result = evaluate_policy(_inputs(risk_tier=RiskTier.R1, **{field: value}))
        assert result.verdict is PolicyVerdict.REQUIRE_APPROVAL
        assert result.rule_id == "P2_reversible_ambiguous_requires_approval"

    def test_tenant_override_forces_approval_even_when_otherwise_clean(self) -> None:
        result = evaluate_policy(
            _inputs(risk_tier=RiskTier.R1, tenant_requires_approval_override=True)
        )
        assert result.verdict is PolicyVerdict.REQUIRE_APPROVAL
        assert result.rule_id == "P5_tenant_requires_approval"

    def test_tenant_override_can_only_add_a_requirement_never_remove_one(self) -> None:
        """``False``/``None`` both defer to the platform default rather than forcing ALLOW -
        the field cannot be used to bypass P1/P2/P3."""
        result = evaluate_policy(
            _inputs(
                risk_tier=RiskTier.R1,
                is_production=True,
                tenant_requires_approval_override=False,
            )
        )
        assert result.verdict is PolicyVerdict.REQUIRE_APPROVAL
        assert result.rule_id == "P1_reversible_production_requires_approval"


class TestAmbiguityDetection:
    def test_every_signal_is_reported_not_just_the_first(self) -> None:
        signals = detect_ambiguity(
            _inputs(
                hypothesis_confidence=0.1,
                competing_hypotheses_conflict=True,
                contradicting_evidence_count=2,
                evidence_stale=True,
                concurrent_incident_same_scope=True,
            )
        )
        assert set(signals) == {
            "confidence_below_threshold",
            "competing_hypotheses_conflict",
            "unexplained_counter_evidence",
            "evidence_stale",
            "concurrent_incident_same_scope",
        }

    def test_no_signals_when_everything_is_clean(self) -> None:
        assert detect_ambiguity(_inputs()) == ()

    def test_model_stated_confidence_alone_does_not_appear_as_a_field(self) -> None:
        """There is no field on PolicyInputs for 'the model says it is sure' - ambiguity is
        computed only from the deterministic inputs the docstring enumerates."""
        assert set(PolicyInputs.__dataclass_fields__) == {
            "risk_tier",
            "is_production",
            "hypothesis_confidence",
            "supporting_evidence_count",
            "contradicting_evidence_count",
            "competing_hypotheses_conflict",
            "unexplained_counter_evidence",
            "evidence_stale",
            "concurrent_incident_same_scope",
            "tenant_requires_approval_override",
            "confidence_threshold",
        }


__all__: list[str] = []
