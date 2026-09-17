"""Structural safety guards.

These assert the *absence* of dangerous shapes. Master specification section 6 forbids
executing arbitrary model-generated production commands, and the approved architecture
makes that structural: no column and no tool input field can carry a free-form command.
"""

from __future__ import annotations

import pytest

from asic.domain.enums import NodeId, RiskTier
from asic.domain.safety import (
    FORBIDDEN_EXECUTION_FIELDS,
    FORBIDDEN_SECRET_FIELDS,
    check_field_names,
    is_forbidden_execution_field,
    is_forbidden_secret_field,
    is_secret_reference,
    normalise_field_name,
)


class TestFieldNameNormalisation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Command", "command"),
            ("shell-command", "shell_command"),
            ("  RAW_COMMAND  ", "raw_command"),
            ("kubectl.command", "kubectl_command"),
            ("api key", "api_key"),
        ],
    )
    def test_normalisation_defeats_cosmetic_variation(self, raw: str, expected: str) -> None:
        """A guard defeated by a hyphen or a capital letter is not a guard."""
        assert normalise_field_name(raw) == expected


class TestExecutionFieldGuard:
    @pytest.mark.parametrize(
        "name",
        ["command", "cmd", "shell", "script", "kubectl", "raw_sql", "manifest_yaml", "eval"],
    )
    def test_execution_channels_are_rejected(self, name: str) -> None:
        assert is_forbidden_execution_field(name)

    @pytest.mark.parametrize("name", ["Command", "SHELL-COMMAND", "Raw_Command"])
    def test_case_and_separator_variants_are_rejected(self, name: str) -> None:
        assert is_forbidden_execution_field(name)

    @pytest.mark.parametrize(
        "name", ["namespace", "deployment", "to_revision", "cluster", "replicas"]
    )
    def test_legitimate_typed_arguments_are_allowed(self, name: str) -> None:
        assert not is_forbidden_execution_field(name)

    def test_check_reports_every_offender(self) -> None:
        offenders = check_field_names(["namespace", "command", "replicas", "script"])
        assert len(offenders) == 2
        assert any("command" in o for o in offenders)
        assert any("script" in o for o in offenders)

    def test_a_safe_argument_set_reports_nothing(self) -> None:
        assert check_field_names(["tenant_id", "cluster", "namespace", "deployment"]) == []


class TestSecretFieldGuard:
    @pytest.mark.parametrize(
        "name", ["password", "api_key", "private_key", "client_secret", "connection_string"]
    )
    def test_secret_columns_are_rejected(self, name: str) -> None:
        assert is_forbidden_secret_field(name)

    @pytest.mark.parametrize("name", ["credential_ref", "secret_ref", "secret_manager_path"])
    def test_secret_references_are_permitted(self, name: str) -> None:
        """Naming a secret is fine; storing one is not."""
        assert is_secret_reference(name)

    def test_guard_categories_do_not_overlap(self) -> None:
        assert FORBIDDEN_EXECUTION_FIELDS.isdisjoint(FORBIDDEN_SECRET_FIELDS)

    def test_check_field_names_rejects_a_bare_string(self) -> None:
        """Passing a string would iterate characters and silently pass."""
        with pytest.raises(TypeError, match="iterable of field names"):
            check_field_names("command")


class TestRiskTier:
    def test_destructive_tier_is_not_agent_invocable(self) -> None:
        """SI-5: a capability the system cannot express is safer than one it is told
        not to use."""
        assert not RiskTier.R3.is_agent_invocable
        for tier in (RiskTier.RO, RiskTier.R1, RiskTier.R2):
            assert tier.is_agent_invocable

    def test_only_ro_is_read_only(self) -> None:
        assert RiskTier.RO.is_read_only
        for tier in (RiskTier.R1, RiskTier.R2, RiskTier.R3):
            assert not tier.is_read_only


class TestNodeTopology:
    def test_control_nodes_never_use_a_model(self) -> None:
        """ADR-0001's central finding: authorization, approval, execution and routing are
        deterministic. A model in any of these paths violates sections 6 and 15."""
        for node in (
            NodeId.G2_INCIDENT_COORDINATOR,
            NodeId.G7_POLICY_GATE,
            NodeId.G8_APPROVAL_SERVICE,
            NodeId.G9_REMEDIATION_EXECUTOR,
            NodeId.S1_TIMELINE_PROJECTION,
            NodeId.S2_NOTIFICATION_SERVICE,
        ):
            assert not node.uses_model, f"{node.value} must be deterministic"

    def test_reasoning_nodes_use_a_model(self) -> None:
        for node in (
            NodeId.G3_INVESTIGATION_PLANNER,
            NodeId.G4_EVIDENCE_COLLECTOR,
            NodeId.G5_HYPOTHESIS_ENGINE,
            NodeId.G6_REMEDIATION_PLANNER,
            NodeId.G10_VERIFIER,
        ):
            assert node.uses_model, f"{node.value} is a reasoning node"

    def test_topology_matches_the_approved_counts(self) -> None:
        """ADR-0001: 12 graph nodes plus 2 derived services; 8 invoke a model."""
        product = [n for n in NodeId if n.in_product_topology]
        assert len(product) == 14
        assert sum(1 for n in product if n.uses_model) == 8

    def test_the_evaluation_judge_is_outside_the_product_topology(self) -> None:
        """ADR-0028: the judge calls a model but is no graph node and holds no contract."""
        from asic.contracts.nodes import NODE_CONTRACTS

        assert [n for n in NodeId if not n.in_product_topology] == [NodeId.E1_EVALUATION_JUDGE]
        assert NodeId.E1_EVALUATION_JUDGE.uses_model
        assert NodeId.E1_EVALUATION_JUDGE not in {c.node_id for c in NODE_CONTRACTS.values()}
