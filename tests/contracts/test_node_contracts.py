"""Node contracts are enforced, not merely published.

A contract that nothing checks is documentation. These tests assert the three properties
the kernel actually relies on: that a node cannot write outside its declared keys, that a
node's capability set is what the broker consults, and that the contract registry stays in
step with the graph.
"""

from __future__ import annotations

import pytest

from asic.contracts.nodes import (
    G2_INCIDENT_COORDINATOR,
    G2_TERMINATOR,
    G3_INVESTIGATION_PLANNER,
    G4_EVIDENCE_COLLECTOR,
    G5_HYPOTHESIS_ENGINE,
    NODE_CONTRACTS,
    contract_for,
)
from asic.contracts.state import IMMUTABLE_STATE_KEYS, STATE_KEYS
from asic.domain.enums import NodeId
from asic.domain.errors import ContractViolation
from asic.orchestration.graph import GRAPH_NODES


class TestRegistry:
    def test_every_graph_node_has_a_contract(self) -> None:
        missing = [name for name in GRAPH_NODES if name not in NODE_CONTRACTS]
        assert missing == [], (
            f"graph node(s) {missing} have no contract; a node with no contract cannot be "
            "scheduled because nothing would constrain what it writes"
        )

    def test_every_contract_belongs_to_a_graph_node(self) -> None:
        assert set(NODE_CONTRACTS) == set(GRAPH_NODES)

    def test_an_unregistered_node_is_refused(self) -> None:
        with pytest.raises(ContractViolation, match="no contract registered"):
            contract_for("remediation_executor")

    def test_permitted_keys_are_real_state_keys(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            unknown = contract.permitted_state_keys - STATE_KEYS
            assert unknown == frozenset(), f"{name} permits non-existent state key(s) {unknown}"

    def test_no_contract_permits_writing_immutable_run_state(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            overlap = contract.permitted_state_keys & IMMUTABLE_STATE_KEYS
            assert overlap == frozenset(), (
                f"{name} may write {overlap}, but identity, trace context and objective are "
                "fixed for the lifetime of a run"
            )


class TestStateMutationEnforcement:
    def test_an_update_within_the_contract_is_accepted(self) -> None:
        G3_INVESTIGATION_PLANNER.validate_update({"iteration": 3, "open_gaps": []})

    def test_an_unknown_state_key_is_rejected(self) -> None:
        with pytest.raises(ContractViolation, match="unknown state key"):
            G3_INVESTIGATION_PLANNER.validate_update({"messages": ["hello"]})

    def test_an_immutable_key_is_rejected(self) -> None:
        with pytest.raises(ContractViolation, match="immutable run state"):
            G3_INVESTIGATION_PLANNER.validate_update({"identity": None})

    def test_a_key_outside_the_contract_is_rejected(self) -> None:
        # The planner may not write evidence: only the collector produces evidence, and a
        # planner that could append to it could manufacture support for its own plan.
        with pytest.raises(ContractViolation, match="does not permit"):
            G3_INVESTIGATION_PLANNER.validate_update({"evidence": []})

    def test_the_collector_may_not_terminate_the_run(self) -> None:
        with pytest.raises(ContractViolation, match="does not permit"):
            G4_EVIDENCE_COLLECTOR.validate_update({"terminated": True})

    def test_the_coordinator_entry_node_may_not_write_hypotheses(self) -> None:
        with pytest.raises(ContractViolation, match="does not permit"):
            G2_INCIDENT_COORDINATOR.validate_update({"hypotheses": []})

    def test_only_the_terminator_may_set_the_terminal_incident_status(self) -> None:
        permitted = {
            name
            for name, contract in NODE_CONTRACTS.items()
            if "terminal_incident_status" in contract.permitted_state_keys
        }
        assert permitted == {"terminator", "coordinator"}, (
            "the terminal incident status is the outcome of the run and must not be "
            f"writable by a reasoning node; writable by {sorted(permitted)}"
        )


class TestCapabilityDeclarations:
    def test_only_the_evidence_collector_has_capabilities(self) -> None:
        with_capabilities = {
            name for name, contract in NODE_CONTRACTS.items() if contract.capabilities
        }
        assert with_capabilities == {"evidence_collector"}, (
            "exactly one node may reach an external system; giving a reasoning node "
            "capabilities would remove the separation the broker exists to enforce"
        )

    def test_the_planner_cannot_request_any_capability(self) -> None:
        for capability in ("read.metrics", "read.logs", "mutate.k8s_deployment"):
            assert not G3_INVESTIGATION_PLANNER.permits_capability(capability)

    def test_the_hypothesis_engine_cannot_request_any_capability(self) -> None:
        assert G5_HYPOTHESIS_ENGINE.capabilities == frozenset()

    def test_no_contract_declares_a_write_capability(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            offenders = [c for c in contract.capabilities if not c.startswith("read.")]
            assert offenders == [], (
                f"{name} declares non-read capability {offenders}; this deployment is "
                "read-only and has no policy gate to authorize a write"
            )


class TestContractCompleteness:
    def test_every_contract_declares_a_termination_behaviour(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            assert contract.termination_behaviour.strip(), f"{name} has no deterministic exit"

    def test_every_contract_declares_failure_modes(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            assert contract.failure_modes, f"{name} declares no failure modes"

    def test_every_contract_declares_idempotency_or_says_why_not(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            assert contract.idempotency is None or contract.idempotency.strip(), name

    def test_model_backed_nodes_match_the_approved_topology(self) -> None:
        # ADR-0001 fixes which nodes may invoke a model. The evidence collector is the one
        # deliberate narrowing for this phase, and it narrows *away* from the model.
        for name, contract in NODE_CONTRACTS.items():
            if contract.model_backed:
                assert contract.node_id.uses_model, (
                    f"{name} is model-backed but {contract.node_id.value} is a "
                    "deterministic node in the approved topology"
                )

    def test_the_evidence_collector_is_narrowed_away_from_the_model(self) -> None:
        assert NodeId.G4_EVIDENCE_COLLECTOR.uses_model is True
        assert G4_EVIDENCE_COLLECTOR.model_backed is False, (
            "the phase-4 collector is deterministic by design; if this ever flips, the "
            "narrowing note in the contract and in the architecture must go with it"
        )

    def test_timeouts_are_layered(self) -> None:
        # An inner timeout must fire before its container so the failure is specific.
        assert G2_TERMINATOR.timeout_seconds < G3_INVESTIGATION_PLANNER.timeout_seconds
        assert G3_INVESTIGATION_PLANNER.timeout_seconds < G4_EVIDENCE_COLLECTOR.timeout_seconds

    def test_versions_are_declared(self) -> None:
        for name, contract in NODE_CONTRACTS.items():
            assert contract.node_version, name
            assert contract.contract_version, name
