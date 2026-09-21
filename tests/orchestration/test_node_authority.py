"""Phase 13 (F-08): the authority model for node-scoped Kubernetes actions.

``k8s.node.cordon`` / ``uncordon`` are not service-scoped: a node is shared infrastructure
with no service label. Their scope is instead explicit and deterministic - frozen
tenant/environment target, node identity bound into the approved action hash, R2, and a
current human approval every time. These tests attack each of those legs.
"""

from __future__ import annotations

from typing import Any

import pytest
import sqlalchemy as sa

from asic.db.models import RemediationAction
from asic.domain.enums import ApprovalDecision, PolicyVerdict
from asic.domain.errors import CapabilityNotGranted
from asic.domain.idempotency import action_version_hash
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.remediation.approval_service import decide
from asic.simulators.provider import SimulatorProvider
from asic.tools.remediation_catalogue import (
    K8S_NODE_CORDON,
    NODE_SCOPED_CAPABILITIES,
    WRITE_CATALOGUE,
)
from tests.conftest import requires_postgres
from tests.orchestration.test_remediation import _run_remediation
from tests.orchestration.test_remediation_security import _prepared
from tests.remediation_fixtures import create_approver

pytestmark = [requires_postgres, pytest.mark.security]


NODE = "node-pool-a-3"  # the node the scenario's cluster actually contains
OTHER_NODE = "node-pool-a-9"


def _node_scenario(node: str = NODE) -> Any:
    """SC-0001 with a scripted R2 proposal to cordon ``node``."""
    from dataclasses import replace

    from asic.simulators.scenarios import (
        _remediation_plan,
        k8s_node_cordon_success,
        k8s_workload_memory_pressure,
        scenario,
    )
    from tests.orchestration.test_remediation import _sim_response

    base = scenario("SC-0001-checkout-latency-after-deploy")
    responses = dict(base.responses)
    responses["mutate.k8s_node|"] = _sim_response(k8s_node_cordon_success)
    # A cluster that actually contains the node: the SI-7 ``node_exists`` precondition is
    # answered from a fresh read, so a node that is not observed there is refused.
    responses["read.k8s_workload|checkout-api"] = _sim_response(k8s_workload_memory_pressure)
    plan = _remediation_plan(tool_name="k8s.node.cordon", arguments={"node": node})
    return replace(base, responses=responses, remediation_planner_script=(plan,))


def _rehash(action: RemediationAction) -> str:
    return action_version_hash(
        action_id=action.id,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments=action.arguments,
        permission_scope=action.permission_scope,
        preconditions=action.preconditions,
        risk_tier=action.risk_tier.value,
    )


def _resume(
    session_factory: Any, remediation_resolver: Any, clock: Any, fixture: Any, outcome: Any
) -> tuple[Any, SimulatorProvider]:
    scenario_obj = _node_scenario()
    provider = SimulatorProvider(scenario_obj, clock=clock)
    resumed = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[provider],
        model=DeterministicModelProvider(scenario_obj),
        clock=clock,
    ).resume(tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id)
    return resumed, provider


def _cordon_calls(provider: SimulatorProvider) -> list[Any]:
    return [call for call in provider.calls if call[0] == "k8s.node.cordon"]


def _awaiting_approval(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
    slug: str,
) -> tuple[Any, Any, RemediationAction, Any]:
    fixture, hypothesis_id = _prepared(kernel_session, session_factory, resolver, clock, slug, True)
    approver = create_approver(kernel_session, fixture)
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _node_scenario(),
    )
    action = kernel_session.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    )
    assert action is not None and action.arguments == {"node": NODE}
    return fixture, approver, action, outcome


def test_the_node_scoped_capability_set_is_exactly_the_node_tools() -> None:
    node_tools = {d.name for d in WRITE_CATALOGUE if d.capability in NODE_SCOPED_CAPABILITIES}
    assert node_tools == {"k8s.node.cordon", "k8s.node.uncordon"}
    # Every one of them is R2 and declares no service scope: the model documented in the
    # catalogue, asserted so the docs cannot drift from the descriptors.
    for descriptor in WRITE_CATALOGUE:
        if descriptor.capability in NODE_SCOPED_CAPABILITIES:
            assert descriptor.risk_tier.value == "r2"
            assert "service" not in {a.name for a in descriptor.arguments}
            assert "node" in {a.name for a in descriptor.arguments}
    assert "service" not in {a.name for a in K8S_NODE_CORDON.arguments}


def test_a_substituted_node_is_refused_and_nothing_is_cordoned(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    """Approve one node, then swap the stored node for another without re-approval."""
    fixture, approver, action, outcome = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock, "node-swap"
    )
    approved_hash = action.action_version_hash
    decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=approved_hash,
        justification="approve cordoning node-7 only",
        clock=clock,
    )
    action.arguments = {"node": OTHER_NODE}  # substitution after approval; hash left stale
    kernel_session.commit()
    resumed, provider = _resume(session_factory, remediation_resolver, clock, fixture, outcome)
    assert resumed.terminated
    assert _cordon_calls(provider) == []
    assert OTHER_NODE not in repr(provider.calls)


def test_a_rehashed_substitution_needs_a_new_approval(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    """Swap the node *and* recompute the hash: the approval is bound to the old hash."""
    fixture, approver, action, outcome = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock, "node-rehash"
    )
    decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="approve cordoning node-7 only",
        clock=clock,
    )
    action.arguments = {"node": OTHER_NODE}
    action.action_version_hash = _rehash(action)
    kernel_session.commit()
    resumed, provider = _resume(session_factory, remediation_resolver, clock, fixture, outcome)
    # The changed action is a different action: it waits for its own approval, and nothing
    # was cordoned on the strength of the old one.
    assert _cordon_calls(provider) == []
    assert OTHER_NODE not in repr(provider.calls)
    assert not resumed.terminated or "approval" in str(resumed.termination_reason).lower()


def test_the_approved_node_is_dispatched_exactly_as_approved(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, approver, action, outcome = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock, "node-ok"
    )
    decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="approve cordoning node-7",
        clock=clock,
    )
    _, provider = _resume(session_factory, remediation_resolver, clock, fixture, outcome)
    calls = _cordon_calls(provider)
    assert len(calls) == 1
    from asic.db.models.tools import ToolExecution

    executions = kernel_session.scalars(
        sa.select(ToolExecution).where(
            ToolExecution.tenant_id == fixture.tenant_id,
            ToolExecution.remediation_action_id == action.id,
            ToolExecution.tool_name == "k8s.node.cordon",
        )
    ).all()
    assert len(executions) == 1
    assert executions[0].arguments_redacted["node"] == NODE
    # Scope came from the frozen target, not the proposal: tenant and environment only.
    assert set(executions[0].resolved_scope) == {"tenant_id", "environment"}


def test_policy_alone_can_never_admit_a_node_action(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    """Even a forged ALLOW verdict cannot skip the human for a node-scoped capability."""
    from asic.db.models.remediation import PolicyDecision
    from asic.domain.enums import RemediationActionStatus
    from asic.remediation.authorization import require_write_authority

    fixture, _approver, action, _outcome = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock, "node-allow"
    )
    policy = kernel_session.scalar(
        sa.select(PolicyDecision).where(PolicyDecision.remediation_action_id == action.id)
    )
    assert policy is not None and policy.verdict is not PolicyVerdict.ALLOW
    # Simulate the corrupted state: verdict ALLOW, action executing, no approval at all.
    # In memory only: the application role cannot UPDATE the append-only policy table, and
    # the session does not autoflush, so the corrupted state is visible to the guard alone.
    policy.verdict = PolicyVerdict.ALLOW
    action.status = RemediationActionStatus.EXECUTING
    from asic.db.models.remediation import RemediationTarget

    target = kernel_session.scalar(
        sa.select(RemediationTarget).where(RemediationTarget.id == action.remediation_target_id)
    )
    assert target is not None
    with pytest.raises(CapabilityNotGranted, match="always requires human approval"):
        require_write_authority(
            kernel_session,
            action=action,
            descriptor=K8S_NODE_CORDON,
            arguments=dict(action.arguments),
            environment_id=fixture.environment.id,
            service_name=str(target.resolved_permission_scope["service"]),
            resolved_scope={
                "tenant_id": target.resolved_permission_scope["tenant_id"],
                "environment": target.resolved_permission_scope["environment"],
            },
            now=clock.now(),
        )


def test_a_node_action_naming_no_node_is_refused(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    from asic.domain.enums import RemediationActionStatus
    from asic.remediation.authorization import require_write_authority

    fixture, _approver, action, _outcome = _awaiting_approval(
        kernel_session, session_factory, resolver, remediation_resolver, clock, "node-none"
    )
    action.status = RemediationActionStatus.EXECUTING
    with pytest.raises(CapabilityNotGranted):
        require_write_authority(
            kernel_session,
            action=action,
            descriptor=K8S_NODE_CORDON,
            arguments={},
            environment_id=fixture.environment.id,
            service_name="checkout-api",
            resolved_scope={},
            now=clock.now(),
        )
