"""Regression and guard-removal tests for remediation authorization and recovery."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from asic.db.models import (
    Alert,
    Approval,
    RemediationAction,
    RemediationBaseline,
    RemediationTarget,
    Service,
    UserRoleAssignment,
)
from asic.db.models.orchestration import WorkflowCheckpoint
from asic.db.models.tools import TenantToolGrant, ToolDefinition, ToolExecution
from asic.db.session import bind_tenant
from asic.domain.enums import ApprovalDecision, IncidentStatus, RiskTier, VerificationVerdict
from asic.domain.errors import DomainError
from asic.domain.idempotency import action_version_hash
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.orchestration.remediation.nodes import executor as executor_module
from asic.orchestration.remediation.nodes.verifier import (
    _evaluate,
    trusted_baseline,
)
from asic.remediation.approval_service import decide
from asic.remediation.dispatch_recovery import DispatchEvidence
from asic.remediation.trust import baseline_provenance
from asic.remediation.verification import profile_for
from asic.simulators.provider import SimulatorProvider
from asic.simulators.scenarios import metrics_recovered, scenario
from asic.tools.broker import ToolBroker
from tests.conftest import requires_postgres
from tests.kernel_fixtures import build_fixture
from tests.orchestration.test_remediation import (
    _post_remediation_scenario,
    _remediation_scenario,
    _run_remediation,
    _sim_response,
)
from tests.remediation_fixtures import (
    create_approver,
    escalate_to_accepted_hypothesis,
)

pytestmark = requires_postgres


def _prepared(
    session: Any, factory: Any, resolver: Any, clock: Any, slug: str, production: bool = False
) -> tuple[Any, Any]:
    fixture = build_fixture(session, slug=slug)
    fixture.environment.is_production = production
    session.commit()
    hypothesis_id = escalate_to_accepted_hypothesis(
        factory, resolver, clock, fixture, scenario("SC-0001-checkout-latency-after-deploy")
    )
    return fixture, hypothesis_id


def _blind_to_evidence(*_args: Any, **_kwargs: Any) -> DispatchEvidence:
    """The executor as it behaved before durable dispatch evidence was consulted."""
    return DispatchEvidence(intent_recorded=False, claimed=False, receipt=None)


def _kernel(
    factory: Any, resolver: Any, clock: Any, model: Any = None, scenario_obj: Any = None
) -> RemediationKernel:
    selected = scenario_obj or _post_remediation_scenario()
    return RemediationKernel(
        session_factory=factory,
        resolver=resolver,
        clock=clock,
        model=model or DeterministicModelProvider(selected),
        providers=[SimulatorProvider(selected, clock=clock)],
    )


def test_resume_uses_persisted_proposal_and_budget(
    kernel_session: Any, session_factory: Any, resolver: Any, remediation_resolver: Any, clock: Any
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "resume-persisted", True
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    before = kernel_session.execute(
        sa.select(WorkflowCheckpoint)
        .where(WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id)
        .order_by(WorkflowCheckpoint.sequence.desc())
        .limit(1)
    ).scalar_one()
    tokens = before.budget_consumed["ledger"]["tokens"]
    assert tokens > 0
    unavailable_model = DeterministicModelProvider(_remediation_scenario(), fail_after=0)
    resumed = _kernel(session_factory, remediation_resolver, clock, unavailable_model).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert not resumed.terminated
    assert unavailable_model.call_count == 0
    after = kernel_session.execute(
        sa.select(WorkflowCheckpoint)
        .where(WorkflowCheckpoint.workflow_run_id == outcome.workflow_run_id)
        .order_by(WorkflowCheckpoint.sequence.desc())
        .limit(1)
    ).scalar_one()
    assert after.budget_consumed["ledger"]["tokens"] == tokens


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("service_id", lambda row: __import__("uuid").uuid4()),
        ("environment_id", lambda row: __import__("uuid").uuid4()),
        ("remediation_target_id", lambda row: __import__("uuid").uuid4()),
        ("remediation_action_id", lambda row: __import__("uuid").uuid4()),
        ("profile_id", lambda row: "attacker-profile"),
        ("profile_version", lambda row: row.profile_version + 1),
        ("criteria_hash", lambda row: "0" * 64),
        ("metric", lambda row: "unrelated_metric"),
        ("source_capability", lambda row: "read.logs"),
        ("source_provider", lambda row: "unapproved-source"),
        ("read_execution_id", lambda row: __import__("uuid").uuid4()),
        ("observed_at", lambda row: row.observed_at - __import__("datetime").timedelta(hours=1)),
        ("observed_at", lambda row: row.captured_at + __import__("datetime").timedelta(seconds=1)),
        ("captured_at", lambda row: row.captured_at + __import__("datetime").timedelta(seconds=1)),
    ],
)
def test_baseline_binding_and_freshness_guards_are_load_bearing(
    field: str,
    replacement: Any,
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, f"baseline-{field.replace('_', '-')}"
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    kernel_session.expire_all()
    action = kernel_session.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    )
    assert action is not None and action.executed_at is not None
    target = kernel_session.get(RemediationTarget, action.remediation_target_id)
    baseline = kernel_session.scalar(
        sa.select(RemediationBaseline).where(RemediationBaseline.remediation_action_id == action.id)
    )
    assert target is not None and baseline is not None
    deps = SimpleNamespace(
        session=kernel_session,
        context=SimpleNamespace(tenant_id=fixture.tenant_id),
        objective=SimpleNamespace(
            service_name=fixture.service.name,
            environment_name=fixture.environment.name,
        ),
        clock=clock,
    )
    profile = profile_for(action.tool_name)
    assert trusted_baseline(deps, profile, baseline, action, target, dispatch_at=action.executed_at)
    original = getattr(baseline, field)
    setattr(baseline, field, replacement(baseline))
    baseline.provenance_hash = baseline_provenance(baseline)
    assert getattr(baseline, field) != original
    assert not trusted_baseline(
        deps, profile, baseline, action, target, dispatch_at=action.executed_at
    )
    verdict, observed, margin = _evaluate(
        deps, profile, dict(action.verification_criteria), baseline, action, target
    )
    assert (verdict, observed, margin) == (
        VerificationVerdict.INCONCLUSIVE,
        {"reason": "invalid trusted baseline"},
        None,
    )
    kernel_session.rollback()


@pytest.mark.parametrize("invalidation", ["expiry", "revocation"])
def test_approval_rechecked_at_dispatch(
    invalidation: str,
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, f"approval-{invalidation}", True
    )
    approver = create_approver(kernel_session, fixture)
    kernel_session.commit()
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    action = kernel_session.execute(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    ).scalar_one()
    approval = decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="reviewed exact action",
        clock=clock,
    )
    kernel_session.commit()
    if invalidation == "expiry":
        clock.advance((approval.expires_at - clock.now()).total_seconds() + 1)
    else:
        kernel_session.execute(
            sa.delete(UserRoleAssignment).where(UserRoleAssignment.user_id == approver.id)
        )
        kernel_session.commit()
    resumed = _kernel(session_factory, remediation_resolver, clock).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert resumed.terminated
    assert resumed.incident_status is not IncidentStatus.RESOLVED
    writes = kernel_session.execute(
        sa.select(sa.func.count())
        .select_from(ToolExecution)
        .where(ToolExecution.tenant_id == fixture.tenant_id, ToolExecution.risk_tier != RiskTier.RO)
    ).scalar_one()
    assert writes == 0
    assert kernel_session.execute(
        sa.select(Approval.id).where(Approval.id == approval.id)
    ).scalar_one()


@pytest.mark.parametrize(
    ("disabled_guard", "expected_writes"),
    [
        # Both guards in place: one dispatch, recovery from durable evidence.
        (None, 1),
        # Recovery from durable evidence alone still stops a blind second dispatch...
        ("claim", 1),
        # ...and so does the broker's effect claim alone.
        ("recovery", 1),
        # Remove both and the unsafe behaviour returns: the effect is applied twice. This
        # is the non-vacuity control for the two guards above.
        ("both", 2),
    ],
)
def test_crash_after_effect_claim_prevents_repeat(
    disabled_guard: str | None,
    expected_writes: int,
    monkeypatch: Any,
    owner_engine: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    factory = sessionmaker(bind=owner_engine, expire_on_commit=False, autoflush=False, future=True)
    setup = Session(owner_engine, expire_on_commit=False, autoflush=False)
    fixture, hypothesis_id = _prepared(
        setup,
        factory,
        resolver,
        clock,
        f"crash-claim-{disabled_guard or 'none'}-{__import__('uuid').uuid4().hex[:8]}",
    )
    tenant_id = fixture.tenant_id
    setup.close()
    original = ToolBroker._invoke_with_deadline
    writes = []

    class ProcessDeath(BaseException):
        pass

    def crash_once(self: Any, provider: Any, descriptor: Any, bound: Any, context: Any) -> Any:
        result = original(self, provider, descriptor, bound, context)
        if descriptor.risk_tier is not RiskTier.RO:
            writes.append(context.idempotency_key)
            if len(writes) == 1:
                raise ProcessDeath()
        return result

    monkeypatch.setattr(ToolBroker, "_invoke_with_deadline", crash_once)
    if disabled_guard in ("claim", "both"):
        monkeypatch.setattr(ToolBroker, "_claim_write", lambda *args: None)
    if disabled_guard in ("recovery", "both"):
        monkeypatch.setattr(executor_module, "dispatch_evidence", _blind_to_evidence)
    with pytest.raises(ProcessDeath):
        _run_remediation(
            factory,
            remediation_resolver,
            clock,
            fixture,
            hypothesis_id,
            _remediation_scenario(),
        )
    check = Session(owner_engine, expire_on_commit=False)
    bind_tenant(check, tenant_id)
    action = check.execute(
        sa.select(RemediationAction).where(RemediationAction.tenant_id == tenant_id)
    ).scalar_one()
    resumed = _kernel(factory, remediation_resolver, clock).resume(
        tenant_id=tenant_id, workflow_run_id=action.workflow_run_id
    )
    check.close()
    assert len(writes) == expected_writes
    if disabled_guard is None:
        assert resumed.terminated
        assert resumed.incident_status is IncidentStatus.ESCALATED


def test_successful_executor_does_not_verify_empty_evidence(
    kernel_session: Any, session_factory: Any, resolver: Any, remediation_resolver: Any, clock: Any
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "empty-verification"
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    clock.advance(400)
    selected = _remediation_scenario()

    def empty(ctx: Any) -> Any:
        return {**metrics_recovered(ctx), "samples": []}

    responses = {**selected.responses, "read.metrics|checkout-api": _sim_response(empty)}
    selected = replace(selected, responses=responses)
    resumed = _kernel(session_factory, remediation_resolver, clock, scenario_obj=selected).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert resumed.terminated
    assert resumed.incident_status is IncidentStatus.ESCALATED


def test_missing_pre_action_baseline_prevents_dispatch(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "missing-baseline"
    )
    selected = _remediation_scenario()

    def empty(ctx: Any) -> Any:
        return {"samples": [], "unit": "seconds", "source": "prometheus", "schema_version": 1}

    selected = replace(
        selected,
        responses={**selected.responses, "read.metrics|checkout-api": _sim_response(empty)},
    )
    provider = SimulatorProvider(selected, clock=clock)
    outcome = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[provider],
        model=DeterministicModelProvider(selected),
        clock=clock,
    ).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        hypothesis_id=hypothesis_id,
        behaviour_version_id=fixture.behaviour_version.id,
        selected_service_id=fixture.service.id,
    )
    assert outcome.terminated
    assert not [call for call in provider.calls if call[0] == "k8s.deployment.rollback"]


def test_unrelated_same_tenant_service_is_not_a_remediation_target(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "unrelated-target"
    )
    unrelated = Service(
        id=__import__("uuid").uuid4(),
        tenant_id=fixture.tenant_id,
        name="unrelated-api",
        display_name="Unrelated API",
        owner_team="other",
        namespaces=["unrelated"],
    )
    kernel_session.add(unrelated)
    kernel_session.commit()
    with pytest.raises(DomainError, match="not associated"):
        _kernel(session_factory, remediation_resolver, clock).start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            hypothesis_id=hypothesis_id,
            behaviour_version_id=fixture.behaviour_version.id,
            selected_service_id=unrelated.id,
        )


def test_resume_dispatches_only_the_frozen_target_after_alert_scope_changes(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "frozen-multiservice", True
    )
    approver = create_approver(kernel_session, fixture)
    second = Service(
        id=__import__("uuid").uuid4(),
        tenant_id=fixture.tenant_id,
        name="payments-api",
        display_name="Payments API",
        owner_team="payments",
        namespaces=["payments"],
    )
    kernel_session.add(second)
    kernel_session.commit()
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    action = kernel_session.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    )
    target = kernel_session.scalar(
        sa.select(RemediationTarget).where(
            RemediationTarget.workflow_run_id == outcome.workflow_run_id
        )
    )
    assert action is not None and target is not None
    assert target.service_id == fixture.service.id
    decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="approved for frozen checkout target",
        clock=clock,
    )
    kernel_session.execute(
        sa.update(Alert)
        .where(Alert.incident_id == fixture.incident.id)
        .values(service_id=second.id)
    )
    kernel_session.commit()

    selected = _post_remediation_scenario()
    provider = SimulatorProvider(selected, clock=clock)
    resumed = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[provider],
        model=DeterministicModelProvider(selected),
        clock=clock,
    ).resume(tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id)
    assert resumed.terminated is False
    assert ("k8s.deployment.rollback", fixture.service.name) in provider.calls
    assert all(service != second.name for _, service in provider.calls)


@pytest.mark.parametrize("revocation", ["grant", "tool"])
@pytest.mark.parametrize("disable_dispatch_refresh", [False, True])
def test_write_grant_is_revalidated_at_dispatch(
    revocation: str,
    disable_dispatch_refresh: bool,
    monkeypatch: Any,
    kernel_session: Any,
    owner_engine: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session,
        session_factory,
        resolver,
        clock,
        f"dispatch-{revocation}-{str(disable_dispatch_refresh).lower()}",
    )
    fixture.environment.is_production = False
    kernel_session.commit()
    selected = _remediation_scenario()
    provider = SimulatorProvider(selected, clock=clock)
    original_menu = ToolBroker.menu_for
    revoked = False

    def revoke_before_dispatch(
        self: ToolBroker, session: Session, contract: Any, *, refresh: bool = False
    ) -> Any:
        nonlocal revoked
        if refresh and contract.node_id.value == "g9_remediation_executor" and not revoked:
            revoked = True
            if revocation == "grant":
                statement = (
                    sa.update(TenantToolGrant)
                    .where(
                        TenantToolGrant.tool_definition_id.in_(
                            sa.select(ToolDefinition.id).where(
                                ToolDefinition.name == "k8s.deployment.rollback"
                            )
                        )
                    )
                    .values(is_enabled=False)
                )
            else:
                with Session(owner_engine) as owner:
                    owner.execute(
                        sa.update(ToolDefinition)
                        .where(ToolDefinition.name == "k8s.deployment.rollback")
                        .values(is_enabled=False)
                    )
                    owner.commit()
                statement = None
            if statement is not None:
                session.execute(statement)
                session.flush()
        return original_menu(
            self,
            session,
            contract,
            refresh=False if disable_dispatch_refresh and refresh else refresh,
        )

    monkeypatch.setattr(ToolBroker, "menu_for", revoke_before_dispatch)
    RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[provider],
        model=DeterministicModelProvider(selected),
        clock=clock,
    ).start(
        tenant_id=fixture.tenant_id,
        incident_id=fixture.incident.id,
        hypothesis_id=hypothesis_id,
        behaviour_version_id=fixture.behaviour_version.id,
        selected_service_id=fixture.service.id,
    )
    if revocation == "tool":
        with Session(owner_engine) as owner:
            owner.execute(
                sa.update(ToolDefinition)
                .where(ToolDefinition.name == "k8s.deployment.rollback")
                .values(is_enabled=True)
            )
            owner.commit()
    writes = [call for call in provider.calls if call[0] == "k8s.deployment.rollback"]
    assert len(writes) == (1 if disable_dispatch_refresh else 0)


def test_permission_scope_mismatch_is_refused_before_dispatch(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "scope-target-mismatch", True
    )
    approver = create_approver(kernel_session, fixture)
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    action = kernel_session.scalar(
        sa.select(RemediationAction).where(
            RemediationAction.workflow_run_id == outcome.workflow_run_id
        )
    )
    assert action is not None
    action.permission_scope = {**action.permission_scope, "service": "payments-api"}
    action.action_version_hash = action_version_hash(
        action_id=action.id,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments=action.arguments,
        permission_scope=action.permission_scope,
        preconditions=action.preconditions,
        risk_tier=action.risk_tier.value,
    )
    kernel_session.commit()
    decide(
        kernel_session,
        tenant_id=fixture.tenant_id,
        action_id=action.id,
        actor_user_id=approver.id,
        decision=ApprovalDecision.APPROVED,
        expected_action_version_hash=action.action_version_hash,
        justification="approve the corrupted row to exercise the final target guard",
        clock=clock,
    )
    provider = SimulatorProvider(_post_remediation_scenario(), clock=clock)
    resumed = RemediationKernel(
        session_factory=session_factory,
        resolver=remediation_resolver,
        providers=[provider],
        model=DeterministicModelProvider(_post_remediation_scenario()),
        clock=clock,
    ).resume(tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id)
    assert resumed.terminated
    assert not [call for call in provider.calls if call[0] == "k8s.deployment.rollback"]


def test_target_and_hypothesis_are_durable_before_the_planner_call(
    owner_engine: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    session_factory = sessionmaker(
        bind=owner_engine, expire_on_commit=False, autoflush=False, future=True
    )
    setup = Session(owner_engine, expire_on_commit=False, autoflush=False)
    fixture, hypothesis_id = _prepared(
        setup,
        session_factory,
        resolver,
        clock,
        f"target-before-planner-{__import__('uuid').uuid4().hex[:8]}",
    )
    setup.close()
    delegate = DeterministicModelProvider(_remediation_scenario())

    class ProcessDeath(BaseException):
        pass

    class CrashingModel:
        provider_name = delegate.provider_name
        model_id = delegate.model_id

        def estimate(self, request: Any) -> Any:
            return delegate.estimate(request)

        def complete(self, request: Any) -> Any:
            raise ProcessDeath()

    with pytest.raises(ProcessDeath):
        RemediationKernel(
            session_factory=session_factory,
            resolver=remediation_resolver,
            providers=[SimulatorProvider(_remediation_scenario(), clock=clock)],
            model=CrashingModel(),
            clock=clock,
        ).start(
            tenant_id=fixture.tenant_id,
            incident_id=fixture.incident.id,
            hypothesis_id=hypothesis_id,
            behaviour_version_id=fixture.behaviour_version.id,
            selected_service_id=fixture.service.id,
        )
    with Session(owner_engine) as owner:
        bind_tenant(owner, fixture.tenant_id)
        target = owner.scalar(
            sa.select(RemediationTarget).where(RemediationTarget.incident_id == fixture.incident.id)
        )
    assert target is not None
    assert target.hypothesis_id == hypothesis_id
    assert target.service_id == fixture.service.id
    assert target.environment_id == fixture.environment.id


def test_trivial_model_verification_criterion_is_rejected_before_action(
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    from asic.simulators.scenarios import _remediation_plan
    from tests.orchestration.test_remediation import _remediation_scenario

    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, "trivial-criterion"
    )
    selected = replace(
        _remediation_scenario(),
        remediation_planner_script=(
            _remediation_plan(
                tool_name="k8s.deployment.rollback",
                arguments={"deployment": "checkout-api", "to_revision": 846},
                threshold=-1,
            ),
        ),
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        selected,
    )
    assert outcome.terminated
    assert "deterministic profile" in str(outcome.termination_reason)
    assert (
        kernel_session.scalar(
            sa.select(sa.func.count())
            .select_from(RemediationAction)
            .where(RemediationAction.workflow_run_id == outcome.workflow_run_id)
        )
        == 0
    )


@pytest.mark.parametrize("observation", ["regression", "stale"])
def test_regressed_or_stale_post_action_evidence_never_verifies(
    observation: str,
    kernel_session: Any,
    session_factory: Any,
    resolver: Any,
    remediation_resolver: Any,
    clock: Any,
) -> None:
    from asic.simulators.scenarios import metrics_latency_regression

    fixture, hypothesis_id = _prepared(
        kernel_session, session_factory, resolver, clock, f"verification-{observation}"
    )
    outcome = _run_remediation(
        session_factory,
        remediation_resolver,
        clock,
        fixture,
        hypothesis_id,
        _remediation_scenario(),
    )
    clock.advance(400)
    selected = _post_remediation_scenario()

    def stale(ctx: Any) -> Any:
        return {**metrics_recovered(ctx), "samples": ["2020-01-01T00:00:00+00:00=0.1"]}

    builder = metrics_latency_regression if observation == "regression" else stale
    selected = replace(
        selected,
        responses={
            **selected.responses,
            "read.metrics|checkout-api": _sim_response(builder),
        },
    )
    resumed = _kernel(session_factory, remediation_resolver, clock, scenario_obj=selected).resume(
        tenant_id=fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
    )
    assert resumed.terminated
    assert resumed.incident_status is not IncidentStatus.RESOLVED
