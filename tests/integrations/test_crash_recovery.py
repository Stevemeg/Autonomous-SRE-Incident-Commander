"""Crash recovery across a real native Kubernetes write.

INTEGRATION + LOCAL SERVICE: the broker, the executor, durable state and audit are real;
the cluster is the deterministic local HTTP server, which *actually changes* when a PATCH
reaches it. That is the point of this module. The simulator's state does not move when a
write is dispatched, so a simulator-only crash test cannot show what this one shows: after
a crash, the system's own applied effect is visible as a changed world, and the question is
whether recovery reads that change as "my effect landed" or as "something else drifted".

The rule under test is SI-8 as the safety policy states it (§5.2): an unknown outcome is
never assumed to be a clean failure. Only durable evidence that *no effect was claimed*
may end in ``failed_clean``; a claim without a conclusive receipt is reconciled and, when
reconciliation cannot confirm it, escalated as a partial effect.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from asic.db.models import RemediationAction, ToolExecution, WorkflowRun
from asic.db.session import bind_tenant
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    IncidentStatus,
    IntegrationKind,
    RemediationActionStatus,
    RiskTier,
    ToolExecutionOutcome,
)
from asic.integrations.provider import NativeIntegrationProvider
from asic.llm.deterministic import DeterministicModelProvider
from asic.orchestration.remediation.kernel import RemediationKernel
from asic.orchestration.remediation.nodes import executor as executor_module
from asic.remediation.dispatch_recovery import DispatchEvidence, DispatchState, dispatch_evidence
from asic.simulators.scenarios import _remediation_plan, scenario
from asic.tools.broker import ToolBroker
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry
from tests.conftest import requires_postgres
from tests.integrations.local_http import LocalHttpServer, Recorded, Scripted
from tests.integrations.test_live_workflows import (
    _committed_fixture,
    _factory,
    _FakeCluster,
    _world,
)
from tests.integrations.world import add_connector, native_provider
from tests.kernel_fixtures import CLOCK_START
from tests.remediation_fixtures import escalate_to_accepted_hypothesis

pytestmark = requires_postgres

DEPLOYMENT_PATH = "/apis/apps/v1/namespaces/checkout/deployments/checkout-api"
HPA_PATH = "/apis/autoscaling/v2/namespaces/checkout/horizontalpodautoscalers/checkout-api"


class ProcessDeath(BaseException):
    """A crash, not a failure: a BaseException no handler in the system catches."""


@dataclass
class Harness:
    """One prepared remediation over a live local cluster, runnable and resumable."""

    fixture: Any
    factory: Callable[[], Session]
    clock: FrozenClock
    cluster: _FakeCluster
    server: LocalHttpServer
    hypothesis_id: uuid.UUID
    scripted: Any

    def kernel(self) -> RemediationKernel:
        return RemediationKernel(
            session_factory=self.factory,
            resolver=CapabilityResolver(ToolRegistry.remediation_full(), max_risk_tier=RiskTier.R2),
            providers=[native_provider()],
            model=DeterministicModelProvider(self.scripted),
            clock=self.clock,
        )

    def start(self) -> Any:
        return self.kernel().start(
            tenant_id=self.fixture.tenant_id,
            incident_id=self.fixture.incident.id,
            hypothesis_id=self.hypothesis_id,
            behaviour_version_id=self.fixture.behaviour_version.id,
            selected_service_id=self.fixture.service_ids[0],
        )

    def resume(self) -> Any:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)
            run_id = session.scalar(
                sa.select(WorkflowRun.id)
                .where(
                    WorkflowRun.tenant_id == self.fixture.tenant_id,
                    WorkflowRun.status.in_(("dead_lettered", "suspended", "running")),
                )
                .order_by(WorkflowRun.created_at.desc())
                .limit(1)
            )
        assert run_id is not None, "no resumable run was left behind"
        return self.kernel().resume(tenant_id=self.fixture.tenant_id, workflow_run_id=run_id)

    def action(self) -> RemediationAction:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)
            return session.scalars(
                sa.select(RemediationAction).where(
                    RemediationAction.tenant_id == self.fixture.tenant_id
                )
            ).one()

    def evidence(self) -> DispatchEvidence:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)
            return dispatch_evidence(
                session, tenant_id=self.fixture.tenant_id, action=self.action()
            )

    def write_executions(self) -> list[ToolExecutionOutcome]:
        with self.factory() as session:
            bind_tenant(session, self.fixture.tenant_id)
            return list(
                session.scalars(
                    sa.select(ToolExecution.outcome).where(
                        ToolExecution.tenant_id == self.fixture.tenant_id,
                        ToolExecution.risk_tier != RiskTier.RO,
                    )
                )
            )

    def patches(self, path: str = DEPLOYMENT_PATH) -> int:
        return len(self.server.calls("PATCH", path))


def _harness(
    owner_engine: sa.Engine,
    app_engine: sa.Engine,
    server: LocalHttpServer,
    slug: str,
    *,
    tool_name: str = "k8s.deployment.rollback",
    arguments: dict[str, Any] | None = None,
) -> Harness:
    cluster = _FakeCluster(server)
    fixture = _committed_fixture(owner_engine, slug)
    for kind in (IntegrationKind.PROMETHEUS, IntegrationKind.KUBERNETES):
        add_connector(owner_engine, _world(fixture), kind, endpoint=server.url)
    factory = _factory(app_engine)
    clock = FrozenClock(start=CLOCK_START)
    investigation = scenario("SC-0001-checkout-latency-after-deploy")
    hypothesis_id = escalate_to_accepted_hypothesis(
        factory, CapabilityResolver(ToolRegistry.read_only()), clock, fixture, investigation
    )
    plan = _remediation_plan(
        tool_name=tool_name,
        arguments=arguments or {"deployment": "checkout-api", "to_revision": 846},
    )
    return Harness(
        fixture=fixture,
        factory=factory,
        clock=clock,
        cluster=cluster,
        server=server,
        hypothesis_id=hypothesis_id,
        scripted=replace(investigation, remediation_planner_script=(plan,)),
    )


@pytest.fixture
def crash_after_response(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Kill the process after the adapter's response, before the receipt can commit."""
    original = ToolBroker._invoke_with_deadline
    dispatched: list[str] = []

    def crash(self: Any, provider: Any, descriptor: Any, bound: Any, context: Any) -> Any:
        result = original(self, provider, descriptor, bound, context)
        if descriptor.risk_tier is not RiskTier.RO and not dispatched:
            dispatched.append(descriptor.name)
            raise ProcessDeath(descriptor.name)
        return result

    monkeypatch.setattr(ToolBroker, "_invoke_with_deadline", crash)
    yield dispatched
    monkeypatch.setattr(ToolBroker, "_invoke_with_deadline", original)


class TestCrashRecoveryMatrix:
    def test_a_crash_before_the_claim_leaves_a_clean_failure_and_no_request(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-a")
        monkeypatch.setattr(
            ToolBroker,
            "_claim_write",
            lambda *args, **kwargs: (_ for _ in ()).throw(ProcessDeath()),
        )
        with pytest.raises(ProcessDeath):
            harness.start()
        assert harness.evidence().state is DispatchState.NO_EFFECT_ATTEMPTED
        monkeypatch.undo()

        harness.resume()
        assert harness.patches() == 0
        assert harness.action().status is RemediationActionStatus.FAILED_CLEAN
        assert harness.write_executions() == []

    def test_b_a_claim_without_a_request_is_reconciled_then_escalated(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-b")
        original = NativeIntegrationProvider.invoke

        def die_before_request(self: Any, descriptor: Any, arguments: Any, context: Any) -> Any:
            if descriptor.risk_tier is not RiskTier.RO:
                raise ProcessDeath(descriptor.name)
            return original(self, descriptor, arguments, context)

        monkeypatch.setattr(NativeIntegrationProvider, "invoke", die_before_request)
        with pytest.raises(ProcessDeath):
            harness.start()
        monkeypatch.undo()

        assert harness.patches() == 0
        assert harness.evidence().state is DispatchState.EFFECT_MAY_HAVE_OCCURRED
        harness.resume()
        # Nothing was sent, but the durable record cannot prove that, so the conservative
        # classification stands: a partial effect for a human, never a clean failure.
        assert harness.action().status is RemediationActionStatus.FAILED_PARTIAL
        assert harness.patches() == 0

    def test_c_an_applied_write_is_never_failed_clean_and_is_not_repeated(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        crash_after_response: list[str],
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-c")
        with pytest.raises(ProcessDeath):
            harness.start()

        assert harness.patches() == 1, "the PATCH really reached the cluster"
        assert harness.cluster.rolled_back.is_set()
        evidence = harness.evidence()
        assert evidence.state is DispatchState.EFFECT_MAY_HAVE_OCCURRED
        assert evidence.receipt is None

        harness.resume()
        action = harness.action()
        assert action.status is not RemediationActionStatus.FAILED_CLEAN
        # Reconciliation reads the cluster and finds the effect, so the applied write is
        # recorded as applied and independent verification still has to pass.
        assert action.status in (
            RemediationActionStatus.SUCCEEDED,
            RemediationActionStatus.VERIFIED,
            RemediationActionStatus.NOT_VERIFIED,
            RemediationActionStatus.INCONCLUSIVE,
        )
        assert harness.patches() == 1, "recovery must never re-apply the effect"

    def test_c2_an_applied_write_that_cannot_be_confirmed_escalates_as_partial(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        crash_after_response: list[str],
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-c2")
        with pytest.raises(ProcessDeath):
            harness.start()
        assert harness.patches() == 1
        # The cluster stops reporting the new revision: reconciliation cannot confirm the
        # effect it may have applied.
        harness.cluster.rolled_back.clear()

        outcome = harness.resume()
        assert harness.action().status is RemediationActionStatus.FAILED_PARTIAL
        assert outcome.incident_status is IncidentStatus.ESCALATED
        assert harness.patches() == 1

    def test_c3_removing_the_evidence_guard_reintroduces_the_unsafe_classification(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        crash_after_response: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-vacuity control for C: the guard, not the scenario, produces the verdict."""
        harness = _harness(owner_engine, app_engine, server, "crash-c3")
        with pytest.raises(ProcessDeath):
            harness.start()
        assert harness.patches() == 1

        monkeypatch.setattr(
            executor_module,
            "dispatch_evidence",
            lambda *a, **k: DispatchEvidence(intent_recorded=False, claimed=False, receipt=None),
        )
        harness.resume()
        # Without the guard the executor reads its own applied effect as external drift and
        # records the applied write as a clean failure - the defect this milestone fixes.
        assert harness.action().status is RemediationActionStatus.FAILED_CLEAN

    def test_d_a_dropped_connection_after_the_effect_is_unknown_not_retried(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-d")

        def apply_then_drop(recorded: Recorded) -> Scripted:
            harness.cluster.rolled_back.set()
            return Scripted(drop=True)

        server.handler("PATCH", DEPLOYMENT_PATH, apply_then_drop)
        harness.start()
        assert harness.patches() == 1, "an unknown outcome is never retried"
        assert harness.write_executions() == [ToolExecutionOutcome.UNKNOWN]
        assert harness.action().status is not RemediationActionStatus.FAILED_CLEAN

    def test_e_a_definitive_refusal_before_any_effect_is_failed_clean(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-e")
        server.route("PATCH", DEPLOYMENT_PATH, Scripted(status=422, body={"message": "rejected"}))
        outcome = harness.start()
        assert harness.write_executions() == [ToolExecutionOutcome.FAILED_CLEAN]
        assert harness.action().status is RemediationActionStatus.FAILED_CLEAN
        assert outcome.incident_status is IncidentStatus.INVESTIGATING
        assert not harness.cluster.rolled_back.is_set()

    def test_f_the_ordinary_successful_write_is_unchanged(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-f")
        outcome = harness.start()
        assert outcome.terminated is False
        harness.clock.advance(90)
        outcome = harness.kernel().resume(
            tenant_id=harness.fixture.tenant_id, workflow_run_id=outcome.workflow_run_id
        )
        assert outcome.incident_status is IncidentStatus.RESOLVED
        assert harness.action().status is RemediationActionStatus.VERIFIED
        assert harness.patches() == 1
        assert harness.write_executions() == [ToolExecutionOutcome.SUCCEEDED]

    def test_g_genuine_precondition_drift_still_fails_clean_before_any_write(
        self, app_engine: sa.Engine, owner_engine: sa.Engine, server: LocalHttpServer
    ) -> None:
        harness = _harness(owner_engine, app_engine, server, "crash-g")
        progressing = harness.cluster._deployment()
        progressing["status"] = {**progressing["status"], "updatedReplicas": 1}
        server.route(
            "GET",
            "/apis/apps/v1/namespaces/checkout/deployments",
            Scripted(body={"items": [progressing]}),
        )
        outcome = harness.start()
        assert harness.patches() == 0
        assert harness.action().status is RemediationActionStatus.FAILED_CLEAN
        assert outcome.incident_status is IncidentStatus.INVESTIGATING

    def test_i_the_same_recovery_holds_for_a_second_effectful_adapter(
        self,
        app_engine: sa.Engine,
        owner_engine: sa.Engine,
        server: LocalHttpServer,
        crash_after_response: list[str],
    ) -> None:
        harness = _harness(
            owner_engine,
            app_engine,
            server,
            "crash-i",
            tool_name="k8s.hpa.adjust",
            arguments={"hpa_name": "checkout-api", "min_replicas": 4, "max_replicas": 8},
        )
        hpa = {
            "metadata": {
                "name": "checkout-api",
                "labels": {"app.kubernetes.io/name": "checkout-api"},
            },
            "spec": {"minReplicas": 2, "maxReplicas": 6},
            "status": {"currentReplicas": 2},
        }
        adjusted = {**hpa, "spec": {"minReplicas": 4, "maxReplicas": 8}}
        state = {"applied": False}

        def list_hpas(_recorded: Recorded) -> Scripted:
            return Scripted(body={"items": [adjusted if state["applied"] else hpa]})

        def read_hpa(_recorded: Recorded) -> Scripted:
            return Scripted(body=adjusted if state["applied"] else hpa)

        def patch_hpa(_recorded: Recorded) -> Scripted:
            state["applied"] = True
            return Scripted(body=adjusted)

        server.handler(
            "GET", "/apis/autoscaling/v2/namespaces/checkout/horizontalpodautoscalers", list_hpas
        )
        server.handler("GET", HPA_PATH, read_hpa)
        server.handler("PATCH", HPA_PATH, patch_hpa)

        with pytest.raises(ProcessDeath):
            harness.start()
        assert harness.patches(HPA_PATH) == 1 and state["applied"]
        assert harness.evidence().state is DispatchState.EFFECT_MAY_HAVE_OCCURRED

        harness.resume()
        assert harness.action().status is not RemediationActionStatus.FAILED_CLEAN
        assert harness.patches(HPA_PATH) == 1
