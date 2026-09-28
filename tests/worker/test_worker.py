"""The deployed worker (F-02): durable claims, full incident flow, duplicates, crash, shutdown.

Every test commits for real (advisory locks and leases are properties of real connections and
real transactions) and scopes each worker to the tenants the test created, so leftovers from
other suites are never touched.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from asic.api import create_app
from asic.db.models import (
    Evidence,
    Hypothesis,
    Incident,
    IncidentEvent,
    InvestigationDispatch,
    Postmortem,
    RemediationAction,
    RemediationRequest,
    ToolExecution,
    Verification,
    WorkflowRun,
)
from asic.db.projections import apply_transition
from asic.db.session import bind_tenant, create_app_engine, session_factory
from asic.domain.clock import FrozenClock
from asic.domain.enums import (
    ActorType,
    IncidentEventType,
    IncidentStatus,
    PostmortemStatus,
    RemediationActionStatus,
    TerminationReason,
    VerificationVerdict,
)
from asic.ingestion.contracts import ConnectorContext
from asic.ingestion.service import IngestionService
from asic.orchestration import kernel as investigation_kernel
from asic.orchestration.kernel import LEASE_DURATION, InvestigationKernel
from asic.tools.capability import CapabilityResolver
from asic.tools.registry import ToolRegistry
from asic.worker.profile import LIVE_MODEL_UNAVAILABLE, SimulatorProfile, build_profile
from asic.worker.runtime import (
    Worker,
    WorkItem,
    WorkKind,
    install_signal_handlers,
    resolve_behaviour_version,
    serve_probes,
)
from asic.worker.settings import ExecutionMode, WorkerConfigurationError, WorkerSettings
from tests.api.test_auth import SETTINGS, _principal, _token
from tests.kernel_fixtures import Fixture, build_fixture

pytestmark = pytest.mark.postgres

REPO = Path(__file__).resolve().parents[2]


class ProcessDeath(BaseException):
    """A kill -9 at a node boundary: nothing runs after it, not even ``except Exception``."""


@pytest.fixture
def worker_factory(app_engine: Engine) -> Callable[[], Session]:
    return sessionmaker(bind=app_engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
def arranger(owner_engine: Engine) -> Iterator[Session]:
    session = Session(bind=owner_engine, expire_on_commit=False, autoflush=False)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def clock() -> FrozenClock:
    # Near real time: the API decides approvals against the system clock.
    return FrozenClock(start=datetime.now(UTC).replace(microsecond=0))


def _settings(**overrides: object) -> WorkerSettings:
    base = WorkerSettings(
        mode=ExecutionMode.SIMULATOR,
        behaviour_version_label="unused",
        concurrency=2,
        poll_seconds=0.1,
        drain_seconds=5,
        retry_backoff_seconds=0,
        health_port=0,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def _worker(
    engine: Engine,
    factory: Callable[[], Session],
    fixture: Fixture,
    clock: FrozenClock,
    **overrides: object,
) -> Worker:
    settings = _settings(**overrides)
    return Worker(
        settings=settings,
        engine=engine,
        factory=factory,
        profile=SimulatorProfile(
            factory,
            scenario_id=settings.simulator_scenario,
            remediation_variant=settings.simulator_remediation_variant,
            clock=clock,
        ),
        behaviour_version_id=fixture.behaviour_version.id,
        clock=clock,
        tenants=[fixture.tenant_id],
    )


def _world(arranger: Session, slug: str) -> Fixture:
    # The fixture's own incident is closed so an ingested alert opens a fresh one.
    fixture = build_fixture(arranger, slug=f"{slug}-{uuid.uuid4().hex[:8]}")
    fixture.incident.status = IncidentStatus.FAILED
    fixture.incident.terminated_at = fixture.incident.opened_at
    fixture.incident.termination_reason = TerminationReason.UNRECOVERABLE_FAILURE
    arranger.commit()
    return fixture


def _ingest(factory: Callable[[], Session], fixture: Fixture, clock: FrozenClock) -> uuid.UUID:
    started = clock.now() - timedelta(minutes=3)
    body = {
        "schema_version": 1,
        "fingerprint": f"latency-{uuid.uuid4().hex[:8]}",
        "title": "checkout-api p95 latency above objective",
        "severity": "high",
        "category": "latency",
        "started_at": started.isoformat(),
        "observed_at": (started + timedelta(minutes=1)).isoformat(),
    }
    result = IngestionService(factory, clock=clock).ingest(
        ConnectorContext(
            tenant_id=fixture.tenant_id,
            connector_id="worker-test",
            source="simulator",
            service_id=fixture.service.id,
            environment_id=fixture.environment.id,
        ),
        json.dumps(body).encode(),
    )
    assert result.incident_id is not None and not result.duplicate
    return result.incident_id


def _count(
    factory: Callable[[], Session], tenant_id: uuid.UUID, model: object, *where: object
) -> int:
    with factory() as session:
        bind_tenant(session, tenant_id)
        value = session.scalar(
            sa.select(sa.func.count()).select_from(model).where(*where)  # type: ignore[arg-type]
        )
        session.expunge_all()
        session.rollback()
    return int(value or 0)


def _status(
    factory: Callable[[], Session], fixture: Fixture, incident_id: uuid.UUID
) -> IncidentStatus:
    with factory() as session:
        bind_tenant(session, fixture.tenant_id)
        value = session.scalar(sa.select(Incident.status).where(Incident.id == incident_id))
        session.expunge_all()
        session.rollback()
    assert value is not None
    return value


# ------------------------------------------------------------------ the whole product path


def test_alert_to_resolution_to_postmortem_is_driven_by_the_worker_alone(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
) -> None:
    fixture = _world(arranger, "wk-flow")
    _principal(arranger, fixture, "responder", "wk-responder")
    _principal(arranger, fixture, "sre_approver", "wk-approver")
    incident_id = _ingest(worker_factory, fixture, clock)
    worker = _worker(app_engine, worker_factory, fixture, clock)

    # 1. alert -> durable dispatch -> worker -> investigation.
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.INVESTIGATION, "completed")
    ]
    assert _status(worker_factory, fixture, incident_id) is IncidentStatus.ESCALATED
    assert _count(worker_factory, fixture.tenant_id, Evidence, Evidence.incident_id == incident_id)
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        hypothesis_id = session.scalar(
            sa.select(Hypothesis.id)
            .where(Hypothesis.incident_id == incident_id)
            .order_by(Hypothesis.rank)
            .limit(1)
        )
        session.expunge_all()
        session.rollback()
    assert hypothesis_id is not None
    assert worker.run_once() == []  # nothing left to do: no re-dispatch of a finished run

    # 2. a responder requests remediation through the API.
    client = TestClient(create_app(settings=SETTINGS, factory=worker_factory))
    requested = client.post(
        f"/api/v1/incidents/{incident_id}/remediation-requests",
        headers={
            "Authorization": f"Bearer {_token(fixture.tenant_id, 'wk-responder')}",
            "Idempotency-Key": uuid.uuid4().hex,
        },
        json={
            "hypothesis_id": str(hypothesis_id),
            "service_id": str(fixture.service.id),
            "justification": "evidence points at the last deployment",
        },
    )
    assert requested.status_code == 202, requested.text

    # 3. the worker starts the remediation graph; production policy requires approval.
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.REMEDIATION_START, "suspended")
    ]
    assert _status(worker_factory, fixture, incident_id) is IncidentStatus.AWAITING_APPROVAL
    assert worker.run_once() == []  # waiting on a human: not resumed, not re-requested

    # 4. an authorised human approves the exact action version through the API.
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        action = session.scalars(
            sa.select(RemediationAction).where(RemediationAction.incident_id == incident_id)
        ).one()
        session.expunge_all()
        session.rollback()
    decided = client.post(
        f"/api/v1/approvals/{action.id}/decide",
        headers={
            "Authorization": f"Bearer {_token(fixture.tenant_id, 'wk-approver')}",
            "Idempotency-Key": uuid.uuid4().hex,
        },
        json={
            "decision": "approved",
            "justification": "rollback matches the deployment evidence",
            "action_version_hash": action.action_version_hash,
        },
    )
    assert decided.status_code == 200, decided.text

    # 5. the worker resumes: execute, then wait for the settling window, then verify.
    # The API stamped the decision with the system clock; a deployed worker shares that clock,
    # so the test's frozen clock catches up with it before the executor checks the approval.
    clock.advance(max(0.0, (datetime.now(UTC) - clock.now()).total_seconds()) + 1)
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.REMEDIATION_RUN, "suspended")
    ]
    assert worker.run_once() == []  # settling window not yet elapsed
    clock.advance(90)
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.REMEDIATION_RUN, "completed")
    ]
    assert _status(worker_factory, fixture, incident_id) is IncidentStatus.RESOLVED

    # 6. G11 drafts the postmortem for the resolved incident; once.
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [(WorkKind.POSTMORTEM, "created")]
    assert worker.run_once() == []

    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        action = session.get(RemediationAction, action.id)
        assert action is not None and action.status is RemediationActionStatus.VERIFIED
        verification = session.scalars(
            sa.select(Verification).where(Verification.remediation_action_id == action.id)
        ).one()
        assert verification.verdict is VerificationVerdict.VERIFIED
        writes = session.scalar(
            sa.select(sa.func.count())
            .select_from(ToolExecution)
            .where(
                ToolExecution.remediation_action_id == action.id,
                ToolExecution.tool_name == action.tool_name,
            )
        )
        assert writes == 1  # exactly one mutating execution
        (draft,) = session.scalars(
            sa.select(Postmortem).where(Postmortem.incident_id == incident_id)
        ).all()
        assert draft.status is PostmortemStatus.DRAFT and draft.review_required
        assert draft.resolution_basis == "independently_verified"
        request = session.scalars(
            sa.select(RemediationRequest).where(RemediationRequest.incident_id == incident_id)
        ).one()
        assert request.status == "started" and request.workflow_run_id is not None
        session.expunge_all()
        session.rollback()


# ------------------------------------------------------------------ concurrency


def test_two_workers_racing_for_one_dispatch_produce_one_logical_execution(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
) -> None:
    fixture = _world(arranger, "wk-race")
    incident_id = _ingest(worker_factory, fixture, clock)
    workers = [_worker(app_engine, worker_factory, fixture, clock) for _ in range(2)]
    barrier = threading.Barrier(2)
    outcomes: list[list[tuple[WorkItem, str]]] = [[], []]

    def run(index: int) -> None:
        barrier.wait()
        outcomes[index] = workers[index].run_once()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    investigations = [
        outcome
        for result in outcomes
        for item, outcome in result
        if item.kind is WorkKind.INVESTIGATION
    ]
    assert investigations.count("completed") == 1, outcomes
    assert (
        _count(
            worker_factory, fixture.tenant_id, WorkflowRun, WorkflowRun.incident_id == incident_id
        )
        == 1
    )
    assert (
        _count(
            worker_factory,
            fixture.tenant_id,
            IncidentEvent,
            IncidentEvent.incident_id == incident_id,
            IncidentEvent.event_type == IncidentEventType.INCIDENT_TERMINATED,
        )
        == 1
    )
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        keys = list(
            session.scalars(
                sa.select(ToolExecution.idempotency_key).where(
                    ToolExecution.incident_id == incident_id
                )
            )
        )
        session.expunge_all()
        session.rollback()
    assert keys and len(keys) == len(set(keys))  # no effect recorded twice


# ------------------------------------------------------------------ crash and recovery


def test_a_worker_killed_mid_investigation_is_recovered_without_repeating_effects(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _world(arranger, "wk-crash")
    incident_id = _ingest(worker_factory, fixture, clock)
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        dispatch_id = session.scalars(
            sa.select(InvestigationDispatch.id).where(
                InvestigationDispatch.incident_id == incident_id
            )
        ).one()
        session.expunge_all()
        session.rollback()

    # The first worker process dies after the third node: no clean-up runs at all.
    monkeypatch.setattr(
        investigation_kernel.InvestigationKernel, "_mark_dead_letter", lambda *_: None
    )
    profile = SimulatorProfile(
        worker_factory,
        scenario_id="SC-0001-checkout-latency-after-deploy",
        remediation_variant="autonomous_verified",
        clock=clock,
    )
    service = profile.investigation_service(fixture.tenant_id, None)

    def die(_name: str, ordinal: int) -> None:
        if ordinal == 3:
            raise ProcessDeath

    dying = InvestigationKernel(
        session_factory=worker_factory,
        resolver=CapabilityResolver(ToolRegistry.read_only()),
        providers=service._providers,
        model=service._model,
        clock=clock,
        interrupt_probe=die,
    )
    with pytest.raises(ProcessDeath):
        dying.start(
            tenant_id=fixture.tenant_id,
            incident_id=incident_id,
            behaviour_version_id=fixture.behaviour_version.id,
            service_ids=[fixture.service.id],
            dispatch_id=dispatch_id,
        )
    executions_before = _count(
        worker_factory, fixture.tenant_id, ToolExecution, ToolExecution.incident_id == incident_id
    )

    worker = _worker(app_engine, worker_factory, fixture, clock)
    # The dead worker's lease is still valid: the new worker refuses to advance the run.
    results = worker.run_once()
    assert [outcome for _, outcome in results] == ["busy"]
    assert (
        _count(
            worker_factory, fixture.tenant_id, WorkflowRun, WorkflowRun.incident_id == incident_id
        )
        == 1
    )

    clock.advance(LEASE_DURATION.total_seconds() + 1)
    results = worker.run_once()
    assert [outcome for _, outcome in results] == ["completed"]
    assert _status(worker_factory, fixture, incident_id) is IncidentStatus.ESCALATED
    assert (
        _count(
            worker_factory, fixture.tenant_id, WorkflowRun, WorkflowRun.incident_id == incident_id
        )
        == 1
    )
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        keys = list(
            session.scalars(
                sa.select(ToolExecution.idempotency_key).where(
                    ToolExecution.incident_id == incident_id
                )
            )
        )
        run = session.scalars(
            sa.select(WorkflowRun).where(WorkflowRun.incident_id == incident_id)
        ).one()
        session.expunge_all()
        session.rollback()
    assert len(keys) == len(set(keys)) >= executions_before
    assert run.resumed_count == 1


def test_a_rejected_remediation_request_hands_the_incident_back_to_a_human(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
) -> None:
    fixture = _world(arranger, "wk-reject")
    requester = _principal(arranger, fixture, "responder", "wk-reject-responder")
    incident_id = _ingest(worker_factory, fixture, clock)
    worker = _worker(app_engine, worker_factory, fixture, clock)
    worker.run_once()
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        hypothesis = session.scalars(
            sa.select(Hypothesis).where(Hypothesis.incident_id == incident_id).limit(1)
        ).one()
        incident = session.get(Incident, incident_id)
        assert incident is not None
        apply_transition(
            session,
            incident=incident,
            target=IncidentStatus.INVESTIGATING,
            actor_type=ActorType.HUMAN,
            source="test",
            correlation_id=uuid.uuid4(),
            justification="reopen",
        )
        # A pending request whose hypothesis is then rejected: the kernel refuses it.
        session.add(
            RemediationRequest(
                tenant_id=fixture.tenant_id,
                incident_id=incident_id,
                hypothesis_id=hypothesis.id,
                service_id=fixture.service.id,
                requested_by_user_id=requester.id,
                justification="test",
            )
        )
        session.commit()
    with arranger.begin():
        bind_tenant(arranger, fixture.tenant_id)
        arranger.execute(
            sa.text("UPDATE hypothesis SET status = 'rejected' WHERE id = :id"),
            {"id": hypothesis.id},
        )
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.REMEDIATION_START, "rejected")
    ]
    assert _status(worker_factory, fixture, incident_id) is IncidentStatus.ESCALATED
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        request = session.scalars(
            sa.select(RemediationRequest).where(RemediationRequest.incident_id == incident_id)
        ).one()
        session.expunge_all()
        session.rollback()
    assert request.status == "rejected" and request.last_error == "start_refused"


# ------------------------------------------------------------------ shutdown, outage, probes


class _BlockingWorker(Worker):
    """Discovers one synthetic item and blocks in it until released."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.release = threading.Event()
        self.started = threading.Event()
        self.handled: list[WorkItem] = []

    def discover(self) -> list[WorkItem]:
        item = WorkItem(WorkKind.POSTMORTEM, uuid.uuid4(), uuid.UUID(int=len(self.handled) + 1))
        return [] if self.stopping else [item]

    def handle(self, item: WorkItem) -> str:
        self.handled.append(item)
        self.started.set()
        self.release.wait(timeout=30)
        return "created"


def _blocking(
    app_engine: Engine, factory: Callable[[], Session], **overrides: object
) -> _BlockingWorker:
    return _BlockingWorker(
        settings=_settings(concurrency=1, **overrides),
        engine=app_engine,
        factory=factory,
        profile=build_profile.__class__,  # never used by the overridden handle
        behaviour_version_id=uuid.uuid4(),
    )


def test_sigterm_stops_claiming_and_lets_in_flight_work_finish(
    app_engine: Engine, worker_factory: Callable[[], Session]
) -> None:
    worker = _blocking(app_engine, worker_factory, drain_seconds=10)
    previous = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    install_signal_handlers(worker)
    try:
        result: list[bool] = []
        loop = threading.Thread(target=lambda: result.append(worker.run_forever()))
        loop.start()
        assert worker.started.wait(10)
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)  # what Kubernetes sends on termination
        time.sleep(0.5)
        assert len(worker.handled) == 1  # no new claim after SIGTERM, one slot busy anyway
        assert worker.health.stopping and not worker.health.ready(60)
        worker.release.set()
        loop.join(timeout=20)
        assert result == [True]  # drained cleanly
    finally:
        signal.signal(signal.SIGTERM, previous[0])
        signal.signal(signal.SIGINT, previous[1])


def test_a_drain_deadline_abandons_rather_than_hangs(
    app_engine: Engine, worker_factory: Callable[[], Session]
) -> None:
    worker = _blocking(app_engine, worker_factory, drain_seconds=0.3)
    result: list[bool] = []
    loop = threading.Thread(target=lambda: result.append(worker.run_forever()))
    loop.start()
    assert worker.started.wait(10)
    worker.stop()
    loop.join(timeout=10)
    assert result == [False]  # abandoned in-flight work; recovered later like a crash
    worker.release.set()


def test_a_database_outage_keeps_the_process_alive_and_unready(tmp_path: Path) -> None:
    engine = create_app_engine(
        "postgresql+psycopg2://nobody@127.0.0.1:1/nothing", connect_args={"connect_timeout": 1}
    )
    factory = session_factory(engine)
    worker = Worker(
        settings=_settings(poll_seconds=0.1),
        engine=engine,
        factory=factory,
        profile=build_profile.__class__,  # type: ignore[arg-type]
        behaviour_version_id=uuid.uuid4(),
    )
    loop = threading.Thread(target=worker.run_forever)
    loop.start()
    time.sleep(1.5)
    assert loop.is_alive()
    assert worker.health.live(60) and not worker.health.ready(60)
    worker.stop()
    loop.join(timeout=10)
    engine.dispose()


def test_probes_report_liveness_readiness_and_hide_metrics_unless_enabled(
    app_engine: Engine, worker_factory: Callable[[], Session], arranger: Session, clock: FrozenClock
) -> None:
    fixture = _world(arranger, "wk-probe")
    worker = _worker(app_engine, worker_factory, fixture, clock, health_port=0)
    server = serve_probes(worker)
    port = server.server_address[1]

    def status(path: str) -> int:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
                return int(response.status)
        except urllib.error.HTTPError as error:
            return int(error.code)

    try:
        assert status("/livez") == 200
        assert status("/readyz") == 503  # no successful poll yet
        worker.run_once()
        assert status("/readyz") == 200
        assert status("/metrics") == 404
        worker.stop()
        assert status("/readyz") == 503  # draining
    finally:
        server.shutdown()


# ------------------------------------------------------------------ configuration


def test_live_mode_refuses_to_start_without_a_live_model(
    worker_factory: Callable[[], Session],
) -> None:
    with pytest.raises(WorkerConfigurationError, match="GAP-08"):
        build_profile(_settings(mode=ExecutionMode.LIVE), worker_factory)
    assert "GAP-08" in LIVE_MODEL_UNAVAILABLE


def test_the_simulator_profile_refuses_production(
    worker_factory: Callable[[], Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASIC_DEPLOYMENT_ENVIRONMENT", "production")
    with pytest.raises(WorkerConfigurationError, match="FR-INT-04"):
        build_profile(_settings(), worker_factory)


@pytest.mark.parametrize(
    ("environ", "message"),
    [
        ({"ASIC_WORKER_EXECUTION_MODE": "simulator"}, "ASIC_BEHAVIOUR_VERSION_LABEL"),
        ({"ASIC_WORKER_EXECUTION_MODE": "turbo", "ASIC_BEHAVIOUR_VERSION_LABEL": "x"}, "live"),
        (
            {"ASIC_BEHAVIOUR_VERSION_LABEL": "x", "ASIC_WORKER_CONCURRENCY": "64"},
            "CONCURRENCY",
        ),
        ({"ASIC_BEHAVIOUR_VERSION_LABEL": "x", "ASIC_WORKER_POLL_SECONDS": "no"}, "numeric"),
    ],
)
def test_invalid_settings_are_refused(environ: dict[str, str], message: str) -> None:
    with pytest.raises(WorkerConfigurationError, match=message):
        WorkerSettings.from_environment(environ)


def test_an_unregistered_or_mismatched_behaviour_version_is_refused(
    worker_factory: Callable[[], Session], arranger: Session
) -> None:
    with pytest.raises(WorkerConfigurationError, match="not registered"):
        resolve_behaviour_version(worker_factory, f"missing-{uuid.uuid4().hex}")
    fixture = _world(arranger, "wk-bv")
    label, version_id = fixture.behaviour_version.label, fixture.behaviour_version.id
    assert resolve_behaviour_version(worker_factory, label) == version_id
    arranger.execute(
        sa.text("UPDATE behaviour_version SET prompt_set_version = 'old' WHERE id = :id"),
        {"id": version_id},
    )
    arranger.commit()
    with pytest.raises(WorkerConfigurationError, match="Register the new behaviour version"):
        resolve_behaviour_version(worker_factory, label)


def test_the_console_entry_point_exists_and_fails_closed_in_live_mode() -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("ASIC_WORKER", "ASIC_DEPLOYMENT"))
    }
    env.update(
        {
            "PYTHONPATH": str(REPO / "src"),
            "ASIC_DATABASE_URL": "postgresql+psycopg2://nobody@127.0.0.1:1/nothing",
            "ASIC_BEHAVIOUR_VERSION_LABEL": "any",
            "ASIC_WORKER_EXECUTION_MODE": "live",
        }
    )
    result = subprocess.run(
        [sys.executable, "-m", "asic.worker"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 2
    assert "GAP-08" in result.stdout + result.stderr


def test_an_unregistered_behaviour_version_blocks_claims_until_registered(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
) -> None:
    """A release whose behaviour version is not registered yet stays unready, claims nothing,
    and starts working once an administrator registers it - no crash loop."""
    fixture = _world(arranger, "wk-bv-late")
    _ingest(worker_factory, fixture, clock)
    label = f"late-{uuid.uuid4().hex[:8]}"
    settings = _settings(poll_seconds=0.1)
    worker = Worker(
        settings=settings,
        engine=app_engine,
        factory=worker_factory,
        profile=SimulatorProfile(
            worker_factory,
            scenario_id=settings.simulator_scenario,
            remediation_variant=settings.simulator_remediation_variant,
            clock=clock,
        ),
        behaviour_version_label=label,
        clock=clock,
        tenants=[fixture.tenant_id],
    )
    with pytest.raises(WorkerConfigurationError, match="not registered"):
        worker.poll()
    assert not worker.health.ready(60)

    arranger.execute(
        sa.text(
            "INSERT INTO behaviour_version (label, code_version, prompt_set_version, "
            "retriever_config_version, policy_version, tool_registry_version, fingerprint) "
            "SELECT :label, code_version, prompt_set_version, retriever_config_version, "
            "policy_version, tool_registry_version, :fp FROM behaviour_version WHERE id = :id"
        ),
        {"label": label, "fp": uuid.uuid4().hex, "id": fixture.behaviour_version.id},
    )
    arranger.commit()
    results = worker.run_once()
    assert [(item.kind, outcome) for item, outcome in results] == [
        (WorkKind.INVESTIGATION, "completed")
    ]
    assert worker.health.ready(60)


def test_the_responder_who_requested_remediation_cannot_approve_it(
    app_engine: Engine,
    worker_factory: Callable[[], Session],
    arranger: Session,
    clock: FrozenClock,
) -> None:
    """Separation of duties: a remediation request is not an approval, and cannot become one."""
    fixture = _world(arranger, "wk-sod")
    _principal(arranger, fixture, "sre_approver", "wk-sod-requester")  # can request AND approve
    _principal(arranger, fixture, "sre_approver", "wk-sod-second")
    incident_id = _ingest(worker_factory, fixture, clock)
    worker = _worker(app_engine, worker_factory, fixture, clock)
    worker.run_once()
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        hypothesis_id = session.scalar(
            sa.select(Hypothesis.id).where(Hypothesis.incident_id == incident_id).limit(1)
        )
        session.rollback()
    client = TestClient(create_app(settings=SETTINGS, factory=worker_factory))

    def headers(subject: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {_token(fixture.tenant_id, subject)}",
            "Idempotency-Key": uuid.uuid4().hex,
        }

    requested = client.post(
        f"/api/v1/incidents/{incident_id}/remediation-requests",
        headers=headers("wk-sod-requester"),
        json={
            "hypothesis_id": str(hypothesis_id),
            "service_id": str(fixture.service.id),
            "justification": "request",
        },
    )
    assert requested.status_code == 202
    worker.run_once()
    with worker_factory() as session:
        bind_tenant(session, fixture.tenant_id)
        action = session.scalars(
            sa.select(RemediationAction).where(RemediationAction.incident_id == incident_id)
        ).one()
        session.expunge_all()
        session.rollback()
    body = {
        "decision": "approved",
        "justification": "self approval attempt",
        "action_version_hash": action.action_version_hash,
    }
    own = client.post(
        f"/api/v1/approvals/{action.id}/decide", headers=headers("wk-sod-requester"), json=body
    )
    assert own.status_code == 409
    assert "cannot also approve" in own.json()["detail"]["message"]
    other = client.post(
        f"/api/v1/approvals/{action.id}/decide", headers=headers("wk-sod-second"), json=body
    )
    assert other.status_code == 200


def test_the_worker_imports_and_refuses_cleanly_without_the_simulator_package() -> None:
    """The production image excludes ``asic.simulators`` (FR-INT-04, ``.dockerignore``).

    The worker, the API and G11 must still import there, and live mode must refuse with its
    GAP-08 message - not crash on an ImportError of test infrastructure.
    """
    code = (
        "import sys\n"
        "sys.modules['asic.simulators'] = None\n"  # exactly what an absent package looks like
        "import asic.worker.__main__, asic.api.app, asic.postmortem.author\n"
        "import asic.ingestion.dispatch, asic.llm.deterministic\n"
        "from asic.worker.profile import build_profile\n"
        "from asic.worker.settings import ExecutionMode, WorkerSettings, "
        "WorkerConfigurationError\n"
        "try:\n"
        "    build_profile(WorkerSettings(mode=ExecutionMode.LIVE, "
        "behaviour_version_label='x'), lambda: None)\n"
        "except WorkerConfigurationError as exc:\n"
        "    print('REFUSED', 'GAP-08' in str(exc))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "REFUSED True" in result.stdout
