"""The durable-work worker: the deployed process that actually drives incidents (Phase 16).

The API records work; it never runs a graph. This process finds recorded work in PostgreSQL -
the system of record, with no broker added for it (ADR-0007) - and drives it through the same
application boundaries every test uses:

========================  ====================================================================
Work kind                 Found as                                    Driven through
========================  ====================================================================
``investigation``         a pending ``investigation_dispatch``, or a  ``InvestigationDispatcher``
                          linked run that is suspended or whose
                          lease expired (a crashed worker)
``remediation_start``     a pending ``remediation_request``           ``RemediationKernel.start``
``remediation_run``       a remediation run that is suspended or      ``RemediationKernel.resume``
                          lease-expired *and* has something new to
                          act on: a recorded approval decision, an
                          elapsed approval window, an elapsed
                          settling window, or a crash
``postmortem``            a resolved incident with no draft since it  ``PostmortemAuthor.draft``
                          was last resolved
========================  ====================================================================

**Who owns an item.** Two layers, deliberately redundant. A session-level PostgreSQL advisory
lock (``pg_try_advisory_lock``) held on a dedicated connection for the life of the item keeps
two workers from even *starting* the same item; it is released on completion and, because it is
session-scoped, by PostgreSQL itself if the worker dies. Beneath it, the kernels' own leases,
the one-live-run-per-incident index, the dispatch/request linkage and effect idempotency remain
the authority: the advisory lock is an efficiency, never the safety argument.

**Concurrency** is a fixed thread pool (``ASIC_WORKER_CONCURRENCY``, at most 8). The poller
claims at most as many items as there are free slots, so work never queues in memory.

**Tenancy.** Discovery walks the global ``tenant`` catalogue and binds each tenant in its own
transaction; every item carries its tenant, and every handler rebinds it. Row-level security is
never bypassed: the worker runs as the ordinary application role.

**Failure.** A failing item is logged with a safe code, counted, and retried after a backoff; an
investigation dispatch or remediation request that fails ``ASIC_WORKER_MAX_ATTEMPTS`` times is
left for an operator (dispatch) or rejected and escalated back to a human (request). A process
that dies mid-item leaves the item recoverable: its advisory lock vanishes with its connection,
and the kernel lease expires. No external effect repeats, because effects are idempotent by
their business key, not because the worker was careful.

**Shutdown.** SIGTERM stops claiming, lets in-flight items finish for ``drain_seconds``, then
exits. A graph node is not preemptible: an item still running when the drain ends is abandoned
exactly as a crash would abandon it, and recovered the same way.
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from asic.db.models import (
    Approval,
    BehaviourVersion,
    Incident,
    InvestigationDispatch,
    PolicyDecision,
    Postmortem,
    RemediationAction,
    RemediationRequest,
    RemediationTarget,
    Tenant,
    Verification,
    WorkflowRun,
)
from asic.db.projections import apply_transition
from asic.db.session import TenantContext, apply_statement_timeouts, bind_tenant
from asic.domain.clock import Clock, SystemClock
from asic.domain.enums import (
    ActorType,
    IncidentStatus,
    RemediationActionStatus,
    TerminationReason,
    WorkflowRunStatus,
)
from asic.domain.errors import DomainError, LeaseNotHeld, UnregisteredCapability
from asic.ingestion.dispatch import InvestigationDispatcher
from asic.llm.prompts import PROMPT_SET_VERSION
from asic.observability import metrics
from asic.observability.logging import log_event
from asic.orchestration.remediation.kernel import RequestAlreadyLinked
from asic.remediation.approval_service import APPROVAL_WINDOW_SECONDS
from asic.tools.catalogue import CATALOGUE_VERSION
from asic.tools.registry import ToolRegistry
from asic.worker.profile import ExecutionProfile
from asic.worker.settings import WorkerConfigurationError, WorkerSettings

_logger = logging.getLogger("asic.worker")

#: Items discovered per kind per tenant per poll. The claim step takes only free slots.
DISCOVERY_LIMIT: Final[int] = 16

_LIVE_RUN: Final = (WorkflowRunStatus.RUNNING, WorkflowRunStatus.SUSPENDED)


class WorkKind(StrEnum):
    INVESTIGATION = "investigation"
    REMEDIATION_START = "remediation_start"
    REMEDIATION_RUN = "remediation_run"
    POSTMORTEM = "postmortem"


@dataclass(frozen=True, slots=True)
class WorkItem:
    kind: WorkKind
    tenant_id: uuid.UUID
    item_id: uuid.UUID

    @property
    def lock_key(self) -> int:
        """A signed 64-bit advisory-lock key, unique per (kind, item) with overwhelming
        probability. A collision could only make two items skip each other, never share one."""
        digest = hashlib.sha256(f"asic-worker:{self.kind.value}:{self.item_id}".encode()).digest()
        return int.from_bytes(digest[:8], "big", signed=True)


@dataclass(slots=True)
class Health:
    """What the probes report. Updated by the poller; read by the probe server."""

    started_at: float = field(default_factory=time.monotonic)
    last_loop: float = field(default_factory=time.monotonic)
    last_successful_poll: float | None = None
    stopping: bool = False
    in_flight: int = 0

    def live(self, window: float) -> bool:
        return time.monotonic() - self.last_loop <= window

    def ready(self, window: float) -> bool:
        return (
            not self.stopping
            and self.last_successful_poll is not None
            and time.monotonic() - self.last_successful_poll <= window
        )


class Worker:
    """One worker process. ``run_forever`` until stopped; ``run_once`` for a single poll."""

    def __init__(
        self,
        *,
        settings: WorkerSettings,
        engine: Engine,
        factory: Callable[[], Session],
        profile: ExecutionProfile,
        behaviour_version_id: uuid.UUID | None = None,
        behaviour_version_label: str | None = None,
        clock: Clock | None = None,
        tenants: Sequence[uuid.UUID] | None = None,
    ) -> None:
        """``tenants`` restricts discovery to a fixed set (a shard, or a test's own tenants);
        ``None`` - the deployed default - serves every tenant in the catalogue.

        With only ``behaviour_version_label``, the version is resolved on each poll until it
        is registered: the worker stays alive but unready and claims nothing meanwhile, so a
        release whose behaviour version is registered after rollout starts does not
        crash-loop."""
        if behaviour_version_id is None and not behaviour_version_label:
            raise WorkerConfigurationError("a behaviour version id or label is required")
        self.settings = settings
        self._tenants = tuple(tenants) if tenants is not None else None
        self._engine = engine
        self._factory = factory
        self._profile = profile
        self._behaviour_version_id = behaviour_version_id
        self._behaviour_version_label = behaviour_version_label
        self._clock = clock or SystemClock()
        self._stop = threading.Event()
        self._executor = ThreadPoolExecutor(
            max_workers=settings.concurrency, thread_name_prefix="asic-worker"
        )
        self._in_flight: dict[WorkItem, Future[str]] = {}
        self._not_before: dict[WorkItem, float] = {}
        self._lock = threading.Lock()
        self.health = Health()

    # ------------------------------------------------------------------ lifecycle

    def stop(self) -> None:
        self._stop.set()
        self.health.stopping = True

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def run_forever(self) -> bool:
        """Poll until stopped, then drain. Returns ``True`` when every in-flight item finished."""
        delay = self.settings.poll_seconds
        while not self._stop.is_set():
            self.health.last_loop = time.monotonic()
            try:
                self.poll()
                delay = self.settings.poll_seconds
            except WorkerConfigurationError as exc:  # e.g. behaviour version not registered yet
                log_event(_logger, "worker.blocked", level=logging.ERROR, reason=str(exc))
                delay = min(30.0, max(self.settings.poll_seconds, delay * 2))
            except Exception as exc:  # database outage: report, back off, keep the process
                log_event(_logger, "worker.poll_failed", level=logging.ERROR, error=exc)
                delay = min(30.0, max(self.settings.poll_seconds, delay * 2))
            self._stop.wait(delay)
        return self.drain(self.settings.drain_seconds)

    def drain(self, seconds: float) -> bool:
        self.stop()
        deadline = time.monotonic() + seconds
        with self._lock:
            pending = list(self._in_flight.values())
        for future in pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # A failure was already logged by the item wrapper; a timeout means abandoned.
            with suppress(Exception):
                future.result(timeout=remaining)
        with self._lock:
            clean = all(f.done() for f in self._in_flight.values())
        self._executor.shutdown(wait=clean, cancel_futures=True)
        log_event(_logger, "worker.stopped", clean=clean, abandoned=0 if clean else len(pending))
        return clean

    def run_once(self, *, wait: bool = True) -> list[tuple[WorkItem, str]]:
        """One discovery-and-claim pass; with ``wait``, block until claimed items finish."""
        claimed = self.poll()
        if not wait:
            return []
        results = []
        for item, future in claimed:
            results.append((item, future.result()))
        return results

    # ------------------------------------------------------------------ polling

    def poll(self) -> list[tuple[WorkItem, Future[str]]]:
        if self._behaviour_version_id is None:
            assert self._behaviour_version_label is not None
            self._behaviour_version_id = resolve_behaviour_version(
                self._factory, self._behaviour_version_label
            )
            log_event(_logger, "worker.behaviour_version_resolved")
        claimed: list[tuple[WorkItem, Future[str]]] = []
        for item in self.discover():
            if self._stop.is_set() or self._free_slots() <= 0:
                break
            future = self._claim_and_submit(item)
            if future is not None:
                claimed.append((item, future))
        self.health.last_successful_poll = time.monotonic()
        return claimed

    def _free_slots(self) -> int:
        with self._lock:
            for item in [i for i, f in self._in_flight.items() if f.done()]:
                del self._in_flight[item]
            self.health.in_flight = len(self._in_flight)
            return self.settings.concurrency - len(self._in_flight)

    def discover(self) -> list[WorkItem]:
        if self._tenants is not None:
            tenants = list(self._tenants)
        else:
            with self._factory() as session:
                tenants = list(session.scalars(sa.select(Tenant.id).order_by(Tenant.id)))
                session.rollback()
        found: list[WorkItem] = []
        now = self._clock.now()
        for tenant_id in tenants:
            with self._factory() as session:
                bind_tenant(session, tenant_id)
                apply_statement_timeouts(session)
                found.extend(self._discover_tenant(session, tenant_id, now))
                session.rollback()
        cutoff = time.monotonic()
        with self._lock:
            busy = {item for item, future in self._in_flight.items() if not future.done()}
        return [
            item for item in found if item not in busy and self._not_before.get(item, 0.0) <= cutoff
        ]

    def _discover_tenant(
        self, session: Session, tenant_id: uuid.UUID, now: datetime
    ) -> Iterator[WorkItem]:
        max_attempts = self.settings.max_attempts
        pending = session.scalars(
            sa.select(InvestigationDispatch.id)
            .where(
                InvestigationDispatch.status == "pending",
                InvestigationDispatch.attempts < max_attempts,
            )
            .order_by(InvestigationDispatch.created_at)
            .limit(DISCOVERY_LIMIT)
        )
        for dispatch_id in pending:
            yield WorkItem(WorkKind.INVESTIGATION, tenant_id, dispatch_id)
        # A linked investigation run nobody is advancing: suspended, or its lease expired
        # because the worker holding it died.
        stranded = session.scalars(
            sa.select(InvestigationDispatch.id)
            .join(
                WorkflowRun,
                sa.and_(
                    WorkflowRun.tenant_id == InvestigationDispatch.tenant_id,
                    WorkflowRun.id == InvestigationDispatch.workflow_run_id,
                ),
            )
            .where(InvestigationDispatch.status == "completed", _stranded(now))
            .limit(DISCOVERY_LIMIT)
        )
        for dispatch_id in stranded:
            yield WorkItem(WorkKind.INVESTIGATION, tenant_id, dispatch_id)

        requests = session.scalars(
            sa.select(RemediationRequest.id)
            .where(
                RemediationRequest.status == "pending",
                RemediationRequest.attempts < max_attempts,
            )
            .order_by(RemediationRequest.created_at)
            .limit(DISCOVERY_LIMIT)
        )
        for request_id in requests:
            yield WorkItem(WorkKind.REMEDIATION_START, tenant_id, request_id)

        runs = session.scalars(
            sa.select(WorkflowRun)
            .join(
                RemediationTarget,
                sa.and_(
                    RemediationTarget.tenant_id == WorkflowRun.tenant_id,
                    RemediationTarget.workflow_run_id == WorkflowRun.id,
                ),
            )
            .where(_stranded(now))
            .limit(DISCOVERY_LIMIT)
        )
        for run in runs:
            if run.status is WorkflowRunStatus.RUNNING or _remediation_ready(session, run, now):
                yield WorkItem(WorkKind.REMEDIATION_RUN, tenant_id, run.id)

        resolved = session.scalars(
            sa.select(Incident.id)
            .where(
                Incident.status == IncidentStatus.RESOLVED,
                ~sa.exists().where(
                    Postmortem.tenant_id == Incident.tenant_id,
                    Postmortem.incident_id == Incident.id,
                    Postmortem.created_at >= Incident.terminated_at,
                ),
            )
            .order_by(Incident.terminated_at)
            .limit(DISCOVERY_LIMIT)
        )
        for incident_id in resolved:
            yield WorkItem(WorkKind.POSTMORTEM, tenant_id, incident_id)

    # ------------------------------------------------------------------ claiming

    def _claim_and_submit(self, item: WorkItem) -> Future[str] | None:
        connection = self._engine.connect()
        try:
            acquired = connection.scalar(
                sa.text("SELECT pg_try_advisory_lock(:key)"), {"key": item.lock_key}
            )
            connection.commit()
        except Exception:
            connection.close()
            raise
        if not acquired:
            connection.close()
            metrics.worker_items_total.add(
                1, {"kind": item.kind.value, "outcome": "claimed_elsewhere"}
            )
            return None
        future = self._executor.submit(self._run_item, item, connection)
        with self._lock:
            self._in_flight[item] = future
            self.health.in_flight = len(self._in_flight)
        return future

    def _run_item(self, item: WorkItem, claim: sa.Connection) -> str:
        started = time.monotonic()
        outcome = "failed"
        try:
            outcome = self.handle(item)
            if outcome in _RETRY_LATER:
                self._not_before[item] = time.monotonic() + self.settings.retry_backoff_seconds
            else:
                self._not_before.pop(item, None)
            return outcome
        except Exception as exc:
            self._not_before[item] = time.monotonic() + self.settings.retry_backoff_seconds
            log_event(
                _logger,
                "worker.item_failed",
                level=logging.ERROR,
                error=exc,
                kind=item.kind.value,
                tenant_id=str(item.tenant_id),
                item_id=str(item.item_id),
            )
            return outcome
        finally:
            metrics.worker_items_total.add(1, {"kind": item.kind.value, "outcome": outcome})
            metrics.worker_item_duration_seconds.record(
                time.monotonic() - started, {"kind": item.kind.value}
            )
            log_event(
                _logger,
                "worker.item",
                kind=item.kind.value,
                outcome=outcome,
                tenant_id=str(item.tenant_id),
                item_id=str(item.item_id),
            )
            try:
                claim.scalar(sa.text("SELECT pg_advisory_unlock(:key)"), {"key": item.lock_key})
                claim.commit()
            finally:
                claim.close()

    # ------------------------------------------------------------------ handlers

    def handle(self, item: WorkItem) -> str:
        if item.kind is WorkKind.INVESTIGATION:
            return self._investigate(item)
        if item.kind is WorkKind.REMEDIATION_START:
            return self._start_remediation(item)
        if item.kind is WorkKind.REMEDIATION_RUN:
            return self._resume_remediation(item)
        return self._draft_postmortem(item)

    @property
    def behaviour_version_id(self) -> uuid.UUID:
        if self._behaviour_version_id is None:
            raise WorkerConfigurationError("behaviour version is not resolved yet")
        return self._behaviour_version_id

    def _investigate(self, item: WorkItem) -> str:
        with self._tenant(item.tenant_id) as session:
            run_id = session.scalar(
                sa.select(InvestigationDispatch.workflow_run_id).where(
                    InvestigationDispatch.id == item.item_id
                )
            )
        dispatcher = InvestigationDispatcher(
            self._factory, self._profile.investigation_service(item.tenant_id, run_id)
        )
        result = dispatcher.dispatch(
            TenantContext(item.tenant_id), item.item_id, self.behaviour_version_id
        )
        return result.status

    def _start_remediation(self, item: WorkItem) -> str:
        with self._tenant(item.tenant_id) as session:
            request = session.scalar(
                sa.select(RemediationRequest)
                .where(RemediationRequest.id == item.item_id)
                .with_for_update()
            )
            if request is None or request.status != "pending":
                return "terminal"
            request.attempts += 1
            attempts = request.attempts
            incident_id, hypothesis_id = request.incident_id, request.hypothesis_id
            service_id = request.service_id
        kernel = self._profile.remediation_kernel(item.tenant_id, None)
        try:
            outcome = kernel.start(
                tenant_id=item.tenant_id,
                incident_id=incident_id,
                hypothesis_id=hypothesis_id,
                behaviour_version_id=self.behaviour_version_id,
                selected_service_id=service_id,
                request_id=item.item_id,
            )
        except RequestAlreadyLinked:
            return "terminal"
        except LeaseNotHeld:
            return "busy"
        except DomainError:
            # The request no longer describes a startable remediation (the incident moved,
            # the hypothesis was superseded). Hand the incident back to a human.
            self._reject(item, incident_id, "start_refused")
            return "rejected"
        except Exception:
            if attempts >= self.settings.max_attempts:
                self._reject(item, incident_id, "attempts_exhausted")
                return "rejected"
            with self._tenant(item.tenant_id) as session:
                session.execute(
                    sa.update(RemediationRequest)
                    .where(
                        RemediationRequest.id == item.item_id,
                        RemediationRequest.status == "pending",
                    )
                    .values(last_error="start_failed")
                )
            raise
        return "completed" if outcome.terminated else "suspended"

    def _reject(self, item: WorkItem, incident_id: uuid.UUID, code: str) -> None:
        with self._tenant(item.tenant_id) as session:
            session.execute(
                sa.update(RemediationRequest)
                .where(
                    RemediationRequest.id == item.item_id,
                    RemediationRequest.status == "pending",
                )
                .values(status="rejected", last_error=code)
            )
            incident = session.scalar(
                sa.select(Incident).where(Incident.id == incident_id).with_for_update()
            )
            live = session.scalar(
                sa.select(sa.func.count())
                .select_from(WorkflowRun)
                .where(WorkflowRun.incident_id == incident_id, WorkflowRun.status.in_(_LIVE_RUN))
            )
            if (
                incident is not None
                and incident.status is IncidentStatus.INVESTIGATING
                and not live
            ):
                apply_transition(
                    session,
                    incident=incident,
                    target=IncidentStatus.ESCALATED,
                    actor_type=ActorType.SYSTEM,
                    source="asic-worker",
                    correlation_id=uuid.uuid4(),
                    termination_reason=TerminationReason.HUMAN_ESCALATION,
                )

    def _resume_remediation(self, item: WorkItem) -> str:
        kernel = self._profile.remediation_kernel(item.tenant_id, item.item_id)
        try:
            outcome = kernel.resume(tenant_id=item.tenant_id, workflow_run_id=item.item_id)
        except LeaseNotHeld:
            return "busy"
        return "completed" if outcome.terminated else "suspended"

    def _draft_postmortem(self, item: WorkItem) -> str:
        return (
            self._profile.postmortem_author()
            .draft(tenant_id=item.tenant_id, incident_id=item.item_id)
            .outcome
        )

    @contextmanager
    def _tenant(self, tenant_id: uuid.UUID) -> Iterator[Session]:
        with self._factory() as session, session.begin():
            bind_tenant(session, tenant_id)
            apply_statement_timeouts(session)
            yield session


#: Outcomes after which the same item should not be retried immediately.
_RETRY_LATER: Final[frozenset[str]] = frozenset(
    {"busy", "suspended", "sources_changed", "failed", "claimed_elsewhere"}
)


def _stranded(now: datetime) -> sa.ColumnElement[bool]:
    return sa.or_(
        WorkflowRun.status == WorkflowRunStatus.SUSPENDED,
        sa.and_(
            WorkflowRun.status == WorkflowRunStatus.RUNNING,
            sa.or_(WorkflowRun.lease_expires_at.is_(None), WorkflowRun.lease_expires_at < now),
        ),
    )


def _remediation_ready(session: Session, run: WorkflowRun, now: datetime) -> bool:
    """Whether a suspended remediation run has anything new to act on.

    Resuming a run that is merely waiting would re-request the same approval or re-check the
    same settling window; that is harmless but noisy. So a waiting run is resumed only when
    the thing it waits for has happened.
    """
    action = session.scalar(
        sa.select(RemediationAction)
        .where(RemediationAction.workflow_run_id == run.id)
        .order_by(RemediationAction.proposed_at.desc())
        .limit(1)
    )
    if action is None:
        return True  # interrupted before a proposal: resume to finish planning
    if action.status is RemediationActionStatus.AWAITING_APPROVAL:
        decided = session.scalar(
            sa.select(sa.func.count())
            .select_from(Approval)
            .where(
                Approval.remediation_action_id == action.id,
                Approval.action_version_hash == action.action_version_hash,
            )
        )
        if decided:
            return True
        evaluated_at = session.scalar(
            sa.select(PolicyDecision.evaluated_at).where(
                PolicyDecision.remediation_action_id == action.id
            )
        )
        window = timedelta(seconds=APPROVAL_WINDOW_SECONDS.get(action.risk_tier, 0))
        return evaluated_at is not None and now >= evaluated_at + window
    if action.executed_at is not None:
        verified = session.scalar(
            sa.select(sa.func.count())
            .select_from(Verification)
            .where(Verification.remediation_action_id == action.id)
        )
        if verified:
            return True
        try:
            settling = ToolRegistry.remediation_full().by_name(action.tool_name).settling_seconds
        except UnregisteredCapability:
            return True
        return now >= action.executed_at + timedelta(seconds=settling)
    return True


def resolve_behaviour_version(factory: Callable[[], Session], label: str) -> uuid.UUID:
    """The registered behaviour version this worker runs as. Refuses a mismatch with the code.

    A behaviour version is registered administratively; the worker only reads it. If its
    prompt set or tool catalogue differs from what this image contains, runs would be
    attributed to a behaviour that did not produce them, so the worker refuses to start.
    """
    with factory() as session:
        row = session.execute(
            sa.select(
                BehaviourVersion.id,
                BehaviourVersion.prompt_set_version,
                BehaviourVersion.tool_registry_version,
            ).where(BehaviourVersion.label == label)
        ).one_or_none()
        session.rollback()
    if row is None:
        raise WorkerConfigurationError(f"behaviour version {label!r} is not registered")
    version_id, prompt_set, catalogue = row
    if prompt_set != PROMPT_SET_VERSION or catalogue != CATALOGUE_VERSION:
        raise WorkerConfigurationError(
            f"behaviour version {label!r} records prompt set {prompt_set} and catalogue "
            f"{catalogue}; this image runs {PROMPT_SET_VERSION} and {CATALOGUE_VERSION}. "
            "Register the new behaviour version before deploying it."
        )
    return uuid.UUID(str(version_id))


# ---------------------------------------------------------------------- probes


class _ProbeHandler(BaseHTTPRequestHandler):
    worker: Worker
    live_window: float
    ready_window: float
    metrics_enabled: bool

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/livez":
            self._send(200 if self.worker.health.live(self.live_window) else 503, {"live": True})
        elif path == "/readyz":
            ok = self.worker.health.ready(self.ready_window)
            self._send(
                200 if ok else 503,
                {"ready": ok, "in_flight": self.worker.health.in_flight},
            )
        elif path == "/metrics" and self.metrics_enabled:
            from asic.observability.setup import render_prometheus

            body, content_type = render_prometheus()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send(404, {"code": "not_found"})

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - silence access log
        return


def serve_probes(worker: Worker, *, metrics_enabled: bool = False) -> ThreadingHTTPServer:
    """Liveness (the poll loop is turning), readiness (a recent poll reached PostgreSQL and the
    worker is not draining) and, optionally, the Prometheus exposition."""
    live_window = max(60.0, worker.settings.poll_seconds * 6)
    ready_window = max(30.0, worker.settings.poll_seconds * 4)
    handler = type(
        "WorkerProbeHandler",
        (_ProbeHandler,),
        {
            "worker": worker,
            "live_window": live_window,
            "ready_window": ready_window,
            "metrics_enabled": metrics_enabled,
        },
    )
    server = ThreadingHTTPServer(
        (worker.settings.health_host, worker.settings.health_port), handler
    )
    threading.Thread(target=server.serve_forever, name="asic-worker-probes", daemon=True).start()
    return server


def install_signal_handlers(worker: Worker) -> None:
    def handle(signum: int, _frame: object) -> None:
        log_event(_logger, "worker.stopping", signal=signal.Signals(signum).name)
        worker.stop()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)


def exit_code_for(clean: bool) -> int:
    """0 after a clean drain. 3 when items were abandoned mid-node; they recover like a crash."""
    return 0 if clean else 3


__all__ = [
    "DISCOVERY_LIMIT",
    "Health",
    "WorkItem",
    "WorkKind",
    "Worker",
    "exit_code_for",
    "install_signal_handlers",
    "resolve_behaviour_version",
    "serve_probes",
]
