"""Run the worker process: ``python -m asic.worker``.

Process wiring only: logging, telemetry, the database engine, the execution profile, the
behaviour version, probes and signals - then the poll loop. Refuses to start on any
configuration it cannot run safely (a live mode with no model, a simulator in production,
plaintext database transport in production, an unregistered behaviour version).
"""

from __future__ import annotations

import logging
import os
import sys

from asic.db.session import create_app_engine, session_factory
from asic.db.tls import DatabaseTlsPolicyError
from asic.observability.logging import configure_logging, log_event
from asic.observability.setup import TelemetrySettings, configure_telemetry
from asic.worker.profile import build_profile
from asic.worker.runtime import (
    Worker,
    exit_code_for,
    install_signal_handlers,
    serve_probes,
)
from asic.worker.settings import WorkerConfigurationError, WorkerSettings

_logger = logging.getLogger("asic.worker")


def main() -> int:
    configure_logging(service="asic-worker", level=os.environ.get("ASIC_LOG_LEVEL", "INFO"))
    configure_telemetry(TelemetrySettings.from_environment(default_service="asic-worker"))
    try:
        settings = WorkerSettings.from_environment()
        engine = create_app_engine(pool_size=settings.pool_size, max_overflow=0)
        factory = session_factory(engine)
        profile = build_profile(settings, factory)
    except (WorkerConfigurationError, DatabaseTlsPolicyError) as exc:
        # Both messages are composed by this code base from configuration names, never from
        # a connection string or a secret, so the reason is safe to log and operators need it.
        log_event(_logger, "worker.refused", level=logging.CRITICAL, error=exc, reason=str(exc))
        return 2
    worker = Worker(
        settings=settings,
        engine=engine,
        factory=factory,
        profile=profile,
        # Resolved on the first poll (and retried until registered): see Worker.__init__.
        behaviour_version_label=settings.behaviour_version_label,
    )
    install_signal_handlers(worker)
    probes = serve_probes(
        worker, metrics_enabled=os.environ.get("ASIC_METRICS_ENABLED", "").lower() == "true"
    )
    log_event(
        _logger,
        "worker.started",
        mode=settings.mode.value,
        concurrency=settings.concurrency,
        poll_seconds=settings.poll_seconds,
    )
    clean = worker.run_forever()
    probes.shutdown()
    code = exit_code_for(clean)
    if not clean:
        # In-flight graph nodes cannot be preempted. Exiting now abandons them exactly as a
        # crash would; their leases expire and another worker resumes them.
        logging.shutdown()
        os._exit(code)
    engine.dispose()
    return code


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
