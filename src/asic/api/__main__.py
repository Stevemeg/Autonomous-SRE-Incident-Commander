"""Run the API process: ``python -m asic.api``.

Process wiring only - structured logging, telemetry providers, then the ASGI server. The
container image, Kubernetes manifests and collector deployment are Phase 14.
"""

from __future__ import annotations

import os

import uvicorn

from asic.api.app import create_app
from asic.observability.logging import configure_logging
from asic.observability.setup import TelemetrySettings, configure_telemetry


def main() -> None:
    configure_logging(service="asic-api", level=os.environ.get("ASIC_LOG_LEVEL", "INFO"))
    configure_telemetry(TelemetrySettings.from_environment(default_service="asic-api"))
    uvicorn.run(
        create_app(),
        host=os.environ.get("ASIC_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("ASIC_API_PORT", "8000")),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover - entry point
    main()
