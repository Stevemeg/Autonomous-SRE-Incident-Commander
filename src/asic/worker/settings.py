"""Worker configuration, read once from the environment and validated at startup."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MAX_CONCURRENCY: Final[int] = 8

#: The simulator profile's default world. A literal, not an import: the simulator package is
#: test infrastructure and is absent from the production image (FR-INT-04).
DEFAULT_SIMULATOR_SCENARIO: Final[str] = "SC-0001-checkout-latency-after-deploy"


class ExecutionMode(StrEnum):
    #: Native adapters and a live model provider. No live model provider exists (GAP-08), so
    #: this mode refuses to start rather than run investigations without reasoning.
    LIVE = "live"
    #: Deterministic simulators and the scripted model: explicit test infrastructure, refused
    #: in a production deployment (FR-INT-04).
    SIMULATOR = "simulator"


class WorkerConfigurationError(RuntimeError):
    """The worker was asked to run in a configuration it must refuse."""


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    mode: ExecutionMode
    behaviour_version_label: str
    concurrency: int = 2
    poll_seconds: float = 5.0
    drain_seconds: float = 20.0
    max_attempts: int = 5
    health_host: str = "127.0.0.1"
    health_port: int = 8081
    simulator_scenario: str = DEFAULT_SIMULATOR_SCENARIO
    simulator_remediation_variant: str = "autonomous_verified"
    #: Minimum seconds between two attempts at the same item after it failed or was busy.
    retry_backoff_seconds: float = 15.0

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> WorkerSettings:
        env = os.environ if environ is None else environ
        try:
            mode = ExecutionMode(env.get("ASIC_WORKER_EXECUTION_MODE", "live").strip().lower())
        except ValueError as exc:
            raise WorkerConfigurationError(
                "ASIC_WORKER_EXECUTION_MODE must be 'live' or 'simulator'"
            ) from exc
        label = env.get("ASIC_BEHAVIOUR_VERSION_LABEL", "").strip()
        if not label:
            raise WorkerConfigurationError(
                "ASIC_BEHAVIOUR_VERSION_LABEL is required: every run records the registered "
                "behaviour version that produced it"
            )
        try:
            settings = cls(
                mode=mode,
                behaviour_version_label=label,
                concurrency=int(env.get("ASIC_WORKER_CONCURRENCY", "2")),
                poll_seconds=float(env.get("ASIC_WORKER_POLL_SECONDS", "5")),
                drain_seconds=float(env.get("ASIC_WORKER_DRAIN_SECONDS", "20")),
                max_attempts=int(env.get("ASIC_WORKER_MAX_ATTEMPTS", "5")),
                health_host=env.get("ASIC_WORKER_HEALTH_HOST", "127.0.0.1"),
                health_port=int(env.get("ASIC_WORKER_HEALTH_PORT", "8081")),
                simulator_scenario=env.get(
                    "ASIC_WORKER_SIMULATOR_SCENARIO", DEFAULT_SIMULATOR_SCENARIO
                ),
                simulator_remediation_variant=env.get(
                    "ASIC_WORKER_SIMULATOR_REMEDIATION_VARIANT", "autonomous_verified"
                ),
                retry_backoff_seconds=float(env.get("ASIC_WORKER_RETRY_BACKOFF_SECONDS", "15")),
            )
        except ValueError as exc:
            raise WorkerConfigurationError("a numeric worker setting is not a number") from exc
        settings.validate()
        return settings

    def validate(self) -> None:
        if not 1 <= self.concurrency <= MAX_CONCURRENCY:
            raise WorkerConfigurationError(
                f"ASIC_WORKER_CONCURRENCY must be between 1 and {MAX_CONCURRENCY}"
            )
        if not 0.1 <= self.poll_seconds <= 300:
            raise WorkerConfigurationError("ASIC_WORKER_POLL_SECONDS must be within 0.1..300")
        if not 0 <= self.drain_seconds <= 600:
            raise WorkerConfigurationError("ASIC_WORKER_DRAIN_SECONDS must be within 0..600")
        if not 1 <= self.max_attempts <= 50:
            raise WorkerConfigurationError("ASIC_WORKER_MAX_ATTEMPTS must be within 1..50")
        if not 0 <= self.health_port <= 65535:
            raise WorkerConfigurationError("ASIC_WORKER_HEALTH_PORT is not a port")

    @property
    def pool_size(self) -> int:
        """Connections per slot: the advisory-lock claim, the node's unit of work, and the
        short side transaction a node opens while it runs (model ledger, broker claim). Plus
        the poller and the readiness probe."""
        return self.concurrency * 3 + 2


__all__ = ["MAX_CONCURRENCY", "ExecutionMode", "WorkerConfigurationError", "WorkerSettings"]
