"""Liveness, readiness and dependency degradation.

* **Liveness** answers "is this process able to serve at all" and touches nothing external.
  A liveness probe that queried the database would restart healthy processes during a
  database incident and turn one outage into two.
* **Readiness** answers "should traffic reach this process": the database must answer
  within a short statement timeout **and** be at the schema revision this code was built
  for. A process running against an older or newer schema is not ready, even though every
  query it happens to try might still succeed.
* **Degradation** is reported per dependency (``up``, ``degraded``, ``down``) and exported as
  ``asic.dependency.up`` so an alert can fire before users notice.

Details returned to callers are closed codes, never exception text or connection strings.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import sqlalchemy as sa
from opentelemetry import metrics as otel_metrics
from opentelemetry.metrics import CallbackOptions, Observation
from sqlalchemy.orm import Session

#: The migration head this build expects. A test pins it to the Alembic script head.
EXPECTED_SCHEMA_REVISION: Final[str] = "0017_evaluation_harness"
READINESS_STATEMENT_TIMEOUT_MS: Final[int] = 1000


class DependencyStatus(StrEnum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass(frozen=True, slots=True)
class DependencyCheck:
    name: str
    status: DependencyStatus
    detail: str
    critical: bool = True


@dataclass(frozen=True, slots=True)
class Readiness:
    ready: bool
    checks: tuple[DependencyCheck, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "ready" if self.ready else "not_ready",
            "dependencies": {
                c.name: {"status": c.status.value, "detail": c.detail, "critical": c.critical}
                for c in self.checks
            },
        }


_meter = otel_metrics.get_meter("asic.health")
readiness_checks = _meter.create_counter(
    "asic.readiness.checks", description="Readiness dependency checks, by dependency and outcome."
)
_last: dict[str, float] = {}
_last_lock = threading.Lock()


def _observe(_options: CallbackOptions) -> Iterable[Observation]:
    with _last_lock:
        return [Observation(value, {"dependency": name}) for name, value in sorted(_last.items())]


dependency_up = _meter.create_observable_gauge(
    "asic.dependency.up",
    callbacks=[_observe],
    description="1 when the dependency was up at the last readiness check, 0.5 degraded, 0 down.",
)


def check_database(
    factory: Callable[[], Session], *, expected_revision: str = EXPECTED_SCHEMA_REVISION
) -> DependencyCheck:
    try:
        with factory() as session, session.begin():
            session.execute(
                sa.text(f"SET LOCAL statement_timeout = {int(READINESS_STATEMENT_TIMEOUT_MS)}")
            )
            revision = session.scalar(sa.text("SELECT version_num FROM alembic_version"))
    except Exception:  # any failure to answer is "down"; the reason is not disclosed
        return DependencyCheck("database", DependencyStatus.DOWN, "unreachable")
    if revision != expected_revision:
        return DependencyCheck("database", DependencyStatus.DEGRADED, "schema_revision_mismatch")
    return DependencyCheck("database", DependencyStatus.UP, "ok")


def evaluate_readiness(checks: Iterable[DependencyCheck]) -> Readiness:
    resolved = tuple(checks)
    for check in resolved:
        value = {DependencyStatus.UP: 1.0, DependencyStatus.DEGRADED: 0.5}.get(check.status, 0.0)
        with _last_lock:
            _last[check.name] = value
        readiness_checks.add(1, {"dependency": check.name, "outcome": check.status.value})
    ready = all(c.status is DependencyStatus.UP for c in resolved if c.critical)
    return Readiness(ready=ready, checks=resolved)


__all__ = [
    "EXPECTED_SCHEMA_REVISION",
    "READINESS_STATEMENT_TIMEOUT_MS",
    "DependencyCheck",
    "DependencyStatus",
    "Readiness",
    "check_database",
    "dependency_up",
    "evaluate_readiness",
]
