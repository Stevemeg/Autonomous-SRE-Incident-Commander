"""The simulator tool provider.

Explicit test and development infrastructure (master specification section 20). It sits at
the *adapter boundary*, behind the broker, exactly where a Prometheus or Kubernetes client
will sit - not inside a node, and not as a special case the broker knows about. That
placement is the point: the pipeline a simulated call takes is byte-for-byte the pipeline a
real call will take, so the authorization, idempotency, audit and trace behaviour proved
against simulators is the behaviour that will hold against real adapters.

What arrives here has already been through authorization, scope resolution and argument
validation. What leaves is validated against the descriptor before any node sees it, so
this class is not trusted to return the right shape - and one scenario deliberately makes
it return the wrong one.

The provider refuses to construct against a non-simulator descriptor, and refuses to run
when the environment marks itself production. A simulator reachable in production would
mean fabricated telemetry presented as real, which is the failure mode section 20 forbids.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from asic.domain.clock import Clock
from asic.domain.enums import ToolProviderKind
from asic.domain.errors import ToolAdapterError, ToolTimeout
from asic.simulators.scenarios import (
    Scenario,
    SimulatedFault,
    SimulationContext,
)
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ProviderHealth

#: Set this to ``production`` and the simulator refuses to start.
DEPLOYMENT_ENV_VAR: Final[str] = "ASIC_DEPLOYMENT_ENVIRONMENT"

_FORBIDDEN_DEPLOYMENTS: Final[frozenset[str]] = frozenset({"production", "prod"})


class SimulatorRefused(RuntimeError):
    """The simulator declined to run where it must not."""


class SimulatorProvider:
    """Deterministic responses for the read-only catalogue, driven by a scenario."""

    __slots__ = ("_attempts", "_calls", "_clock", "_scenario")

    def __init__(self, scenario: Scenario, *, clock: Clock) -> None:
        deployment = os.environ.get(DEPLOYMENT_ENV_VAR, "").strip().lower()
        if deployment in _FORBIDDEN_DEPLOYMENTS:
            raise SimulatorRefused(
                f"{DEPLOYMENT_ENV_VAR}={deployment!r}: the simulator will not run in a "
                "production deployment. Simulated telemetry presented as real is the "
                "failure mode this refusal exists to make impossible."
            )
        self._scenario = scenario
        self._clock = clock
        self._attempts: Counter[str] = Counter()
        self._calls: list[tuple[str, str]] = []

    @property
    def kind(self) -> ToolProviderKind:
        return ToolProviderKind.SIMULATOR

    @property
    def scenario(self) -> Scenario:
        return self._scenario

    @property
    def calls(self) -> tuple[tuple[str, str], ...]:
        """``(tool_name, service)`` for every call that reached this provider.

        Used by tests that need to prove a call did *not* happen - a de-duplicated request,
        or a refused one.
        """
        return tuple(self._calls)

    def list_tools(self) -> tuple[str, ...]:
        return (
            "deploy.list",
            "k8s.workload.read",
            "knowledge.search",
            "logs.query",
            "metrics.query",
            "traces.query",
        )

    def supports(self, descriptor: ToolDescriptor) -> bool:
        return (
            descriptor.provider_kind is ToolProviderKind.SIMULATOR
            and descriptor.name in self.list_tools()
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=True, detail=f"scenario {self._scenario.scenario_id}")

    def invoke(
        self,
        descriptor: ToolDescriptor,
        arguments: Mapping[str, Any],
        context: InvocationContext,
    ) -> Mapping[str, Any]:
        service = str(arguments.get("service", ""))
        self._calls.append((descriptor.name, service))

        response = self._scenario.response_for(descriptor.capability, service)
        if response is None:
            # No fixture for this pair means the source genuinely has nothing for this
            # service. An empty answer is a finding; inventing one would not be.
            return self._empty_result(descriptor, arguments)

        key = f"{descriptor.capability}|{service}"
        self._attempts[key] += 1
        attempt = self._attempts[key]

        # A fault applies to the first ``fault_clears_after_attempts`` attempts, or to
        # every attempt when that is zero. Attempts beyond it fall through to the builder,
        # which is how a transient upstream error that recovers on retry is expressed.
        faulting = response.fault is not None and (
            response.fault_clears_after_attempts == 0
            or attempt <= response.fault_clears_after_attempts
        )
        if faulting:
            assert response.fault is not None
            if response.fault is SimulatedFault.MALFORMED_RESULT:
                # Signalled by returning the wrong shape rather than by raising, so that
                # the *broker's* result validation is what catches it.
                return self._malformed_result(descriptor)
            self._raise(response.fault, descriptor, context)

        if response.builder is None:  # pragma: no cover - SimulatedResponse forbids this
            raise ToolAdapterError(
                f"{descriptor.name}: scenario response has neither builder nor fault",
                transient=False,
            )
        return response.builder(self._context_for(arguments))

    def _raise(
        self,
        fault: SimulatedFault,
        descriptor: ToolDescriptor,
        context: InvocationContext,
    ) -> None:
        """Raise the typed failure the broker classifies. Never returns."""
        if fault is SimulatedFault.TIMEOUT:
            raise ToolTimeout(
                f"{descriptor.name}: simulated upstream did not answer within "
                f"{context.timeout_seconds}s"
            )
        if fault is SimulatedFault.TRANSIENT_ERROR:
            raise ToolAdapterError(
                f"{descriptor.name}: simulated upstream returned 503 service unavailable",
                transient=True,
            )
        raise ToolAdapterError(
            f"{descriptor.name}: simulated upstream rejected the query "
            "(backend unavailable for this tenant)",
            transient=False,
        )

    @staticmethod
    def _malformed_result(descriptor: ToolDescriptor) -> Mapping[str, Any]:
        """A payload that is well-formed JSON and the wrong shape entirely."""
        return {"unexpected": f"{descriptor.name} returned an undeclared envelope"}

    def _context_for(self, arguments: Mapping[str, Any]) -> SimulationContext:
        window_start = _as_datetime(arguments.get("window_start"), self._clock.now())
        window_end = _as_datetime(arguments.get("window_end"), self._clock.now())
        return SimulationContext(
            tenant_id=str(arguments.get("tenant_id", uuid.UUID(int=0))),
            environment=str(arguments.get("environment", "unknown")),
            service=str(arguments.get("service", "unknown")),
            window_start=window_start,
            window_end=window_end,
            now=self._clock.now(),
            arguments=dict(arguments),
        )

    def _empty_result(
        self, descriptor: ToolDescriptor, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """A well-formed result carrying nothing.

        Every declared collection field is present and empty, so an empty answer still
        satisfies the descriptor and is distinguishable from a failure.
        """
        payload: dict[str, Any] = {
            "source": f"{descriptor.name}-simulator",
            "schema_version": 1,
            "environment": str(arguments.get("environment", "unknown")),
            "service": str(arguments.get("service", "unknown")),
        }
        for field in descriptor.result_fields:
            if field.name not in payload:
                payload[field.name] = [] if field.name.endswith("s") else False
        return payload


def _as_datetime(value: object, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return fallback


__all__ = ["DEPLOYMENT_ENV_VAR", "SimulatorProvider", "SimulatorRefused"]
