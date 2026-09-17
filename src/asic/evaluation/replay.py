"""Recording and replay at the provider seams - the same seams production uses.

A run under evaluation is executed with its tool providers and model provider wrapped in
recorders. The recording - every tool result or failure and every model response, in order -
is sealed into a :class:`ReplayFixture` and stored. Replaying swaps the wrapped providers for
:class:`ReplayToolProvider` and :class:`ReplayModelProvider`, which serve exactly the recorded
answers to the same kernels, broker, persistence and trace code.

Replay is strict. A request that does not match the next recorded entry (a different tool,
different non-scope arguments, a different model node or prompt version) raises
:class:`ReplayDivergence`: a replay that silently served an answer to a different question
would be a fabrication, not a reproduction. Scope arguments (tenant, environment, service)
are deliberately excluded from matching, because a replay runs in a fresh world whose
identifiers differ; everything that determines *what was asked* is compared.

Replay providers are fixture infrastructure: they refuse production deployments and cannot
be combined with live integrations in one broker.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from asic.domain.enums import ToolProviderKind
from asic.domain.errors import ModelProviderError, ToolAdapterError, ToolFailure, ToolTimeout
from asic.evaluation.versioning import REPLAY_FORMAT_VERSION, canonical, digest
from asic.integrations.credentials import is_production_deployment
from asic.llm.port import ModelCallEstimate, ModelProvider, ModelRequest, ModelResponse
from asic.tools.descriptor import ToolDescriptor
from asic.tools.provider import InvocationContext, ProviderHealth, ToolProvider

#: Scope arguments differ between an original run and its replay world.
_SCOPE_ARGUMENTS: Final[frozenset[str]] = frozenset(
    {"tenant_id", "environment", "service", "namespace"}
)


class ReplayDivergence(ToolFailure):
    """The replayed run asked something the recording never answered."""


class ReplayRefused(RuntimeError):
    """A replay fixture failed verification or was used where it must not be."""


def request_identity(descriptor: ToolDescriptor, arguments: Mapping[str, Any]) -> str:
    return digest(
        {
            "tool": descriptor.name,
            "version": descriptor.version,
            "arguments": {k: v for k, v in arguments.items() if k not in _SCOPE_ARGUMENTS},
        }
    )


def model_identity(request: ModelRequest) -> str:
    return digest(
        {
            "node": request.node_id.value,
            "prompt_id": request.prompt_id,
            "prompt_version": request.prompt_version,
            "prompt_hash": request.prompt_hash,
        }
    )


@dataclass(frozen=True, slots=True)
class ReplayFixture:
    scenario_key: str
    scenario_digest: str
    tool_calls: tuple[Mapping[str, Any], ...]
    model_calls: tuple[Mapping[str, Any], ...]
    format_version: int = REPLAY_FORMAT_VERSION

    def content(self) -> dict[str, Any]:
        value: dict[str, Any] = canonical(
            {
                "format_version": self.format_version,
                "scenario_key": self.scenario_key,
                "scenario_digest": self.scenario_digest,
                "tool_calls": list(self.tool_calls),
                "model_calls": list(self.model_calls),
            }
        )
        return value

    @property
    def digest(self) -> str:
        return digest(self.content())

    @classmethod
    def load(cls, content: Mapping[str, Any], *, expected_digest: str) -> ReplayFixture:
        """Rebuild and verify. A tampered or truncated fixture is refused."""
        if digest(content) != expected_digest:
            raise ReplayRefused("replay fixture content does not match its digest")
        if content.get("format_version") != REPLAY_FORMAT_VERSION:
            raise ReplayRefused("unsupported replay fixture format version")
        return cls(
            scenario_key=str(content["scenario_key"]),
            scenario_digest=str(content["scenario_digest"]),
            tool_calls=tuple(content["tool_calls"]),
            model_calls=tuple(content["model_calls"]),
            format_version=int(content["format_version"]),
        )


class _Tape:
    def __init__(self) -> None:
        self.tool_calls: list[dict[str, Any]] = []
        self.model_calls: list[dict[str, Any]] = []
        self.lock = threading.Lock()


class Recorder:
    """Owns the tape shared by a run's recording providers."""

    def __init__(self) -> None:
        self._tape = _Tape()

    def wrap_tools(self, providers: Sequence[ToolProvider]) -> list[ToolProvider]:
        return [RecordingToolProvider(p, self._tape) for p in providers]

    def wrap_model(self, model: ModelProvider) -> ModelProvider:
        return RecordingModelProvider(model, self._tape)

    def fixture(self, *, scenario_key: str, scenario_digest: str) -> ReplayFixture:
        with self._tape.lock:
            return ReplayFixture(
                scenario_key=scenario_key,
                scenario_digest=scenario_digest,
                tool_calls=tuple(self._tape.tool_calls),
                model_calls=tuple(self._tape.model_calls),
            )

    @property
    def tool_call_count(self) -> int:
        return len(self._tape.tool_calls)


class RecordingToolProvider:
    """Delegates unchanged and records the observable answer, including failures."""

    def __init__(self, delegate: ToolProvider, tape: _Tape) -> None:
        self._delegate = delegate
        self._tape = tape

    @property
    def kind(self) -> ToolProviderKind:
        return self._delegate.kind

    def list_tools(self) -> tuple[str, ...]:
        return self._delegate.list_tools()

    def supports(self, descriptor: ToolDescriptor) -> bool:
        return self._delegate.supports(descriptor)

    def health(self) -> ProviderHealth:
        return self._delegate.health()

    def invoke(
        self, descriptor: ToolDescriptor, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        entry: dict[str, Any] = {
            "identity": request_identity(descriptor, arguments),
            "tool": descriptor.name,
        }
        try:
            result = self._delegate.invoke(descriptor, arguments, context)
        except ToolTimeout as exc:
            entry.update(outcome="timeout", message=str(exc)[:300])
            self._append(entry)
            raise
        except ToolAdapterError as exc:
            entry.update(outcome="error", transient=exc.transient, message=str(exc)[:300])
            self._append(entry)
            raise
        entry.update(outcome="result", payload=canonical(dict(result)))
        self._append(entry)
        return result

    def _append(self, entry: dict[str, Any]) -> None:
        with self._tape.lock:
            self._tape.tool_calls.append(entry)


class RecordingModelProvider:
    def __init__(self, delegate: ModelProvider, tape: _Tape) -> None:
        self._delegate = delegate
        self._tape = tape

    @property
    def provider_name(self) -> str:
        return self._delegate.provider_name

    @property
    def model_id(self) -> str:
        return self._delegate.model_id

    def estimate(self, request: ModelRequest) -> ModelCallEstimate:
        return self._delegate.estimate(request)

    def complete(self, request: ModelRequest) -> ModelResponse:
        entry: dict[str, Any] = {"identity": model_identity(request), "node": request.node_id.value}
        try:
            response = self._delegate.complete(request)
        except ModelProviderError as exc:
            entry.update(outcome="error", transient=exc.transient, message=str(exc)[:300])
            with self._tape.lock:
                self._tape.model_calls.append(entry)
            raise
        entry.update(
            outcome="response",
            response={
                "text": response.text,
                "provider": response.provider,
                "model_id": response.model_id,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cost_usd": response.cost_usd,
                "finish_reason": response.finish_reason,
            },
        )
        with self._tape.lock:
            self._tape.model_calls.append(entry)
        return response


def _refuse_production() -> None:
    if is_production_deployment():
        raise ReplayRefused("replay providers cannot run in a production deployment")


class ReplayToolProvider:
    """Serves recorded tool answers, strictly in order."""

    def __init__(self, fixture: ReplayFixture) -> None:
        _refuse_production()
        self._calls = list(fixture.tool_calls)
        self._cursor = 0
        self._lock = threading.Lock()
        self._tools = frozenset(str(c["tool"]) for c in self._calls)

    @property
    def kind(self) -> ToolProviderKind:
        # Fixture family: never native, so the broker refuses it next to a live integration.
        return ToolProviderKind.SIMULATOR

    @property
    def remaining(self) -> int:
        return len(self._calls) - self._cursor

    def list_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def supports(self, descriptor: ToolDescriptor) -> bool:
        # Every registered tool is routed here so an unrecorded call diverges loudly
        # instead of silently reaching some other provider.
        return True

    def health(self) -> ProviderHealth:
        return ProviderHealth(available=True, detail="replay fixture")

    def invoke(
        self, descriptor: ToolDescriptor, arguments: Mapping[str, Any], context: InvocationContext
    ) -> Mapping[str, Any]:
        with self._lock:
            if self._cursor >= len(self._calls):
                raise ReplayDivergence(f"replay has no recorded answer for {descriptor.name}")
            entry = self._calls[self._cursor]
            if entry["identity"] != request_identity(descriptor, arguments):
                raise ReplayDivergence(
                    f"replay diverged at call {self._cursor}: expected {entry['tool']}, "
                    f"got {descriptor.name} with different arguments"
                )
            self._cursor += 1
        if entry["outcome"] == "timeout":
            raise ToolTimeout(str(entry.get("message", "recorded timeout")))
        if entry["outcome"] == "error":
            raise ToolAdapterError(
                str(entry.get("message", "recorded error")), transient=bool(entry.get("transient"))
            )
        return dict(entry["payload"])


class ReplayModelProvider:
    """Serves recorded model responses, strictly in order."""

    def __init__(self, fixture: ReplayFixture, *, provider_name: str, model_id: str) -> None:
        _refuse_production()
        self._calls = list(fixture.model_calls)
        self._cursor = 0
        self._lock = threading.Lock()
        self._provider_name = provider_name
        self._model_id = model_id

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def remaining(self) -> int:
        return len(self._calls) - self._cursor

    def estimate(self, request: ModelRequest) -> ModelCallEstimate:
        with self._lock:
            if self._cursor >= len(self._calls):
                return ModelCallEstimate(1, 1, 0.0, replay_safe_without_durable_reservation=True)
            entry = self._calls[self._cursor]
        response = entry.get("response") or {}
        return ModelCallEstimate(
            max_input_tokens=int(response.get("input_tokens", 1)),
            max_output_tokens=int(response.get("output_tokens", 1)),
            max_cost_usd=float(response.get("cost_usd", 0.0)),
            replay_safe_without_durable_reservation=True,
        )

    def complete(self, request: ModelRequest) -> ModelResponse:
        with self._lock:
            if self._cursor >= len(self._calls):
                raise ModelProviderError("replay has no recorded model response", transient=False)
            entry = self._calls[self._cursor]
            if entry["identity"] != model_identity(request):
                raise ModelProviderError(
                    f"replay diverged at model call {self._cursor}", transient=False
                )
            self._cursor += 1
        if entry["outcome"] == "error":
            raise ModelProviderError(
                str(entry.get("message", "")), transient=bool(entry.get("transient"))
            )
        return ModelResponse(**entry["response"])


__all__ = [
    "Recorder",
    "ReplayDivergence",
    "ReplayFixture",
    "ReplayModelProvider",
    "ReplayRefused",
    "ReplayToolProvider",
    "model_identity",
    "request_identity",
]
