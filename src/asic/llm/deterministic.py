"""A deterministic model provider driven by a scenario script.

Explicit test and development infrastructure, in the same sense as the tool simulators
(master specification section 20). It replays the ``planner_script`` and
``hypothesis_script`` of a :class:`~asic.simulators.scenarios.Scenario`, in order, one
response per call.

What this is *not*: a component that decides anything. It has no model in it and no logic
that inspects the incident. If a run reaches a good conclusion, it is because the scenario
scripted a model that reached one and the deterministic code around it accepted the
conclusion as evidence-supported - and the scenarios include scripts whose conclusions are
rejected, contradicted, unparseable, or absent.

The token counts and costs it reports are derived from the actual prompt and response
lengths using a stated approximation. They are *not* measurements of any real provider, and
the rate constants below say so where they are defined.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from asic.domain.enums import NodeId
from asic.domain.errors import ModelProviderError
from asic.llm.port import ModelRequest, ModelResponse
from asic.simulators.scenarios import Scenario

#: Rough characters-per-token ratio used to derive plausible counts from text length. An
#: approximation for exercising budget accounting, not a measurement of any tokenizer.
_CHARS_PER_TOKEN: Final[int] = 4

#: Nominal price per thousand tokens. A placeholder for exercising the cost budget; it is
#: not a quoted rate for any provider and no cost figure derived from it is a measurement.
_NOMINAL_USD_PER_1K_INPUT: Final[float] = 0.003
_NOMINAL_USD_PER_1K_OUTPUT: Final[float] = 0.015

PROVIDER_NAME: Final[str] = "deterministic-simulator"
MODEL_ID: Final[str] = "scripted-1"


class DeterministicModelProvider:
    """Replays a scenario's scripted responses."""

    __slots__ = ("_calls", "_cursors", "_fail_after", "_scripts")

    def __init__(self, scenario: Scenario, *, fail_after: int | None = None) -> None:
        """
        Args:
            scenario: supplies the per-node scripts.
            fail_after: raise a transient provider error once this many calls have been
                served. Used by the outage tests; ``None`` never fails.
        """
        self._scripts: dict[NodeId, tuple[str, ...]] = {
            NodeId.G3_INVESTIGATION_PLANNER: scenario.planner_script,
            NodeId.G5_HYPOTHESIS_ENGINE: scenario.hypothesis_script,
        }
        self._cursors: dict[NodeId, int] = dict.fromkeys(self._scripts, 0)
        self._fail_after = fail_after
        self._calls = 0

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    @property
    def model_id(self) -> str:
        return MODEL_ID

    @property
    def call_count(self) -> int:
        return self._calls

    def remaining(self, node_id: NodeId) -> int:
        script = self._scripts.get(node_id, ())
        return max(0, len(script) - self._cursors.get(node_id, 0))

    def complete(self, request: ModelRequest) -> ModelResponse:
        self._calls += 1
        if self._fail_after is not None and self._calls > self._fail_after:
            raise ModelProviderError(
                f"{PROVIDER_NAME}: simulated provider outage after {self._fail_after} calls",
                transient=True,
            )

        script = self._scripts.get(request.node_id)
        if script is None:
            raise ModelProviderError(
                f"no script for {request.node_id.value}; a node calling a model with no "
                "scripted response would otherwise get silence and invent a meaning for it",
                transient=False,
            )

        cursor = self._cursors[request.node_id]
        if cursor >= len(script):
            # Exhausting the script is not silently absorbed. A run that asks for more
            # reasoning steps than the scenario describes has left the scenario, and the
            # honest answer is an error rather than a repeated last response.
            raise ModelProviderError(
                f"{request.node_id.value} requested completion {cursor + 1} but the "
                f"scenario scripts only {len(script)}; the run has outgrown its fixture",
                transient=False,
            )

        text = script[cursor]
        self._cursors[request.node_id] = cursor + 1
        return _respond(request.prompt_text, text)

    def script_for(self, node_id: NodeId) -> Sequence[str]:
        return self._scripts.get(node_id, ())


def _respond(prompt_text: str, output_text: str) -> ModelResponse:
    input_tokens = max(1, len(prompt_text) // _CHARS_PER_TOKEN)
    output_tokens = max(1, len(output_text) // _CHARS_PER_TOKEN)
    cost = (
        input_tokens / 1000 * _NOMINAL_USD_PER_1K_INPUT
        + output_tokens / 1000 * _NOMINAL_USD_PER_1K_OUTPUT
    )
    return ModelResponse(
        text=output_text,
        provider=PROVIDER_NAME,
        model_id=MODEL_ID,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=round(cost, 6),
        finish_reason="stop",
    )


__all__ = ["MODEL_ID", "PROVIDER_NAME", "DeterministicModelProvider"]
