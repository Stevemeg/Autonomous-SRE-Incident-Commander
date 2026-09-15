"""The model provider port.

ADR-0005 chose a thin internal interface over LiteLLM. This is that interface, and it is
deliberately narrow: one method, taking a rendered prompt and returning text plus the
metadata a trace needs. Everything richer - tool calling, streaming, structured output
modes - is a provider capability we would then have to emulate for every provider, and
none of it is needed by nodes that ask for one JSON object.

**A provider returns text, not objects.** That is not a simplification; it is the point.
Model output is untrusted until it has been parsed and validated by the calling node, and a
port that returned a typed object would have done that parsing somewhere invisible. Making
the node parse the text is what makes malformed output a case the tests can reach, and one
scenario deliberately reaches it.

**No provider SDK is wired in this phase.** The only implementation is
:class:`~asic.llm.deterministic.DeterministicModelProvider`, which replays scripted
responses from a scenario. Reasoning quality is a Phase 7 concern and cannot be evaluated
before the Phase 11 harness exists; adding a live provider now would make every test
non-deterministic and every run cost money, in exchange for nothing this phase can measure.
The seam is what this phase owes, and the seam is here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from asic.domain.enums import NodeId


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """One call to a model.

    ``prompt_text`` is already rendered, with untrusted content fenced by
    :func:`asic.domain.untrusted.render_untrusted`. ``prompt_hash`` identifies the
    *template*, so it is safe to record and is what a trace carries in place of content.
    """

    node_id: NodeId
    prompt_id: str
    prompt_version: str
    prompt_hash: str
    prompt_text: str
    #: Zero by default. Determinism matters more than variety for an investigation, and a
    #: sampled root cause is not a better root cause.
    temperature: float = 0.0
    max_output_tokens: int = 2048
    #: Correlates the call with the run that made it. Never contains incident content.
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """What a provider returned, plus what a trace and a budget need to know."""

    text: str
    provider: str
    model_id: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    finish_reason: str

    def __post_init__(self) -> None:
        if min(self.input_tokens, self.output_tokens) < 0 or self.cost_usd < 0:
            raise ValueError("token counts and cost cannot be negative")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class ModelCallEstimate:
    """A provider-enforced upper bound used before a hard-budget call.

    Providers that cannot bound a request must refuse it rather than return an optimistic
    estimate.  Actual usage is checked against these bounds after completion.
    """

    max_input_tokens: int
    max_output_tokens: int
    max_cost_usd: float
    #: True only when an interrupted call can be replayed without consuming an external
    #: token/cost allowance. The deterministic scripted provider has this property. A live
    #: provider must remain false until durable cross-process reservations are implemented.
    replay_safe_without_durable_reservation: bool = False

    def __post_init__(self) -> None:
        if min(self.max_input_tokens, self.max_output_tokens) < 0 or self.max_cost_usd < 0:
            raise ValueError("model call estimates must be non-negative")

    @property
    def max_total_tokens(self) -> int:
        return self.max_input_tokens + self.max_output_tokens


@runtime_checkable
class ModelProvider(Protocol):
    """A source of model completions."""

    @property
    def provider_name(self) -> str:
        """Stable identifier recorded on every span and behaviour version."""

    @property
    def model_id(self) -> str:
        """The specific model. A different model is a different behaviour version."""

    def complete(self, request: ModelRequest) -> ModelResponse:
        """Produce one completion.

        Raises:
            ModelProviderError: transient or permanent. A transient failure is retried and,
                in a later phase, fails over to a secondary provider; a sustained outage
                pauses the incident rather than failing it, because the evidence already
                gathered is expensive and worth keeping.
        """

    def estimate(self, request: ModelRequest) -> ModelCallEstimate:
        """Return a hard upper bound without consuming or advancing the request."""


__all__ = ["ModelCallEstimate", "ModelProvider", "ModelRequest", "ModelResponse"]
