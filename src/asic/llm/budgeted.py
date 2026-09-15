"""Hard-ceiling model invocation shared by every reasoning node."""

from __future__ import annotations

from asic.domain.budget import BudgetState
from asic.domain.errors import ModelProviderError
from asic.llm.port import ModelProvider, ModelRequest, ModelResponse


def complete_with_budget(
    provider: ModelProvider, request: ModelRequest, budget: BudgetState
) -> tuple[ModelResponse, BudgetState]:
    """Refuse before invocation unless the provider's entire bounded call fits.

    The returned budget is reconciled to actual usage, never to the reservation. A
    provider exceeding its declared bound is a provider-contract failure and cannot be
    treated as a valid completion.
    """
    estimate = provider.estimate(request)
    budget.require_headroom(
        tokens=estimate.max_total_tokens,
        cost_usd=estimate.max_cost_usd,
    )
    if not estimate.replay_safe_without_durable_reservation:
        raise ModelProviderError(
            "model provider requires durable cross-process token/cost reservations",
            transient=False,
        )
    response = provider.complete(request)
    if (
        response.input_tokens > estimate.max_input_tokens
        or response.output_tokens > estimate.max_output_tokens
        or response.cost_usd > estimate.max_cost_usd
    ):
        raise ModelProviderError(
            "model provider exceeded its pre-call token/cost reservation",
            transient=False,
        )
    return response, budget.charge(tokens=response.total_tokens, cost_usd=response.cost_usd)


__all__ = ["complete_with_budget"]
