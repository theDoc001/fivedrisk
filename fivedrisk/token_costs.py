"""Token cost table for cost-management admission check.

Provider-published per-call cost ranges for common LLM classes. Costs are
expressed in USD per 1M tokens, taken from public pricing pages as of
early 2026. Numbers update over time; this file is the canonical source
for the per-tool-call reservation worst-case estimate.

Cost formula: cost_usd = (input_tokens × in_rate) + (output_tokens × out_rate)
where rates below are USD per 1M tokens.

For reservation purposes, the @gate enforcement uses a WORST-CASE
projection: max output tokens defaults to the policy's configured cap or
the model's documented maximum, whichever is smaller. This ensures the
budget accumulator never under-reserves.

NOTE: this table is intentionally simple. It tracks tokens, not wall
time, retry count, or delegation depth. Fuller cost-management surfaces
(useful-progress monitoring, multi-agent budget envelopes, post-step
reconciliation) live outside OSS scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ModelCost:
    """Per-token cost ranges for a model class.

    All rates are USD per 1,000,000 tokens.
    """

    model_class: str                       # human-readable identifier
    input_usd_per_million: float           # cost per 1M input tokens
    output_usd_per_million: float          # cost per 1M output tokens
    default_max_output_tokens: int = 4096  # used when no policy cap is set

    def estimate_cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate the dollar cost of a single call."""
        return (
            input_tokens * self.input_usd_per_million / 1_000_000.0
            + output_tokens * self.output_usd_per_million / 1_000_000.0
        )

    def worst_case_tokens(self, input_tokens: int, output_token_cap: Optional[int] = None) -> int:
        """Worst-case token count for reservation accounting.

        Worst case = input tokens + the smaller of (configured cap, model max).
        """
        cap = output_token_cap if output_token_cap is not None else self.default_max_output_tokens
        return input_tokens + min(cap, self.default_max_output_tokens)


# ─── Cost table (USD per 1M tokens) ────────────────────────────
# Source: public pricing pages, early 2026. Update as providers change rates.

MODEL_COSTS: dict[str, ModelCost] = {
    # OpenAI GPT-4-class
    "gpt-4-class": ModelCost(
        model_class="OpenAI GPT-4-class",
        input_usd_per_million=10.0,
        output_usd_per_million=30.0,
        default_max_output_tokens=4096,
    ),
    # Anthropic Claude Sonnet-class
    "claude-sonnet-class": ModelCost(
        model_class="Anthropic Claude Sonnet-class",
        input_usd_per_million=3.0,
        output_usd_per_million=15.0,
        default_max_output_tokens=8192,
    ),
    # Anthropic Claude Opus-class
    "claude-opus-class": ModelCost(
        model_class="Anthropic Claude Opus-class",
        input_usd_per_million=15.0,
        output_usd_per_million=75.0,
        default_max_output_tokens=8192,
    ),
    # Google Gemini Pro-class
    "gemini-pro-class": ModelCost(
        model_class="Google Gemini Pro-class",
        input_usd_per_million=1.25,
        output_usd_per_million=5.0,
        default_max_output_tokens=8192,
    ),
    # Mistral Large-class
    "mistral-large-class": ModelCost(
        model_class="Mistral Large-class",
        input_usd_per_million=2.0,
        output_usd_per_million=6.0,
        default_max_output_tokens=4096,
    ),
}


def get_model_cost(model_class: str) -> Optional[ModelCost]:
    """Look up cost for a model class. Returns None if unknown."""
    return MODEL_COSTS.get(model_class)


def worst_case_tokens_for_call(
    model_class: str,
    input_tokens: int,
    output_token_cap: Optional[int] = None,
) -> int:
    """Compute worst-case token count for reservation.

    Returns input_tokens if the model class is unknown (conservative: do
    not under-reserve, but also do not block on unknown models).
    """
    cost = get_model_cost(model_class)
    if cost is None:
        return input_tokens + (output_token_cap or 4096)
    return cost.worst_case_tokens(input_tokens, output_token_cap)
