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

    def estimate_cost_eur(
        self,
        input_tokens: int,
        output_tokens: int,
        eur_per_usd: float = None,  # type: ignore[assignment]
    ) -> float:
        """Estimate the euro cost of a single call.

        Currency conversion only — this is a display/reporting convenience for
        non-USD deployments, not a cost model change. ``eur_per_usd`` is the
        deployer's USD->EUR rate (config-as-data); defaults to
        ``DEFAULT_EUR_PER_USD`` when unset. No risk weighting is applied.
        """
        rate = DEFAULT_EUR_PER_USD if eur_per_usd is None else eur_per_usd
        return self.estimate_cost_usd(input_tokens, output_tokens) * rate

    def worst_case_tokens(self, input_tokens: int, output_token_cap: Optional[int] = None) -> int:
        """Worst-case token count for reservation accounting.

        Worst case = input tokens + the smaller of (configured cap, model max).
        """
        cap = output_token_cap if output_token_cap is not None else self.default_max_output_tokens
        return input_tokens + min(cap, self.default_max_output_tokens)


# ─── Currency conversion (reporting only) ──────────────────────
# Example USD->EUR rate for non-USD deployments. This is a display convenience
# (config-as-data — override per deployment); it does NOT alter the cost model
# or apply any risk weighting. USD remains the canonical unit above.
DEFAULT_EUR_PER_USD: float = 0.92


# ─── Concrete model id -> model class ──────────────────────────
# Provider model ids (e.g. "claude-sonnet-4-6") map to the generic cost class
# used in the table below. Deployers pass a concrete model id; this resolves it
# to the class whose published rates apply. Prefix-matched so dated point
# releases (…-4-6, …-4-7) resolve without a table edit.
MODEL_TO_CLASS: dict[str, str] = {
    "claude-sonnet": "claude-sonnet-class",
    "claude-3-5-sonnet": "claude-sonnet-class",
    "claude-opus": "claude-opus-class",
    "claude-3-opus": "claude-opus-class",
    "gpt-4": "gpt-4-class",
    "gpt-4o": "gpt-4-class",
    "gemini-1.5-pro": "gemini-pro-class",
    "gemini-pro": "gemini-pro-class",
    "mistral-large": "mistral-large-class",
}


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


def resolve_model_class(model_id: str) -> Optional[str]:
    """Resolve a concrete provider model id to its cost class.

    Exact match on a table key wins; otherwise the longest matching prefix in
    MODEL_TO_CLASS is used so dated point releases (…-4-6) resolve to their
    class without a per-release table edit. Returns None if unresolvable.
    """
    if not model_id:
        return None
    if model_id in MODEL_COSTS:
        return model_id
    if model_id in MODEL_TO_CLASS:
        return MODEL_TO_CLASS[model_id]
    matches = [p for p in MODEL_TO_CLASS if model_id.startswith(p)]
    if matches:
        return MODEL_TO_CLASS[max(matches, key=len)]
    return None


def get_model_cost(model_class: str) -> Optional[ModelCost]:
    """Look up cost for a model class. Returns None if unknown."""
    return MODEL_COSTS.get(model_class)


def get_model_cost_for_model(model_id: str) -> Optional[ModelCost]:
    """Look up cost for a concrete provider model id (resolves class first)."""
    cls = resolve_model_class(model_id)
    return MODEL_COSTS.get(cls) if cls else None


def worst_case_tokens_for_call(
    model_class: str,
    input_tokens: int,
    output_token_cap: Optional[int] = None,
) -> int:
    """Compute worst-case token count for reservation.

    For an unknown model class, returns input_tokens + (output_token_cap or
    4096) — a conservative default that does not under-reserve (Low-8: the code
    adds a default output cap; the old docstring wrongly said input_tokens only).
    """
    cost = get_model_cost(model_class)
    if cost is None:
        return input_tokens + (output_token_cap or 4096)
    return cost.worst_case_tokens(input_tokens, output_token_cap)
