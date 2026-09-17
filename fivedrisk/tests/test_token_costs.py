"""Tests for token_costs model->class resolution and EUR reporting.

FinOps hygiene/i18n only: currency conversion + concrete-model-id resolution.
No risk weighting, no cost model change.
"""

from __future__ import annotations

from fivedrisk.token_costs import (
    DEFAULT_EUR_PER_USD,
    get_model_cost,
    get_model_cost_for_model,
    resolve_model_class,
)


class TestModelClassResolution:
    def test_dated_point_release_resolves_to_class(self) -> None:
        assert resolve_model_class("claude-sonnet-4-6") == "claude-sonnet-class"

    def test_opus_point_release_resolves(self) -> None:
        assert resolve_model_class("claude-opus-4-1") == "claude-opus-class"

    def test_exact_class_key_passthrough(self) -> None:
        assert resolve_model_class("claude-sonnet-class") == "claude-sonnet-class"

    def test_unknown_model_returns_none(self) -> None:
        assert resolve_model_class("llama-99b-local") is None

    def test_empty_returns_none(self) -> None:
        assert resolve_model_class("") is None

    def test_get_cost_for_concrete_model(self) -> None:
        mc = get_model_cost_for_model("claude-sonnet-4-6")
        assert mc is not None
        assert mc is get_model_cost("claude-sonnet-class")


class TestEurReporting:
    def test_eur_is_usd_times_rate(self) -> None:
        mc = get_model_cost("claude-sonnet-class")
        usd = mc.estimate_cost_usd(1000, 500)
        eur = mc.estimate_cost_eur(1000, 500, eur_per_usd=0.9)
        assert abs(eur - usd * 0.9) < 1e-12

    def test_eur_default_rate(self) -> None:
        mc = get_model_cost("claude-sonnet-class")
        usd = mc.estimate_cost_usd(1000, 500)
        eur = mc.estimate_cost_eur(1000, 500)
        assert abs(eur - usd * DEFAULT_EUR_PER_USD) < 1e-12

    def test_usd_unchanged_by_currency_helper(self) -> None:
        # The canonical USD estimate is untouched — currency is display only.
        mc = get_model_cost("claude-opus-class")
        assert mc.estimate_cost_usd(1_000_000, 0) == 15.0
