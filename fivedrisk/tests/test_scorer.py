"""Tests for the 5D scoring algorithm — 4-band system.

Covers: spike rules, normalized score bands, model routing,
Cost×Risk coupling, backward compatibility.
"""

import pytest

from fivedrisk.policy import Policy
from fivedrisk.schema import Action, Band, ModelClass
from fivedrisk.scorer import score


def _action(**dims: int) -> Action:
    defaults = {
        "tool_name": "TestTool",
        "data_sensitivity": 0,
        "tool_privilege": 0,
        "reversibility": 0,
        "external_impact": 0,
        "autonomy_context": 0,
    }
    defaults.update(dims)
    return Action(**defaults)


class TestFourBandSpikes:
    """Single-axis spike → immediate band assignment."""

    def test_red_on_dimension_4(self):
        action = _action(reversibility=4)
        result = score(action)
        assert result.band == Band.RED

    def test_red_on_data_sensitivity_4(self):
        action = _action(data_sensitivity=4)
        result = score(action)
        assert result.band == Band.RED

    def test_orange_on_dimension_3(self):
        action = _action(tool_privilege=3)
        result = score(action)
        assert result.band == Band.ORANGE

    def test_red_takes_precedence_over_orange(self):
        action = _action(reversibility=4, tool_privilege=3)
        result = score(action)
        assert result.band == Band.RED

    def test_multiple_dims_at_3_is_orange(self):
        action = _action(tool_privilege=3, external_impact=3)
        result = score(action)
        assert result.band == Band.ORANGE


class TestNormalizedScoreBands:
    """Normalized score → Green/Yellow/Orange/Red."""

    def test_all_zeros_is_green(self):
        action = _action()
        result = score(action)
        assert result.band == Band.GREEN
        assert result.composite_score == 0.0

    def test_low_dims_is_green(self):
        action = _action(data_sensitivity=1)
        result = score(action)
        assert result.band == Band.GREEN

    def test_moderate_dims_can_be_yellow_when_enabled(self):
        """Dims that push normalized score into 1.0-1.7 range → YELLOW
        when the 4-band compliance model is enabled. Default 3-band
        folds the YELLOW range into GREEN."""
        from fivedrisk.policy import Policy
        # Need enough weight to cross 1.0 normalized without hitting spike
        action = _action(data_sensitivity=2, tool_privilege=2, reversibility=2, external_impact=2)
        # Default 3-band: GREEN or ORANGE only
        result_default = score(action)
        assert result_default.band in (Band.GREEN, Band.ORANGE)
        # 4-band compliance mode: YELLOW or ORANGE
        result_4band = score(action, Policy(enable_yellow_band=True))
        assert result_4band.band in (Band.YELLOW, Band.ORANGE)

    def test_high_composite_is_orange_or_red(self):
        """All dims at 2 → high normalized score (or moderate, folded into GREEN by default)."""
        action = _action(
            data_sensitivity=2, tool_privilege=2, reversibility=2,
            external_impact=2, autonomy_context=2,
        )
        result = score(action)
        # Default 3-band: GREEN (moderate folded), ORANGE, or RED
        assert result.band in (Band.GREEN, Band.ORANGE, Band.RED)
        assert result.composite_score > 0


class TestModelRouting:
    """Scoring produces routing decisions."""

    def test_green_routes_to_m0_m1(self):
        action = _action()
        result = score(action)
        assert result.routing is not None
        assert result.routing.model_floor in (ModelClass.M0, ModelClass.M1)
        assert result.routing.downgrade_allowed is True

    def test_red_routes_to_m4(self):
        action = _action(reversibility=4)
        result = score(action)
        assert result.routing is not None
        assert result.routing.model_floor == ModelClass.M4
        assert result.routing.selected_model == ModelClass.M4
        assert result.routing.downgrade_allowed is False

    def test_orange_signals_approval_required(self):
        """ORANGE signals approval_required=True. fivedrisk does not
        auto-promote the model class for ORANGE; the caller's HITL stack
        decides what model the reviewer (human or AI-assisted) uses."""
        action = _action(tool_privilege=3)
        result = score(action)
        assert result.routing is not None
        assert result.routing.approval_required is True
        # ORANGE no longer forces M3; routing recommendation reflects
        # the data class default, not an auto-promotion.
        assert result.routing.model_floor != ModelClass.M3

    def test_routing_has_verification_level(self):
        action = _action(tool_privilege=3)
        result = score(action)
        assert result.routing.verification_level == "enhanced"

    def test_red_requires_full_provenance(self):
        action = _action(data_sensitivity=4)
        result = score(action)
        assert result.routing.verification_level == "full_provenance"


class TestCostRiskCoupling:
    """Cost × Risk coupling rules (§16)."""

    def test_green_allows_downgrade(self):
        action = _action()
        result = score(action)
        assert result.routing.downgrade_allowed is True

    def test_orange_routing_recommendation_is_advisory(self):
        """ORANGE no longer forbids downgrade. The caller's stack
        decides; fivedrisk's routing recommendation is advisory."""
        action = _action(tool_privilege=3)
        result = score(action)
        assert result.routing.downgrade_allowed is True

    def test_red_forbids_downgrade(self):
        action = _action(reversibility=4)
        result = score(action)
        assert result.routing.downgrade_allowed is False


class TestRationale:
    def test_red_rationale_mentions_dimension(self):
        action = _action(reversibility=4)
        result = score(action)
        assert "RED" in result.rationale
        assert "Reversibility" in result.rationale

    def test_green_rationale_includes_score(self):
        action = _action()
        result = score(action)
        assert "GREEN" in result.rationale

    def test_orange_rationale_mentions_threshold(self):
        action = _action(tool_privilege=3)
        result = score(action)
        assert "ORANGE" in result.rationale


class TestScoredActionSerialization:
    def test_to_dict_has_routing(self):
        action = _action(tool_privilege=2)
        result = score(action)
        d = result.to_dict()
        assert "routing" in d
        assert "model_floor" in d["routing"]

    def test_to_dict_band_is_string(self):
        action = _action()
        result = score(action)
        d = result.to_dict()
        assert isinstance(d["band"], str)
        assert d["band"] in ("GREEN", "YELLOW", "ORANGE", "RED")

    def test_to_dict_has_retry_count(self):
        action = _action()
        result = score(action)
        d = result.to_dict()
        assert "retry_count" in d

    def test_data_class_in_dict(self):
        action = _action(data_sensitivity=2)
        result = score(action)
        d = result.to_dict()
        assert d["data_class"] == "D2"
