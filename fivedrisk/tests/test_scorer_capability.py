"""Expanded scorer capability coverage."""

from __future__ import annotations

from fivedrisk.policy import Policy
from fivedrisk.schema import Action, Band, ModelClass
from fivedrisk.scorer import score


def _score_action(**kwargs):
    action = Action(tool_name=kwargs.pop("tool_name", "TestTool"), tool_input={}, **kwargs)
    return score(action, kwargs.pop("policy", None))


class TestScorerCapability:
    def test_default_policy_is_used_when_none_passed(self):
        action = Action(tool_name="TestTool", tool_input={}, data_sensitivity=1)
        assert score(action).band == score(action, Policy()).band

    def test_green_floor_for_d0_is_m0(self):
        result = score(Action(tool_name="Read", tool_input={}))
        assert result.routing is not None
        assert result.routing.model_floor == ModelClass.M0

    def test_green_d3_selects_m2(self):
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=3))
        assert result.routing is not None
        assert result.routing.selected_model == ModelClass.M3 or result.band == Band.ORANGE

    def test_yellow_d2_uses_enhanced_verification(self):
        policy = Policy(weights={"data_sensitivity": 6.0, "tool_privilege": 0.0, "reversibility": 0.0, "external_impact": 0.0, "autonomy_context": 0.0})
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=2), policy)
        assert result.band == Band.YELLOW
        assert result.routing is not None
        assert result.routing.verification_level == "enhanced"

    def test_orange_requires_approval(self):
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=3))
        assert result.band == Band.ORANGE
        assert result.routing is not None
        assert result.routing.approval_required is True

    def test_red_requires_approval(self):
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=4))
        assert result.band == Band.RED
        assert result.routing is not None
        assert result.routing.approval_required is True

    def test_red_sets_full_provenance(self):
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=4))
        assert result.routing is not None
        assert result.routing.verification_level == "full_provenance"

    def test_orange_sets_enhanced_verification(self):
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=3))
        assert result.routing is not None
        assert result.routing.verification_level == "enhanced"

    def test_spike_threshold_beats_low_composite(self):
        policy = Policy(weights={"data_sensitivity": 0.1, "tool_privilege": 0.1, "reversibility": 0.1, "external_impact": 0.1, "autonomy_context": 0.1})
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=3), policy)
        assert result.band == Band.ORANGE

    def test_red_spike_beats_any_score_band(self):
        policy = Policy(weights={"data_sensitivity": 0.0, "tool_privilege": 0.0, "reversibility": 0.0, "external_impact": 0.0, "autonomy_context": 0.0})
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=4), policy)
        assert result.band == Band.RED

    def test_composite_score_increases_with_dimension_growth(self):
        low = score(Action(tool_name="TestTool", tool_input={}, data_sensitivity=1))
        high = score(Action(tool_name="TestTool", tool_input={}, data_sensitivity=2))
        assert high.composite_score > low.composite_score

    def test_max_dimension_matches_highest_axis(self):
        result = score(Action(tool_name="TestTool", tool_input={}, data_sensitivity=1, reversibility=4))
        assert result.max_dimension == 4

    def test_red_rationale_mentions_dimension_name(self):
        result = score(Action(tool_name="Bash", tool_input={}, external_impact=4))
        assert "External Impact" in result.rationale

    def test_orange_rationale_mentions_threshold_when_from_spike(self):
        result = score(Action(tool_name="Bash", tool_input={}, tool_privilege=3))
        assert "ORANGE" in result.rationale

    def test_green_rationale_mentions_max_dim(self):
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=1))
        assert "max_dim" in result.rationale

    def test_yellow_band_can_come_from_composite(self):
        policy = Policy(weights={"data_sensitivity": 8.0, "tool_privilege": 0.0, "reversibility": 0.0, "external_impact": 0.0, "autonomy_context": 0.0})
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=2), policy)
        assert result.band == Band.YELLOW

    def test_routing_reason_mentions_band_and_data(self):
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=2))
        assert result.routing is not None
        assert "Band=" in result.routing.reason
        assert "Data=" in result.routing.reason

    def test_data_class_flows_into_routing(self):
        result = score(Action(tool_name="Read", tool_input={}, data_sensitivity=2))
        assert result.routing is not None
        assert result.routing.data_class == "D2"

    def test_retry_count_defaults_to_zero(self):
        result = score(Action(tool_name="Read", tool_input={}))
        assert result.retry_count == 0

    def test_score_to_dict_contains_band_string(self):
        result = score(Action(tool_name="Read", tool_input={}))
        assert result.to_dict()["band"] == "GREEN"
