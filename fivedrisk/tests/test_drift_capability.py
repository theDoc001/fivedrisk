"""Expanded drift and Markov capability coverage."""

from __future__ import annotations

import pytest

from fivedrisk.drift import SessionAccumulator
from fivedrisk.markov import (
    MarkovDriftTracker,
    activity_tier_from_action,
    build_transition_matrix,
    compute_absorption_probabilities,
    data_tier_from_action,
    index_to_state,
    make_default_transition_matrix,
    matmul,
    matrix_inverse,
    state_to_index,
)
from fivedrisk.schema import Action, Band, ScoredAction


pytestmark = pytest.mark.safety_drift


def _scored(
    data_sensitivity: int = 0,
    band: Band = Band.GREEN,
    tool_privilege: int = 0,
    reversibility: int = 0,
    external_impact: int = 0,
) -> ScoredAction:
    action = Action(
        tool_name="TestTool",
        tool_input={},
        data_sensitivity=data_sensitivity,
        tool_privilege=tool_privilege,
        reversibility=reversibility,
        external_impact=external_impact,
    )
    return ScoredAction(
        action=action,
        band=band,
        composite_score=0.5,
        max_dimension=max(data_sensitivity, tool_privilege, reversibility, external_impact),
        rationale="test",
        policy_version="0.3.0",
    )


def _high_risk_matrix() -> list[list[float]]:
    matrix = make_default_transition_matrix()
    matrix[0] = [0.0 for _ in range(16)]
    matrix[0][0] = 0.05
    matrix[0][10] = 0.95
    assert abs(sum(matrix[0]) - 1.0) < 1e-9
    return matrix


class TestDriftCapability:
    def test_state_to_index_rejects_negative_data(self):
        try:
            state_to_index(-1, 0)
        except AssertionError:
            pass
        else:
            raise AssertionError("Expected negative data tier to fail")

    def test_state_to_index_rejects_large_activity(self):
        try:
            state_to_index(0, 4)
        except AssertionError:
            pass
        else:
            raise AssertionError("Expected activity tier above range to fail")

    def test_index_to_state_rejects_large_index(self):
        try:
            index_to_state(16)
        except AssertionError:
            pass
        else:
            raise AssertionError("Expected out-of-range index to fail")

    def test_matrix_inverse_supports_one_by_one(self):
        assert matrix_inverse([[2.0]]) == [[0.5]]

    def test_matmul_rejects_mismatched_dimensions(self):
        try:
            matmul([[1.0, 2.0]], [[1.0, 2.0]])
        except ValueError:
            pass
        else:
            raise AssertionError("Expected mismatched dimensions to fail")

    def test_build_transition_matrix_reflects_observed_frequency(self):
        matrix = build_transition_matrix([[(0, 0), (0, 1)], [(0, 0), (0, 1)], [(0, 0), (1, 0)]])
        row = matrix[state_to_index(0, 0)]
        assert abs(row[state_to_index(0, 1)] - (2.0 / 3.0)) < 1e-9
        assert abs(row[state_to_index(1, 0)] - (1.0 / 3.0)) < 1e-9

    def test_build_transition_matrix_rejects_invalid_state(self):
        try:
            build_transition_matrix([[(9, 0)]])
        except AssertionError:
            pass
        else:
            raise AssertionError("Expected invalid state to fail")

    def test_default_matrix_has_non_negative_probabilities(self):
        matrix = make_default_transition_matrix()
        assert all(value >= 0.0 for row in matrix for value in row)

    def test_absorption_probabilities_include_every_state(self):
        probs = compute_absorption_probabilities(make_default_transition_matrix())
        assert set(probs) == set(range(16))

    def test_absorption_probability_for_clean_state_is_below_one(self):
        probs = compute_absorption_probabilities(make_default_transition_matrix())
        assert probs[state_to_index(0, 0)] < 1.0

    def test_data_tier_mapping_for_high_sensitivity_caps_at_three(self):
        assert data_tier_from_action(_scored(data_sensitivity=4)) == 3

    def test_data_tier_mapping_for_mid_sensitivity(self):
        assert data_tier_from_action(_scored(data_sensitivity=2)) == 2

    def test_activity_tier_mapping_green(self):
        assert activity_tier_from_action(_scored(band=Band.GREEN)) == 0

    def test_activity_tier_mapping_yellow(self):
        assert activity_tier_from_action(_scored(band=Band.YELLOW)) == 1

    def test_activity_tier_mapping_orange(self):
        assert activity_tier_from_action(_scored(band=Band.ORANGE)) == 2

    def test_activity_tier_mapping_red(self):
        assert activity_tier_from_action(_scored(band=Band.RED)) == 3

    def test_markov_tracker_state_is_monotonic(self):
        tracker = MarkovDriftTracker(make_default_transition_matrix(), "session-a")
        tracker.record(_scored(data_sensitivity=1, band=Band.YELLOW))
        tracker.record(_scored(data_sensitivity=0, band=Band.GREEN))
        assert tracker.current_state == (1, 1)

    def test_markov_tracker_reset_clears_state(self):
        tracker = MarkovDriftTracker(make_default_transition_matrix(), "session-a")
        tracker.record(_scored(data_sensitivity=2, band=Band.ORANGE))
        tracker.reset()
        assert tracker.current_state == (0, 0)

    def test_markov_tracker_can_force_red_with_custom_matrix(self):
        tracker = MarkovDriftTracker(_high_risk_matrix(), "session-a")
        bump = tracker.record(_scored(data_sensitivity=0, band=Band.GREEN))
        assert bump is not None
        assert bump.escalated_band == Band.RED

    def test_markov_tracker_falls_back_to_counter_drift(self):
        tracker = MarkovDriftTracker(make_default_transition_matrix(), "session-a")
        tracker.record(_scored(data_sensitivity=0))
        tracker.record(_scored(data_sensitivity=1))
        bump = tracker.record(_scored(data_sensitivity=2))
        assert bump is not None
        assert "data_exposure" in bump.reason

    def test_session_accumulator_snapshot_tracks_counts(self):
        acc = SessionAccumulator(session_id="session-a")
        acc.record(_scored(data_sensitivity=1, external_impact=2))
        snap = acc.snapshot()
        assert snap["action_count"] == 1
        assert snap["external_endpoint_count"] == 1
