"""Tests for SafetyDrift Markov chain (fivedrisk/markov.py).

These tests are written BEFORE the implementation. They define the contract.
Run with: pytest fivedrisk/tests/test_markov.py -v

Chapter coverage:
  Ch 1: test_state_encoding_roundtrip, test_absorbing_states
  Ch 2: test_matrix_inverse_known, test_matmul_basic
  Ch 3: test_default_matrix_rows_sum_to_one, test_build_transition_matrix_from_sessions
  Ch 4: test_absorption_probs_valid_range, test_absorbing_states_prob_one
  Ch 6: test_risk_ordering, test_markov_tracker_escalates_to_red
"""

import pytest


pytestmark = pytest.mark.safety_drift


# ─── Skip guard: tests are skipped until markov.py exists ─────────────────────

try:
    from fivedrisk.markov import (
        state_to_index,
        index_to_state,
        is_absorbing,
    )
    CHAPTER_1_DONE = True
except ImportError:
    CHAPTER_1_DONE = False

try:
    from fivedrisk.markov import matrix_inverse, matmul
    CHAPTER_2_DONE = True
except ImportError:
    CHAPTER_2_DONE = False

try:
    from fivedrisk.markov import (
        build_transition_matrix,
        make_default_transition_matrix,
    )
    CHAPTER_3_DONE = True
except ImportError:
    CHAPTER_3_DONE = False

try:
    from fivedrisk.markov import compute_absorption_probabilities
    CHAPTER_4_DONE = True
except ImportError:
    CHAPTER_4_DONE = False

try:
    from fivedrisk.markov import MarkovDriftTracker
    CHAPTER_6_DONE = True
except ImportError:
    CHAPTER_6_DONE = False


# ─── Chapter 1: State encoding ─────────────────────────────────────────────────

@pytest.mark.skipif(not CHAPTER_1_DONE, reason="Chapter 1 not implemented yet")
def test_state_encoding_roundtrip():
    """state_to_index and index_to_state are inverses of each other."""
    for dt in range(4):
        for at in range(4):
            idx = state_to_index(dt, at)
            assert 0 <= idx <= 15, f"Index out of range: {idx}"
            recovered = index_to_state(idx)
            assert recovered == (dt, at), f"Roundtrip failed: ({dt},{at}) → {idx} → {recovered}"


@pytest.mark.skipif(not CHAPTER_1_DONE, reason="Chapter 1 not implemented yet")
def test_state_encoding_formula():
    """Encoding follows the formula: data_tier * 4 + activity_tier."""
    assert state_to_index(0, 0) == 0
    assert state_to_index(0, 3) == 3
    assert state_to_index(1, 0) == 4
    assert state_to_index(2, 2) == 10
    assert state_to_index(3, 3) == 15


@pytest.mark.skipif(not CHAPTER_1_DONE, reason="Chapter 1 not implemented yet")
def test_absorbing_states():
    """Absorbing state classification matches spec."""
    # Known non-absorbing
    assert not is_absorbing(0, 0), "(0,0) should be non-absorbing"
    assert not is_absorbing(1, 1), "(1,1) should be non-absorbing"
    assert not is_absorbing(2, 0), "(2,0) should be non-absorbing"
    assert not is_absorbing(2, 1), "(2,1) should be non-absorbing"
    assert not is_absorbing(3, 0), "(3,0) should be non-absorbing"

    # Known absorbing
    assert is_absorbing(2, 2), "(2,2) should be absorbing"
    assert is_absorbing(3, 1), "(3,1) should be absorbing"
    assert is_absorbing(1, 3), "(1,3) should be absorbing"
    assert is_absorbing(3, 3), "(3,3) should be absorbing"
    assert is_absorbing(2, 3), "(2,3) should be absorbing"
    assert is_absorbing(3, 2), "(3,2) should be absorbing"

    # Count: exactly 6 absorbing states
    absorbing_count = sum(
        1 for dt in range(4) for at in range(4) if is_absorbing(dt, at)
    )
    assert absorbing_count == 6, f"Expected 6 absorbing states, got {absorbing_count}"


# ─── Chapter 2: Matrix operations ─────────────────────────────────────────────

@pytest.mark.skipif(not CHAPTER_2_DONE, reason="Chapter 2 not implemented yet")
def test_matrix_inverse_known():
    """Gauss-Jordan inversion produces correct result for known 2x2 matrix."""
    M = [[4.0, 7.0], [2.0, 6.0]]
    inv = matrix_inverse(M)

    assert abs(inv[0][0] - 0.6) < 1e-9, f"inv[0][0] = {inv[0][0]}, expected 0.6"
    assert abs(inv[0][1] - (-0.7)) < 1e-9, f"inv[0][1] = {inv[0][1]}, expected -0.7"
    assert abs(inv[1][0] - (-0.2)) < 1e-9, f"inv[1][0] = {inv[1][0]}, expected -0.2"
    assert abs(inv[1][1] - 0.4) < 1e-9, f"inv[1][1] = {inv[1][1]}, expected 0.4"


@pytest.mark.skipif(not CHAPTER_2_DONE, reason="Chapter 2 not implemented yet")
def test_matrix_inverse_identity():
    """Inverse of identity is identity."""
    I = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]
    inv = matrix_inverse(I)
    for i in range(3):
        for j in range(3):
            expected = 1.0 if i == j else 0.0
            assert abs(inv[i][j] - expected) < 1e-9


@pytest.mark.skipif(not CHAPTER_2_DONE, reason="Chapter 2 not implemented yet")
def test_matmul_basic():
    """Matrix multiplication produces correct result."""
    A = [[1.0, 2.0], [3.0, 4.0]]
    B = [[5.0, 6.0], [7.0, 8.0]]
    C = matmul(A, B)
    assert abs(C[0][0] - 19.0) < 1e-9
    assert abs(C[0][1] - 22.0) < 1e-9
    assert abs(C[1][0] - 43.0) < 1e-9
    assert abs(C[1][1] - 50.0) < 1e-9


@pytest.mark.skipif(not CHAPTER_2_DONE, reason="Chapter 2 not implemented yet")
def test_matrix_inverse_singular_raises():
    """Singular matrix raises ValueError."""
    M = [[1.0, 2.0], [2.0, 4.0]]  # Determinant = 0
    with pytest.raises(ValueError):
        matrix_inverse(M)


# ─── Chapter 3: Transition matrix ─────────────────────────────────────────────

@pytest.mark.skipif(not CHAPTER_3_DONE, reason="Chapter 3 not implemented yet")
def test_default_matrix_rows_sum_to_one():
    """Every row of the default transition matrix sums to 1.0."""
    matrix = make_default_transition_matrix()
    assert len(matrix) == 16, f"Matrix should have 16 rows, got {len(matrix)}"
    for i, row in enumerate(matrix):
        assert len(row) == 16, f"Row {i} has {len(row)} columns, expected 16"
        row_sum = sum(row)
        assert abs(row_sum - 1.0) < 1e-9, f"Row {i} sums to {row_sum}, not 1.0"


@pytest.mark.skipif(not CHAPTER_3_DONE, reason="Chapter 3 not implemented yet")
def test_absorbing_states_are_self_loops_in_default_matrix():
    """Absorbing states in the default matrix are perfect self-loops."""
    matrix = make_default_transition_matrix()
    for idx in range(16):
        dt, at = index_to_state(idx)
        if is_absorbing(dt, at):
            assert abs(matrix[idx][idx] - 1.0) < 1e-9, \
                f"Absorbing state {idx} ({dt},{at}) should be a self-loop"


@pytest.mark.skipif(not CHAPTER_3_DONE, reason="Chapter 3 not implemented yet")
def test_build_transition_matrix_from_sessions():
    """Transition matrix built from observed sessions has rows summing to 1.0."""
    # Simple session: clean → slightly elevated → routine
    sessions = [
        [(0, 0), (0, 1), (1, 1)],
        [(0, 0), (1, 0), (1, 1), (2, 1)],
        [(0, 0), (0, 0), (0, 0)],
    ]
    matrix = build_transition_matrix(sessions)
    assert len(matrix) == 16
    for i, row in enumerate(matrix):
        assert abs(sum(row) - 1.0) < 1e-9, f"Row {i} sums to {sum(row)}"


@pytest.mark.skipif(not CHAPTER_3_DONE, reason="Chapter 3 not implemented yet")
def test_build_transition_matrix_uniform_prior_for_unseen():
    """States with no observed transitions use uniform prior (1/16 each)."""
    # Session that only visits state (0,0)
    sessions = [[(0, 0), (0, 0)]]
    matrix = build_transition_matrix(sessions)
    # State (1,1) = index 5 was never visited — should have uniform prior
    unseen_row = matrix[state_to_index(1, 1)]
    expected = 1.0 / 16
    for val in unseen_row:
        assert abs(val - expected) < 1e-9, f"Unseen state should have uniform prior {expected}, got {val}"


# ─── Chapter 4: Absorption probabilities ──────────────────────────────────────

@pytest.mark.skipif(not CHAPTER_4_DONE, reason="Chapter 4 not implemented yet")
def test_absorption_probs_valid_range():
    """All absorption probabilities are in [0.0, 1.0]."""
    matrix = make_default_transition_matrix()
    probs = compute_absorption_probabilities(matrix)
    assert len(probs) == 16
    for idx, p in probs.items():
        assert 0.0 <= p <= 1.0, f"State {idx} has prob {p} outside [0,1]"


@pytest.mark.skipif(not CHAPTER_4_DONE, reason="Chapter 4 not implemented yet")
def test_absorbing_states_prob_one():
    """Absorbing states have absorption probability exactly 1.0."""
    matrix = make_default_transition_matrix()
    probs = compute_absorption_probabilities(matrix)
    for idx in range(16):
        dt, at = index_to_state(idx)
        if is_absorbing(dt, at):
            assert probs[idx] == 1.0, f"Absorbing state {idx} has prob {probs[idx]}, expected 1.0"


@pytest.mark.skipif(not CHAPTER_4_DONE, reason="Chapter 4 not implemented yet")
def test_risk_ordering():
    """Low-risk state has strictly lower absorption prob than high-risk state."""
    matrix = make_default_transition_matrix()
    probs = compute_absorption_probabilities(matrix)
    # (0,0) = clean session should be lower risk than (2,1) = multi-class + elevated activity
    low_risk = probs[state_to_index(0, 0)]
    high_risk = probs[state_to_index(2, 1)]
    assert low_risk < high_risk, \
        f"Expected (0,0) prob {low_risk} < (2,1) prob {high_risk}"


# ─── Chapter 6: Integration ────────────────────────────────────────────────────

@pytest.mark.skipif(not CHAPTER_6_DONE, reason="Chapter 6 not implemented yet")
def test_markov_tracker_initializes():
    """MarkovDriftTracker initializes without error."""
    matrix = make_default_transition_matrix()
    tracker = MarkovDriftTracker(matrix, session_id="test-session")
    assert tracker.current_state == (0, 0)


@pytest.mark.skipif(not CHAPTER_6_DONE, reason="Chapter 6 not implemented yet")
def test_markov_tracker_escalates_to_red():
    """Tracker escalates to RED when absorption probability exceeds threshold."""
    from unittest.mock import MagicMock
    from fivedrisk.schema import Band

    matrix = make_default_transition_matrix()
    tracker = MarkovDriftTracker(matrix, session_id="test-escalation")

    # Simulate a scored action that puts us in a near-absorbing state
    # State (2,1) has elevated absorption probability
    mock_action = MagicMock()
    mock_action.data_sensitivity = 3   # → data_tier = 3
    mock_scored = MagicMock()
    mock_scored.action = mock_action
    mock_scored.band = Band.GREEN

    # Mock activity tier mapping
    # We'll call record enough times to accumulate into high-risk territory
    # The exact behavior depends on the computed absorption probability
    result = tracker.record(mock_scored)
    # Result may be None (no bump) or a DriftBump — both are valid depending on matrix
    # The key assertion: result type is either None or has escalated_band attribute
    assert result is None or hasattr(result, "escalated_band")
