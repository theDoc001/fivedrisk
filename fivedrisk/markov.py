"""SafetyDrift Markov chain utilities and tracker.

This module adds a compact 16-state absorbing Markov model for estimating
whether a session is drifting toward dangerous compositional behavior.
"""

from __future__ import annotations

from typing import Any, Optional

from .drift import DriftBump, SessionAccumulator
from .schema import Band


STATE_COUNT = 16
TIER_COUNT = 4
PIVOT_EPSILON = 1e-12
ROW_SUM_TOLERANCE = 1e-9


def state_to_index(data_tier: int, activity_tier: int) -> int:
    """Encode a state tuple into its canonical 0-15 index."""
    assert 0 <= data_tier < TIER_COUNT, f"data_tier out of range: {data_tier}"
    assert 0 <= activity_tier < TIER_COUNT, (
        f"activity_tier out of range: {activity_tier}"
    )
    return data_tier * TIER_COUNT + activity_tier


def index_to_state(idx: int) -> tuple[int, int]:
    """Decode a canonical 0-15 state index into `(data_tier, activity_tier)`."""
    assert 0 <= idx < STATE_COUNT, f"state index out of range: {idx}"
    return divmod(idx, TIER_COUNT)


def is_absorbing(data_tier: int, activity_tier: int) -> bool:
    """Return whether the state is considered dangerous/absorbing."""
    assert 0 <= data_tier < TIER_COUNT, f"data_tier out of range: {data_tier}"
    assert 0 <= activity_tier < TIER_COUNT, (
        f"activity_tier out of range: {activity_tier}"
    )
    return (
        (data_tier >= 2 and activity_tier >= 2)
        or (data_tier >= 1 and activity_tier >= 3)
        or (data_tier >= 3 and activity_tier >= 1)
    )


def matrix_inverse(matrix: list[list[float]]) -> list[list[float]]:
    """Invert a square matrix using Gauss-Jordan elimination."""
    size = len(matrix)
    if size == 0:
        raise ValueError("matrix must be non-empty")
    if any(len(row) != size for row in matrix):
        raise ValueError("matrix must be square")

    augmented: list[list[float]] = []
    for row_index, row in enumerate(matrix):
        identity_row = [0.0] * size
        identity_row[row_index] = 1.0
        augmented.append([float(value) for value in row] + identity_row)

    for col in range(size):
        pivot_row = None
        for row in range(col, size):
            if abs(augmented[row][col]) > PIVOT_EPSILON:
                pivot_row = row
                break
        if pivot_row is None:
            raise ValueError("matrix is singular")

        if pivot_row != col:
            augmented[col], augmented[pivot_row] = augmented[pivot_row], augmented[col]

        pivot = augmented[col][col]
        if abs(pivot) < PIVOT_EPSILON:
            raise ValueError("matrix is singular")

        augmented[col] = [value / pivot for value in augmented[col]]

        for row in range(size):
            if row == col:
                continue
            factor = augmented[row][col]
            if abs(factor) < PIVOT_EPSILON:
                continue
            augmented[row] = [
                current - factor * pivot_value
                for current, pivot_value in zip(augmented[row], augmented[col])
            ]

    inverse = [row[size:] for row in augmented]
    return inverse


def matmul(a_matrix: list[list[float]], b_matrix: list[list[float]]) -> list[list[float]]:
    """Multiply two matrices using the standard row-by-column algorithm."""
    if not a_matrix or not b_matrix:
        raise ValueError("matrices must be non-empty")

    a_rows = len(a_matrix)
    a_cols = len(a_matrix[0])
    b_rows = len(b_matrix)
    b_cols = len(b_matrix[0])

    if any(len(row) != a_cols for row in a_matrix):
        raise ValueError("left matrix has inconsistent row lengths")
    if any(len(row) != b_cols for row in b_matrix):
        raise ValueError("right matrix has inconsistent row lengths")
    if a_cols != b_rows:
        raise ValueError("matrix dimensions do not align for multiplication")

    result: list[list[float]] = []
    for row in range(a_rows):
        result_row: list[float] = []
        for col in range(b_cols):
            value = 0.0
            for k in range(a_cols):
                value += a_matrix[row][k] * b_matrix[k][col]
            result_row.append(value)
        result.append(result_row)
    return result


def build_transition_matrix(
    session_states: list[list[tuple[int, int]]],
) -> list[list[float]]:
    """Build a transition matrix from observed session state sequences."""
    counts = [[0.0 for _ in range(STATE_COUNT)] for _ in range(STATE_COUNT)]

    for session in session_states:
        for data_tier, activity_tier in session:
            state_to_index(data_tier, activity_tier)
        for current, following in zip(session, session[1:]):
            from_idx = state_to_index(current[0], current[1])
            to_idx = state_to_index(following[0], following[1])
            counts[from_idx][to_idx] += 1.0

    uniform_row = [1.0 / STATE_COUNT for _ in range(STATE_COUNT)]
    matrix: list[list[float]] = []
    for row in counts:
        total = sum(row)
        if total == 0.0:
            matrix.append(uniform_row.copy())
        else:
            matrix.append([value / total for value in row])

    assert all(abs(sum(row) - 1.0) < ROW_SUM_TOLERANCE for row in matrix)
    return matrix


def _nearest_absorbing_state(data_tier: int, activity_tier: int) -> int:
    """Return the index of the nearest absorbing state by Manhattan distance."""
    absorbing_indices = [
        idx
        for idx in range(STATE_COUNT)
        if is_absorbing(*index_to_state(idx))
    ]
    best_idx = absorbing_indices[0]
    best_distance = None
    for idx in absorbing_indices:
        candidate_data, candidate_activity = index_to_state(idx)
        distance = abs(candidate_data - data_tier) + abs(candidate_activity - activity_tier)
        candidate_key = (distance, idx)
        if best_distance is None or candidate_key < best_distance:
            best_distance = candidate_key
            best_idx = idx
    return best_idx


def make_default_transition_matrix() -> list[list[float]]:
    """Create the handcrafted cold-start transition matrix."""
    matrix = [[0.0 for _ in range(STATE_COUNT)] for _ in range(STATE_COUNT)]

    for idx in range(STATE_COUNT):
        data_tier, activity_tier = index_to_state(idx)
        if is_absorbing(data_tier, activity_tier):
            matrix[idx][idx] = 1.0
            continue

        row = [0.0 for _ in range(STATE_COUNT)]
        activity_prob = 0.0
        data_prob = 0.0
        jump_prob = 0.05

        if activity_tier < TIER_COUNT - 1:
            next_activity_idx = state_to_index(data_tier, activity_tier + 1)
            row[next_activity_idx] += 0.25
            activity_prob = 0.25

        if data_tier < TIER_COUNT - 1:
            next_data_idx = state_to_index(data_tier + 1, activity_tier)
            row[next_data_idx] += 0.10
            data_prob = 0.10

        jump_idx = _nearest_absorbing_state(data_tier, activity_tier)
        row[jump_idx] += jump_prob

        stay_prob = 1.0 - activity_prob - data_prob - jump_prob
        row[idx] += stay_prob
        matrix[idx] = row

    assert all(abs(sum(row) - 1.0) < ROW_SUM_TOLERANCE for row in matrix)
    return matrix


def compute_absorption_probabilities(
    transition_matrix: list[list[float]],
) -> dict[int, float]:
    """Compute bounded absorption risk scores for all 16 states.

    The standard absorbing-chain mass `sum(B[i])` is 1.0 for every transient
    state in the handcrafted cold-start matrix because every transient state
    eventually reaches a dangerous state. To preserve useful ordering, the
    returned scalar discounts that absorption mass by expected steps to
    absorption, derived from the fundamental matrix.
    """
    if len(transition_matrix) != STATE_COUNT:
        raise ValueError("transition matrix must have 16 rows")
    if any(len(row) != STATE_COUNT for row in transition_matrix):
        raise ValueError("transition matrix must be 16x16")
    assert all(abs(sum(row) - 1.0) < ROW_SUM_TOLERANCE for row in transition_matrix)

    transient_states: list[int] = []
    absorbing_states: list[int] = []
    for idx in range(STATE_COUNT):
        state = index_to_state(idx)
        if is_absorbing(*state):
            absorbing_states.append(idx)
        else:
            transient_states.append(idx)

    assert len(transient_states) == 10, f"expected 10 transient states, got {len(transient_states)}"
    assert len(absorbing_states) == 6, f"expected 6 absorbing states, got {len(absorbing_states)}"

    q_matrix = [
        [transition_matrix[i][j] for j in transient_states]
        for i in transient_states
    ]
    r_matrix = [
        [transition_matrix[i][j] for j in absorbing_states]
        for i in transient_states
    ]

    identity_minus_q: list[list[float]] = []
    for row_idx in range(len(q_matrix)):
        row: list[float] = []
        for col_idx in range(len(q_matrix)):
            identity_value = 1.0 if row_idx == col_idx else 0.0
            row.append(identity_value - q_matrix[row_idx][col_idx])
        identity_minus_q.append(row)

    fundamental = matrix_inverse(identity_minus_q)
    absorption_matrix = matmul(fundamental, r_matrix)

    probabilities: dict[int, float] = {idx: 1.0 for idx in absorbing_states}
    for row_idx, state_idx in enumerate(transient_states):
        absorption_mass = sum(absorption_matrix[row_idx])
        expected_steps = sum(fundamental[row_idx])
        assert expected_steps > 0.0, "expected absorption steps must be positive"
        probability = absorption_mass / expected_steps
        probabilities[state_idx] = min(1.0, max(0.0, probability))

    return probabilities


def data_tier_from_action(scored: Any) -> int:
    """Map action data sensitivity into the 0-3 Markov data tier."""
    sensitivity = int(scored.action.data_sensitivity)
    if sensitivity <= 0:
        return 0
    if sensitivity == 1:
        return 1
    if sensitivity == 2:
        return 2
    return 3


def activity_tier_from_action(scored: Any) -> int:
    """Map scored action band into the 0-3 Markov activity tier."""
    band = scored.band
    if band == Band.GREEN:
        return 0
    if band == Band.YELLOW:
        return 1
    if band == Band.ORANGE:
        return 2
    if band == Band.RED:
        return 3
    raise ValueError(f"unsupported band: {band!r}")


def _band_rank(band: Band) -> int:
    """Return a monotonic order for band comparisons."""
    order = {
        Band.GREEN: 0,
        Band.YELLOW: 1,
        Band.ORANGE: 2,
        Band.RED: 3,
    }
    return order[band]


class MarkovDriftTracker:
    """Markov-chain SafetyDrift tracker with counter-based fallback."""

    THRESHOLD_ORANGE = 0.3
    THRESHOLD_RED = 0.7

    def __init__(self, transition_matrix: list[list[float]], session_id: str):
        """Initialize the tracker for one session."""
        self._fallback = SessionAccumulator(session_id=session_id)
        self._current_data_tier = 0
        self._current_activity_tier = 0
        self._absorption_probs = compute_absorption_probabilities(transition_matrix)

    def record(self, scored_action: Any) -> Optional[DriftBump]:
        """Update the current state and return a band bump if thresholds are crossed."""
        self._current_data_tier = max(
            self._current_data_tier,
            data_tier_from_action(scored_action),
        )
        self._current_activity_tier = max(
            self._current_activity_tier,
            activity_tier_from_action(scored_action),
        )

        current_idx = state_to_index(
            self._current_data_tier,
            self._current_activity_tier,
        )
        probability = self._absorption_probs[current_idx]

        target_band: Optional[Band] = None
        if probability >= self.THRESHOLD_RED:
            target_band = Band.RED
        elif probability >= self.THRESHOLD_ORANGE:
            target_band = Band.ORANGE

        if target_band is not None and _band_rank(target_band) > _band_rank(scored_action.band):
            return DriftBump(
                original_band=scored_action.band,
                escalated_band=target_band,
                reason=(
                    "markov_absorption:"
                    f" state={self.current_state}, prob={probability:.3f}"
                ),
                accumulator_snapshot={
                    "current_state": self.current_state,
                    "absorption_probability": probability,
                },
            )

        if target_band is not None:
            return None

        return self._fallback.record(scored_action)

    @property
    def current_state(self) -> tuple[int, int]:
        """Return the current cumulative Markov state."""
        return (self._current_data_tier, self._current_activity_tier)

    def reset(self) -> None:
        """Reset both the Markov state and the fallback accumulator."""
        self._current_data_tier = 0
        self._current_activity_tier = 0
        self._fallback.reset()
