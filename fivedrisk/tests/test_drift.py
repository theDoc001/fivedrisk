"""Tests for SafetyDrift MVP — session accumulator.

Covers the 5 core attack scenarios:
1. Single high-risk action (no drift, 5D handles directly)
2. Prompt injection via retrieved content (drift detects external accumulation)
3. Compositional exfiltration (10 GREENs → drift escalates)
4. Malicious code generation (drift detects privilege + external)
5. Incremental privilege escalation (drift detects data class spread)
"""
import pytest

from fivedrisk.drift import SessionAccumulator, DriftBump, _bump_band
from fivedrisk.schema import Action, Band, ScoredAction
from fivedrisk.scorer import score
from fivedrisk.policy import Policy


pytestmark = pytest.mark.safety_drift


# ─── Helpers ────────────────────────────────────────────────────

def _make_scored(
    tool_name: str = "Read",
    data_sensitivity: int = 0,
    tool_privilege: int = 0,
    reversibility: int = 0,
    external_impact: int = 0,
    autonomy_context: int = 0,
    band: Band = Band.GREEN,
) -> ScoredAction:
    """Create a ScoredAction for testing without going through full scoring."""
    action = Action(
        tool_name=tool_name,
        data_sensitivity=data_sensitivity,
        tool_privilege=tool_privilege,
        reversibility=reversibility,
        external_impact=external_impact,
        autonomy_context=autonomy_context,
    )
    return ScoredAction(
        action=action,
        band=band,
        composite_score=0.5,
        max_dimension=max(data_sensitivity, tool_privilege, reversibility, external_impact, autonomy_context),
        rationale="test",
        policy_version="test",
    )


# ─── Band bump helper ──────────────────────────────────────────

class TestBumpBand:
    def test_green_to_yellow(self):
        assert _bump_band(Band.GREEN, 1) == Band.YELLOW

    def test_green_to_orange(self):
        assert _bump_band(Band.GREEN, 2) == Band.ORANGE

    def test_yellow_to_red(self):
        assert _bump_band(Band.YELLOW, 2) == Band.RED

    def test_red_stays_red(self):
        assert _bump_band(Band.RED, 1) == Band.RED

    def test_cap_at_red(self):
        assert _bump_band(Band.GREEN, 10) == Band.RED


# ─── Scenario 1: Single high-risk action (no drift needed) ─────

class TestNoDrift:
    def test_single_green_no_bump(self):
        acc = SessionAccumulator(session_id="test-1")
        scored = _make_scored(tool_name="Read", data_sensitivity=0)
        bump = acc.record(scored)
        assert bump is None

    def test_few_greens_no_bump(self):
        acc = SessionAccumulator(session_id="test-2")
        for _ in range(5):
            scored = _make_scored(tool_name="Read", data_sensitivity=0)
            bump = acc.record(scored)
        assert bump is None

    def test_single_orange_no_bump(self):
        """A single ORANGE action shouldn't trigger drift — 5D already handles it."""
        acc = SessionAccumulator(session_id="test-3")
        scored = _make_scored(tool_name="Bash", tool_privilege=3, band=Band.ORANGE)
        bump = acc.record(scored)
        assert bump is None  # No cumulative pattern yet


# ─── Scenario 3: Compositional exfiltration (10 GREENs = RED) ──

class TestCompositionalExfiltration:
    def test_10_reads_across_data_classes(self):
        """10 GREEN file reads touching D0, D1, D2 → drift catches it."""
        acc = SessionAccumulator(session_id="test-exfil")

        # Read public files (D0)
        for _ in range(3):
            scored = _make_scored(data_sensitivity=0)
            acc.record(scored)

        # Read internal files (D1)
        for _ in range(3):
            scored = _make_scored(data_sensitivity=1)
            acc.record(scored)

        # Read sensitive files (D2)
        for _ in range(3):
            scored = _make_scored(data_sensitivity=2)
            acc.record(scored)

        # One more — this should trigger on data_classes_seen >= 3
        scored = _make_scored(data_sensitivity=2)
        bump = acc.record(scored)

        assert bump is not None
        assert bump.escalated_band.value != bump.original_band.value
        assert "data_exposure" in bump.reason
        assert bump.escalated_band in (Band.YELLOW, Band.ORANGE)

    def test_long_green_runway_amplifies(self):
        """10+ consecutive GREENs with accumulation → stealth pattern detected."""
        acc = SessionAccumulator(session_id="test-stealth")

        # Slowly accumulate across data classes, all GREEN
        classes = [0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 2]
        bump = None
        for ds in classes:
            scored = _make_scored(data_sensitivity=ds)
            bump = acc.record(scored)

        # By action 12 we have 3 data classes + 12 green streak → bump
        assert bump is not None
        assert "green_runway" in bump.reason


# ─── Scenario 2: External accumulation (reconnaissance) ─────────

class TestExternalAccumulation:
    def test_many_webfetches(self):
        """5+ WebFetch calls → external_endpoint accumulation."""
        acc = SessionAccumulator(session_id="test-recon")

        for _ in range(6):
            scored = _make_scored(
                tool_name="WebFetch",
                external_impact=2,
            )
            bump = acc.record(scored)

        assert bump is not None
        assert "external_contact" in bump.reason


# ─── Scenario 5: Incremental privilege escalation ───────────────

class TestPrivilegeEscalation:
    def test_privilege_after_runway(self):
        """Low-priv reads followed by high-priv Bash → caught after N actions."""
        acc = SessionAccumulator(session_id="test-priv")

        # 4 harmless reads
        for _ in range(4):
            acc.record(_make_scored(tool_name="Read", tool_privilege=0))

        # High-privilege Bash — but session has been building up
        scored = _make_scored(tool_name="Bash", tool_privilege=3)
        bump = acc.record(scored)

        assert bump is not None
        assert "privilege_escalation" in bump.reason


# ─── Scenario 4: Destructive sequence ──────────────────────────

class TestDestructiveSequence:
    def test_multiple_deletes(self):
        """3+ irreversible operations → caught."""
        acc = SessionAccumulator(session_id="test-destroy")

        for _ in range(3):
            scored = _make_scored(
                tool_name="Bash",
                reversibility=3,
                tool_privilege=2,
            )
            bump = acc.record(scored)

        assert bump is not None
        assert "irreversibility" in bump.reason


# ─── Snapshot and reset ────────────────────────────────────────

class TestSnapshotAndReset:
    def test_snapshot(self):
        acc = SessionAccumulator(session_id="test-snap")
        acc.record(_make_scored(data_sensitivity=1))
        snap = acc.snapshot()
        assert snap["session_id"] == "test-snap"
        assert snap["action_count"] == 1
        assert "D1" in snap["data_classes_seen"]

    def test_reset_clears_state(self):
        acc = SessionAccumulator(session_id="test-reset")
        for _ in range(5):
            acc.record(_make_scored(data_sensitivity=2, external_impact=2))
        acc.reset()
        assert acc.action_count == 0
        assert len(acc.data_classes_seen) == 0
        assert acc.external_endpoint_count == 0

    def test_no_bump_after_reset(self):
        """After HITL intervention + reset, counters start fresh."""
        acc = SessionAccumulator(session_id="test-post-reset")
        for _ in range(6):
            acc.record(_make_scored(external_impact=2))
        acc.reset()
        scored = _make_scored(external_impact=2)
        bump = acc.record(scored)
        assert bump is None  # Fresh start


# ─── Edge cases ────────────────────────────────────────────────

class TestEdgeCases:
    def test_already_red_no_bump(self):
        """If action is already RED, drift doesn't bump further."""
        acc = SessionAccumulator(session_id="test-red")
        for _ in range(10):
            acc.record(_make_scored(data_sensitivity=2, external_impact=2))
        # This one is already RED
        scored = _make_scored(data_sensitivity=3, band=Band.RED, external_impact=3)
        bump = acc.record(scored)
        # RED bumped to RED is same band → no bump returned
        assert bump is None

    def test_mixed_bands_reset_green_streak(self):
        """Non-GREEN action resets the green streak counter."""
        acc = SessionAccumulator(session_id="test-streak")
        for _ in range(8):
            acc.record(_make_scored())  # GREEN
        acc.record(_make_scored(band=Band.YELLOW, tool_privilege=2))
        assert acc.green_streak == 0
