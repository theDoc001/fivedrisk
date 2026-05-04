"""5D Risk Governance Engine — SafetyDrift MVP (session accumulator).

Tracks cumulative risk across a sequence of actions within a session.
When cumulative exposure exceeds thresholds, bumps the next action's
band regardless of its individual score.

Inspired by SafetyDrift (arxiv 2603.27148, March 2025) — the insight
that individual GREEN actions can compose into a RED sequence.

MVP implementation: O(1) per action, no Markov math, ~30 lines of core logic.
Full Markov chain implementation planned for 5D Standard tier.

Usage:
    from fivedrisk.drift import SessionAccumulator

    session = SessionAccumulator(session_id="abc-123")

    # After each 5D score:
    bump = session.record(scored_action)
    if bump:
        # The sequence is trending dangerous — bump the band
        scored_action.band = bump.escalated_band
        scored_action.rationale += f" [SafetyDrift: {bump.reason}]"

Thresholds (configurable via constructor):
    - data_classes_seen >= 3 distinct classes → bump +1 band
    - external_endpoints >= 5 contacts → bump +1 band
    - irreversible_ops >= 3 → bump +1 band
    - privilege_ceiling >= 3 AND action_count >= 5 → bump +1 band
    - total GREEN actions >= 10 with any accumulator at warning → bump +1 band
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Set

from .schema import Band, ScoredAction


# ─── Band escalation helper ────────────────────────────────────

_BAND_ORDER = [Band.GREEN, Band.YELLOW, Band.ORANGE, Band.RED]


def _bump_band(current: Band, levels: int = 1) -> Band:
    """Bump a band up by N levels, capped at RED."""
    idx = _BAND_ORDER.index(current)
    new_idx = min(idx + levels, len(_BAND_ORDER) - 1)
    return _BAND_ORDER[new_idx]


# ─── Drift result ──────────────────────────────────────────────

@dataclass
class DriftBump:
    """Result of a SafetyDrift check — non-None means the band should be bumped."""
    original_band: Band
    escalated_band: Band
    reason: str
    accumulator_snapshot: dict


# ─── Session Accumulator ───────────────────────────────────────

@dataclass
class SessionAccumulator:
    """Tracks cumulative risk within a single session (conversation/task).

    Call record() after every ScoredAction. If the return value is not None,
    the caller should escalate the action's band.

    Stateless per-action scoring misses:
    - 10 file reads across different data classes → exfiltration
    - 5 WebFetch calls to different domains → reconnaissance
    - 3 deletes in a row → destructive sequence
    - High privilege actions after a long GREEN runway → escalation

    The accumulator catches these patterns with O(1) counters.
    """
    session_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ─── Counters ───────────────────────────────────────────────
    action_count: int = 0
    green_streak: int = 0                    # consecutive GREEN actions

    # Data exposure tracking
    data_classes_seen: Set[str] = field(default_factory=set)  # {"D0", "D1", "D2", "D3"}

    # External contact tracking
    external_endpoint_count: int = 0         # actions with external_impact >= 2

    # Irreversibility tracking
    irreversible_count: int = 0              # actions with reversibility >= 3

    # Privilege ceiling
    max_privilege_seen: int = 0              # highest tool_privilege in session

    # ─── Thresholds (configurable) ──────────────────────────────
    data_class_threshold: int = 3            # distinct data classes before bump
    external_threshold: int = 5              # external contacts before bump
    irreversible_threshold: int = 3          # irreversible ops before bump
    privilege_ceiling_threshold: int = 3     # privilege level + action count gate
    green_runway_threshold: int = 10         # long GREEN streak with high accumulation
    privilege_action_threshold: int = 5      # min actions before privilege gate fires

    def record(self, scored: ScoredAction) -> Optional[DriftBump]:
        """Record a scored action and check for cumulative risk escalation.

        Call this AFTER score() but BEFORE acting on the result.
        If the return is not None, the caller should bump the band.

        Returns:
            DriftBump if escalation needed, None if sequence looks safe.
        """
        action = scored.action
        self.action_count += 1

        # Update counters
        self.data_classes_seen.add(action.data_class)

        if action.external_impact >= 2:
            self.external_endpoint_count += 1

        if action.reversibility >= 3:
            self.irreversible_count += 1

        self.max_privilege_seen = max(self.max_privilege_seen, action.tool_privilege)

        if scored.band == Band.GREEN:
            self.green_streak += 1
        else:
            self.green_streak = 0

        # ─── Check thresholds ───────────────────────────────────
        reasons: list[str] = []

        if len(self.data_classes_seen) >= self.data_class_threshold:
            reasons.append(
                f"data_exposure: {len(self.data_classes_seen)} distinct data classes "
                f"accessed ({', '.join(sorted(self.data_classes_seen))})"
            )

        if self.external_endpoint_count >= self.external_threshold:
            reasons.append(
                f"external_contact: {self.external_endpoint_count} external actions"
            )

        if self.irreversible_count >= self.irreversible_threshold:
            reasons.append(
                f"irreversibility: {self.irreversible_count} irreversible operations"
            )

        if (self.max_privilege_seen >= self.privilege_ceiling_threshold
                and self.action_count >= self.privilege_action_threshold):
            reasons.append(
                f"privilege_escalation: max_privilege={self.max_privilege_seen} "
                f"after {self.action_count} actions"
            )

        # Long GREEN runway with accumulation = stealth pattern
        if (self.green_streak >= self.green_runway_threshold
                and len(reasons) > 0):
            reasons.append(
                f"green_runway: {self.green_streak} consecutive GREENs "
                f"masking cumulative exposure"
            )

        if not reasons:
            return None

        # Calculate bump magnitude: 1 reason = +1 band, 2+ = +2 (capped at RED)
        bump_levels = min(len(reasons), 2)
        escalated = _bump_band(scored.band, bump_levels)

        if escalated == scored.band:
            return None  # Already at or above escalated level

        return DriftBump(
            original_band=scored.band,
            escalated_band=escalated,
            reason="; ".join(reasons),
            accumulator_snapshot=self.snapshot(),
        )

    def snapshot(self) -> dict:
        """Return current accumulator state for logging/auditing."""
        return {
            "session_id": self.session_id,
            "action_count": self.action_count,
            "green_streak": self.green_streak,
            "data_classes_seen": sorted(self.data_classes_seen),
            "external_endpoint_count": self.external_endpoint_count,
            "irreversible_count": self.irreversible_count,
            "max_privilege_seen": self.max_privilege_seen,
        }

    def reset(self) -> None:
        """Reset accumulator (new session or after HITL intervention)."""
        self.action_count = 0
        self.green_streak = 0
        self.data_classes_seen.clear()
        self.external_endpoint_count = 0
        self.irreversible_count = 0
        self.max_privilege_seen = 0
