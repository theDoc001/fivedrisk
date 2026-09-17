"""Regression tests for the OSS bug-fix batch (OSS-1 / OSS-2 / OSS-3).

- OSS-1 (P0): band RED/ORANGE blocks must raise a FivedriskDenial subclass
  (BandBlockError), NOT a bare ValueError, so a caller's broad `except
  ValueError` (JSON/validation) cannot swallow the primary security decision.
- OSS-2 (P1): the advertised `floor` feature — a hard minimum band per matching
  action that holds regardless of score and cannot be lowered at runtime.
- OSS-3 (P1): band-score keys are read only from `bands:`; `validate` warns when
  they are misplaced under `thresholds:` (and vice-versa).
"""

from __future__ import annotations

import asyncio

import pytest

from fivedrisk import (
    Band,
    BandBlockError,
    DestinationBlockError,
    FivedriskDenial,
    FloorRule,
    Policy,
    SessionRequiredError,
    configure,
    gate,
    load_policy,
    score,
)
from fivedrisk.cli import (
    _floor_control_warnings,
    _policy_placement_warnings,
    _validate_policy_config,
)
from fivedrisk.logger import DecisionLog
from fivedrisk.schema import Action


def _reset(tmp_path) -> DecisionLog:
    log = DecisionLog(tmp_path / "hooks.db")
    configure(log_path=log.path)
    return log


# ─────────────────────────── OSS-1 ───────────────────────────

class TestOSS1BandBlockIsNotValueError:
    def test_bandblockerror_is_denial_not_valueerror(self):
        assert issubclass(BandBlockError, FivedriskDenial)
        assert not issubclass(BandBlockError, ValueError)

    def test_broad_except_valueerror_cannot_swallow_red_sync(self, tmp_path):
        """The load-bearing OSS-1 regression: a caller that wraps the gated
        call in a broad `except ValueError` MUST still be denied on a RED
        action. Before the fix the block was a ValueError and got swallowed →
        the action executed (fail-open)."""
        _reset(tmp_path)

        @gate(tool_name="Bash")
        def dangerous(command: str) -> str:
            return "EXECUTED"

        def vulnerable_caller() -> str:
            # This is the ubiquitous fail-open shape the fix must defeat.
            try:
                return dangerous(command="rm -rf /important/data")
            except ValueError:
                return "SWALLOWED-THEN-EXECUTED"

        # The RED block escapes the broad except ValueError as a denial.
        with pytest.raises(BandBlockError):
            vulnerable_caller()

    def test_red_block_raises_bandblockerror_async(self, tmp_path):
        _reset(tmp_path)

        @gate(tool_name="Bash")
        async def dangerous(command: str) -> str:
            return "EXECUTED"

        with pytest.raises(BandBlockError):
            asyncio.run(dangerous(command="rm -rf /important/data"))

    def test_orange_block_raises_bandblockerror_sync(self, tmp_path):
        _reset(tmp_path)

        @gate(tool_name="Bash")
        def elevated(command: str) -> str:
            return "EXECUTED"

        with pytest.raises(BandBlockError):
            elevated(command="docker compose up -d")


# ─────────────────────────── OSS-2 ───────────────────────────

class TestOSS2PolicyFloor:
    def test_floor_raises_green_action_to_red(self):
        policy = Policy(floor=[FloorRule(tool_name="Read", band=Band.RED, reason="always-red")])
        result = score(Action(tool_name="Read", tool_input={"file_path": "/x"}), policy)
        assert result.band == Band.RED
        assert "always-red" in result.rationale

    def test_floor_only_raises_never_demotes(self):
        # A GREEN floor on an action that scores RED must NOT lower the band.
        policy = Policy(floor=[FloorRule(tool_name="Bash", band=Band.GREEN)])
        result = score(
            Action(tool_name="Bash", tool_privilege=4, reversibility=4), policy
        )
        assert result.band == Band.RED

    def test_command_contains_gates_the_match(self):
        policy = Policy(
            floor=[FloorRule(tool_name="Bash", band=Band.RED, command_contains="DROP TABLE")]
        )
        hit = score(
            Action(tool_name="Bash", tool_input={"command": "psql -c 'DROP TABLE users'"}),
            policy,
        )
        miss = score(
            Action(tool_name="Bash", tool_input={"command": "SELECT 1"}), policy
        )
        assert hit.band == Band.RED
        assert miss.band == Band.GREEN

    def test_highest_band_wins_on_multiple_matches(self):
        policy = Policy(
            floor=[
                FloorRule(tool_name="Read", band=Band.ORANGE),
                FloorRule(tool_name="Read", band=Band.RED),
            ]
        )
        assert score(Action(tool_name="Read"), policy).band == Band.RED

    def test_load_policy_parses_floor_block(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - tool_name: Bash\n"
            "    command_contains: 'DROP TABLE'\n"
            "    band: RED\n"
            "    reason: no-destructive-sql\n"
        )
        policy = load_policy(str(p))
        assert len(policy.floor) == 1
        rule = policy.floor[0]
        assert rule.tool_name == "Bash"
        assert rule.band == Band.RED
        assert rule.command_contains == "DROP TABLE"
        assert rule.reason == "no-destructive-sql"

    def test_validate_flags_floor_missing_band(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("floor:\n  - tool_name: Bash\n    command_contains: X\n")
        errors = _validate_policy_config(str(p))
        assert any("band" in e for e in errors), errors

    def test_validate_flags_floor_invalid_band(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("floor:\n  - tool_name: Bash\n    band: PURPLE\n")
        errors = _validate_policy_config(str(p))
        assert any("invalid band" in e for e in errors), errors

    def test_gate_enforces_floor_at_runtime(self, tmp_path):
        """The 'cannot be overridden at runtime' guarantee: a Read that scores
        GREEN is blocked by the gate when a floor pins it to RED."""
        pfile = tmp_path / "policy.yaml"
        pfile.write_text("floor:\n  - tool_name: Read\n    band: RED\n    reason: locked\n")
        configure(log_path=tmp_path / "hooks.db", policy_path=str(pfile))

        @gate(tool_name="Read")
        def read_file(file_path: str) -> str:
            return "EXECUTED"

        with pytest.raises(BandBlockError):
            read_file(file_path="/tmp/public.txt")


# ─────────────────────────── OSS-3 ───────────────────────────

class TestOSS3BandScoreKeyPlacement:
    def test_misplaced_band_score_is_silently_ignored(self, tmp_path):
        """Documents the underlying defect: a band score under `thresholds:` is
        dropped and the default is used."""
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  orange_score: 0.1\n")
        policy = load_policy(str(p))
        assert policy.orange_score == 1.8  # default, NOT 0.1 → the value was ignored

    def test_validate_warns_band_score_under_thresholds(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  orange_score: 1.8\n  yellow_score: 1.0\n")
        warnings = _policy_placement_warnings(str(p))
        assert any("orange_score" in w for w in warnings)
        assert any("yellow_score" in w for w in warnings)
        assert all("bands:" in w for w in warnings)

    def test_validate_warns_threshold_under_bands(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("bands:\n  red_threshold: 4\n")
        warnings = _policy_placement_warnings(str(p))
        assert any("red_threshold" in w for w in warnings)

    def test_correct_placement_yields_no_warnings(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "thresholds:\n  red_threshold: 4\n  orange_threshold: 3\n"
            "bands:\n  yellow_score: 1.0\n  orange_score: 1.8\n  red_score: 2.5\n"
        )
        assert _policy_placement_warnings(str(p)) == []

    def test_green_score_is_not_a_placement_key(self, tmp_path):
        # green_score is "everything below yellow" (always 0.0) and load_policy
        # never reads it from bands:, so warning to move it there would be
        # misleading. It must produce NO placement warning wherever it sits.
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  green_score: 0.5\n")
        warnings = _policy_placement_warnings(str(p))
        assert not any("green_score" in w for w in warnings)


# ── Sibling fail-open fix: session-required + destination blocks are denials ──

class TestSiblingFailOpenFix:
    """The two non-band gate blocks (session-required, destination-policy) now
    raise FivedriskDenial subclasses, so a broad `except ValueError` cannot
    swallow them — mirroring the OSS-1 BandBlockError fix."""

    def test_session_required_raises_denial_not_valueerror(self, tmp_path):
        configure(log_path=str(tmp_path / "s.db"), require_session_id=True)

        @gate(tool_name="Bash")
        def run(command: str) -> str:
            return "EXECUTED"

        with pytest.raises(SessionRequiredError) as ei:
            run(command="echo hi")
        assert isinstance(ei.value, FivedriskDenial)
        assert not isinstance(ei.value, ValueError)

    def test_destination_block_raises_denial_not_valueerror(self, tmp_path):
        configure(log_path=str(tmp_path / "d.db"), destination_denylist=["evil.com"])

        @gate(tool_name="WebFetch")
        def fetch(url: str) -> str:
            return "FETCHED"

        with pytest.raises(DestinationBlockError) as ei:
            fetch(url="https://evil.com/x")
        assert isinstance(ei.value, FivedriskDenial)
        assert not isinstance(ei.value, ValueError)

    def test_on_block_still_intercepts_session_and_destination(self, tmp_path):
        # on_block continues to short-circuit both sites (no raise when supplied).
        seen: list[str] = []
        configure(log_path=str(tmp_path / "b.db"), require_session_id=True)

        @gate(tool_name="Bash", on_block=lambda r: seen.append(r) or "HANDLED")
        def run(command: str) -> str:
            return "EXECUTED"

        assert run(command="echo hi") == "HANDLED"
        assert seen and "session id required" in seen[0]


# ── Floor best-effort command_contains warning ──

class TestFloorCommandContainsWarning:
    """`validate` warns when a RED/ORANGE hard control is gated on the evadable
    `command_contains` substring instead of an unconditional tool_name floor."""

    def test_warns_on_red_command_contains_floor(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n  - tool_name: Bash\n    band: RED\n"
            "    command_contains: 'DROP TABLE'\n"
        )
        warnings = _floor_control_warnings(str(p))
        assert any("EVADABLE" in w and "Bash" in w for w in warnings)

    def test_no_warning_for_tool_name_only_floor(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("floor:\n  - tool_name: file_sar\n    band: RED\n")
        assert _floor_control_warnings(str(p)) == []

    def test_no_warning_for_low_band_command_contains(self, tmp_path):
        # A GREEN/YELLOW advisory floor keyed on command_contains is not a hard
        # control, so it is not flagged.
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n  - tool_name: Bash\n    band: GREEN\n"
            "    command_contains: 'noqa'\n"
        )
        assert _floor_control_warnings(str(p)) == []
