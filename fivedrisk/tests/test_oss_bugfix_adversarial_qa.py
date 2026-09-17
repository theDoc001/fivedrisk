"""ADVERSARIAL QA reproducers for the OSS-1/2/3 bug-fix batch.

Written by the independent QA verification gate as an INDEPENDENT double-check of
the author's `test_oss_bugfix_batch.py`. These go past the author's tests:

  #1 Fuzz `command_contains` (floor substring gate) with newline / injection /
     unicode / case / whitespace / empty / huge / non-str inputs — prove it
     never CRASHES and never DEMOTES, and CHARACTERIZE the evasions (a naive
     case-sensitive substring gate is trivially bypassable).
  #2 Property: the policy floor is strictly monotonic (raise-only) across the
     full band x tool x dimension space — it must NEVER demote.
  #3 Async fail-closed under `on_block=None`: a floored RED denial must escape a
     broad `except ValueError`; and we MEASURE that a broad `except Exception`
     still swallows it (scoping limit of the OSS-1 fix).
  #4 FINDING probes: the two flagged NON-band sites (destination-policy block and
     session-required block) STILL raise a bare `ValueError` and ARE swallowed by
     a broad `except ValueError` — the exact OSS-1 fail-open, unfixed. These
     tests assert the SAFE contract and therefore FAIL today (that is the point:
     a reproduced, measured fail-open to size the follow-up item).

Run:
    pytest fivedrisk/tests/test_oss_bugfix_adversarial_qa.py -v
"""

from __future__ import annotations

import asyncio
import itertools
import sys

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
    score,
)
from fivedrisk import hooks as hooks_mod
from fivedrisk.schema import Action

BAND_ORDER = [Band.GREEN, Band.YELLOW, Band.ORANGE, Band.RED]


def _reset(tmp_path, **kw):
    configure(log_path=str(tmp_path / "qa.db"), **kw)


# ══════════════════════════ #1  FUZZ command_contains ══════════════════════════

class TestFuzzCommandContainsNoCrashNoDemote:
    """The floor substring gate must be SAFE on adversarial tool input: it may
    never raise out of matched_floor/score, and a matching floor may only raise."""

    @pytest.mark.parametrize("payload", [
        "psql -c 'DROP TABLE users'",
        "psql -c 'DROP TABLE\nusers'",           # embedded newline
        "'; DROP TABLE users; --",               # sql-injection shape
        "DROP TABLE" * 5000,                      # huge
        "\x00DROP TABLE\x00",                     # NUL bytes
        "DROP TABLE \U0001F4A5 users",            # emoji / astral plane
        "ＤＲＯＰ　ＴＡＢＬＥ",                      # fullwidth unicode
        "‮ELBAT PORD",                       # right-to-left override
        "",                                       # empty
    ])
    def test_no_crash_on_adversarial_command(self, payload):
        policy = Policy(floor=[FloorRule(tool_name="Bash", band=Band.RED,
                                         command_contains="DROP TABLE")])
        # Must not raise regardless of payload shape.
        result = score(Action(tool_name="Bash", tool_input={"command": payload}), policy)
        assert result.band in BAND_ORDER

    def test_non_string_tool_input_values_do_not_crash(self):
        policy = Policy(floor=[FloorRule(tool_name="Bash", band=Band.RED,
                                         command_contains="DROP TABLE")])
        for val in (None, 12345, b"DROP TABLE bytes", {"nested": "DROP TABLE"}, ["DROP TABLE"]):
            result = score(Action(tool_name="Bash", tool_input={"x": val}), policy)
            assert result.band in BAND_ORDER

    def test_match_only_raises_never_lowers_on_adversarial_input(self):
        # An action that already scores RED must stay RED even when the floor's
        # command_contains does NOT match the adversarial payload.
        policy = Policy(floor=[FloorRule(tool_name="Bash", band=Band.GREEN,
                                         command_contains="DROP TABLE")])
        result = score(
            Action(tool_name="Bash", tool_input={"command": "rm -rf /"},
                   tool_privilege=4, reversibility=4),
            policy,
        )
        assert result.band == Band.RED  # GREEN floor cannot demote a RED action


class TestFuzzCommandContainsEVASIONS:
    """CHARACTERIZATION: the floor `command_contains` is a naive case-sensitive
    substring. These document (not endorse) how an 'ALWAYS RED' control keyed on
    command_contains is bypassed. Fail-OPEN direction: the floor silently does
    NOT fire. For a hard control, floor by tool_name (no command_contains) —
    which is unconditional and NOT evadable (see test at bottom)."""

    def _red_floor(self):
        return Policy(floor=[FloorRule(tool_name="Bash", band=Band.RED,
                                       command_contains="DROP TABLE")])

    @pytest.mark.parametrize("evasion", [
        "drop table users",                       # lowercase
        "DrOp TaBlE users",                        # mixed case
        "DROP  TABLE users",                       # double space
        "DROP\tTABLE users",                       # tab instead of space
        "DROP/**/TABLE users",                     # sql comment splice
        "ＤＲＯＰ ＴＡＢＬＥ users",                 # fullwidth homoglyphs
        "RFJPUCBUQUJMRQ==",                        # base64('DROP TABLE')
    ])
    def test_command_contains_is_evadable_floor_does_not_fire(self, evasion):
        # The operator BELIEVES this is 'ALWAYS RED'. It is not.
        result = score(Action(tool_name="Bash", tool_input={"command": evasion}),
                       self._red_floor())
        assert result.band == Band.GREEN, (
            "If this ever becomes RED the gate got smarter; today the floor is evaded."
        )

    def test_join_across_values_can_spuriously_match(self):
        # str.join(" ") of values means a substring spanning two values matches
        # even though it appears in NEITHER value alone. Fail-CLOSED (over-raise)
        # direction, but a surprising false positive worth knowing.
        result = score(
            Action(tool_name="Bash", tool_input={"a": "... DROP", "b": "TABLE ..."}),
            self._red_floor(),
        )
        assert result.band == Band.RED

    def test_tool_name_only_floor_is_unconditional_and_not_evadable(self):
        # The ROBUST hard control: no command_contains -> fires on every call.
        policy = Policy(floor=[FloorRule(tool_name="file_sar", band=Band.RED,
                                         reason="SAR filing always needs approval")])
        for payload in ("anything", "", "ｓｎｅａｋｙ", "drop table"):
            r = score(Action(tool_name="file_sar", tool_input={"x": payload}), policy)
            assert r.band == Band.RED


# ══════════════════════════ #2  FLOOR MONOTONICITY (property) ══════════════════

class TestFloorStrictlyMonotonic:
    """Exhaustive property: for EVERY dimension vector, EVERY floor band, and
    both floor-applies / floor-does-not-apply, the floored band is >= the
    unfloored band AND >= the floor band. The floor may only RAISE."""

    TOOLS = ["Read", "Bash", "Write", "WebFetch", "UnknownTool"]

    def test_exhaustive_monotonic_raise_only(self):
        dims_space = list(itertools.product(range(5), repeat=5))  # 3125 vectors
        checked = 0
        for tool in self.TOOLS:
            for dims in dims_space:
                act = Action(
                    tool_name=tool,
                    data_sensitivity=dims[0], tool_privilege=dims[1],
                    reversibility=dims[2], external_impact=dims[3],
                    autonomy_context=dims[4],
                )
                base = score(act, Policy()).band  # unfloored (yellow off -> 3-band)
                for fb in BAND_ORDER:
                    # (a) floor matches this tool
                    pol_hit = Policy(floor=[FloorRule(tool_name=tool, band=fb)])
                    got = score(act, pol_hit).band
                    assert BAND_ORDER.index(got) >= BAND_ORDER.index(base), (
                        tool, dims, fb, "demoted below computed")
                    assert BAND_ORDER.index(got) >= BAND_ORDER.index(fb), (
                        tool, dims, fb, "below floor")
                    assert got == max(base, fb, key=BAND_ORDER.index)
                    # (b) floor targets a DIFFERENT tool -> must not change band
                    pol_miss = Policy(floor=[FloorRule(tool_name="__none__", band=fb)])
                    assert score(act, pol_miss).band == base
                    checked += 1
        assert checked == len(self.TOOLS) * len(dims_space) * len(BAND_ORDER)

    def test_multiple_matching_floors_take_highest_band(self):
        act = Action(tool_name="Read")
        for combo in itertools.permutations(BAND_ORDER, 2):
            pol = Policy(floor=[FloorRule(tool_name="Read", band=combo[0]),
                                FloorRule(tool_name="Read", band=combo[1])])
            expected = max(combo, key=BAND_ORDER.index)
            assert score(act, pol).band == expected


# ══════════════════════════ #3  ASYNC FAIL-CLOSED ══════════════════════════════

class TestAsyncFloorRedFailClosed:
    """A floored-RED async action with on_block=None must DENY. We measure how it
    behaves under the two broad-except shapes a real caller writes."""

    def _floor_red_policy(self):
        return Policy(floor=[FloorRule(tool_name="move_funds", band=Band.RED,
                                       reason="unattended fund movement always RED")])

    def test_direct_await_except_valueerror_still_denied(self, tmp_path):
        _reset(tmp_path)
        pol = self._floor_red_policy()

        @gate(tool_name="move_funds", policy=pol)
        async def move(amount: int) -> str:
            return "MOVED"

        async def vulnerable_caller():
            try:
                return await move(amount=1_000_000)
            except ValueError:
                return "SWALLOWED-THEN-EXECUTED"

        with pytest.raises(BandBlockError):
            asyncio.run(vulnerable_caller())

    @pytest.mark.skipif(
        sys.version_info < (3, 11),
        reason="asyncio.TaskGroup / ExceptionGroup (and except* syntax) require Python 3.11+",
    )
    def test_taskgroup_except_valueerror_still_denied(self, tmp_path):
        # NOTE: kept syntactically 3.10-safe — `except*` is a SyntaxError on 3.10
        # and would break collection of the whole module (which must import on
        # 3.10 per requires-python >=3.10). The security assertion is identical:
        # a gated deny inside a TaskGroup propagates as an ExceptionGroup carrying
        # BandBlockError, so a caller filtering for ValueError cannot swallow it.
        _reset(tmp_path)
        pol = self._floor_red_policy()

        @gate(tool_name="move_funds", policy=pol)
        async def move(amount: int) -> str:
            return "MOVED"

        async def driver():
            async with asyncio.TaskGroup() as tg:
                tg.create_task(move(amount=1_000_000))

        with pytest.raises(BaseExceptionGroup) as ei:
            asyncio.run(driver())
        # the group carries the security denial, not a ValueError
        assert any(isinstance(e, BandBlockError) for e in ei.value.exceptions)
        assert not any(isinstance(e, ValueError) for e in ei.value.exceptions)

    def test_MEASURE_broad_except_Exception_swallows_denial(self, tmp_path):
        """SCOPING LIMIT (not a regression): BandBlockError subclasses Exception,
        so `except Exception` swallows it and the action is treated as allowed.
        The OSS-1 fix defends against `except ValueError`, NOT `except
        Exception`. Documented so the boundary is explicit."""
        _reset(tmp_path)
        pol = self._floor_red_policy()

        @gate(tool_name="move_funds", policy=pol)
        async def move(amount: int) -> str:
            return "MOVED"

        async def caller():
            try:
                return await move(amount=1_000_000)
            except Exception:
                return "SWALLOWED"

        assert asyncio.run(caller()) == "SWALLOWED"  # denial WAS swallowed
        assert not issubclass(BandBlockError, ValueError)  # but not by except ValueError


# ══════════════════════════ #4  FIXED: sibling sites now fail-CLOSED ════════════
# These assert the SAFE contract (a security block must escape a broad
# `except ValueError`). They FAILED before the sibling fail-open fix because both
# sites raised a bare ValueError; the fix converts them to FivedriskDenial
# subclasses (SessionRequiredError / DestinationBlockError), mirroring OSS-1
# BandBlockError, so a broad `except ValueError` can no longer swallow them.

class TestFindingNonBandSitesFailOpen:

    def test_FINDING_destination_block_swallowed_by_except_valueerror(self, tmp_path):
        _reset(tmp_path, destination_denylist=["evil.com"])

        executed = {"ran": False}

        @gate(tool_name="WebFetch")
        def fetch(url: str) -> str:
            executed["ran"] = True
            return "FETCHED"

        def vulnerable_caller():
            try:
                return fetch(url="https://evil.com/exfil")
            except ValueError:
                return "SWALLOWED"

        # SAFE contract: the denial must ESCAPE the broad `except ValueError`
        # (i.e. it is a FivedriskDenial, not a ValueError) and the wrapped fn
        # must NOT run.
        with pytest.raises(FivedriskDenial):
            vulnerable_caller()
        assert executed["ran"] is False, "FAIL-OPEN: denylisted fetch executed"

    def test_FINDING_session_required_block_swallowed_by_except_valueerror(self, tmp_path):
        _reset(tmp_path, require_session_id=True)

        executed = {"ran": False}

        @gate(tool_name="Bash")
        def run(command: str) -> str:
            executed["ran"] = True
            return "EXECUTED"

        def vulnerable_caller():
            try:
                return run(command="echo hi")  # no session_id supplied
            except ValueError:
                return "SWALLOWED"

        with pytest.raises(FivedriskDenial):
            vulnerable_caller()
        assert executed["ran"] is False, "FAIL-OPEN: action ran with no session_id"

    def test_CHARACTERIZE_destination_block_is_fivedrisk_denial(self, tmp_path):
        """Characterization of the FIXED contract: the destination block raises a
        DestinationBlockError (a FivedriskDenial), NOT a swallowable ValueError —
        the same shape as the band path (BandBlockError)."""
        _reset(tmp_path, destination_denylist=["evil.com"])

        @gate(tool_name="WebFetch")
        def fetch(url: str) -> str:
            return "FETCHED"

        with pytest.raises(DestinationBlockError) as ei:
            fetch(url="https://evil.com/exfil")
        assert isinstance(ei.value, FivedriskDenial)
        assert not isinstance(ei.value, ValueError), (
            "destination block must NOT be a ValueError -> unswallowable by "
            "`except ValueError`")

    def test_CHARACTERIZE_session_required_block_is_fivedrisk_denial(self, tmp_path):
        """Sibling characterization for the session-required block."""
        _reset(tmp_path, require_session_id=True)

        @gate(tool_name="Bash")
        def run(command: str) -> str:
            return "EXECUTED"

        with pytest.raises(SessionRequiredError) as ei:
            run(command="echo hi")
        assert isinstance(ei.value, FivedriskDenial)
        assert not isinstance(ei.value, ValueError)
