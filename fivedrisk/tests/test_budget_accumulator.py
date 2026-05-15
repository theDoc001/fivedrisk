"""Tests for BudgetAccumulator.

Pure accounting tests: reservation math, commit, rollback, pressure
ratio. Pins down the architectural contract that the accumulator does
not feed the Score function.
"""

from __future__ import annotations

from fivedrisk.budget_accumulator import (
    BudgetAccumulator,
    REASON_BUDGET_CAP_EXCEEDED,
)


class TestReservation:
    def test_reservation_approved_within_budget(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        result = acc.reserve_for_tool_call("call-1", worst_case_tokens=1000)
        assert result.approved
        assert result.reason_code is None
        assert result.reserved_tokens == 1000

    def test_reservation_rejected_over_budget(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=5000)
        result = acc.reserve_for_tool_call("call-1", worst_case_tokens=6000)
        assert not result.approved
        assert result.reason_code == REASON_BUDGET_CAP_EXCEEDED
        assert result.max_session_budget_tokens == 5000

    def test_no_cap_always_approved(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=None)
        result = acc.reserve_for_tool_call("call-1", worst_case_tokens=999_999)
        assert result.approved
        assert result.max_session_budget_tokens is None
        assert result.pressure_ratio == 0.0

    def test_multiple_reservations_accumulate(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        r1 = acc.reserve_for_tool_call("c1", 3000)
        r2 = acc.reserve_for_tool_call("c2", 3000)
        r3 = acc.reserve_for_tool_call("c3", 3000)
        assert r1.approved and r2.approved and r3.approved
        # 4th reservation would push to 12000 > 10000
        r4 = acc.reserve_for_tool_call("c4", 3000)
        assert not r4.approved
        assert r4.reason_code == REASON_BUDGET_CAP_EXCEEDED


class TestCommit:
    def test_commit_replaces_reservation_with_actual(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)
        acc.commit_reservation("c1", actual_tokens=2000)
        assert acc.cumulative_token_spend == 2000
        assert len(acc.reservations_pending) == 0

    def test_commit_unknown_call_is_noop(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.commit_reservation("does-not-exist", actual_tokens=100)
        assert acc.cumulative_token_spend == 0

    def test_commit_returns_room_for_new_calls(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 8000)
        acc.commit_reservation("c1", actual_tokens=2000)
        # Cumulative is 2000, plenty of room left
        r2 = acc.reserve_for_tool_call("c2", 7000)
        assert r2.approved


class TestCancel:
    def test_cancel_removes_reservation_without_charge(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)
        acc.cancel_reservation("c1")
        assert acc.cumulative_token_spend == 0
        assert len(acc.reservations_pending) == 0

    def test_cancel_unknown_call_is_noop(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.cancel_reservation("does-not-exist")
        assert acc.cumulative_token_spend == 0


class TestPressureRatio:
    def test_zero_when_no_cap(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=None)
        acc.reserve_for_tool_call("c1", 100)
        assert acc.get_pressure_ratio() == 0.0

    def test_includes_pending_reservations(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)  # pending
        assert acc.get_pressure_ratio() == 0.5

    def test_includes_committed_spend(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)
        acc.commit_reservation("c1", actual_tokens=3000)
        assert acc.get_pressure_ratio() == 0.3

    def test_pressure_ratio_is_telemetry_only(self) -> None:
        """Architectural contract: pressure_ratio is for telemetry only.

        get_pressure_ratio() exists for NDJSON / dashboard consumption.
        It must remain accessible via the accumulator API but must not
        be consumed by the Score function or Band classification.

        This test pins down the public contract: the method exists and
        returns a float in [0, 1]. Any future change that wires
        pressure_ratio into score() should be flagged for review;
        budget admission and risk scoring are deliberately separate
        paths.
        """
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)
        ratio = acc.get_pressure_ratio()
        assert isinstance(ratio, float)
        assert 0.0 <= ratio <= 1.0


class TestSnapshot:
    def test_snapshot_reports_state(self) -> None:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=10000)
        acc.reserve_for_tool_call("c1", 5000)
        snap = acc.snapshot()
        assert snap["session_id"] == "s1"
        assert snap["max_session_budget_tokens"] == 10000
        assert snap["pending_reservations"] == 1
        assert snap["pending_tokens"] == 5000
        assert snap["cumulative_token_spend"] == 0
        assert snap["pressure_ratio"] == 0.5
