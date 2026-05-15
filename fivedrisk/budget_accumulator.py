"""Per-session budget accumulator for cost-management primitives.

This module is pure accounting. It tracks cumulative token spend per
session and answers reservation requests. It does NOT feed the 5D Score
function or Band classification — budget admission and risk scoring are
deliberately separate paths.

The accumulator answers three operational questions:

  1. Can this tool call be reserved without exceeding the session budget?
     (used by the @gate interceptor to decide direct DENY vs allow)
  2. How much have I spent vs my cap, as a ratio?
     (informational; pressure_ratio is for telemetry, not scoring)
  3. Roll the reservation forward to actual cost when the call completes,
     freeing the difference back into the session budget.

Architectural contract: this module exports get_pressure_ratio() for
telemetry / NDJSON consumption only. The ratio is not wired into Score
or Band calculation anywhere in this codebase. Budget breach surfaces
as a direct DENY at the @gate reservation gate, separate from the risk
scoring path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional


@dataclass
class Reservation:
    """One outstanding tool-call reservation.

    Created by reserve_for_tool_call(). Resolved by commit_reservation()
    (actual cost) or rolled back by cancel_reservation() (call aborted).
    """

    tool_id: str
    worst_case_tokens: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ReservationResult:
    """Outcome of a reservation attempt."""

    approved: bool
    reason_code: Optional[str] = None       # None when approved, else error code
    cumulative_token_spend: int = 0
    max_session_budget_tokens: Optional[int] = None
    pressure_ratio: float = 0.0
    reserved_tokens: int = 0                # the amount that would be reserved


# Reason codes used in NDJSON budget_intervention events.
REASON_BUDGET_CAP_EXCEEDED = "BUDGET_CAP_EXCEEDED"
REASON_BUDGET_RESERVATION_BLOCKED = "BUDGET_RESERVATION_BLOCKED"


@dataclass
class BudgetAccumulator:
    """Per-session token-budget accumulator.

    Usage:
        acc = BudgetAccumulator(session_id="s1", max_session_budget_tokens=100_000)
        result = acc.reserve_for_tool_call("call-1", worst_case_tokens=5_000)
        if not result.approved:
            # @gate emits DENY + budget_intervention NDJSON event
            ...
        else:
            actual = run_the_call()
            acc.commit_reservation("call-1", actual_tokens=actual)
    """

    session_id: str
    max_session_budget_tokens: Optional[int] = None
    cumulative_token_spend: int = 0
    reservations_pending: Dict[str, Reservation] = field(default_factory=dict)

    def reserve_for_tool_call(
        self,
        tool_id: str,
        worst_case_tokens: int,
    ) -> ReservationResult:
        """Attempt to reserve the worst-case token cost for a tool call.

        If the reservation would push committed+pending spend above
        max_session_budget_tokens, the reservation is REJECTED and the
        caller is expected to emit a direct DENY (NOT a Score modifier).

        If max_session_budget_tokens is None (no cap configured), the
        reservation is always approved; pressure_ratio is reported as 0.
        """
        if self.max_session_budget_tokens is None:
            # No cap configured. Track the reservation for accounting but
            # do not gate.
            self.reservations_pending[tool_id] = Reservation(
                tool_id=tool_id, worst_case_tokens=worst_case_tokens
            )
            return ReservationResult(
                approved=True,
                cumulative_token_spend=self.cumulative_token_spend,
                max_session_budget_tokens=None,
                pressure_ratio=0.0,
                reserved_tokens=worst_case_tokens,
            )

        pending_total = sum(r.worst_case_tokens for r in self.reservations_pending.values())
        projected_total = self.cumulative_token_spend + pending_total + worst_case_tokens

        if projected_total > self.max_session_budget_tokens:
            return ReservationResult(
                approved=False,
                reason_code=REASON_BUDGET_CAP_EXCEEDED,
                cumulative_token_spend=self.cumulative_token_spend,
                max_session_budget_tokens=self.max_session_budget_tokens,
                pressure_ratio=self._compute_pressure_ratio(),
                reserved_tokens=worst_case_tokens,
            )

        self.reservations_pending[tool_id] = Reservation(
            tool_id=tool_id, worst_case_tokens=worst_case_tokens
        )
        return ReservationResult(
            approved=True,
            cumulative_token_spend=self.cumulative_token_spend,
            max_session_budget_tokens=self.max_session_budget_tokens,
            pressure_ratio=self._compute_pressure_ratio(),
            reserved_tokens=worst_case_tokens,
        )

    def commit_reservation(self, tool_id: str, actual_tokens: int) -> None:
        """Replace the worst-case reservation with the actual token cost.

        If actual_tokens < worst_case, the difference is returned to the
        session budget. If the reservation does not exist (e.g. already
        committed or rolled back), this is a no-op.
        """
        if tool_id not in self.reservations_pending:
            return
        del self.reservations_pending[tool_id]
        self.cumulative_token_spend += max(0, actual_tokens)

    def cancel_reservation(self, tool_id: str) -> None:
        """Roll back a reservation without committing any spend.

        Used when a tool call is aborted before invocation. No-op if the
        reservation does not exist.
        """
        self.reservations_pending.pop(tool_id, None)

    def get_pressure_ratio(self) -> float:
        """Return cumulative_spend / max_budget. 0.0 if no cap configured.

        For telemetry / NDJSON consumption only. Score and Band
        classification do not consume budget state; budget admission is a
        separate path.
        """
        return self._compute_pressure_ratio()

    def _compute_pressure_ratio(self) -> float:
        if self.max_session_budget_tokens is None or self.max_session_budget_tokens == 0:
            return 0.0
        pending_total = sum(r.worst_case_tokens for r in self.reservations_pending.values())
        return (self.cumulative_token_spend + pending_total) / self.max_session_budget_tokens

    def snapshot(self) -> dict:
        """Return current accumulator state for logging/auditing."""
        return {
            "session_id": self.session_id,
            "cumulative_token_spend": self.cumulative_token_spend,
            "max_session_budget_tokens": self.max_session_budget_tokens,
            "pending_reservations": len(self.reservations_pending),
            "pending_tokens": sum(r.worst_case_tokens for r in self.reservations_pending.values()),
            "pressure_ratio": self._compute_pressure_ratio(),
        }
