#!/usr/bin/env python3
"""Fail-closed publication window gate for fivedrisk.

The only permitted window is 19:00 inclusive through 07:00 exclusive in
Europe/Tirane. The command deliberately has no time, timezone, or force override.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from dataclasses import dataclass
from typing import Callable, Sequence

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment,misc]
    ZoneInfoNotFoundError = Exception  # type: ignore[assignment,misc]


ZONE_NAME = "Europe/Tirane"
OPEN_HOUR = 19
CLOSE_HOUR = 7
SCHEDULES = frozenset({"5 17 * * *", "5 18 * * *"})
ACTIONS = (
    "attestation",
    "github-release",
    "merge",
    "package-publish",
    "plugin-publish",
    "push",
    "ruleset-update",
    "tag",
    "workflow-dispatch",
)


class ReleaseWindowError(RuntimeError):
    """Raised when the gate cannot establish a trustworthy decision."""


@dataclass(frozen=True)
class WindowDecision:
    allowed: bool
    local_time: dt.datetime
    reason: str


def _tirane_zone() -> dt.tzinfo:
    if ZoneInfo is None:
        raise ReleaseWindowError("zoneinfo is unavailable")
    try:
        return ZoneInfo(ZONE_NAME)
    except (ZoneInfoNotFoundError, OSError) as exc:
        raise ReleaseWindowError(f"timezone data unavailable for {ZONE_NAME}") from exc


def decide(instant: dt.datetime, *, zone: dt.tzinfo | None = None) -> WindowDecision:
    """Return the window decision for an aware instant, failing on ambiguity."""

    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise ReleaseWindowError("clock returned a naive or invalid datetime")
    try:
        if instant.utcoffset() is None:
            raise ReleaseWindowError("clock returned a naive datetime")
        local = instant.astimezone(zone or _tirane_zone())
    except ReleaseWindowError:
        raise
    except Exception as exc:
        raise ReleaseWindowError("clock conversion failed") from exc
    allowed = local.hour >= OPEN_HOUR or local.hour < CLOSE_HOUR
    boundary = "inside" if allowed else "outside"
    return WindowDecision(
        allowed=allowed,
        local_time=local,
        reason=f"{boundary} the 19:00-07:00 {ZONE_NAME} publication window",
    )


def current_decision(
    *, clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc)
) -> WindowDecision:
    try:
        instant = clock()
    except Exception as exc:
        raise ReleaseWindowError("clock read failed") from exc
    return decide(instant)


def scheduled_slot_matches(schedule: str, local_time: dt.datetime) -> bool:
    """Accept only the UTC cron that represents 19:05 at the current offset."""

    if schedule not in SCHEDULES:
        raise ReleaseWindowError("unknown scheduled publication expression")
    offset = local_time.utcoffset()
    if offset is None or offset.total_seconds() % 3600:
        raise ReleaseWindowError("unsupported local UTC offset")
    utc_hour = (OPEN_HOUR - int(offset.total_seconds() // 3600)) % 24
    return schedule == f"5 {utc_hour} * * *"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=ACTIONS)
    parser.add_argument(
        "--scheduled-expression",
        choices=sorted(SCHEDULES),
        help="GitHub schedule event value; validates the active DST slot",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        decision = current_decision()
        if args.scheduled_expression and not scheduled_slot_matches(
            args.scheduled_expression, decision.local_time
        ):
            print("INACTIVE: alternate Europe/Tirane DST schedule slot")
            return 3
    except ReleaseWindowError as exc:
        print(f"DENY: release-window gate failed closed: {exc}", file=sys.stderr)
        return 2
    stamp = decision.local_time.isoformat(timespec="seconds")
    if not decision.allowed:
        print(f"DENY: {args.action} at {stamp}: {decision.reason}", file=sys.stderr)
        return 2
    print(f"ALLOW: {args.action} at {stamp}: {decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
