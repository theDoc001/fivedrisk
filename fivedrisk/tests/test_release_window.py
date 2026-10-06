from __future__ import annotations

import datetime as dt
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_window", ROOT / "tools" / "release_window.py"
)
assert SPEC and SPEC.loader
release_window = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_window
SPEC.loader.exec_module(release_window)


def _utc(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value).replace(tzinfo=dt.timezone.utc)


@pytest.mark.parametrize(
    ("local_value", "allowed"),
    [
        ("2026-01-15T18:59:59+01:00", False),
        ("2026-01-15T19:00:00+01:00", True),
        ("2026-01-15T06:59:59+01:00", True),
        ("2026-01-15T07:00:00+01:00", False),
    ],
)
def test_exact_local_boundaries(local_value: str, allowed: bool):
    instant = dt.datetime.fromisoformat(local_value)
    assert release_window.decide(instant).allowed is allowed


@pytest.mark.parametrize(
    ("utc_value", "expected_hour", "expected_offset"),
    [
        ("2026-01-15T18:00:00", 19, dt.timedelta(hours=1)),
        ("2026-07-15T17:00:00", 19, dt.timedelta(hours=2)),
        ("2026-03-29T00:59:59", 1, dt.timedelta(hours=1)),
        ("2026-03-29T01:00:00", 3, dt.timedelta(hours=2)),
        ("2026-10-25T00:59:59", 2, dt.timedelta(hours=2)),
        ("2026-10-25T01:00:00", 2, dt.timedelta(hours=1)),
    ],
)
def test_iana_timezone_conversion(
    utc_value: str, expected_hour: int, expected_offset: dt.timedelta
):
    decision = release_window.decide(_utc(utc_value))
    assert decision.local_time.hour == expected_hour
    assert decision.local_time.utcoffset() == expected_offset


def test_naive_time_fails_closed():
    with pytest.raises(release_window.ReleaseWindowError, match="naive"):
        release_window.decide(dt.datetime(2026, 1, 1, 20))


def test_clock_exception_fails_closed():
    def broken_clock() -> dt.datetime:
        raise OSError("clock unavailable")

    with pytest.raises(release_window.ReleaseWindowError, match="clock read failed"):
        release_window.current_decision(clock=broken_clock)


def test_missing_timezone_data_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def missing_zone(_: str):
        raise release_window.ZoneInfoNotFoundError("missing")

    monkeypatch.setattr(release_window, "ZoneInfo", missing_zone)
    with pytest.raises(release_window.ReleaseWindowError, match="timezone data"):
        release_window.decide(_utc("2026-01-15T18:00:00"))


@pytest.mark.parametrize(
    ("utc_value", "schedule", "matches"),
    [
        ("2026-01-15T18:05:00", "5 18 * * *", True),
        ("2026-01-15T18:05:00", "5 17 * * *", False),
        ("2026-07-15T17:05:00", "5 17 * * *", True),
        ("2026-07-15T17:05:00", "5 18 * * *", False),
    ],
)
def test_scheduled_slot_tracks_dst(utc_value: str, schedule: str, matches: bool):
    local = release_window.decide(_utc(utc_value)).local_time
    assert release_window.scheduled_slot_matches(schedule, local) is matches


def test_inactive_dst_schedule_is_a_clean_noop(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        release_window,
        "current_decision",
        lambda: release_window.decide(_utc("2026-07-15T18:05:00")),
    )
    assert release_window.main(
        ["--action", "workflow-dispatch", "--scheduled-expression", "5 18 * * *"]
    ) == 3


def test_documented_gate_command_ignores_hostile_pythonpath(tmp_path: Path):
    (tmp_path / "zoneinfo.py").write_text(
        "raise RuntimeError('hostile PYTHONPATH module loaded')\n", encoding="utf-8"
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-I", "tools/release_window.py", "--help"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "hostile PYTHONPATH" not in result.stderr


def test_every_shipped_gate_invocation_uses_isolated_python():
    hook = (ROOT / ".githooks" / "pre-push").read_text(encoding="utf-8")
    assert 'python3 -I "$gate" --action push' in hook
    for workflow_name in ("release-gate.yml", "publish.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        gate_lines = [
            line.strip()
            for line in workflow.splitlines()
            if "tools/release_window.py" in line
            and "python" in line
            and "grep -F" not in line
        ]
        assert gate_lines
        assert all("python -I tools/release_window.py" in line for line in gate_lines)
