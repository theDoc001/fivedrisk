"""Contract tests for the standalone benchmark comparison gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "benchmarks" / "check_regression.py"


def _result(tmp_path: Path, current: dict, baseline: dict) -> subprocess.CompletedProcess[str]:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    return subprocess.run(
        (sys.executable, "-I", str(CHECKER), str(current_path), str(baseline_path)),
        check=False,
        capture_output=True,
        text=True,
    )


def _measurement(*, python: str = "3.14.6", p99_us: float = 100.0) -> dict:
    return {
        "env": {"cpu": "arm64", "platform": "Darwin", "python": python},
        "scenarios": {"steady_state": {"p99_us": p99_us}},
    }


def test_identical_environment_and_results_pass(tmp_path):
    baseline = _measurement()
    result = _result(tmp_path, baseline, baseline)
    assert result.returncode == 0, result.stderr


def test_python_runtime_mismatch_fails_closed(tmp_path):
    result = _result(
        tmp_path,
        _measurement(python="3.12.12"),
        _measurement(python="3.14.6"),
    )
    assert result.returncode == 1
    assert "python" in result.stderr


def test_same_environment_latency_regression_still_fails(tmp_path):
    result = _result(tmp_path, _measurement(p99_us=200.0), _measurement())
    assert result.returncode == 1
    assert "steady_state" in result.stderr
