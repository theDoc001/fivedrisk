"""Contract tests for the standalone benchmark comparison gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "benchmarks" / "check_regression.py"
AGGREGATOR = ROOT / "benchmarks" / "aggregate_results.py"


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


def _aggregate_result(
    tmp_path: Path, subject: str, first: dict, second: dict
) -> subprocess.CompletedProcess[str]:
    first_path = tmp_path / f"{subject}-a.json"
    second_path = tmp_path / f"{subject}-b.json"
    first_path.write_text(json.dumps(first), encoding="utf-8")
    second_path.write_text(json.dumps(second), encoding="utf-8")
    return subprocess.run(
        (
            sys.executable,
            "-I",
            str(AGGREGATOR),
            "--subject",
            subject,
            str(first_path),
            str(second_path),
        ),
        check=False,
        capture_output=True,
        text=True,
    )


def test_aggregate_combines_asymmetric_three_run_results_order_independently(tmp_path):
    first = _measurement(p99_us=90.0) | {"runs": 3}
    second = _measurement(p99_us=150.0) | {"runs": 3}
    result = _aggregate_result(tmp_path, "base", first, second)

    assert result.returncode == 0, result.stderr
    aggregate = json.loads(result.stdout)
    assert aggregate["runs"] == 6
    assert aggregate["subject"] == "base"
    assert aggregate["scenarios"]["steady_state"]["p99_us"] == 120.0

    reversed_result = subprocess.run(
        (
            sys.executable,
            "-I",
            str(AGGREGATOR),
            "--subject",
            "base",
            str(tmp_path / "base-b.json"),
            str(tmp_path / "base-a.json"),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert reversed_result.returncode == 0, reversed_result.stderr
    assert json.loads(reversed_result.stdout) == aggregate


def test_aggregate_rejects_environment_mismatch(tmp_path):
    first = _measurement(python="3.14.6") | {"runs": 3}
    second = _measurement(python="3.14.7") | {"runs": 3}
    result = _aggregate_result(tmp_path, "candidate", first, second)

    assert result.returncode != 0
    assert "environment" in result.stderr.lower()


def test_aggregate_rejects_nonfinite_measurement_and_invalid_runs(tmp_path):
    invalid_measurement = _measurement(p99_us=float("nan")) | {"runs": 3}
    result = _aggregate_result(
        tmp_path, "candidate", invalid_measurement, _measurement() | {"runs": 3}
    )
    assert result.returncode != 0
    assert "finite" in result.stderr.lower()

    invalid_runs = _measurement() | {"runs": 0}
    result = _aggregate_result(
        tmp_path, "candidate", invalid_runs, _measurement() | {"runs": 3}
    )
    assert result.returncode != 0
    assert "positive integer" in result.stderr.lower()


def test_aggregate_rejects_scenario_metric_and_subject_mixing(tmp_path):
    other_scenario = _measurement() | {"runs": 3}
    other_scenario["scenarios"] = {"different": {"p99_us": 100.0}}
    result = _aggregate_result(
        tmp_path, "base", _measurement() | {"runs": 3}, other_scenario
    )
    assert result.returncode != 0
    assert "scenario" in result.stderr.lower()

    other_metric = _measurement() | {"runs": 3}
    other_metric["scenarios"]["steady_state"]["p50_us"] = 50.0
    result = _aggregate_result(
        tmp_path, "candidate", _measurement() | {"runs": 3}, other_metric
    )
    assert result.returncode != 0
    assert "metric" in result.stderr.lower()

    mixed_path = tmp_path / "base-a.json"
    mixed_path.write_text(json.dumps(_measurement() | {"runs": 3}), encoding="utf-8")
    candidate_path = tmp_path / "candidate-a.json"
    candidate_path.write_text(json.dumps(_measurement() | {"runs": 3}), encoding="utf-8")
    result = subprocess.run(
        (
            sys.executable,
            "-I",
            str(AGGREGATOR),
            "--subject",
            "base",
            str(mixed_path),
            str(candidate_path),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "subject" in result.stderr.lower()
