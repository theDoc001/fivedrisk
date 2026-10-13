"""Acceptance contracts for the paired crossover performance gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
AGGREGATOR = ROOT / "benchmarks" / "aggregate_paired_results.py"
CHECKER = ROOT / "benchmarks" / "check_regression.py"
DRIVER = ROOT / "benchmarks" / "bench_ci.py"
DESIGNS = {
    "abba": ("base", "candidate", "candidate", "base"),
    "baab": ("candidate", "base", "base", "candidate"),
}


def _measurement(p99_us: float, *, runs_marker=...) -> dict:
    value = {
        "env": {"cpu": "arm64", "platform": "Darwin", "python": "3.14.6"},
        "scenarios": {
            "steady": {"n": 2000, "p50_us": 50.0, "p99_us": p99_us},
        },
    }
    if runs_marker is not ...:
        value["runs"] = runs_marker
    return value


def _write_blocks(
    root: Path,
    *,
    candidate_by_design: dict[str, float] | None = None,
    value_for=None,
) -> None:
    root.mkdir()
    candidate_by_design = candidate_by_design or {"abba": 110.0, "baab": 110.0}
    for block in range(1, 13):
        design = "abba" if block % 2 else "baab"
        for position, subject in enumerate(DESIGNS[design], start=1):
            if value_for is None:
                p99 = 100.0 if subject == "base" else candidate_by_design[design]
            else:
                p99 = value_for(block, design, position, subject)
            path = root / f"block-{block:02d}-{design}-pos-{position}-{subject}.json"
            path.write_text(json.dumps(_measurement(p99)), encoding="utf-8")


def _run_aggregator(tmp_path: Path, **kwargs) -> tuple[subprocess.CompletedProcess[str], dict]:
    runs = tmp_path / "runs"
    output = tmp_path / "summaries"
    _write_blocks(runs, **kwargs)
    result = subprocess.run(
        (
            sys.executable,
            "-I",
            str(AGGREGATOR),
            "--input-dir",
            str(runs),
            "--output-dir",
            str(output),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    diagnostics = {}
    if (output / "diagnostics.json").exists():
        diagnostics = json.loads((output / "diagnostics.json").read_text())
    return result, diagnostics


def test_crossover_aggregator_classifies_stable_pass(tmp_path):
    result, diagnostics = _run_aggregator(tmp_path)
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"
    assert diagnostics["block_count"] == 12
    assert diagnostics["design_counts"] == {"abba": 6, "baab": 6}


def test_crossover_aggregator_classifies_stable_regression_and_exits_nonzero(tmp_path):
    base = 26.0 / 0.31
    candidate = base + 26.0
    result, diagnostics = _run_aggregator(
        tmp_path,
        value_for=lambda _b, _d, _p, subject: (
            base if subject == "base" else candidate
        ),
    )
    assert result.returncode == 1
    assert diagnostics["scenarios"]["steady"]["classification"] == "stable-regression"


@pytest.mark.parametrize(
    "candidate_by_design",
    (
        {"abba": 140.0, "baab": 100.0},
        {"abba": 200.0, "baab": 125.0},
    ),
)
def test_crossover_aggregator_classifies_design_disagreement_as_inconclusive(
    tmp_path, candidate_by_design
):
    result, diagnostics = _run_aggregator(
        tmp_path, candidate_by_design=candidate_by_design
    )
    assert result.returncode == 1
    assert diagnostics["scenarios"]["steady"]["classification"] == "inconclusive"


@pytest.mark.parametrize("drift", ("additive", "multiplicative"))
def test_crossover_position_balance_cancels_synthetic_drift(tmp_path, drift):
    def value_for(_block, _design, position, _subject):
        if drift == "additive":
            return 100.0 + 10.0 * position
        return 100.0 * (1.1 ** position)

    result, diagnostics = _run_aggregator(tmp_path, value_for=value_for)
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"


def test_crossover_median_resists_one_extreme_block(tmp_path):
    def value_for(block, _design, _position, subject):
        if block == 1 and subject == "candidate":
            return 10_000.0
        return 110.0 if subject == "candidate" else 100.0

    result, diagnostics = _run_aggregator(tmp_path, value_for=value_for)
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"


@pytest.mark.parametrize(
    ("base", "candidate"),
    ((100.0, 130.0), (100.0, 125.0)),
)
def test_threshold_equality_is_not_a_breach(tmp_path, base, candidate):
    result, diagnostics = _run_aggregator(
        tmp_path,
        value_for=lambda _b, _d, _p, subject: base if subject == "base" else candidate,
    )
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"


@pytest.mark.parametrize(
    "defect", ("missing", "duplicate", "extra", "mislabeled", "reordered")
)
def test_crossover_aggregator_rejects_invalid_block_structure(tmp_path, defect):
    runs = tmp_path / "runs"
    _write_blocks(runs)
    target = runs / "block-01-abba-pos-1-base.json"
    if defect == "missing":
        target.unlink()
    elif defect == "duplicate":
        duplicate = runs / "block-01-abba-pos-1-base-copy.json"
        duplicate.write_text(target.read_text(), encoding="utf-8")
    elif defect == "extra":
        (runs / "extra.json").write_text("{}", encoding="utf-8")
    elif defect == "mislabeled":
        target.rename(runs / "block-01-abba-pos-1-candidate.json")
    else:
        other = runs / "block-01-abba-pos-2-candidate.json"
        target.rename(runs / "block-01-abba-pos-2-base.json")
        other.rename(runs / "block-01-abba-pos-1-candidate.json")
    result = subprocess.run(
        (
            sys.executable, "-I", str(AGGREGATOR), "--input-dir", str(runs),
            "--output-dir", str(tmp_path / "summaries"),
        ),
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 1


@pytest.mark.parametrize(
    "defect",
    (
        "environment", "scenario", "metric", "runs_true", "runs_float",
        "runs_zero", "runs_negative", "nan", "nonpositive",
    ),
)
def test_crossover_aggregator_rejects_malformed_or_incomparable_inputs(tmp_path, defect):
    runs = tmp_path / "runs"
    _write_blocks(runs)
    target = runs / "block-12-baab-pos-4-candidate.json"
    value = json.loads(target.read_text())
    if defect == "environment":
        value["env"]["python"] = "3.14.7"
    elif defect == "scenario":
        value["scenarios"] = {"other": value["scenarios"].pop("steady")}
    elif defect == "metric":
        value["scenarios"]["steady"]["p95_us"] = 80.0
    elif defect == "runs_true":
        value["runs"] = True
    elif defect == "runs_float":
        value["runs"] = 1.0
    elif defect == "runs_zero":
        value["runs"] = 0
    elif defect == "runs_negative":
        value["runs"] = -1
    elif defect == "nan":
        value["scenarios"]["steady"]["p99_us"] = float("nan")
    else:
        value["scenarios"]["steady"]["p99_us"] = 0.0
    target.write_text(json.dumps(value), encoding="utf-8")

    result = subprocess.run(
        (
            sys.executable, "-I", str(AGGREGATOR), "--input-dir", str(runs),
            "--output-dir", str(tmp_path / "summaries"),
        ),
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 1


def test_single_run_driver_schema_is_accepted_by_aggregator(tmp_path):
    generated = subprocess.run(
        (sys.executable, "-B", "-I", str(DRIVER), "--runs", "1", "--json"),
        check=False, capture_output=True, text=True, cwd=tmp_path,
    )
    assert generated.returncode == 0, generated.stderr
    measurement = json.loads(generated.stdout)
    assert "runs" not in measurement

    runs = tmp_path / "runs"
    runs.mkdir()
    for block in range(1, 13):
        design = "abba" if block % 2 else "baab"
        for position, subject in enumerate(DESIGNS[design], start=1):
            path = runs / f"block-{block:02d}-{design}-pos-{position}-{subject}.json"
            path.write_text(json.dumps(measurement), encoding="utf-8")
    result = subprocess.run(
        (
            sys.executable, "-I", str(AGGREGATOR), "--input-dir", str(runs),
            "--output-dir", str(tmp_path / "summaries"),
        ),
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("invalid", ("0", "-1"))
def test_driver_cli_rejects_invalid_run_count_before_benchmark(tmp_path, invalid):
    result = subprocess.run(
        (sys.executable, "-B", "-I", str(DRIVER), "--runs", invalid, "--json"),
        check=False, capture_output=True, text=True, cwd=tmp_path,
    )
    assert result.returncode != 0
    assert "positive integer" in result.stderr
    assert result.stdout == ""


def test_benchmark_workflow_uses_protected_tools_and_balanced_crossover_blocks():
    workflow = (ROOT / ".github" / "workflows" / "bench.yml").read_text()
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.pull_request.head.sha" in workflow
    assert 'cp "$BASE_TREE/benchmarks/bench_ci.py"' in workflow
    assert 'cp "$BASE_TREE/benchmarks/check_regression.py"' in workflow
    assert 'cp "$BASE_TREE/benchmarks/aggregate_paired_results.py"' in workflow
    assert "aggregator=protected-base" in workflow
    assert "seq -w 1 12" in workflow
    assert 'design="abba"' in workflow
    assert 'subjects="base candidate candidate base"' in workflow
    assert 'subjects="candidate base base candidate"' in workflow
    assert "--runs 1 --json" in workflow
    assert "--threshold 0.30 --min-abs-us 25" in workflow
    assert "positive-control-current.json" in workflow
    assert "persist-credentials: false" in workflow
    assert 'python-version: "3.14.6"' in workflow
    assert "bootstrap-candidate-infrastructure-only" not in workflow
    assert "c22213b513d4be167a0704244ad08c54e4ed1984" not in workflow
    assert 'cp "$CANDIDATE_TREE/benchmarks/aggregate_paired_results.py"' not in workflow


def test_benchmark_driver_documents_the_enforced_dual_threshold():
    driver = DRIVER.read_text()
    assert "more than 20%" not in driver
    assert "greater than 30%" in driver
    assert "greater than 25" in driver


def test_frozen_comparator_rejects_synthetic_slowdown_and_python_mismatch(tmp_path):
    baseline = _measurement(100.0)
    current = _measurement(131.0)
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    current_path.write_text(json.dumps(current), encoding="utf-8")
    slowdown = subprocess.run(
        (
            sys.executable, "-I", str(CHECKER), str(current_path), str(baseline_path),
            "--threshold", "0.30", "--min-abs-us", "25",
        ),
        check=False, capture_output=True, text=True,
    )
    assert slowdown.returncode == 1

    current["env"]["python"] = "3.14.7"
    current_path.write_text(json.dumps(current), encoding="utf-8")
    mismatch = subprocess.run(
        (sys.executable, "-I", str(CHECKER), str(current_path), str(baseline_path)),
        check=False, capture_output=True, text=True,
    )
    assert mismatch.returncode == 1
    assert "python" in mismatch.stderr
