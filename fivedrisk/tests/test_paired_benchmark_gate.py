"""Acceptance contracts for the paired same-runner performance gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
AGGREGATOR = ROOT / "benchmarks" / "aggregate_paired_results.py"
CHECKER = ROOT / "benchmarks" / "check_regression.py"


def _measurement(p99_us: float, *, runs: int = 1) -> dict:
    return {
        "env": {"cpu": "arm64", "platform": "Darwin", "python": "3.14.6"},
        "runs": runs,
        "scenarios": {
            "steady": {"n": 1000, "p50_us": 50.0, "p99_us": p99_us},
        },
    }


def _write_pairs(
    root: Path,
    *,
    base_first_candidate: float,
    candidate_first_candidate: float,
    outlier_pair: int | None = None,
) -> None:
    root.mkdir()
    for pair in range(1, 13):
        order = "base-first" if pair % 2 else "candidate-first"
        candidate = (
            base_first_candidate if order == "base-first" else candidate_first_candidate
        )
        if pair == outlier_pair:
            candidate = 10_000.0
        for subject, value in (("base", 100.0), ("candidate", candidate)):
            path = root / f"pair-{pair:02d}-{order}-{subject}.json"
            path.write_text(json.dumps(_measurement(value)), encoding="utf-8")


def _aggregate(tmp_path: Path, **kwargs) -> tuple[subprocess.CompletedProcess[str], dict]:
    runs = tmp_path / "runs"
    output = tmp_path / "summaries"
    _write_pairs(runs, **kwargs)
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


def test_paired_aggregator_classifies_stable_pass(tmp_path):
    result, diagnostics = _aggregate(
        tmp_path, base_first_candidate=110.0, candidate_first_candidate=110.0
    )
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"
    assert diagnostics["pair_count"] == 12
    assert diagnostics["order_counts"] == {"base-first": 6, "candidate-first": 6}


def test_paired_aggregator_classifies_stable_regression(tmp_path):
    result, diagnostics = _aggregate(
        tmp_path, base_first_candidate=140.0, candidate_first_candidate=140.0
    )
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "stable-regression"


def test_paired_aggregator_classifies_order_effect_as_inconclusive(tmp_path):
    result, diagnostics = _aggregate(
        tmp_path, base_first_candidate=140.0, candidate_first_candidate=90.0
    )
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "inconclusive"


def test_paired_aggregator_resists_one_outlier_and_is_permutation_invariant(tmp_path):
    result, diagnostics = _aggregate(
        tmp_path, base_first_candidate=110.0, candidate_first_candidate=110.0,
        outlier_pair=1,
    )
    assert result.returncode == 0, result.stderr
    assert diagnostics["scenarios"]["steady"]["classification"] == "pass"

    runs = tmp_path / "runs"
    first = runs / "pair-01-base-first-candidate.json"
    third = runs / "pair-03-base-first-candidate.json"
    first_text, third_text = first.read_text(), third.read_text()
    first.write_text(third_text, encoding="utf-8")
    third.write_text(first_text, encoding="utf-8")
    second_output = tmp_path / "summaries-permuted"
    rerun = subprocess.run(
        (
            sys.executable, "-I", str(AGGREGATOR), "--input-dir", str(runs),
            "--output-dir", str(second_output),
        ),
        check=False, capture_output=True, text=True,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert json.loads((second_output / "overall-candidate.json").read_text()) == json.loads(
        (tmp_path / "summaries" / "overall-candidate.json").read_text()
    )


@pytest.mark.parametrize("defect", ("environment", "scenario", "metric", "runs", "nan"))
def test_paired_aggregator_rejects_malformed_or_incomparable_inputs(tmp_path, defect):
    runs = tmp_path / "runs"
    _write_pairs(runs, base_first_candidate=110.0, candidate_first_candidate=110.0)
    target = runs / "pair-12-candidate-first-candidate.json"
    value = json.loads(target.read_text())
    if defect == "environment":
        value["env"]["python"] = "3.14.7"
    elif defect == "scenario":
        value["scenarios"] = {"other": value["scenarios"].pop("steady")}
    elif defect == "metric":
        value["scenarios"]["steady"]["p95_us"] = 80.0
    elif defect == "runs":
        value["runs"] = 0
    else:
        value["scenarios"]["steady"]["p99_us"] = float("nan")
    target.write_text(json.dumps(value), encoding="utf-8")

    result = subprocess.run(
        (
            sys.executable, "-I", str(AGGREGATOR), "--input-dir", str(runs),
            "--output-dir", str(tmp_path / "summaries"),
        ),
        check=False, capture_output=True, text=True,
    )
    assert result.returncode != 0


def test_benchmark_workflow_uses_protected_tools_and_balanced_fresh_processes():
    workflow = (ROOT / ".github" / "workflows" / "bench.yml").read_text()
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.pull_request.head.sha" in workflow
    assert 'cp "$BASE_TREE/benchmarks/bench_ci.py"' in workflow
    assert 'cp "$BASE_TREE/benchmarks/check_regression.py"' in workflow
    assert "aggregate_paired_results.py" in workflow
    assert "seq -w 1 12" in workflow
    assert '10#$pair % 2' in workflow
    assert "--runs 1 --json" in workflow
    assert workflow.count("--threshold 0.30 --min-abs-us 25") == 4
    assert "positive-control-current.json" in workflow
    assert "persist-credentials: false" in workflow
    assert 'python-version: "3.14.6"' in workflow


def test_benchmark_driver_documents_the_enforced_dual_threshold():
    driver = (ROOT / "benchmarks" / "bench_ci.py").read_text()
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
