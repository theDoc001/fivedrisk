"""CLI and benchmark-runner coverage."""

from __future__ import annotations

import json

import pytest

from fivedrisk.benchmarks import run_runtime_benchmarks
from fivedrisk.cli import main
from fivedrisk.harness import build_default_registry, run_harness
from fivedrisk.logger import DecisionLog
from fivedrisk.schema import Action, Band, ScoredAction


def _invoke_cli(monkeypatch, capsys, argv: list[str]) -> tuple[int, str]:
    """Run the CLI and return `(exit_code, stdout)`."""
    monkeypatch.setattr("sys.argv", argv)
    exit_code = 0
    try:
        main()
    except SystemExit as exc:
        exit_code = exc.code
    output = capsys.readouterr().out
    return exit_code, output


class TestBenchmarkRunner:
    def test_runner_returns_passing_summary(self, tmp_path):
        summary = run_runtime_benchmarks(tmp_path / "bench.db")
        assert summary["failed"] == 0
        assert summary["passed"] == summary["total"]

    def test_runner_reports_total_cases(self, tmp_path):
        summary = run_runtime_benchmarks(tmp_path / "bench.db")
        assert summary["total"] == 39

    def test_runner_reports_suite_breakdown(self, tmp_path):
        summary = run_runtime_benchmarks(tmp_path / "bench.db")
        assert summary["suites"]["prompt_injection"] == 14
        assert summary["suites"]["egress"] == 12
        assert summary["suites"]["runtime_policy"] == 10
        assert summary["suites"]["retrieved_fixtures"] == 3

    def test_runner_uses_requested_log_path(self, tmp_path):
        path = tmp_path / "bench.db"
        run_runtime_benchmarks(path)
        assert path.exists()

    def test_runner_failures_list_is_empty_on_pass(self, tmp_path):
        summary = run_runtime_benchmarks(tmp_path / "bench.db")
        assert summary["failures"] == []

    def test_harness_registry_reports_all_cases(self):
        registry = build_default_registry()
        assert len(registry) == 39
        assert {scenario.suite for scenario in registry} == {
            "prompt_injection",
            "egress",
            "runtime_policy",
            "retrieved_fixtures",
        }

    def test_harness_summary_can_include_per_case_results(self, tmp_path):
        summary = run_harness(tmp_path / "bench.db").to_dict(include_results=True)
        assert summary["failed"] == 0
        assert len(summary["results"]) == 39
        assert summary["evaluation_mode"] == "deterministic_expectation_match"
        assert summary["mission_verdict"] == "met_registry_expectations"
        assert {
            "suite",
            "case",
            "kind",
            "mission",
            "expected_layer",
            "control_type",
            "expected",
            "observed",
            "passed",
            "verdict",
            "reason",
        }.issubset(summary["results"][0])

    def test_harness_summary_reports_control_mix(self, tmp_path):
        summary = run_harness(tmp_path / "bench.db").to_dict(include_results=False)
        assert summary["control_counts"] == {"positive": 33, "negative": 6}
        assert summary["observed_outcomes"]["allow"] == 6
        assert "statistical security proof" in summary["claim_limitations"][1]


class TestCliBenchmark:
    def test_benchmark_text_command_succeeds(self, monkeypatch, capsys, tmp_path):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "bench.db"), "benchmark"],
        )
        assert code == 0
        assert "5D runtime benchmark" in output
        assert "Evaluation: deterministic_expectation_match" in output
        assert "Claim limit:" in output

    def test_benchmark_json_command_succeeds(self, monkeypatch, capsys, tmp_path):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "bench.db"), "--format", "json", "benchmark"],
        )
        payload = json.loads(output)
        assert code == 0
        assert payload["failed"] == 0

    def test_benchmark_json_reports_pass_rate(self, monkeypatch, capsys, tmp_path):
        _, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "bench.db"), "--format", "json", "benchmark"],
        )
        payload = json.loads(output)
        assert payload["pass_rate"] == 1.0

    def test_benchmark_accepts_format_after_subcommand(self, monkeypatch, capsys, tmp_path):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "bench.db"), "benchmark", "--format", "json"],
        )
        payload = json.loads(output)
        assert code == 0
        assert payload["failed"] == 0

    def test_benchmark_json_can_include_per_scenario_results(self, monkeypatch, capsys, tmp_path):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            [
                "fivedrisk",
                "--log-path",
                str(tmp_path / "bench.db"),
                "benchmark",
                "--format",
                "json",
                "--include-results",
            ],
        )
        payload = json.loads(output)
        assert code == 0
        assert len(payload["results"]) == 39


class TestCliStats:
    def test_stats_uses_four_band_labels(self, monkeypatch, capsys, tmp_path):
        log = DecisionLog(tmp_path / "stats.db")
        for band in (Band.GREEN, Band.YELLOW, Band.ORANGE, Band.RED):
            log.log(
                ScoredAction(
                    action=Action(tool_name="Read", tool_input={}),
                    band=band,
                    composite_score=1.0,
                    max_dimension=1,
                    rationale="test",
                    policy_version="0.3.0",
                )
            )
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "stats.db"), "stats"],
        )
        assert code == 0
        assert "GREEN" in output
        assert "YELLOW" in output
        assert "ORANGE" in output
        assert "RED" in output

    def test_stats_json_reports_by_band(self, monkeypatch, capsys, tmp_path):
        log = DecisionLog(tmp_path / "stats.db")
        log.log(
            ScoredAction(
                action=Action(tool_name="Read", tool_input={}),
                band=Band.GREEN,
                composite_score=1.0,
                max_dimension=1,
                rationale="test",
                policy_version="0.3.0",
            )
        )
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "stats.db"), "--format", "json", "stats"],
        )
        payload = json.loads(output)
        assert code == 0
        assert payload["by_band"]["GREEN"] == 1


class TestCliValidate:
    def test_validate_builtin_policy_succeeds(self, monkeypatch, capsys):
        code, output = _invoke_cli(monkeypatch, capsys, ["fivedrisk", "validate"])
        assert code == 0
        assert "Policy valid" in output

    def test_validate_policy_file_succeeds(self, monkeypatch, capsys, tmp_path):
        # F-E: an absolute tmp path so this passes regardless of the cwd (it previously
        # relied on a relative `policy.yaml` present only when run from `dev/`).
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("version: '0.2.0'\n")
        code, output = _invoke_cli(monkeypatch, capsys, ["fivedrisk", "validate", str(policy_path)])
        assert code == 0
        assert f"Policy valid: {policy_path}" in output

    def test_validate_json_reports_valid(self, monkeypatch, capsys):
        code, output = _invoke_cli(monkeypatch, capsys, ["fivedrisk", "--format", "json", "validate"])
        payload = json.loads(output)
        assert code == 0
        assert payload["valid"] is True

    def test_validate_rejects_bad_semantic_review_regex(self, monkeypatch, capsys, tmp_path):
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            """
semantic_review_patterns:
  medical-claim:
    - "["
"""
        )
        code, output = _invoke_cli(monkeypatch, capsys, ["fivedrisk", "validate", str(policy_path)])
        assert code == 1
        assert "semantic_review_patterns.medical-claim invalid regex" in output

    def test_validate_rejects_non_list_semantic_review_patterns(self, monkeypatch, capsys, tmp_path):
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            """
semantic_review_patterns:
  medical-claim: "(?i)cures cancer"
"""
        )
        code, output = _invoke_cli(monkeypatch, capsys, ["fivedrisk", "validate", str(policy_path)])
        assert code == 1
        assert "semantic_review_patterns.medical-claim must be a list" in output


class TestCliScore:
    def test_score_json_exit_code_for_green_is_zero(self, monkeypatch, capsys):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--format", "json", "score", "--dry-run", '{"tool_name":"Read","tool_input":{"file_path":"/tmp/a"}}'],
        )
        payload = json.loads(output)
        assert code == 0
        assert payload["band"] == "GREEN"

    def test_score_text_includes_rationale(self, monkeypatch, capsys):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "score", "--dry-run", '{"tool_name":"Bash","tool_input":{"command":"docker compose up -d"}}'],
        )
        # H6/Q7: ORANGE ("mandatory approval") blocks -> exit 2 (only exit 2 blocks
        # under host hook semantics; exit 1 would let the action run unreviewed).
        assert code == 2
        assert "[5D ORANGE]" in output

    def test_score_orange_exits_blocking_code_2(self, monkeypatch, capsys):
        # Explicit H6 regression: ORANGE must exit 2, not 1.
        code, _ = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "score", "--dry-run", '{"tool_name":"Bash","tool_input":{"command":"docker compose up -d"}}'],
        )
        assert code == 2


class TestCliScanOutput:
    def test_leak_output_blocks_exit_2(self, monkeypatch, capsys):
        # E1: PostToolUse egress scan — a leaking result blocks with exit 2.
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--format", "json", "scan-output",
             '{"tool_name":"Bash","tool_result":"password=hunter2secret"}'],
        )
        assert code == 2
        assert json.loads(output)["decision"] == "block"

    def test_clean_output_exit_0(self, monkeypatch, capsys):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--format", "json", "scan-output",
             '{"tool_name":"Read","tool_result":"the analysis is positive"}'],
        )
        assert code == 0
        assert json.loads(output) == {}
