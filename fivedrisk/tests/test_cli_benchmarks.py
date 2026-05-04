"""CLI and benchmark-runner coverage."""

from __future__ import annotations

import json

import pytest

from fivedrisk.benchmarks import run_runtime_benchmarks
from fivedrisk.cli import main
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


class TestCliBenchmark:
    def test_benchmark_text_command_succeeds(self, monkeypatch, capsys, tmp_path):
        code, output = _invoke_cli(
            monkeypatch,
            capsys,
            ["fivedrisk", "--log-path", str(tmp_path / "bench.db"), "benchmark"],
        )
        assert code == 0
        assert "5D runtime benchmark" in output

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
        assert code == 1
        assert "[5D ORANGE]" in output
