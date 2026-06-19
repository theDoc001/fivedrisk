"""Tests for the plugin-IPC gateway (spec §6 L-1, L-5, L-6, §13)."""

from __future__ import annotations

import io
import json
import sqlite3
from typing import Any, Dict

import pytest

from fivedrisk import gateway
from fivedrisk.logger import DecisionLog
from fivedrisk.policy import Policy


@pytest.fixture
def log(tmp_path):
    """Per-test DecisionLog rooted in tmp_path."""
    return DecisionLog(tmp_path / "decisions.db")


@pytest.fixture
def policy():
    return Policy()


# ─── score_action_dict ────────────────────────────────────────────


def test_score_action_dict_green(policy, log):
    """A benign Read action scores GREEN."""
    request = {"tool_name": "Read", "params": {"file_path": "/tmp/x.txt"}}
    decision = gateway.score_action_dict(request, policy, log=log)

    assert decision["band"] == "GREEN"
    assert decision["scores"]["data_sensitivity"] == 0
    assert decision["scores"]["tool_privilege"] == 0
    assert decision["scores"]["reversibility"] == 0
    assert decision["audit_log_id"] >= 1
    assert decision["decision_id"] == f"dec-{decision['audit_log_id']}"
    assert "error" not in decision


def test_score_action_dict_red(policy, log):
    """rm -rf trips the bash overrides → RED."""
    request = {"tool_name": "Bash", "params": {"command": "rm -rf /tmp/data"}}
    decision = gateway.score_action_dict(request, policy, log=log)

    assert decision["band"] == "RED"
    # bash_override pushes tool_privilege and reversibility to 4
    assert decision["scores"]["tool_privilege"] == 4
    assert decision["scores"]["reversibility"] == 4


def test_score_action_dict_orange(policy, log):
    """A Bash command that hits a single high-risk axis → ORANGE."""
    # `docker` bash override sets tool_privilege=3, reversibility=2;
    # single-axis spike at 3 hits the ORANGE threshold.
    request = {"tool_name": "Bash", "params": {"command": "docker run --rm img"}}
    decision = gateway.score_action_dict(request, policy, log=log)

    assert decision["band"] == "ORANGE"
    assert decision["scores"]["tool_privilege"] >= 3


def test_score_action_dict_missing_tool_name(policy, log):
    request = {"params": {"command": "ls"}}
    decision = gateway.score_action_dict(request, policy, log=log)
    assert "error" in decision
    assert decision["error_type"] == "InvalidRequest"


def test_score_action_dict_non_dict_params(policy, log):
    request = {"tool_name": "Bash", "params": "rm -rf /"}
    decision = gateway.score_action_dict(request, policy, log=log)
    assert "error" in decision
    assert decision["error_type"] == "InvalidRequest"


# ─── serve_stdio ──────────────────────────────────────────────────


def _run_stdio(monkeypatch, lines, tmp_path):
    """Helper: feed `lines` into stdin, capture stdout, return JSON list."""
    monkeypatch.setattr("sys.stdin", io.StringIO("".join(lines)))
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    gateway.serve_stdio(policy_path=None, log_path=str(tmp_path / "log.db"))
    output_lines = [ln for ln in captured.getvalue().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in output_lines]


def test_serve_stdio_round_trip(monkeypatch, tmp_path):
    """Send two actions, get two decisions back, in order."""
    inputs = [
        json.dumps({"tool_name": "Read", "params": {"file_path": "/tmp/a"}}) + "\n",
        json.dumps({"tool_name": "Bash", "params": {"command": "rm -rf /tmp/b"}}) + "\n",
    ]
    decisions = _run_stdio(monkeypatch, inputs, tmp_path)

    assert len(decisions) == 2
    assert decisions[0]["band"] == "GREEN"
    assert decisions[1]["band"] == "RED"


def test_serve_stdio_skips_blank_lines(monkeypatch, tmp_path):
    inputs = [
        "\n",
        json.dumps({"tool_name": "Read", "params": {"file_path": "/tmp/a"}}) + "\n",
        "   \n",
    ]
    decisions = _run_stdio(monkeypatch, inputs, tmp_path)
    assert len(decisions) == 1
    assert decisions[0]["band"] == "GREEN"


def test_invalid_json_input(monkeypatch, tmp_path):
    """Malformed JSON returns an error JSON; loop does NOT crash."""
    inputs = [
        "not json at all\n",
        json.dumps({"tool_name": "Read", "params": {"file_path": "/tmp/a"}}) + "\n",
    ]
    decisions = _run_stdio(monkeypatch, inputs, tmp_path)

    assert len(decisions) == 2
    assert decisions[0]["error_type"] == "JSONDecodeError"
    assert decisions[1]["band"] == "GREEN"


# ─── score_oneshot ────────────────────────────────────────────────


def test_score_oneshot(monkeypatch, tmp_path):
    """One JSON in, one JSON out."""
    request = json.dumps({"tool_name": "Read", "params": {"file_path": "/tmp/a"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(request))
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)

    gateway.score_oneshot(policy_path=None, log_path=str(tmp_path / "log.db"))

    out_lines = [ln for ln in captured.getvalue().splitlines() if ln.strip()]
    assert len(out_lines) == 1
    decision = json.loads(out_lines[0])
    assert decision["band"] == "GREEN"
    assert decision["scores"]["data_sensitivity"] == 0


def test_score_oneshot_empty_stdin(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)

    gateway.score_oneshot(policy_path=None, log_path=str(tmp_path / "log.db"))

    decision = json.loads(captured.getvalue().strip())
    assert decision["error_type"] == "InvalidRequest"


# ─── resolve ──────────────────────────────────────────────────────


def test_resolve_idempotent(policy, tmp_path):
    """Calling resolve twice with the same args produces the same row state."""
    log_path = tmp_path / "log.db"
    log = DecisionLog(log_path)

    request = {"tool_name": "Bash", "params": {"command": "rm -rf /tmp/x"}}
    decision = gateway.score_action_dict(request, policy, log=log)
    decision_id = decision["decision_id"]

    first = gateway.resolve(decision_id, "deny", audit_log_path=str(log_path))
    second = gateway.resolve(decision_id, "deny", audit_log_path=str(log_path))

    assert first == second
    assert first["resolution"] == "deny"
    assert first["audit_log_id"] == decision["audit_log_id"]


def test_resolve_overwrite(policy, tmp_path):
    """Calling resolve with a different resolution overwrites (last-write-wins)."""
    log_path = tmp_path / "log.db"
    log = DecisionLog(log_path)

    request = {"tool_name": "Bash", "params": {"command": "rm -rf /tmp/x"}}
    decision = gateway.score_action_dict(request, policy, log=log)
    decision_id = decision["decision_id"]

    gateway.resolve(decision_id, "deny", audit_log_path=str(log_path))
    result = gateway.resolve(decision_id, "allow-once", audit_log_path=str(log_path))
    assert result["resolution"] == "allow-once"


def test_resolve_accepts_bare_integer(policy, tmp_path):
    log_path = tmp_path / "log.db"
    log = DecisionLog(log_path)
    request = {"tool_name": "Read", "params": {"file_path": "/tmp/a"}}
    decision = gateway.score_action_dict(request, policy, log=log)
    bare = str(decision["audit_log_id"])

    result = gateway.resolve(bare, "allow-always", audit_log_path=str(log_path))
    assert result["resolution"] == "allow-always"


def test_resolve_rejects_unknown_resolution(tmp_path):
    result = gateway.resolve(
        "dec-1", "yolo", audit_log_path=str(tmp_path / "log.db")
    )
    assert result["error_type"] == "InvalidResolution"


def test_resolve_rejects_malformed_id(tmp_path):
    result = gateway.resolve("not-a-number", "deny", audit_log_path=str(tmp_path / "log.db"))
    assert result["error_type"] == "InvalidDecisionId"


def test_resolve_unknown_row(policy, tmp_path):
    log_path = tmp_path / "log.db"
    DecisionLog(log_path)  # create schema
    result = gateway.resolve("dec-9999", "deny", audit_log_path=str(log_path))
    assert result["error_type"] == "NotFound"


# ─── trace propagation ───────────────────────────────────────────


def test_trace_fields_round_trip(policy, tmp_path):
    """trace_id, span_id, parent_span_id flow through metadata into log + response."""
    log_path = tmp_path / "log.db"
    log = DecisionLog(log_path)

    request = {
        "tool_name": "Read",
        "params": {"file_path": "/tmp/x"},
        "trace_id": "trace-abc-123",
        "span_id": "span-1",
        "parent_span_id": "span-0",
        "agent_id": "agent-x",
        "session_id": "sess-y",
        "run_id": "run-z",
    }
    decision = gateway.score_action_dict(request, policy, log=log)

    # 1. Decision dict echoes the trace fields.
    assert decision["trace_id"] == "trace-abc-123"
    assert decision["span_id"] == "span-1"
    assert decision["parent_span_id"] == "span-0"
    assert decision["agent_id"] == "agent-x"
    assert decision["session_id"] == "sess-y"
    assert decision["run_id"] == "run-z"

    # 2. Audit log persisted the metadata JSON.
    with sqlite3.connect(log_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT metadata, session_id FROM decisions WHERE id = ?",
            (decision["audit_log_id"],),
        ).fetchone()
    assert row["session_id"] == "sess-y"
    persisted = json.loads(row["metadata"])
    assert persisted["trace_id"] == "trace-abc-123"
    assert persisted["span_id"] == "span-1"
    assert persisted["parent_span_id"] == "span-0"
    assert persisted["agent_id"] == "agent-x"
    assert persisted["run_id"] == "run-z"


# ─── CLI main() dispatch ─────────────────────────────────────────


def test_main_score_subcommand(monkeypatch, tmp_path):
    request = json.dumps({"tool_name": "Read", "params": {"file_path": "/tmp/a"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(request))
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)

    rc = gateway.main(["score", "--log-path", str(tmp_path / "log.db")])
    assert rc == 0
    decision = json.loads(captured.getvalue().strip())
    assert decision["band"] == "GREEN"


def test_main_resolve_subcommand(monkeypatch, policy, tmp_path):
    log_path = tmp_path / "log.db"
    log = DecisionLog(log_path)
    request = {"tool_name": "Read", "params": {"file_path": "/tmp/a"}}
    decision = gateway.score_action_dict(request, policy, log=log)

    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    rc = gateway.main([
        "resolve",
        "--decision-id", decision["decision_id"],
        "--resolution", "allow-once",
        "--log-path", str(log_path),
    ])
    assert rc == 0
    out = json.loads(captured.getvalue().strip())
    assert out["resolution"] == "allow-once"


def test_main_resolve_returns_nonzero_on_bad_id(monkeypatch, tmp_path):
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    rc = gateway.main([
        "resolve",
        "--decision-id", "bogus",
        "--resolution", "deny",
        "--log-path", str(tmp_path / "log.db"),
    ])
    assert rc == 1
