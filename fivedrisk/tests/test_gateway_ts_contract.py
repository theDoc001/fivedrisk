"""M4 — gateway wire-contract lock for the TypeScript client (clients/typescript).

The TS client (`clients/typescript/src/gateway.ts`) parses specific fields off the
gateway's JSON-lines protocol. These tests spawn the real gateway exactly as the TS
client does and assert the contract it depends on, so a future gateway change that
would break the TS client fails HERE, in the Python suite, instead of silently in JS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _run_gateway(requests):
    """Spawn the isolated installed gateway bootstrap, send requests, return
    (handshake_dict, [response_dicts]) — mirrors the TS client's transport."""
    proc = subprocess.Popen(
        [sys.executable, "-I", "-m", "fivedrisk._bootstrap", "gateway", "stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    payload = "".join(json.dumps(r) + "\n" for r in requests)
    try:
        out, _ = proc.communicate(payload, timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("gateway did not respond within 30s")
    lines = [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    assert lines, "gateway emitted no output"
    return lines[0], lines[1:]


def test_handshake_shape():
    handshake, _ = _run_gateway([{"id": "1", "tool_name": "Read", "params": {"file_path": "/tmp/a"}}])
    assert handshake["ready"] is True
    assert handshake["protocol_version"] == 1   # TS client's EXPECTED_PROTOCOL_VERSION
    assert handshake["engine"] == "fivedrisk"
    assert handshake["engine_version"].startswith("0.7.")
    patch = handshake["engine_version"].removeprefix("0.7.")
    assert patch.isdigit() and int(patch) >= 1


def test_id_echoed_for_correlation():
    _, responses = _run_gateway([
        {"id": "abc", "tool_name": "Read", "params": {"file_path": "/tmp/a"}},
    ])
    assert responses[0]["id"] == "abc"


def test_scored_response_has_fields_ts_client_reads():
    _, responses = _run_gateway([
        {"id": "1", "tool_name": "Read", "params": {"file_path": "/tmp/a"}},
    ])
    r = responses[0]
    for field in ("decision_id", "band", "scores", "composite_score", "rationale", "audit_log_id"):
        assert field in r, f"gateway dropped field the TS client reads: {field}"
    # band must be one of the exact four the TS band->sentinel map keys on
    assert r["band"] in ("GREEN", "YELLOW", "ORANGE", "RED")


def test_red_action_bands_red_so_ts_blocks():
    _, responses = _run_gateway([
        {"id": "1", "tool_name": "Bash", "params": {"command": "rm -rf /data"}},
    ])
    assert responses[0]["band"] == "RED"   # TS bandToSentinel("RED") -> "block"


def test_error_shape_for_bad_request():
    # a request missing tool_name → gateway returns {error, error_type}; the TS
    # client maps any error to a fail-closed BLOCK verdict.
    _, responses = _run_gateway([{"id": "1", "params": {"x": 1}}])
    r = responses[0]
    assert "error" in r and "error_type" in r


def test_multiple_requests_correlate_by_id():
    _, responses = _run_gateway([
        {"id": "a", "tool_name": "Read", "params": {"file_path": "/tmp/a"}},
        {"id": "b", "tool_name": "Bash", "params": {"command": "rm -rf /data"}},
    ])
    by_id = {r.get("id"): r for r in responses}
    assert by_id["a"]["band"] == "GREEN"
    assert by_id["b"]["band"] == "RED"


def test_documented_isolated_one_shot_gateway_command_runs():
    request = json.dumps({
        "id": "red", "tool_name": "Bash", "params": {"command": "rm -rf /"},
    }) + "\n"
    proc = subprocess.run(
        [sys.executable, "-I", "-m", "fivedrisk._bootstrap", "gateway", "score"],
        input=request, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    response = json.loads(proc.stdout)
    assert response["band"] == "RED"


def test_documented_options_first_gateway_command_runs(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")
    audit = tmp_path / "decisions.db"
    request = json.dumps({
        "id": "configured", "tool_name": "Read", "params": {"file_path": "/tmp/a"},
    }) + "\n"
    proc = subprocess.run(
        [
            sys.executable, "-I", "-m", "fivedrisk._bootstrap",
            "--policy", str(policy), "--log-path", str(audit),
            "gateway", "score",
        ],
        input=request, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    response = json.loads(proc.stdout)
    assert response["band"] == "GREEN"
    assert audit.is_file()


def test_isolated_gateway_bootstrap_ignores_hostile_cwd_and_pythonpath(tmp_path):
    marker = tmp_path / "shadow-ran"
    shadow = tmp_path / "fivedrisk"
    shadow.mkdir()
    (shadow / "__init__.py").write_text('__version__ = "0.7.1"\n')
    (shadow / "_bootstrap.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
    )
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    proc = subprocess.Popen(
        [sys.executable, "-I", "-m", "fivedrisk._bootstrap", "gateway", "stdio"],
        cwd=tmp_path, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    request = json.dumps({
        "id": "red", "tool_name": "Bash", "params": {"command": "rm -rf /"},
    }) + "\n"
    stdout, stderr = proc.communicate(request, timeout=30)
    assert proc.returncode == 0, stderr
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert lines[0]["engine_version"] == "0.7.1"
    assert lines[1]["band"] == "RED"
    assert not marker.exists()
