"""Fail-closed runtime checks for the bundled Claude Code plugin hook launcher."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


DEV = Path(__file__).resolve().parents[2]
PLUGIN = DEV / "fivedrisk-plugin"
HOOKS = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
COMMANDS = {
    phase: HOOKS[phase][0]["hooks"][0]["command"]
    for phase in ("PreToolUse", "PostToolUse")
}


def _run_hook(
    phase: str,
    payload: str | dict,
    cwd: Path,
    *,
    env_updates: dict[str, str | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "FIVEDRISK_PYTHON": sys.executable,
        "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
        "FIVEDRISK_AUDIT_PATH": str((cwd / "fivedrisk-hook-audit.db").resolve()),
    }
    for key, value in (env_updates or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        COMMANDS[phase], shell=True, input=stdin, cwd=cwd, env=env,
        capture_output=True, text=True, timeout=30,
    )


def _make_fake_environment(root: Path, version: str | None) -> Path:
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(root)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    python = root / "bin" / "python"
    if version is None:
        return python
    site_dir = Path(subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip())
    package = site_dir / "fivedrisk"
    package.mkdir()
    (package / "__init__.py").write_text(f'__version__ = "{version}"\n')
    bootstrap_source = (
        "import os\n"
        "print(os.environ.get('FIVEDRISK_FAKE_OUTPUT', "
        "'{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}'))\n"
    )
    (package / "__main__.py").write_text(bootstrap_source)
    (package / "_bootstrap.py").write_text(bootstrap_source)
    dist = site_dir / f"fivedrisk-{version}.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: fivedrisk\nVersion: {version}\n"
    )
    (dist / "RECORD").write_text("fivedrisk/__init__.py,,\n")
    return python


def test_hook_commands_use_only_explicit_quoted_interpreter_and_plugin_root():
    assert HOOKS["PreToolUse"][0]["matcher"] == "*"
    assert HOOKS["PostToolUse"][0]["matcher"] == "*"
    for command in COMMANDS.values():
        assert '"$FIVEDRISK_PYTHON"' in command
        assert '"$FIVEDRISK_PYTHON" -I' in command
        assert '"$CLAUDE_PLUGIN_ROOT/scripts/run_hook.py"' in command
        assert "python -m" not in command
        assert "python3 -m" not in command


@pytest.mark.parametrize(
    "missing", ["FIVEDRISK_PYTHON", "CLAUDE_PLUGIN_ROOT", "FIVEDRISK_AUDIT_PATH"]
)
def test_unset_required_hook_environment_blocks(tmp_path, missing):
    out = _run_hook(
        "PreToolUse", {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={missing: None},
    )
    assert out.returncode == 2
    assert "required hook environment is unset; blocking" in out.stderr


@pytest.mark.parametrize("configured", ["python", "/definitely/missing/python"])
def test_relative_or_missing_interpreter_blocks(tmp_path, configured):
    out = _run_hook(
        "PreToolUse", {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={"FIVEDRISK_PYTHON": configured},
    )
    assert out.returncode == 2


def test_interpreter_without_fivedrisk_blocks(tmp_path):
    python = _make_fake_environment(tmp_path / "empty env", None)
    out = _run_hook(
        "PreToolUse", {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={"FIVEDRISK_PYTHON": str(python)},
    )
    assert out.returncode == 2
    assert "distribution is not installed" in out.stderr


@pytest.mark.parametrize(("version", "accepted"), [
    ("0.1.0", False),
    ("0.6.0", False),
    ("0.7.0rc1", False),
    ("0.7.0", False),
    ("0.7.1", True),
    ("0.7.9", True),
    ("0.8.0", False),
])
def test_hook_launcher_enforces_stable_supported_version(tmp_path, version, accepted):
    python = _make_fake_environment(tmp_path / "version env", version)
    out = _run_hook(
        "PreToolUse", {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={"FIVEDRISK_PYTHON": str(python)},
    )
    assert (out.returncode == 0) is accepted, out.stdout + out.stderr
    if not accepted:
        assert out.returncode == 2


@pytest.mark.parametrize(("payload", "expected_decision"), [
    ({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a"}}, "allow"),
    ({"tool_name": "Bash", "tool_input": {"command": "docker compose up -d"}}, "ask"),
    ({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/a"}}, "deny"),
])
def test_pretooluse_emits_structured_green_orange_red_decisions(tmp_path, payload, expected_decision):
    out = _run_hook("PreToolUse", payload, tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    result = json.loads(out.stdout)
    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert result["hookSpecificOutput"]["permissionDecision"] == expected_decision
    assert (tmp_path / "fivedrisk-hook-audit.db").is_file()


@pytest.mark.parametrize(("payload", "blocked"), [
    ({"tool_name": "Read", "tool_result": "ordinary analysis"}, False),
    ({"tool_name": "Read", "tool_result": "password=hunter2secret"}, True),
    ({"tool_name": "Read", "tool_response": "password=hunter2secret"}, True),
    ({"tool_name": "Read", "tool_output": "password=hunter2secret"}, True),
    ({"tool_name": "Read", "output": "safe", "tool_response": "password=hunter2secret"}, True),
])
def test_posttooluse_normalizes_all_claude_output_fields(tmp_path, payload, blocked):
    out = _run_hook("PostToolUse", payload, tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    result = json.loads(out.stdout)
    if blocked:
        assert result["decision"] == "block"
    else:
        assert result == {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}


@pytest.mark.parametrize("phase", ["PreToolUse", "PostToolUse"])
def test_malformed_hook_input_is_converted_to_blocking_exit_2(tmp_path, phase):
    out = _run_hook(phase, "{not-json", tmp_path)
    assert out.returncode == 2
    assert "hook input is not valid JSON" in out.stderr


@pytest.mark.parametrize(("phase", "child_output"), [
    ("PreToolUse", ""),
    ("PreToolUse", "not-json"),
    ("PreToolUse", "{}\n{}"),
    ("PreToolUse", "[]"),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"allow"}}'),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"later"}}'),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}'),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":""}}'),
    ("PostToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}'),
    ("PostToolUse", '{"decision":"allow","reason":"wrong"}'),
    ("PostToolUse", '{"decision":"block","reason":""}'),
    ("PostToolUse", '{"decision":"block","reason":"leak","hookSpecificOutput":{"hookEventName":"PostToolUse"}}'),
])
def test_hook_launcher_rejects_invalid_or_ambiguous_child_output(tmp_path, phase, child_output):
    python = _make_fake_environment(tmp_path / "fake env", "0.7.1")
    out = _run_hook(
        phase, {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={
            "FIVEDRISK_PYTHON": str(python),
            "FIVEDRISK_FAKE_OUTPUT": child_output,
        },
    )
    assert out.returncode == 2
    assert "invalid structured output" in out.stderr


@pytest.mark.parametrize(("phase", "child_output", "expected"), [
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}', "allow"),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"review"}}', "ask"),
    ("PreToolUse", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"blocked"}}', "deny"),
    ("PostToolUse", '{"hookSpecificOutput":{"hookEventName":"PostToolUse"}}', "clean"),
    ("PostToolUse", '{"decision":"block","reason":"leak"}', "block"),
])
def test_hook_launcher_canonicalizes_valid_child_output(tmp_path, phase, child_output, expected):
    python = _make_fake_environment(tmp_path / "fake env", "0.7.1")
    out = _run_hook(
        phase, {"tool_name": "Read", "tool_input": {}}, tmp_path,
        env_updates={
            "FIVEDRISK_PYTHON": str(python),
            "FIVEDRISK_FAKE_OUTPUT": child_output,
        },
    )
    assert out.returncode == 0, out.stdout + out.stderr
    result = json.loads(out.stdout)
    observed = result.get("decision", result.get("hookSpecificOutput", {}).get("permissionDecision", "clean"))
    assert observed == expected


def test_operator_policy_path_with_spaces_is_passed_and_missing_path_blocks(tmp_path):
    policy = tmp_path / "policy directory" / "strict policy.yaml"
    policy.parent.mkdir()
    policy.write_text(
        "version: '0.7.0'\n"
        "tool_defaults:\n"
        "  Read:\n"
        "    tool_privilege: 4\n",
        encoding="utf-8",
    )
    payload = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a"}}
    strict = _run_hook(
        "PreToolUse", payload, tmp_path,
        env_updates={"FIVEDRISK_POLICY_PATH": str(policy)},
    )
    missing = _run_hook(
        "PreToolUse", payload, tmp_path,
        env_updates={"FIVEDRISK_POLICY_PATH": str(tmp_path / "missing policy.yaml")},
    )
    assert strict.returncode == 0, strict.stdout + strict.stderr
    assert json.loads(strict.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert missing.returncode == 2
    assert "missing or unreadable" in missing.stderr


def test_invalid_wrapper_mode_blocks(tmp_path):
    env = {**os.environ, "FIVEDRISK_PYTHON": sys.executable}
    out = subprocess.run(
        [sys.executable, str(PLUGIN / "scripts" / "run_hook.py"), "unknown"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 2
    assert "hook mode must be exactly" in out.stderr


def test_isolated_bootstrap_ignores_hostile_cwd_and_pythonpath_shadow(tmp_path):
    marker = tmp_path / "shadow-ran"
    shadow = tmp_path / "fivedrisk"
    shadow.mkdir()
    (shadow / "__init__.py").write_text('__version__ = "0.7.1"\n')
    (shadow / "_bootstrap.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        "print('{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
        "\"permissionDecision\":\"allow\"}}')\n"
    )
    out = _run_hook(
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
        tmp_path,
        env_updates={"PYTHONPATH": str(tmp_path)},
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not marker.exists()


@pytest.mark.parametrize(
    ("phase", "payload", "expected"),
    [
        (
            "PreToolUse",
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /target"}},
            "deny",
        ),
        (
            "PostToolUse",
            {"tool_name": "Read", "tool_response": "password=hunter2secret"},
            "block",
        ),
    ],
)
def test_outer_launcher_ignores_hostile_subprocess_shadow(
    tmp_path, phase, payload, expected
):
    marker = tmp_path / "subprocess-shadow-ran"
    shadow = tmp_path / "subprocess.py"
    shadow.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        "class Result:\n"
        "    returncode = 0\n"
        "    stdout = '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}'\n"
        "    stderr = ''\n"
        "def run(*args, **kwargs): return Result()\n",
        encoding="utf-8",
    )
    positive = subprocess.run(
        [sys.executable, "-c", "import subprocess"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert positive.returncode == 0
    assert marker.exists(), "hostile shadow fixture did not execute in the positive control"
    marker.unlink()

    out = _run_hook(
        phase,
        payload,
        tmp_path,
        env_updates={"PYTHONPATH": str(tmp_path)},
    )
    assert out.returncode == 0, out.stdout + out.stderr
    result = json.loads(out.stdout)
    observed = result.get(
        "decision",
        result.get("hookSpecificOutput", {}).get("permissionDecision", "clean"),
    )
    assert observed == expected
    assert not marker.exists()
