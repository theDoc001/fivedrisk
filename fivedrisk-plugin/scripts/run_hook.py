"""Fail-closed launcher for the bundled Claude Code hook commands."""

from __future__ import annotations

import importlib.metadata as metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def _block(message: str) -> int:
    print(f"fivedrisk: {message}; blocking", file=sys.stderr)
    return 2


def _validated_policy_argument(mode: str) -> list[str] | None:
    raw = os.environ.get("FIVEDRISK_POLICY_PATH")
    if not raw or mode != "pre":
        return []
    policy = Path(raw)
    if not policy.is_file() or not os.access(policy, os.R_OK):
        return None
    return ["--policy", str(policy)]


def _canonical_output(mode: str, raw: str) -> dict | None:
    """Validate one structured Claude hook result and discard untrusted extras."""
    try:
        result = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(result, dict):
        return None

    if mode == "pre":
        if set(result) != {"hookSpecificOutput"}:
            return None
        specific = result.get("hookSpecificOutput")
        if not isinstance(specific, dict):
            return None
        decision = specific.get("permissionDecision")
        expected_keys = {"hookEventName", "permissionDecision"}
        if decision in {"ask", "deny"}:
            expected_keys.add("permissionDecisionReason")
        if set(specific) != expected_keys:
            return None
        if specific.get("hookEventName") != "PreToolUse":
            return None
        if decision not in {"allow", "ask", "deny"}:
            return None
        canonical = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
            }
        }
        if decision in {"ask", "deny"}:
            reason = specific.get("permissionDecisionReason")
            if not isinstance(reason, str) or not reason.strip():
                return None
            canonical["hookSpecificOutput"]["permissionDecisionReason"] = reason
        return canonical

    if set(result) == {"hookSpecificOutput"}:
        specific = result.get("hookSpecificOutput")
        if specific == {"hookEventName": "PostToolUse"}:
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
        return None
    if set(result) == {"decision", "reason"} and result.get("decision") == "block":
        reason = result.get("reason")
        if isinstance(reason, str) and reason.strip():
            return {"decision": "block", "reason": reason}
    return None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in {"pre", "post"}:
        return _block("hook mode must be exactly 'pre' or 'post'")
    mode = args[0]

    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        return _block(f"hook input is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        return _block("hook input must be a JSON object")
    expected_event = "PreToolUse" if mode == "pre" else "PostToolUse"
    supplied_event = payload.get("hook_event_name")
    if supplied_event is not None and supplied_event != expected_event:
        return _block(
            f"hook event {supplied_event!r} does not match launcher mode {mode!r}"
        )
    payload["hook_event_name"] = expected_event

    configured = os.environ.get("FIVEDRISK_PYTHON", "")
    configured_path = Path(configured)
    if not configured or not configured_path.is_absolute():
        return _block("FIVEDRISK_PYTHON must name the verified absolute interpreter")
    try:
        configured_resolved = configured_path.resolve(strict=True)
        running_resolved = Path(sys.executable).resolve(strict=True)
    except OSError as exc:
        return _block(f"interpreter resolution failed: {exc}")
    if configured_resolved != running_resolved:
        return _block("FIVEDRISK_PYTHON does not match the running interpreter")

    try:
        version = metadata.version("fivedrisk")
    except metadata.PackageNotFoundError:
        return _block("fivedrisk distribution is not installed")
    version_match = re.fullmatch(r"0\.7\.(\d+)", version)
    if version_match is None or int(version_match.group(1)) < 1:
        return _block(
            f"unsupported fivedrisk version {version!r}; require stable >=0.7.1,<0.8.0"
        )

    policy_args = _validated_policy_argument(mode)
    if policy_args is None:
        return _block("FIVEDRISK_POLICY_PATH is missing or unreadable")
    cli_args = [
        sys.executable, "-I", "-m", "fivedrisk._bootstrap", *policy_args,
        "--format", "json", "claude-hook", "-",
    ]

    try:
        completed = subprocess.run(
            cli_args,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
    except Exception as exc:  # fail closed across launcher/OS failures
        return _block(f"hook launcher failed: {exc}")
    if completed.returncode == 0:
        canonical = _canonical_output(mode, completed.stdout)
        if canonical is None:
            sys.stderr.write(completed.stderr)
            return _block("hook command returned invalid structured output")
        print(json.dumps(canonical, separators=(",", ":")))
        sys.stderr.write(completed.stderr)
        return 0
    sys.stderr.write(completed.stderr)
    return _block(f"hook command returned unexpected status {completed.returncode}")


if __name__ == "__main__":
    raise SystemExit(main())
