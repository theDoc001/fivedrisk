"""5D Risk Governance Engine: IPC gateway for plugin integrations.

Persistent stdio + one-shot subprocess modes that let non-Python plugins
(OpenClaw, Node, Go, Rust) call the scoring engine over JSON-lines.

Spec: openclaw-integration-spec.md §6 L-1, L-5, L-6 and §13.

Three subcommands:

    python -m fivedrisk.gateway stdio --policy <path>
        Long-lived process. Reads one JSON request per stdin line, writes
        one JSON decision per stdout line. Exits on stdin EOF or SIGTERM.

    python -m fivedrisk.gateway score --policy <path>
        One-shot. Reads one JSON request from stdin, writes one decision
        to stdout, exits.

    python -m fivedrisk.gateway resolve --decision-id <id> --resolution <res>
        Updates the audit log row with an OpenClaw onResolution outcome.
        Idempotent.

Request shape (JSON object, one per line in stdio mode):

    {
      "tool_name": "Bash",
      "params": {"command": "rm -rf /"},
      "agent_id": "agent-1",          (optional)
      "session_id": "sess-1",         (optional)
      "run_id": "run-1",              (optional)
      "trace_id": "trace-abc",        (optional)
      "span_id": "span-1",            (optional)
      "parent_span_id": "span-0",     (optional)
      "autonomy": 0                   (optional, 0-4)
    }

Decision shape (JSON object):

    {
      "decision_id": "dec-42",
      "band": "RED",
      "scores": {
        "data_sensitivity": 0, "tool_privilege": 4, "reversibility": 4,
        "external_impact": 0, "autonomy_context": 0
      },
      "rationale": "RED: Bash: Tool Privilege=4 ...",
      "routing": {"model_floor": "M4", "selected_model": "M4", ...},
      "audit_log_id": 42,
      "trace_id": "trace-abc",
      "span_id": "span-1"
    }

Trace propagation uses the existing ``Action.metadata`` dict (no schema
migration). The audit log already persists ``metadata`` as JSON; the
SIEM correlation fields ride through that surface.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .classifier import classify_tool_call
from .logger import DEFAULT_LOG_PATH, DecisionLog
from .policy import Policy, load_policy
from .scorer import score


# Trace / correlation fields lifted from the request into Action.metadata.
# Order matters only for readability of the resulting dict.
_TRACE_FIELDS = (
    "agent_id",
    "session_id",
    "run_id",
    "trace_id",
    "span_id",
    "parent_span_id",
)

# OpenClaw onResolution outcomes accepted by ``resolve``. Validation is
# permissive: anything else is rejected to keep the audit log enum-clean.
_VALID_RESOLUTIONS = frozenset({
    "allow-once",
    "allow-always",
    "deny",
    "timeout",
    "cancelled",
})


def score_action_dict(
    request: Dict[str, Any],
    policy: Policy,
    log: Optional[DecisionLog] = None,
) -> Dict[str, Any]:
    """Score a JSON-shaped request and return a serialisable decision dict.

    Pure-ish: side effect is one append to the audit log (via ``log``).
    No stdin/stdout I/O happens here; ``serve_stdio`` and ``score_oneshot``
    are the I/O wrappers.

    Args:
        request: Decoded JSON request. Must include ``tool_name``. ``params``
            is the tool input (``tool_input`` accepted as a synonym).
        policy: Loaded ``Policy`` instance.
        log: Optional pre-opened ``DecisionLog``. When None a default is opened.

    Returns:
        Decision dict ready for ``json.dumps``. On invalid input shape an
        ``{"error": "...", "error_type": "..."}`` dict is returned; the
        function never raises for caller-supplied bad input.
    """
    if not isinstance(request, dict):
        return {"error": "request must be a JSON object", "error_type": "InvalidRequest"}

    tool_name = request.get("tool_name") or request.get("name")
    if not tool_name:
        return {"error": "tool_name is required", "error_type": "InvalidRequest"}

    tool_input = request.get("params")
    if tool_input is None:
        tool_input = request.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return {
            "error": "params/tool_input must be a JSON object",
            "error_type": "InvalidRequest",
        }

    autonomy = request.get("autonomy")
    if autonomy is not None and not isinstance(autonomy, int):
        return {"error": "autonomy must be an integer", "error_type": "InvalidRequest"}

    try:
        action = classify_tool_call(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=policy,
            autonomy_context=autonomy,
            source=request.get("source", "gateway"),
        )
    except (ValueError, TypeError) as exc:
        return {"error": str(exc), "error_type": type(exc).__name__}

    # Trace + correlation fields ride through Action.metadata. No schema
    # migration: the existing logger already persists metadata as JSON.
    for field in _TRACE_FIELDS:
        val = request.get(field)
        if val is not None:
            action.metadata[field] = val

    try:
        scored = score(action, policy)
    except Exception as exc:  # defensive: scorer should not raise on valid Action
        return {"error": str(exc), "error_type": type(exc).__name__}

    # Propagate session_id onto ScoredAction so DecisionLog stores it in the
    # dedicated column too.
    session_id = request.get("session_id")
    if session_id is not None:
        scored.session_id = session_id

    if log is None:
        log = DecisionLog()

    row_id = log.log(scored)

    routing_dict: Optional[Dict[str, Any]] = None
    if scored.routing is not None:
        routing_dict = scored.routing.to_dict()

    decision: Dict[str, Any] = {
        "decision_id": f"dec-{row_id}",
        "band": str(scored.band),
        "scores": {
            "data_sensitivity": action.data_sensitivity,
            "tool_privilege": action.tool_privilege,
            "reversibility": action.reversibility,
            "external_impact": action.external_impact,
            "autonomy_context": action.autonomy_context,
        },
        "composite_score": round(scored.composite_score, 3),
        "max_dimension": scored.max_dimension,
        "rationale": scored.rationale,
        "routing": routing_dict,
        "audit_log_id": row_id,
        "policy_version": scored.policy_version,
    }

    # Echo trace fields back so the plugin can correlate without re-emitting.
    for field in _TRACE_FIELDS:
        if field in action.metadata:
            decision[field] = action.metadata[field]

    return decision


def serve_stdio(policy_path: Optional[str] = None, log_path: Optional[str] = None) -> None:
    """Long-lived JSON-lines server on stdin/stdout.

    Loads the policy once at startup. Reads one JSON object per line from
    stdin, writes one JSON object per line to stdout, flushes after each
    line. Exits cleanly when stdin reaches EOF.

    Malformed input (bad JSON, missing fields) produces an error JSON line;
    the loop continues. The only exit paths are stdin EOF and KeyboardInterrupt.
    """
    policy = load_policy(policy_path)
    log = DecisionLog(log_path) if log_path else DecisionLog()

    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            request = json.loads(stripped)
        except json.JSONDecodeError as exc:
            response: Dict[str, Any] = {
                "error": f"invalid JSON: {exc}",
                "error_type": "JSONDecodeError",
            }
        else:
            response = score_action_dict(request, policy, log=log)

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def score_oneshot(policy_path: Optional[str] = None, log_path: Optional[str] = None) -> None:
    """One-shot scoring: read one JSON from stdin, write one to stdout, exit."""
    policy = load_policy(policy_path)
    log = DecisionLog(log_path) if log_path else DecisionLog()

    raw = sys.stdin.read().strip()
    if not raw:
        response: Dict[str, Any] = {
            "error": "no input on stdin",
            "error_type": "InvalidRequest",
        }
    else:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as exc:
            response = {
                "error": f"invalid JSON: {exc}",
                "error_type": "JSONDecodeError",
            }
        else:
            response = score_action_dict(request, policy, log=log)

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def resolve(
    decision_id: str,
    resolution: str,
    audit_log_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Update the audit log row with an OpenClaw onResolution outcome.

    Idempotent: calling twice with the same arguments leaves the row in
    the same state. Calling twice with different resolutions overwrites
    (last write wins). This matches the existing ``DecisionLog.update_outcome``
    contract.

    Args:
        decision_id: The gateway-issued id (``dec-<row_id>``) or a bare integer.
        resolution: One of ``allow-once``, ``allow-always``, ``deny``,
            ``timeout``, ``cancelled``.
        audit_log_path: Path to the SQLite log. Defaults to the library default.

    Returns:
        A dict with the updated row's id, resolution, and tool metadata.
        On failure (bad id, bad resolution, row not found) returns
        ``{"error": ..., "error_type": ...}``.
    """
    if resolution not in _VALID_RESOLUTIONS:
        return {
            "error": (
                f"resolution must be one of {sorted(_VALID_RESOLUTIONS)}, "
                f"got {resolution!r}"
            ),
            "error_type": "InvalidResolution",
        }

    row_id = _parse_decision_id(decision_id)
    if row_id is None:
        return {
            "error": f"could not parse decision_id {decision_id!r}",
            "error_type": "InvalidDecisionId",
        }

    log_path = Path(audit_log_path) if audit_log_path else DEFAULT_LOG_PATH

    try:
        with sqlite3.connect(log_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, tool_name, band, outcome FROM decisions WHERE id = ?",
                (row_id,),
            ).fetchone()
            if row is None:
                return {
                    "error": f"decision {decision_id} not found",
                    "error_type": "NotFound",
                }
            conn.execute(
                "UPDATE decisions SET outcome = ? WHERE id = ?",
                (resolution, row_id),
            )
            updated = conn.execute(
                "SELECT id, tool_name, band, outcome FROM decisions WHERE id = ?",
                (row_id,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        return {"error": str(exc), "error_type": "OperationalError"}

    return {
        "decision_id": f"dec-{updated['id']}",
        "audit_log_id": updated["id"],
        "tool_name": updated["tool_name"],
        "band": updated["band"],
        "resolution": updated["outcome"],
    }


def _parse_decision_id(decision_id: str) -> Optional[int]:
    """Accept ``dec-42`` or ``42``. Return the integer row id, or None."""
    if not isinstance(decision_id, str):
        return None
    s = decision_id.strip()
    if s.startswith("dec-"):
        s = s[len("dec-") :]
    try:
        return int(s)
    except ValueError:
        return None


def main(args: Optional[List[str]] = None) -> int:
    """CLI dispatch for ``python -m fivedrisk.gateway``.

    Returns:
        Process exit code (0 on success, non-zero on failure).
    """
    parser = argparse.ArgumentParser(
        prog="fivedrisk.gateway",
        description="JSON-lines IPC gateway for plugin integrations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_stdio = subparsers.add_parser(
        "stdio",
        help="Long-lived stdio JSON-lines server",
    )
    p_stdio.add_argument("--policy", type=str, default=None, help="Path to policy.yaml")
    p_stdio.add_argument("--log-path", type=str, default=None, help="Audit log path")

    p_score = subparsers.add_parser(
        "score",
        help="One-shot scoring: stdin JSON in, stdout JSON out",
    )
    p_score.add_argument("--policy", type=str, default=None, help="Path to policy.yaml")
    p_score.add_argument("--log-path", type=str, default=None, help="Audit log path")

    p_resolve = subparsers.add_parser(
        "resolve",
        help="Update an audit log row with an onResolution outcome",
    )
    p_resolve.add_argument("--decision-id", required=True, help="dec-<n> or <n>")
    p_resolve.add_argument(
        "--resolution",
        required=True,
        help="allow-once | allow-always | deny | timeout | cancelled",
    )
    p_resolve.add_argument("--log-path", type=str, default=None, help="Audit log path")

    parsed = parser.parse_args(args)

    if parsed.command == "stdio":
        serve_stdio(policy_path=parsed.policy, log_path=parsed.log_path)
        return 0
    if parsed.command == "score":
        score_oneshot(policy_path=parsed.policy, log_path=parsed.log_path)
        return 0
    if parsed.command == "resolve":
        result = resolve(
            decision_id=parsed.decision_id,
            resolution=parsed.resolution,
            audit_log_path=parsed.log_path,
        )
        sys.stdout.write(json.dumps(result) + "\n")
        sys.stdout.flush()
        return 0 if "error" not in result else 1

    return 2  # unreachable: argparse enforces required=True


if __name__ == "__main__":
    sys.exit(main())
