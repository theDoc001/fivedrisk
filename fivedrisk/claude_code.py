"""Claude Code hook adapter — structured PreToolUse / PostToolUse decisions.

The exit-code hooks (`fivedrisk score` / `fivedrisk scan-output`) can only allow
or block, so an ORANGE "needs human approval" action collapses into a hard deny.
This adapter emits Claude Code's *structured* hook output, which has a native
approval channel: ORANGE maps to `permissionDecision: "ask"` (Claude surfaces the
call to the user) instead of a silent hard deny. It closes the loop by pairing the
pre-tool gate with the already-shipped PostToolUse egress scan.

Mapping (Claude Code HAS an approval channel, so APPROVE routes to "ask"):
    GREEN / YELLOW  (EXECUTE) -> "allow"
    ORANGE          (APPROVE) -> "ask"    (native human-in-the-loop)
    RED / injection / error (BLOCK) -> "deny"   (fail-closed; unknown -> deny)

Schemas per https://code.claude.com/docs/en/hooks (2026). Exit-code note: emit the
JSON with exit 0 and Claude applies the decision; the older top-level
`{"decision": "block"|"approve"}` PreToolUse form is deprecated in favour of
`hookSpecificOutput.permissionDecision`.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Tuple

from .adapters import APPROVE, BLOCK, EXECUTE, to_verdict
from .logger import DecisionLog
from .policy import Policy

# Claude Code's native approval channel means APPROVE is "ask", not a hard deny.
# An unknown sentinel is not in the map → deny (fail-closed).
_SENTINEL_TO_PERMISSION: Dict[str, str] = {EXECUTE: "allow", APPROVE: "ask", BLOCK: "deny"}


def pretooluse_hook(
    payload: Dict[str, Any],
    policy: Optional[Policy] = None,
    log: Optional[DecisionLog] = None,
    *,
    source: str = "claude-code",
) -> Tuple[Dict[str, Any], bool]:
    """Score a Claude Code PreToolUse payload → (structured hook output, blocked).

    Reads ``tool_name`` / ``tool_input`` / ``session_id`` from the payload and runs
    the shared M0 verdict socket. ``tool_input`` is passed through unchanged — a
    non-dict fails CLOSED inside ``to_verdict`` (never coerced into a benign shape).
    ``blocked`` is True only for a hard deny; an "ask" is NOT a block (the user may
    still approve it).
    """
    verdict = to_verdict(
        payload.get("tool_name"),
        payload.get("tool_input", {}),
        policy,
        session_id=payload.get("session_id"),
        log=log,
        source=source,
    )
    decision = _SENTINEL_TO_PERMISSION.get(verdict.sentinel, "deny")  # unknown → deny
    hook_output: Dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if decision != "allow":  # reason is required for deny/ask
        hook_output["hookSpecificOutput"]["permissionDecisionReason"] = (
            f"5D {verdict.band}: {verdict.reason}"
        )
    return hook_output, decision == "deny"


# Claude Code has used `tool_response` for the PostToolUse result; other hosts /
# older versions use `tool_output` or `output`. The egress scan reads `tool_result`.
# A fail-closed gate must not bet on ONE field name, so we scan the UNION of every
# candidate output field (QA-M2 finding): a leak in any of them is caught, and a
# benign field can never shadow a leaking sibling.
_OUTPUT_FIELDS = ("tool_result", "tool_response", "tool_output", "output")


def _normalize_post_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Fold every candidate output field into the ``tool_result`` key the egress
    scan reads, so no leak escapes because Claude used a different field name."""
    parts = [str(payload[k]) for k in _OUTPUT_FIELDS if k in payload and payload[k] is not None]
    if not parts:
        return payload
    normalized = dict(payload)
    normalized["tool_result"] = "\n".join(parts)
    return normalized


def posttooluse_hook(
    payload: Dict[str, Any],
    tool_use_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Scan a Claude Code PostToolUse payload → (structured hook output, blocked).

    Thin reuse of the shipped async ``fivedrisk_post_tool`` egress scan. The tool
    already ran (PostToolUse can't stop it), so a leak/injection-echo surfaces as
    ``decision: "block"`` — which halts Claude and records an audit row.

    Fails CLOSED: if the scan itself raises (e.g. the audit sink is unwritable), we
    still emit a block rather than letting the CLI crash and the output flow through
    unscanned (QA-M2 finding).
    """
    from .hooks import fivedrisk_post_tool

    tuid = str(tool_use_id or payload.get("tool_use_id") or payload.get("id") or "claude-code")
    try:
        result = asyncio.run(fivedrisk_post_tool(_normalize_post_payload(payload), tuid))
    except Exception as exc:  # governance gate must fail closed, never crash-open
        return {"decision": "block", "reason": f"5D egress scan failed closed: {exc}"}, True
    if result.get("decision") == "block":
        return {"decision": "block", "reason": result.get("reason", "5D egress block")}, True
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}, False
