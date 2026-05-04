"""5D Risk Governance Engine — Claude Agent SDK hooks + runtime gates.

Drop-in PreToolUse/PostToolUse hooks for the Claude Agent SDK.
Also provides:
  - scan_input_for_injection(): call before any LLM prompt
  - scan_output_for_leakage(): call on any LLM output
  - @gate decorator: wrap any Python function with 5D scoring
  - rate_limit_check(): DoS defense — call at message ingestion
  - configure(): set policy, log path, autonomy context

Usage with Agent SDK:
    from fivedrisk.hooks import fivedrisk_pre_tool, fivedrisk_post_tool

    async for msg in query(
        prompt="...",
        options=ClaudeAgentOptions(
            hooks={
                "PreToolUse": [HookMatcher(matcher=".*", hooks=[fivedrisk_pre_tool])],
                "PostToolUse": [HookMatcher(matcher=".*", hooks=[fivedrisk_post_tool])],
            }
        ),
    ):
        print(msg)

Usage for builder.py / arbitrary functions:
    from fivedrisk.hooks import scan_input_for_injection, scan_output_for_leakage, gate

    # Scan LLM input
    injection = scan_input_for_injection(user_goal)
    if injection:
        raise ValueError(f"Injection pattern detected: {injection}")

    # Scan LLM output
    leak = scan_output_for_leakage(llm_response)
    if leak:
        raise ValueError(f"Sensitive data in output: {leak}")

    # Gate any Python function
    @gate(tool_name="write_vault_file", autonomy_context=1)
    def write_to_vault(path, content):
        ...
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import re
import time
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Any, Callable, Dict, Iterable, Optional

from .classifier import classify_tool_call
from .detectors import (
    DETECTOR_CORPUS_VERSION,
    EGRESS_PATTERNS,
    INJECTION_PATTERNS,
    RETRIEVAL_TOOLS,
)
from .logger import DecisionLog
from .markov import MarkovDriftTracker, make_default_transition_matrix
from .policy import Policy, load_policy
from .schema import Band
from .scorer import _route_model, score

# ─── Module-level defaults — override via configure() ──────────

_policy: Policy = Policy()
_log: Optional[DecisionLog] = None
_autonomy_context: int = 0
_drift_transition_matrix: list[list[float]] = make_default_transition_matrix()
_drift_trackers: Dict[str, MarkovDriftTracker] = {}
_require_session_id: bool = False
_destination_allowlist: Optional[frozenset[str]] = None
_destination_denylist: frozenset[str] = frozenset()
_enforce_destination_policy: bool = False

SESSION_ID_KEYS = ("session_id", "thread_id", "conversation_id", "run_id")

# ─── Rate limiting state ────────────────────────────────────────
# Tracks action timestamps per session_id (or source string).
# Sliding window of 60 seconds.

_RATE_LIMIT_WINDOW_SECONDS: int = 60
_RATE_LIMIT_MAX_ACTIONS: int = 120        # hard cap: actions per window per session
_RATE_LIMIT_BURST_THRESHOLD: int = 30     # burst: >30 actions in 10 seconds → ORANGE
_HITL_QUEUE_MAX_DEPTH: int = 20           # max pending HITL cards before refusing new actions

_action_timestamps: Dict[str, deque] = defaultdict(deque)   # session_id → deque of timestamps
_hitl_queue_depth: int = 0                                   # global pending HITL card count


@dataclass(frozen=True)
class DestinationPolicyResult:
    """Outcome of a destination policy check."""

    decision: str
    reason: str
    destinations: tuple[str, ...]


def configure(
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    autonomy_context: int = 0,
    rate_limit_max: int = 120,
    hitl_queue_max: int = 20,
    drift_transition_matrix: Optional[list[list[float]]] = None,
    require_session_id: bool = False,
    destination_allowlist: Optional[Iterable[str]] = None,
    destination_denylist: Optional[Iterable[str]] = None,
    enforce_destination_policy: bool = False,
) -> None:
    """Configure the hooks module.

    Call once at agent startup to set policy, log location,
    autonomy context, and DoS defense thresholds.
    """
    global _policy, _log, _autonomy_context
    global _RATE_LIMIT_MAX_ACTIONS, _HITL_QUEUE_MAX_DEPTH
    global _drift_transition_matrix, _drift_trackers
    global _require_session_id, _destination_allowlist
    global _destination_denylist, _enforce_destination_policy
    _policy = load_policy(policy_path)
    _log = DecisionLog(log_path) if log_path else DecisionLog()
    _autonomy_context = autonomy_context
    _RATE_LIMIT_MAX_ACTIONS = rate_limit_max
    _HITL_QUEUE_MAX_DEPTH = hitl_queue_max
    _drift_transition_matrix = (
        drift_transition_matrix
        if drift_transition_matrix is not None
        else make_default_transition_matrix()
    )
    _drift_trackers = {}
    _require_session_id = require_session_id
    _destination_allowlist = (
        frozenset(_normalize_destination(value) for value in destination_allowlist)
        if destination_allowlist is not None
        else None
    )
    _destination_denylist = frozenset(
        _normalize_destination(value) for value in (destination_denylist or [])
    )
    _enforce_destination_policy = enforce_destination_policy


def hitl_queue_increment() -> None:
    """Call when a HITL card is pushed to the queue."""
    global _hitl_queue_depth
    _hitl_queue_depth += 1


def hitl_queue_decrement() -> None:
    """Call when a HITL card is resolved (approved/rejected)."""
    global _hitl_queue_depth
    _hitl_queue_depth = max(0, _hitl_queue_depth - 1)


# ─── Rate limit check ──────────────────────────────────────────

def rate_limit_check(session_id: str) -> Optional[str]:
    """Check if this session is exceeding rate limits.

    Returns None if OK, or a string reason if the action should be blocked.

    Call this at message ingestion before any tool scoring.
    This is the DoS defense layer — separate from 5D scoring.

    Defenses:
    1. Sliding window: >_RATE_LIMIT_MAX_ACTIONS in 60s → block
    2. Burst detection: >_RATE_LIMIT_BURST_THRESHOLD in 10s → warn (ORANGE equivalent)
    3. HITL queue depth: if queue is full, block until queue drains
    """
    now = time.monotonic()
    window = _action_timestamps[session_id]

    # Prune timestamps older than the window
    cutoff_60 = now - _RATE_LIMIT_WINDOW_SECONDS
    while window and window[0] < cutoff_60:
        window.popleft()

    window.append(now)

    # Check 1: sliding window limit
    if len(window) > _RATE_LIMIT_MAX_ACTIONS:
        return (
            f"Rate limit exceeded: {len(window)} actions in {_RATE_LIMIT_WINDOW_SECONDS}s "
            f"(max {_RATE_LIMIT_MAX_ACTIONS}). Slow down."
        )

    # Check 2: burst detection (>30 in last 10 seconds)
    cutoff_10 = now - 10
    recent = sum(1 for t in window if t > cutoff_10)
    if recent > _RATE_LIMIT_BURST_THRESHOLD:
        return (
            f"Burst detected: {recent} actions in 10s (max {_RATE_LIMIT_BURST_THRESHOLD}). "
            f"Possible abuse — session temporarily throttled."
        )

    # Check 3: HITL queue depth
    if _hitl_queue_depth >= _HITL_QUEUE_MAX_DEPTH:
        return (
            f"HITL queue at capacity ({_hitl_queue_depth}/{_HITL_QUEUE_MAX_DEPTH}). "
            f"Approve or reject pending decisions before submitting new actions."
        )

    return None


def session_id_conventions() -> dict[str, Any]:
    """Return the supported session identity conventions for integrations."""
    return {
        "accepted_keys": list(SESSION_ID_KEYS),
        "detector_corpus_version": DETECTOR_CORPUS_VERSION,
        "require_session_id": _require_session_id,
    }


def _normalize_destination(destination: str) -> str:
    """Normalize a destination into a lowercase host-ish token."""
    normalized = destination.strip().lower()
    normalized = re.sub(r"^[a-z][a-z0-9+.-]*://", "", normalized)
    normalized = normalized.split("/")[0]
    normalized = normalized.split("@")[-1]
    normalized = normalized.split(":")[0]
    return normalized


def extract_external_destinations(tool_name: str, tool_input: Dict[str, Any]) -> list[str]:
    """Extract host destinations from runtime tool input."""
    candidates: set[str] = set()
    input_text = str(tool_input)

    for match in re.findall(r"(?i)\b(?:https?|ssh)://([a-z0-9.-]+\.[a-z]{2,})", input_text):
        candidates.add(_normalize_destination(match))

    for match in re.findall(r"(?i)\b(?:curl|wget)\b(?:[^'\"]|\s)+?(https?://[^\s'\"<>]+)", input_text):
        candidates.add(_normalize_destination(match))

    for match in re.findall(r"(?i)\b(?:ssh|scp|rsync)\b(?:[^'\"]|\s)+?([a-z0-9.-]+\.[a-z]{2,}):?", input_text):
        candidates.add(_normalize_destination(match))

    if tool_name in {"WebFetch", "WebSearch"}:
        for key in ("url", "urls", "domain", "domains", "host", "hosts"):
            value = tool_input.get(key)
            if isinstance(value, str):
                candidates.add(_normalize_destination(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        candidates.add(_normalize_destination(item))

    return sorted(value for value in candidates if value)


def check_destination_policy(
    tool_name: str,
    tool_input: Dict[str, Any],
) -> Optional[DestinationPolicyResult]:
    """Check extracted destinations against configured allow/deny lists."""
    destinations = extract_external_destinations(tool_name, tool_input)
    if not destinations:
        return None

    blocked = [value for value in destinations if value in _destination_denylist]
    if blocked:
        return DestinationPolicyResult(
            decision="block",
            reason=f"5D destination denylist: {', '.join(blocked)}",
            destinations=tuple(destinations),
        )

    if _destination_allowlist is not None:
        unknown = [value for value in destinations if value not in _destination_allowlist]
        if unknown:
            decision = "block" if _enforce_destination_policy else "warn"
            return DestinationPolicyResult(
                decision=decision,
                reason=f"5D destination not in allowlist: {', '.join(unknown)}",
                destinations=tuple(destinations),
            )

    return None


def scan_input_for_injection(text: str, source: str = "unknown") -> Optional[str]:
    """Scan raw input text for prompt injection patterns.

    Call BEFORE passing any text to an LLM.
    Returns None if clean, or a string describing the match if suspicious.

    Sources to always scan:
    - User messages from untrusted channels (Discord, email, web forms)
    - Content retrieved from web pages (WebFetch results)
    - Content read from external files
    - Any text that came from outside the vault

    Sources that are generally safe (but can still be scanned):
    - Vault-internal content written by Dot
    - Hardcoded system prompts from DB (DECISION-005)
    """
    for pattern, label in INJECTION_PATTERNS:
        if re.search(pattern, text):
            return f"[{label}] Matched: {pattern[:50]}..."
    return None


def scan_output_for_leakage(text: str) -> Optional[str]:
    """Scan LLM output or tool result for sensitive data or injection echoes.

    Call AFTER receiving any LLM response, BEFORE acting on it or returning
    it to the user.

    Returns None if clean, or a string describing the match if suspicious.
    """
    for pattern, label in EGRESS_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return f"[{label}] Matched: {pattern[:50]}..."
    return None


def scan_retrieved_content(text: str, source: str = "retrieved") -> Optional[str]:
    """Scan fetched/read content for indirect prompt-injection instructions."""
    injection = scan_input_for_injection(text, source=source)
    if injection:
        return f"retrieved-content {injection}"
    return None


# ─── @gate decorator ───────────────────────────────────────────

def gate(
    tool_name: str,
    autonomy_context: int = 0,
    policy: Optional[Policy] = None,
    log: Optional[DecisionLog] = None,
    on_block: Optional[Callable[[str], Any]] = None,
):
    """Decorator: wrap any Python function with 5D scoring.

    The decorated function is gated through the 5D engine before execution.
    If the action scores ASK or STOP, the function is NOT called and
    on_block() is invoked instead (or ValueError is raised if on_block is None).

    Args:
        tool_name: The logical name for this action in the policy/log.
        autonomy_context: 0 (interactive) to 4 (fully unattended).
        policy: Override module-level policy.
        log: Override module-level log.
        on_block: Callable(reason: str) → Any. Called instead of the
                  decorated function if action is blocked. If None, raises ValueError.

    Example:
        @gate(tool_name="write_vault_file", autonomy_context=1)
        def write_to_vault(path: str, content: str) -> None:
            Path(path).write_text(content)

        @gate(tool_name="send_discord_message", autonomy_context=0,
              on_block=lambda r: logger.warning("blocked", reason=r))
        def send_message(channel_id, text):
            ...
    """
    _use_policy = policy or _policy
    _use_log = log or _log or DecisionLog()

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Build tool_input from args/kwargs for classifier
            tool_input: Dict[str, Any] = {}
            if args:
                tool_input["_args"] = str(args)
            if kwargs:
                tool_input.update({k: str(v) for k, v in kwargs.items()})

            action = classify_tool_call(
                tool_name=tool_name,
                tool_input=tool_input,
                policy=_use_policy,
                autonomy_context=autonomy_context,
                source="gate-decorator",
            )
            session_id = _resolve_gate_session_id(args, kwargs)
            if _require_session_id and session_id is None:
                reason = _session_required_message()
                if on_block:
                    return on_block(reason)
                raise ValueError(reason)

            destination_check = check_destination_policy(tool_name, tool_input)
            if destination_check and destination_check.decision == "block":
                if on_block:
                    return on_block(destination_check.reason)
                raise ValueError(destination_check.reason)

            result = score(action, _use_policy)
            if session_id:
                _apply_drift(result, session_id)
            if destination_check and destination_check.decision == "warn":
                result.rationale = (
                    f"{result.rationale} [DestinationPolicy: {destination_check.reason}]"
                )
            _use_log.log(result)

            if result.band in (Band.STOP, Band.RED):
                reason = f"5D STOP ({result.band}): {result.rationale}"
                if on_block:
                    return on_block(reason)
                raise ValueError(reason)

            if result.band in (Band.ASK, Band.ORANGE):
                reason = f"5D ASK ({result.band}): {result.rationale}"
                if on_block:
                    return on_block(reason)
                raise ValueError(reason)

            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            tool_input: Dict[str, Any] = {}
            if args:
                tool_input["_args"] = str(args)
            if kwargs:
                tool_input.update({k: str(v) for k, v in kwargs.items()})

            action = classify_tool_call(
                tool_name=tool_name,
                tool_input=tool_input,
                policy=_use_policy,
                autonomy_context=autonomy_context,
                source="gate-decorator",
            )
            session_id = _resolve_gate_session_id(args, kwargs)
            if _require_session_id and session_id is None:
                reason = _session_required_message()
                if on_block:
                    return (await on_block(reason)) if inspect.iscoroutinefunction(on_block) else on_block(reason)
                raise ValueError(reason)

            destination_check = check_destination_policy(tool_name, tool_input)
            if destination_check and destination_check.decision == "block":
                if on_block:
                    return (await on_block(destination_check.reason)) if inspect.iscoroutinefunction(on_block) else on_block(destination_check.reason)
                raise ValueError(destination_check.reason)

            result = score(action, _use_policy)
            if session_id:
                _apply_drift(result, session_id)
            if destination_check and destination_check.decision == "warn":
                result.rationale = (
                    f"{result.rationale} [DestinationPolicy: {destination_check.reason}]"
                )
            _use_log.log(result)

            if result.band in (Band.STOP, Band.RED):
                reason = f"5D STOP ({result.band}): {result.rationale}"
                if on_block:
                    return (await on_block(reason)) if asyncio.iscoroutinefunction(on_block) else on_block(reason)
                raise ValueError(reason)

            if result.band in (Band.ASK, Band.ORANGE):
                reason = f"5D ASK ({result.band}): {result.rationale}"
                if on_block:
                    return (await on_block(reason)) if asyncio.iscoroutinefunction(on_block) else on_block(reason)
                raise ValueError(reason)

            if inspect.iscoroutinefunction(fn):
                return await fn(*args, **kwargs)
            return fn(*args, **kwargs)

        return async_wrapper if inspect.iscoroutinefunction(fn) else wrapper

    return decorator


# ─── Agent SDK hooks ───────────────────────────────────────────

def _extract_tool_info(input_data: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """Extract tool name and input from Agent SDK hook input_data."""
    tool_name = input_data.get("tool_name", input_data.get("name", "Unknown"))
    tool_input = input_data.get("tool_input", input_data.get("input", {}))
    if isinstance(tool_input, str):
        tool_input = {"command": tool_input}
    return tool_name, tool_input


def _context_get(context: Any, key: str) -> Optional[str]:
    """Read a string identifier from dict-like or object hook context."""
    if context is None:
        return None
    if isinstance(context, dict):
        value = context.get(key)
    else:
        value = getattr(context, key, None)
    return value if isinstance(value, str) and value else None


def _resolve_session_id(
    input_data: Dict[str, Any],
    tool_use_id: str,
    context: Any,
) -> Optional[str]:
    """Resolve the session identifier used for logging and drift tracking."""
    for key in SESSION_ID_KEYS:
        value = input_data.get(key)
        if isinstance(value, str) and value:
            return value
    for key in SESSION_ID_KEYS:
        value = _context_get(context, key)
        if value:
            return value
    if _require_session_id:
        return None
    return tool_use_id


def _resolve_gate_session_id(
    args: tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Optional[str]:
    """Resolve an optional session identifier for `@gate` calls."""
    session_id = kwargs.get("session_id")
    if isinstance(session_id, str) and session_id:
        return session_id

    if args:
        candidate = getattr(args[0], "session_id", None)
        if isinstance(candidate, str) and candidate:
            return candidate

    if _require_session_id:
        return None
    return None


def _get_drift_tracker(session_id: str) -> MarkovDriftTracker:
    """Return the Markov drift tracker for a session."""
    tracker = _drift_trackers.get(session_id)
    if tracker is None:
        tracker = MarkovDriftTracker(_drift_transition_matrix, session_id=session_id)
        _drift_trackers[session_id] = tracker
    return tracker


def _apply_drift(result: Any, session_id: str) -> None:
    """Apply session-level drift escalation to a scored action in place."""
    result.session_id = session_id
    bump = _get_drift_tracker(session_id).record(result)
    if bump is None:
        return

    result.band = bump.escalated_band
    result.rationale = f"{result.rationale} [SafetyDrift: {bump.reason}]"
    result.routing = _route_model(result.band, result.action.data_class)


def _session_required_message() -> str:
    """Return a consistent message for strict session-id enforcement."""
    return (
        "5D session id required: provide one of "
        f"{', '.join(SESSION_ID_KEYS)} to enable runtime drift tracking"
    )


async def fivedrisk_pre_tool(
    input_data: Dict[str, Any],
    tool_use_id: str,
    context: Any = None,
) -> Dict[str, Any]:
    """PreToolUse hook: score the action, gate execution.

    Also scans tool input text for injection patterns (L1 defense).

    Returns:
        Empty dict → allow (GREEN band).
        {"decision": "block", "reason": "..."} → block (ORANGE or RED band,
        or injection detected).
    """
    tool_name, tool_input = _extract_tool_info(input_data)
    session_id = _resolve_session_id(input_data, tool_use_id, context)
    if _require_session_id and session_id is None:
        return {"decision": "block", "reason": _session_required_message()}

    # L1: injection scan on tool input text before scoring
    input_text = str(tool_input)
    injection = scan_input_for_injection(input_text, source=f"tool:{tool_name}")
    if injection:
        return {
            "decision": "block",
            "reason": f"5D injection detected in tool input: {injection}",
        }

    destination_check = check_destination_policy(tool_name, tool_input)
    if destination_check and destination_check.decision == "block":
        return {
            "decision": "block",
            "reason": destination_check.reason,
            "destinations": list(destination_check.destinations),
        }

    action = classify_tool_call(
        tool_name=tool_name,
        tool_input=tool_input,
        policy=_policy,
        autonomy_context=_autonomy_context,
        source="agent-sdk",
    )

    result = score(action, _policy)
    _apply_drift(result, session_id)
    if destination_check and destination_check.decision == "warn":
        result.rationale = (
            f"{result.rationale} [DestinationPolicy: {destination_check.reason}]"
        )

    # Log every decision
    log = _log or DecisionLog()
    row_id = log.log(result)

    if result.band == Band.RED:
        return {
            "decision": "block",
            "reason": f"5D STOP: {result.rationale}",
            "5d_score": result.to_dict(),
            "log_id": row_id,
        }
    elif result.band == Band.ORANGE:
        return {
            "decision": "block",
            "reason": f"5D ASK: {result.rationale}. Approve? (yes/no)",
            "5d_score": result.to_dict(),
            "log_id": row_id,
        }

    # GREEN/YELLOW — allow execution
    return {}


async def fivedrisk_post_tool(
    input_data: Dict[str, Any],
    tool_use_id: str,
    context: Any = None,
) -> Dict[str, Any]:
    """PostToolUse hook: validate output for leakage and injection echoes.

    Scans:
    1. Sensitive data patterns (credentials, PII, crypto keys)
    2. Injection-echo patterns (LLM output echoing injection trigger phrases —
       indicates the model was successfully corrupted by a prompt injection)
    3. Suspicious exfiltration commands in output

    Returns:
        Empty dict → output is clean.
        {"decision": "block", "reason": "..."} → output blocked.
    """
    tool_name, _ = _extract_tool_info(input_data)
    output = str(input_data.get("tool_result", input_data.get("output", "")))

    if tool_name in RETRIEVAL_TOOLS:
        retrieved_injection = scan_retrieved_content(output, source=f"tool:{tool_name}")
        if retrieved_injection:
            return {
                "decision": "block",
                "reason": f"5D retrieved-content block: {retrieved_injection}",
            }

    leak = scan_output_for_leakage(output)
    if leak:
        return {
            "decision": "block",
            "reason": f"5D egress block: {leak}",
        }

    return {}
