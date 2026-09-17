"""5D Risk Governance Engine — Claude Agent SDK hooks + runtime gates.

Drop-in PreToolUse/PostToolUse hooks for the Claude Agent SDK.
Also provides:
  - scan_input_for_injection(): call before any LLM prompt
  - scan_output_for_leakage(): call on any LLM output
  - @gate decorator: wrap any Python function with 5D scoring
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
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from .budget_accumulator import BudgetAccumulator, ReservationResult
from .classifier import classify_tool_call
from .detectors import (
    DETECTOR_CORPUS_VERSION,
    EGRESS_PATTERNS,
    INJECTION_PATTERNS,
    RETRIEVAL_TOOLS,
)
from .events import (
    NDJSONEventChannel,
    REASON_BUDGET_CAP_EXCEEDED,
    REASON_IDENTITY_REQUIRED_NOT_SUPPLIED,
)
from .logger import DecisionLog
from .markov import MarkovDriftTracker, make_default_transition_matrix
from .policy import Policy, load_policy
from .schema import ActingIdentity, Band, PrincipalType
from .scorer import _route_model, score
from .token_costs import resolve_model_class, worst_case_tokens_for_call

# ─── Module-level defaults — override via configure() ──────────

_policy: Policy = Policy()
_log: Optional[DecisionLog] = None
# M4: lazily-created shared default log for the unconfigured path, so a runtime
# that never calls configure() does not reconstruct DecisionLog (and rerun the
# schema DDL) on every single tool call.
_default_log: Optional[DecisionLog] = None
_autonomy_context: int = 0
_drift_transition_matrix: list[list[float]] = make_default_transition_matrix()
_drift_trackers: Dict[str, MarkovDriftTracker] = {}
# M2: cap tracked sessions so a long-lived process cannot grow _drift_trackers /
# _budget_accumulators without bound. Oldest-inserted session evicted (FIFO).
MAX_TRACKED_SESSIONS: int = 10_000
# M1 (Q6, minimal locking): serialize the check-then-act that lazily creates and
# evicts per-session state, so concurrent threads cannot double-create or race
# eviction. Per-BudgetAccumulator reserve/commit is separately locked internally.
_state_lock = threading.Lock()
_require_session_id: bool = False
_destination_allowlist: Optional[frozenset[str]] = None
_destination_denylist: frozenset[str] = frozenset()
_semantic_review_patterns: tuple[tuple[str, str], ...] = ()

SESSION_ID_KEYS = ("session_id", "thread_id", "conversation_id", "run_id")

# ─── Retry-budget state ─────────────────────────────────────────
# `policy.retry_budget` shipped for several releases parsed onto the Policy object and read by
# NOTHING. A key an operator can set, a reviewer can approve and a change record can capture,
# which does nothing, is worse than no key at all: everyone in the approval chain believes the
# control exists. It is enforced here rather than deleted, because the NAME is the control.
#
# Counted per (session, action) where the action is (tool_name, tool_input_hash) — the hash the
# decision log already records, reused rather than reinvented. Same FIFO session bound as the
# drift trackers and budget accumulators above.
_retry_counts: Dict[str, Dict[str, int]] = {}

# ─── Cost-management state ──────────────────────────────────────
_budget_accumulators: Dict[str, BudgetAccumulator] = {}
_event_channel: Optional[NDJSONEventChannel] = None
_default_model_class: Optional[str] = None
_default_estimated_input_tokens: int = 1000


# ─── DENY exceptions ─────────────────────────────────────────────

class FivedriskDenial(Exception):
    """Base for security DENY exceptions raised by @gate.

    Low-9: these deliberately do NOT subclass ValueError. A gate DENY that was a
    ValueError got silently swallowed by any caller's broad `except ValueError`
    (JSON parsing, input validation) — the action then proceeded as if allowed,
    a fail-open. Catch `FivedriskDenial` (or the specific subclasses) explicitly.
    """


class BudgetExceededError(FivedriskDenial):
    """Raised by @gate when a tool call would exceed the session budget."""


class IdentityRequiredError(FivedriskDenial):
    """Raised by @gate when policy.identity_required is True and the
    caller supplied no acting_identity (or ANONYMOUS)."""


class BandBlockError(FivedriskDenial):
    """Raised by @gate when an action's risk band (RED or ORANGE) blocks it.

    Like the other FivedriskDenial subclasses, this deliberately does NOT
    subclass ValueError. The band decision is the PRIMARY security verdict of
    the gate; if it were a ValueError a caller's broad `except ValueError`
    (JSON parsing, input validation) would swallow a RED/ORANGE block and the
    action would proceed as if allowed — a fail-open. Catch `FivedriskDenial`
    (or `BandBlockError`) explicitly to handle a block."""


class SessionRequiredError(FivedriskDenial):
    """Raised by @gate when policy requires a session id and none was supplied.

    Sibling of the OSS-1 BandBlockError fix: this security block deliberately
    does NOT subclass ValueError, so a caller's broad `except ValueError` cannot
    silently swallow it and let the action run without the required session
    identity — a fail-open. Catch `FivedriskDenial` (or `SessionRequiredError`)."""


class RetryBudgetExceededError(FivedriskDenial):
    """Raised when one action is attempted more times in a session than `policy.retry_budget`.

    A refusal ends an ACTION. Without a budget, an agent is free to attempt the same action
    indefinitely, and a control that refuses individual actions in an unbounded loop is not a
    control on the agent. This bounds the loop.

    Opt-in: `retry_budget` defaults to None and enforces nothing until a deployment declares a
    number. The right number is per action class — low for an irreversible external effect,
    higher for something idempotent — and it also depends on whether this interception point
    sits below the caller's own retry policy, so it is not a value to pick on their behalf.
    """


class DestinationBlockError(FivedriskDenial):
    """Raised by @gate when a tool call targets a blocked destination.

    Fires on a denylisted host, or, when an allowlist is declared, on a host not
    on the allowlist. Sibling of the OSS-1 BandBlockError fix: this security
    block deliberately does NOT subclass ValueError, so a caller's broad
    `except ValueError` cannot silently swallow it and let the egress proceed —
    a fail-open. Catch `FivedriskDenial` (or `DestinationBlockError`)."""


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
    drift_transition_matrix: Optional[list[list[float]]] = None,
    require_session_id: bool = False,
    destination_allowlist: Optional[Iterable[str]] = None,
    destination_denylist: Optional[Iterable[str]] = None,
    semantic_review_patterns: Optional[dict[str, list[str]]] = None,
    event_path: Optional[str] = None,
    default_model_class: Optional[str] = None,
    default_estimated_input_tokens: int = 1000,
) -> None:
    """Configure the hooks module.

    Call once at agent startup to set policy, log location, and
    autonomy context.

    New in OSS-COST-MVP-001:
      - `event_path`: optional path to an NDJSON event log file. Emits
        risk_decision, budget_intervention, and identity_required_denial
        events with shared trace_id/session_id for correlation.
      - `default_model_class`: model class label used for budget
        reservation when the caller does not pass one explicitly. See
        token_costs.MODEL_COSTS for valid identifiers.
      - `default_estimated_input_tokens`: conservative default for
        per-call input token count when caller does not supply one.
    """
    global _policy, _log, _autonomy_context
    global _drift_transition_matrix, _drift_trackers
    global _require_session_id, _destination_allowlist
    global _destination_denylist
    global _semantic_review_patterns
    global _budget_accumulators, _event_channel, _retry_counts
    global _default_model_class, _default_estimated_input_tokens
    _policy = load_policy(policy_path)
    _log = DecisionLog(log_path) if log_path else DecisionLog()
    _autonomy_context = autonomy_context
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
    _semantic_review_patterns = _flatten_semantic_review_patterns(
        semantic_review_patterns
        if semantic_review_patterns is not None
        else _policy.semantic_review_patterns
    )
    _budget_accumulators = {}
    _retry_counts = {}
    _event_channel = NDJSONEventChannel(path=event_path) if event_path else None
    _default_model_class = default_model_class
    _default_estimated_input_tokens = default_estimated_input_tokens


# ─── Budget admission helpers (OSS-COST-MVP-001) ────────────────


def _get_or_create_budget_accumulator(
    session_id: str, policy: Policy
) -> BudgetAccumulator:
    """Lazy-create a per-session budget accumulator from the policy cap."""
    with _state_lock:
        if session_id not in _budget_accumulators:
            _budget_accumulators[session_id] = BudgetAccumulator(
                session_id=session_id,
                max_session_budget_tokens=policy.max_session_budget_tokens,
            )
            _evict_oldest_if_over_cap(_budget_accumulators)
        return _budget_accumulators[session_id]


def _perform_budget_admission(
    tool_id: str,
    tool_name: str,
    session_id: Optional[str],
    policy: Policy,
    estimated_input_tokens: int,
    model_class: Optional[str],
    acting_identity: Optional[ActingIdentity] = None,
) -> ReservationResult:
    """Reserve worst-case tokens for this tool call.

    Returns the ReservationResult. Caller checks `.approved`. On
    rejection, emits a budget_intervention NDJSON event and the caller
    raises BudgetExceededError.
    """
    if session_id is None or policy.max_session_budget_tokens is None:
        # No session or no cap; admit without reservation tracking.
        return ReservationResult(
            approved=True,
            cumulative_token_spend=0,
            max_session_budget_tokens=policy.max_session_budget_tokens,
            pressure_ratio=0.0,
            reserved_tokens=0,
        )

    acc = _get_or_create_budget_accumulator(session_id, policy)
    effective_model_class = model_class or _default_model_class
    if effective_model_class is None:
        # No model class configured. Use input_tokens + default output cap.
        worst_case = estimated_input_tokens + (policy.max_tool_call_budget_tokens or 4096)
    else:
        # U2: a concrete model id ("claude-sonnet-4-6") is NOT a cost-class key, so
        # passing it straight to worst_case_tokens_for_call silently falls to the
        # generic input+cap fallback and under-sizes the reservation (fail-open on
        # cost). Resolve id -> tuned class first. Genuinely-unknown ids resolve to
        # None and still fall to the generic fallback inside worst_case_tokens_for_call.
        resolved_class = resolve_model_class(effective_model_class) or effective_model_class
        worst_case = worst_case_tokens_for_call(
            resolved_class,
            estimated_input_tokens,
            policy.max_tool_call_budget_tokens,
        )

    result = acc.reserve_for_tool_call(tool_id=tool_id, worst_case_tokens=worst_case)

    if not result.approved and _event_channel is not None:
        _event_channel.emit_budget_intervention(
            session_id=session_id,
            reason_code=result.reason_code or REASON_BUDGET_CAP_EXCEEDED,
            cumulative_token_spend=result.cumulative_token_spend,
            max_session_budget_tokens=result.max_session_budget_tokens,
            pressure_ratio=result.pressure_ratio,
            tool_id=tool_id,
            tool_name=tool_name,
            reserved_tokens=result.reserved_tokens,
            acting_identity=acting_identity,
        )

    return result


def _perform_identity_admission(
    tool_name: str,
    session_id: Optional[str],
    policy: Policy,
    acting_identity: Optional[ActingIdentity],
) -> bool:
    """Check identity_required policy. Returns True if admitted.

    On rejection, emits an identity_required_denial NDJSON event.
    """
    if not policy.identity_required:
        return True
    if acting_identity is None or acting_identity.principal_type == PrincipalType.ANONYMOUS:
        if _event_channel is not None:
            _event_channel.emit_identity_required_denial(
                session_id=session_id,
                tool_name=tool_name,
                attempted_identity=acting_identity,
            )
        return False
    return True


# Low-10 (2026-07-11): the rate_limit_check + hitl_queue_increment/decrement
# "DoS defense layer" was exported but never invoked by any runtime path
# (fivedrisk_pre_tool / @gate / gateway). Deleted per OSS-DEADCODE-RATELIMIT-001;
# archived at ../../archive/hooks_rate_limit_hitl_layer_deleted-2026-07-11.py.


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

    # M8: optionally consume a userinfo segment (`user[:pass]@`) BEFORE capturing
    # the host, so `https://allowed.com@evil.com/x` resolves to `evil.com`, not the
    # allowlisted-looking `allowed.com` before the `@`.
    for match in re.findall(
        r"(?i)\b(?:https?|ssh)://(?:[a-z0-9.\-_~%!$&'()*+,;=:]+@)?([a-z0-9.-]+\.[a-z]{2,})",
        input_text,
    ):
        candidates.add(_normalize_destination(match))

    # P0 (audit O1): the gap between the command and the URL/host is `[^'"]+?` — NOT
    # `(?:[^'"]|\s)+?`. The `|\s` branch was redundant (whitespace ∉ {', "} so it is already in
    # `[^'"]`) but its ambiguous overlap caused exponential backtracking on a long whitespace run
    # (measured 5.7s at 24 spaces after `curl`), freezing the gate. Dropping it is provably
    # language-identical and unambiguous. See test_redos_destination_extraction.
    for match in re.findall(r"(?i)\b(?:curl|wget)\b[^'\"]+?(https?://[^\s'\"<>]+)", input_text):
        candidates.add(_normalize_destination(match))

    for match in re.findall(r"(?i)\b(?:ssh|scp|rsync)\b[^'\"]+?([a-z0-9.-]+\.[a-z]{2,}):?", input_text):
        candidates.add(_normalize_destination(match))

    # D2 (dogfooding, 2026-09-10; fixed 2026-09-16). These keys used to be read only when
    # `tool_name` was literally "WebFetch" or "WebSearch". Every other integrator got no
    # structured destination extraction, and the gap was not uniform: the generic URL regex
    # above requires an alphabetic TLD, so a public host like `evil.example.com` survived a
    # custom tool name while `127.0.0.1` and `192.168.1.1` did not. Loopback and RFC1918 are
    # the class a destination control most exists to catch, so the control was blindest
    # exactly where it mattered. The key NAMES are the signal, not the tool's name.
    for key in ("url", "urls", "domain", "domains", "host", "hosts"):
        value = tool_input.get(key)
        if isinstance(value, str):
            candidates.add(_normalize_destination(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    candidates.add(_normalize_destination(item))

    return sorted(value for value in candidates if value)


def _record_attempt(session_id, tool_name: str, tool_input_hash: str) -> int:
    """Count this attempt at one action in one session and return the running total.

    Returns 0 when there is no session to count within: an uncorrelated call cannot be told
    apart from a first attempt, and inventing a shared bucket for them would collapse every
    unidentifiable action together — which would deny the wrong things and look like a control.
    """
    if not session_id:
        return 0
    key = f"{tool_name}::{tool_input_hash}"
    with _state_lock:
        seen = _retry_counts.setdefault(session_id, {})
        n = seen.get(key, 0) + 1
        seen[key] = n
        while len(_retry_counts) > MAX_TRACKED_SESSIONS:
            _retry_counts.pop(next(iter(_retry_counts)))
    return n


def check_retry_budget(policy, session_id, tool_name: str, tool_input_hash: str):
    """Count the attempt and return a denial reason once the budget is exceeded, else None.

    Counting happens on EVERY call, whether or not a budget is declared, so that turning the
    budget on mid-session does not read a count of zero for actions already attempted.
    """
    n = _record_attempt(session_id, tool_name, tool_input_hash)
    budget = getattr(policy, "retry_budget", None)
    if budget is None or n <= budget:
        return None
    return (f"5D retry budget: attempt {n} at this action in this session exceeds "
            f"retry_budget={budget}")


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
            # A declared allowlist is an enforcement decision. There is no setting that
            # downgrades a miss to a warning: a configuration that lets a non-allowlisted
            # destination proceed is a fail-open, and fail-open is not a setting.
            return DestinationPolicyResult(
                decision="block",
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


def _flatten_semantic_review_patterns(
    patterns: Optional[dict[str, list[str]]],
) -> tuple[tuple[str, str], ...]:
    """Normalize profile semantic-review patterns into `(pattern, label)` pairs."""
    if not patterns:
        return ()
    flattened: list[tuple[str, str]] = []
    for label, label_patterns in patterns.items():
        for pattern in label_patterns:
            flattened.append((pattern, label))
    return tuple(flattened)


def scan_semantic_review(
    text: str,
    patterns: Optional[Iterable[tuple[str, str]]] = None,
) -> Optional[str]:
    """Return a profile semantic-review hit, if configured.

    This is deliberately not a broad semantic classifier. It is a
    deployment-profile cue that says: this agent's mission treats this content
    class as requiring observer/HITL review.
    """
    active_patterns = tuple(patterns) if patterns is not None else _semantic_review_patterns
    for pattern, label in active_patterns:
        if re.search(pattern, text):
            return f"[{label}] Matched: {pattern[:50]}..."
    return None


# ─── @gate decorator ───────────────────────────────────────────

def gate(
    tool_name: str,
    autonomy_context: int = 0,
    policy: Optional[Policy] = None,
    log: Optional[DecisionLog] = None,
    on_block: Optional[Callable[[str], Any]] = None,
    acting_identity: Optional[ActingIdentity] = None,
    model_class: Optional[str] = None,
    estimated_input_tokens: Optional[int] = None,
):
    """Decorator: wrap any Python function with 5D scoring.

    The decorated function is gated through the 5D engine before execution.
    If the action scores ASK or STOP, the function is NOT called and
    on_block() is invoked instead (or a FivedriskDenial subclass is raised if
    on_block is None).

    Args:
        tool_name: The logical name for this action in the policy/log.
        autonomy_context: 0 (interactive) to 4 (fully unattended).
        policy: Override module-level policy.
        log: Override module-level log.
        on_block: Callable(reason: str) → Any. Called instead of the
                  decorated function if action is blocked. If None, raises the
                  matching FivedriskDenial subclass (BandBlockError,
                  BudgetExceededError, IdentityRequiredError,
                  SessionRequiredError, or DestinationBlockError).

    Example:
        @gate(tool_name="write_vault_file", autonomy_context=1)
        def write_to_vault(path: str, content: str) -> None:
            Path(path).write_text(content)

        @gate(tool_name="send_discord_message", autonomy_context=0,
              on_block=lambda r: logger.warning("blocked", reason=r))
        def send_message(channel_id, text):
            ...
    """
    # M3: policy/log are resolved at CALL time inside each wrapper, not here.
    # Binding _policy/_log at decoration time silently pinned the default policy
    # even when configure() ran later in main() — the common decorate-at-import,
    # configure-in-main pattern.
    _decorator_acting_identity = acting_identity
    _decorator_model_class = model_class
    _decorator_input_tokens = estimated_input_tokens

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # M3: resolve policy/log at call time (see gate() note above).
            _use_policy = policy or _policy
            _use_log = log or _effective_log()
            # Pop per-call overrides before building tool_input
            call_acting_identity = kwargs.pop(
                "_fivedrisk_acting_identity", _decorator_acting_identity
            )
            call_model_class = kwargs.pop(
                "_fivedrisk_model_class", _decorator_model_class
            )
            call_input_tokens = kwargs.pop(
                "_fivedrisk_input_tokens",
                _decorator_input_tokens
                if _decorator_input_tokens is not None
                else _default_estimated_input_tokens,
            )

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
            if call_acting_identity is not None:
                action.acting_identity = call_acting_identity

            session_id = _resolve_gate_session_id(args, kwargs)
            if _require_session_id and session_id is None:
                reason = _session_required_message()
                if on_block:
                    return on_block(reason)
                raise SessionRequiredError(reason)

            # Identity admission
            if not _perform_identity_admission(
                tool_name, session_id, _use_policy, call_acting_identity
            ):
                reason = (
                    f"5D IDENTITY_REQUIRED_NOT_SUPPLIED ({tool_name}): "
                    f"policy requires identity, none supplied"
                )
                if on_block:
                    return on_block(reason)
                raise IdentityRequiredError(reason)

            # Budget admission
            tool_call_id = uuid.uuid4().hex[:12]
            reservation = _perform_budget_admission(
                tool_id=tool_call_id,
                tool_name=tool_name,
                session_id=session_id,
                policy=_use_policy,
                estimated_input_tokens=call_input_tokens,
                model_class=call_model_class,
                acting_identity=call_acting_identity,
            )
            if not reservation.approved:
                reason = (
                    f"5D {reservation.reason_code} ({tool_name}): "
                    f"projected spend would exceed max_session_budget_tokens"
                )
                if on_block:
                    return on_block(reason)
                raise BudgetExceededError(reason)

            destination_check = check_destination_policy(tool_name, tool_input)
            if destination_check and destination_check.decision == "block":
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                # O3-sibling: this @gate destination-input denial returns/raises
                # BEFORE the score-time log below, so the denial was unaudited on
                # the primary path. Audit it once via the shipped egress-block
                # writer. source distinguishes the @gate entry path from the
                # SDK-hook (pre-tool-input-block) and gateway (gateway-input-block).
                _use_log.log_egress_block(
                    tool_name, destination_check.reason, session_id, source="gate-input-block"
                )
                if on_block:
                    return on_block(destination_check.reason)
                raise DestinationBlockError(destination_check.reason)

            result = score(action, _use_policy)
            # Retry budget. Counted after scoring so the fingerprint is the one the decision
            # log records, and enforced BEFORE the action runs. Denial is a refusal like any
            # other: nothing executed, and the reservation is rolled back.
            _retry_n = _record_attempt(session_id, result.action.tool_name,
                                       result.action.tool_input_hash)
            # 🔴 Fill `retry_count`, which was declared on ScoredAction, serialised into the CLI
            # JSON and the LangGraph state as a constant 0, and never written. A field that is
            # always 0 in an evidence surface is a false zero, not a missing value.
            result.retry_count = _retry_n
            _budget = getattr(_use_policy, "retry_budget", None)
            _retry_reason = (
                f"5D retry budget: attempt {_retry_n} at this action in this session exceeds "
                f"retry_budget={_budget}"
                if _budget is not None and _retry_n > _budget else None)
            if _retry_reason:
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                _use_log.log(result, config_hash=_use_policy.content_hash(),
                             policy_preset=_use_policy.preset_name)
                if on_block:
                    return on_block(_retry_reason)
                raise RetryBudgetExceededError(_retry_reason)
            if session_id:
                _apply_drift(result, session_id, _use_policy)
            # Bind the decision to the policy that produced it. Without these two the
            # record cannot answer "which policy was in force, and which posture was
            # declared", which is the first question asked after an incident.
            _use_log.log(
                result,
                config_hash=_use_policy.content_hash(),
                policy_preset=_use_policy.preset_name,
            )

            # Emit risk_decision NDJSON event with identity correlation
            if _event_channel is not None:
                _event_channel.emit_risk_decision(
                    session_id=session_id,
                    scored_action=result,
                    acting_identity=call_acting_identity,
                )

            if result.band == Band.RED:
                reason = f"5D RED ({result.band}): {result.rationale}"
                # roll back the reservation; the action did not execute
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                if on_block:
                    return on_block(reason)
                raise BandBlockError(reason)

            if result.band == Band.ORANGE:
                reason = f"5D ORANGE ({result.band}): {result.rationale}"
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                if on_block:
                    return on_block(reason)
                raise BandBlockError(reason)

            try:
                return fn(*args, **kwargs)
            finally:
                # Commit at worst-case (conservative; actual token count
                # is unknown to OSS @gate). Replace with measured count
                # by passing _fivedrisk_actual_tokens in callable kwargs
                # if your wrapper has post-call instrumentation.
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].commit_reservation(
                        tool_call_id, actual_tokens=reservation.reserved_tokens
                    )

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            # M3: resolve policy/log at call time (see gate() note above).
            _use_policy = policy or _policy
            _use_log = log or _effective_log()
            call_acting_identity = kwargs.pop(
                "_fivedrisk_acting_identity", _decorator_acting_identity
            )
            call_model_class = kwargs.pop(
                "_fivedrisk_model_class", _decorator_model_class
            )
            call_input_tokens = kwargs.pop(
                "_fivedrisk_input_tokens",
                _decorator_input_tokens
                if _decorator_input_tokens is not None
                else _default_estimated_input_tokens,
            )
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
            if call_acting_identity is not None:
                action.acting_identity = call_acting_identity

            session_id = _resolve_gate_session_id(args, kwargs)
            if _require_session_id and session_id is None:
                reason = _session_required_message()
                if on_block:
                    return (await on_block(reason)) if inspect.iscoroutinefunction(on_block) else on_block(reason)
                raise SessionRequiredError(reason)

            # OSS-PASS-THROUGH-IDENTITY-001 admission
            if not _perform_identity_admission(
                tool_name, session_id, _use_policy, call_acting_identity
            ):
                reason = (
                    f"5D IDENTITY_REQUIRED_NOT_SUPPLIED ({tool_name}): "
                    f"policy requires identity, none supplied"
                )
                if on_block:
                    return (await on_block(reason)) if inspect.iscoroutinefunction(on_block) else on_block(reason)
                raise IdentityRequiredError(reason)

            # OSS-COST-MVP-001 budget admission
            tool_call_id = uuid.uuid4().hex[:12]
            reservation = _perform_budget_admission(
                tool_id=tool_call_id,
                tool_name=tool_name,
                session_id=session_id,
                policy=_use_policy,
                estimated_input_tokens=call_input_tokens,
                model_class=call_model_class,
                acting_identity=call_acting_identity,
            )
            if not reservation.approved:
                reason = (
                    f"5D {reservation.reason_code} ({tool_name}): "
                    f"projected spend would exceed max_session_budget_tokens"
                )
                if on_block:
                    return (await on_block(reason)) if inspect.iscoroutinefunction(on_block) else on_block(reason)
                raise BudgetExceededError(reason)

            destination_check = check_destination_policy(tool_name, tool_input)
            if destination_check and destination_check.decision == "block":
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                # O3-sibling (async): same as the sync @gate path — audit the
                # destination-input denial once before the return/raise, since
                # both happen before the score-time log below.
                _use_log.log_egress_block(
                    tool_name, destination_check.reason, session_id, source="gate-input-block"
                )
                if on_block:
                    return (await on_block(destination_check.reason)) if inspect.iscoroutinefunction(on_block) else on_block(destination_check.reason)
                raise DestinationBlockError(destination_check.reason)

            result = score(action, _use_policy)
            # Retry budget. Counted after scoring so the fingerprint is the one the decision
            # log records, and enforced BEFORE the action runs. Denial is a refusal like any
            # other: nothing executed, and the reservation is rolled back.
            _retry_n = _record_attempt(session_id, result.action.tool_name,
                                       result.action.tool_input_hash)
            # 🔴 Fill `retry_count`, which was declared on ScoredAction, serialised into the CLI
            # JSON and the LangGraph state as a constant 0, and never written. A field that is
            # always 0 in an evidence surface is a false zero, not a missing value.
            result.retry_count = _retry_n
            _budget = getattr(_use_policy, "retry_budget", None)
            _retry_reason = (
                f"5D retry budget: attempt {_retry_n} at this action in this session exceeds "
                f"retry_budget={_budget}"
                if _budget is not None and _retry_n > _budget else None)
            if _retry_reason:
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                _use_log.log(result, config_hash=_use_policy.content_hash(),
                             policy_preset=_use_policy.preset_name)
                if on_block:
                    return on_block(_retry_reason)
                raise RetryBudgetExceededError(_retry_reason)
            if session_id:
                _apply_drift(result, session_id, _use_policy)
            # Bind the decision to the policy that produced it. Without these two the
            # record cannot answer "which policy was in force, and which posture was
            # declared", which is the first question asked after an incident.
            _use_log.log(
                result,
                config_hash=_use_policy.content_hash(),
                policy_preset=_use_policy.preset_name,
            )

            if _event_channel is not None:
                _event_channel.emit_risk_decision(
                    session_id=session_id,
                    scored_action=result,
                    acting_identity=call_acting_identity,
                )

            if result.band == Band.RED:
                reason = f"5D RED ({result.band}): {result.rationale}"
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                if on_block:
                    return (await on_block(reason)) if asyncio.iscoroutinefunction(on_block) else on_block(reason)
                raise BandBlockError(reason)

            if result.band == Band.ORANGE:
                reason = f"5D ORANGE ({result.band}): {result.rationale}"
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].cancel_reservation(tool_call_id)
                if on_block:
                    return (await on_block(reason)) if asyncio.iscoroutinefunction(on_block) else on_block(reason)
                raise BandBlockError(reason)

            try:
                if inspect.iscoroutinefunction(fn):
                    return await fn(*args, **kwargs)
                return fn(*args, **kwargs)
            finally:
                if session_id and session_id in _budget_accumulators:
                    _budget_accumulators[session_id].commit_reservation(
                        tool_call_id, actual_tokens=reservation.reserved_tokens
                    )

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


def _evict_oldest_if_over_cap(store: Dict[str, Any], cap: int = MAX_TRACKED_SESSIONS) -> None:
    """M2: bound a per-session store by evicting oldest-inserted keys (FIFO)."""
    while len(store) > cap:
        del store[next(iter(store))]


def _get_drift_tracker(session_id: str) -> MarkovDriftTracker:
    """Return the Markov drift tracker for a session.

    M2 note: drift accumulates only when the CALLER supplies a stable session id
    (see SESSION_ID_KEYS). With no caller session id, `_resolve_session_id` falls
    back to the per-call tool_use_id, so each call gets its own tracker and drift
    does not accumulate across the session — an explicit, documented limitation,
    not a silent failure. The FIFO cap below stops those per-call trackers from
    leaking in a long-lived process.
    """
    with _state_lock:
        tracker = _drift_trackers.get(session_id)
        if tracker is None:
            tracker = MarkovDriftTracker(_drift_transition_matrix, session_id=session_id)
            _drift_trackers[session_id] = tracker
            _evict_oldest_if_over_cap(_drift_trackers)
        return tracker


def _effective_log() -> DecisionLog:
    """Return the configured log, or a lazily-created shared default (M4).

    Avoids reconstructing DecisionLog (and re-running the schema DDL) on every
    call when configure() was never invoked.
    """
    global _default_log
    if _log is not None:
        return _log
    if _default_log is None:
        _default_log = DecisionLog()
    return _default_log


def _apply_drift(result: Any, session_id: str, policy: Optional[Policy] = None) -> None:
    """Apply session-level drift escalation to a scored action in place."""
    result.session_id = session_id
    bump = _get_drift_tracker(session_id).record(result)
    if bump is None:
        return

    result.band = bump.escalated_band
    result.rationale = f"{result.rationale} [SafetyDrift: {bump.reason}]"
    # Low-12: pass the effective policy so a drift-bumped action still honors
    # yellow_model_escalation when re-routing. Without it the re-route silently
    # dropped the caller's YELLOW escalation opt-in.
    result.routing = _route_model(
        result.band, result.action.data_class, policy=policy or _policy
    )


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
        reason = f"5D injection detected in tool input: {injection}"
        # O3: these pre-tool input blocks return BEFORE scoring/logging, so the
        # SDK-hook path was weaker than the gateway (which logs its input blocks).
        # Audit the denial via the shipped egress-block writer so "audits every
        # decision" holds for the highest-signal denials. The @gate path audits
        # its own destination-input denials separately (source=gate-input-block,
        # honoring the per-call log= override); this call covers only these
        # pre-tool early returns.
        _effective_log().log_egress_block(
            tool_name, reason, session_id, source="pre-tool-input-block"
        )
        return {"decision": "block", "reason": reason}

    semantic_review = scan_semantic_review(input_text)
    if semantic_review:
        reason = f"5D ASK: semantic review required in tool input: {semantic_review}"
        _effective_log().log_egress_block(
            tool_name, reason, session_id, source="pre-tool-input-block"
        )
        return {
            "decision": "block",
            "reason": reason,
            "semantic_review": True,
        }

    destination_check = check_destination_policy(tool_name, tool_input)
    if destination_check and destination_check.decision == "block":
        _effective_log().log_egress_block(
            tool_name, destination_check.reason, session_id, source="pre-tool-input-block"
        )
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

    # Log every decision
    log = _effective_log()
    row_id = log.log(
        result,
        config_hash=_policy.content_hash(),
        policy_preset=_policy.preset_name,
    )

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
    session_id = _resolve_session_id(input_data, tool_use_id, context)

    def _block(reason: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # M7: egress blocks are now written to the audit trail (they were not
        # before), so an operator can reconstruct why an output was blocked.
        row_id = _effective_log().log_egress_block(tool_name, reason, session_id)
        result = {"decision": "block", "reason": reason, "log_id": row_id}
        if extra:
            result.update(extra)
        return result

    if tool_name in RETRIEVAL_TOOLS:
        retrieved_injection = scan_retrieved_content(output, source=f"tool:{tool_name}")
        if retrieved_injection:
            return _block(f"5D retrieved-content block: {retrieved_injection}")

    leak = scan_output_for_leakage(output)
    if leak:
        return _block(f"5D egress block: {leak}")

    semantic_review = scan_semantic_review(output)
    if semantic_review:
        return _block(
            f"5D ASK: semantic review required in tool output: {semantic_review}",
            {"semantic_review": True},
        )

    return {}
