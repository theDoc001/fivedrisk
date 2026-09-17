"""Framework adapter kit — the one canonical verdict socket every integration builds on.

Extracted from ``gateway.score_action_dict`` so every adapter (CrewAI, OpenAI, ADK,
Pydantic AI, the config MCP, TS-over-gateway, the setup skill) shares ONE scoring path
and ONE band→sentinel map instead of re-deriving the flow. Reuse-first: this calls the
already-shipped scan / classify / score / drift layers. It constructs NO new score and
NO fused cost×risk (that boundary stays out of OSS).

Adapter authors need two things:
  * ``to_verdict(tool_name, tool_input, ...) -> Verdict`` — the shared decision.
  * ``band_to_sentinel(band) -> str`` — the canonical, never-demote mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .classifier import classify_tool_call
from .hooks import (
    _apply_drift,
    _flatten_semantic_review_patterns,
    scan_input_for_injection,
    scan_semantic_review,
)
from .logger import DecisionLog
from .policy import Policy
from .schema import Band
from .scorer import score

# ─── Canonical sentinel vocabulary (what an adapter should DO with a banded action)
EXECUTE = "execute"   # run the tool  (GREEN, YELLOW)
APPROVE = "approve"   # hold for human approval before running  (ORANGE)
BLOCK = "block"       # deny  (RED, any pre-score input block, any error)

# Canonical band → sentinel. INVARIANT (QA-1, guardrail-integrity spine):
#   * RED  never maps to anything but BLOCK.
#   * ORANGE never maps to EXECUTE (it is APPROVE — a hold, not a pass).
#   * an unknown / unparseable band FAILS CLOSED to BLOCK.
# Adapters WITHOUT a native approval channel MUST treat APPROVE as BLOCK
# (fail-closed) — never as EXECUTE. `sentinel_blocks()` encodes that.
_BAND_SENTINEL: Dict[str, str] = {
    "GREEN": EXECUTE,
    "YELLOW": EXECUTE,
    "ORANGE": APPROVE,
    "RED": BLOCK,
}


def band_to_sentinel(band: Any) -> str:
    """Map a `Band` (or its str name) to the canonical sentinel. Never demotes.

    Accepts a `Band` enum, a bare band name (``"RED"``, any case, surrounding
    whitespace tolerated), or its enum-repr form (``"Band.RED"`` — exactly one
    leading ``BAND.`` prefix). WHOLE-TOKEN match only: a string that merely
    *ends* in a band name (``"evil.red.green"``, ``"x.green"``) is NOT a band —
    it fails closed to BLOCK. This is the anti-demotion spine (QA-1): a garbage
    or attacker-influenced label can never be normalized into a GO.
    """
    if isinstance(band, Band):
        name = band.name
    else:
        name = str(band).strip().upper()
        if name.startswith("BAND."):  # tolerate one enum-repr prefix, nothing more
            name = name[len("BAND."):]
    return _BAND_SENTINEL.get(name, BLOCK)  # unknown → fail closed to BLOCK


def sentinel_blocks(sentinel: str, *, has_approval_channel: bool = False) -> bool:
    """Whether an adapter should STOP the tool call for this sentinel.

    EXECUTE never stops. BLOCK always stops. APPROVE stops unless the host has a
    real approval channel to route it to — a host without one MUST fail closed.
    """
    if sentinel == EXECUTE:
        return False
    if sentinel == APPROVE:
        return not has_approval_channel
    return True  # BLOCK, or anything unrecognized → stop


_TRACE_FIELDS = (
    "agent_id",
    "session_id",
    "run_id",
    "trace_id",
    "span_id",
    "parent_span_id",
)


@dataclass
class Verdict:
    """One 5D decision, framework-agnostic. ``sentinel`` is the canonical action."""

    band: str                       # "GREEN" | "YELLOW" | "ORANGE" | "RED"
    sentinel: str                   # EXECUTE | APPROVE | BLOCK
    blocked: bool                   # True unless the tool should EXECUTE
    reason: str                     # human rationale
    decision_id: Optional[str] = None
    audit_log_id: Optional[int] = None
    scores: Optional[Dict[str, int]] = None      # per-dimension (None on a pre-score block)
    composite_score: Optional[float] = None
    max_dimension: Optional[int] = None
    routing: Optional[Dict[str, Any]] = None
    policy_version: Optional[str] = None
    error: Optional[str] = None                  # set on invalid input (fail-closed)
    error_type: Optional[str] = None
    pre_score_block: bool = False                # blocked by injection/semantic BEFORE scoring
    block_reason: Optional[str] = None           # raw scan reason on a pre-score block
    scored_action: Optional[Any] = None          # the ScoredAction, for adapters wanting richness
    trace: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """True only when the tool call should proceed (EXECUTE)."""
        return self.sentinel == EXECUTE


def to_verdict(
    tool_name: Optional[str],
    tool_input: Optional[Dict[str, Any]],
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    log: Optional[DecisionLog] = None,
    autonomy: Optional[int] = None,
    source: str = "adapter",
    trace: Optional[Dict[str, Any]] = None,
) -> Verdict:
    """Score one tool call and return a framework-agnostic :class:`Verdict`.

    The single shared path: validate → injection/semantic scan (block) → classify →
    score → Markov drift (if ``session_id``) → audit-log. **Fails CLOSED (BLOCK)** on
    any invalid input or scorer error — an adapter must never EXECUTE on an error.
    """
    policy = policy or Policy()
    trace = dict(trace or {})
    if session_id is not None:
        trace.setdefault("session_id", session_id)

    def _fail_closed(reason: str, *, error: Optional[str] = None,
                     error_type: Optional[str] = None) -> Verdict:
        return Verdict(band="RED", sentinel=BLOCK, blocked=True, reason=reason,
                       error=error, error_type=error_type, trace=trace)

    if not tool_name:
        return _fail_closed("tool_name is required",
                            error="tool_name is required", error_type="InvalidRequest")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        return _fail_closed("params/tool_input must be a JSON object",
                            error="params/tool_input must be a JSON object",
                            error_type="InvalidRequest")
    if autonomy is not None and not isinstance(autonomy, int):
        return _fail_closed("autonomy must be an integer",
                            error="autonomy must be an integer", error_type="InvalidRequest")

    # Pre-score input layers: injection scan, then policy-driven semantic review.
    input_text = str(tool_input)
    raw_reason: Optional[str] = None
    injection = scan_input_for_injection(input_text, source=f"tool:{tool_name}")
    if injection:
        raw_reason = f"injection detected in tool input: {injection}"
    else:
        semantic = scan_semantic_review(
            input_text,
            patterns=_flatten_semantic_review_patterns(policy.semantic_review_patterns),
        )
        if semantic:
            raw_reason = f"semantic review required: {semantic}"
    if raw_reason:
        if log is None:
            log = DecisionLog()
        row_id = log.log_egress_block(tool_name, raw_reason, session_id,
                                      source=f"{source}-input-block")
        return Verdict(
            band="RED", sentinel=BLOCK, blocked=True,
            reason=f"5D input block: {raw_reason}", pre_score_block=True,
            block_reason=raw_reason, decision_id=f"dec-{row_id}",
            audit_log_id=row_id, trace=trace,
        )

    try:
        action = classify_tool_call(
            tool_name=tool_name, tool_input=tool_input, policy=policy,
            autonomy_context=autonomy, source=source,
        )
    except (ValueError, TypeError) as exc:
        return _fail_closed(str(exc), error=str(exc), error_type=type(exc).__name__)

    for key, val in trace.items():
        if val is not None:
            action.metadata[key] = val

    try:
        scored = score(action, policy)
    except Exception as exc:  # defensive: scorer should not raise on a valid Action
        return _fail_closed(str(exc), error=str(exc), error_type=type(exc).__name__)

    if session_id is not None:
        scored.session_id = session_id
        _apply_drift(scored, session_id, policy)

    if log is None:
        log = DecisionLog()
    row_id = log.log(scored)

    sentinel = band_to_sentinel(scored.band)
    return Verdict(
        band=str(scored.band),
        sentinel=sentinel,
        blocked=(sentinel != EXECUTE),
        reason=scored.rationale,
        decision_id=f"dec-{row_id}",
        audit_log_id=row_id,
        scores={
            "data_sensitivity": action.data_sensitivity,
            "tool_privilege": action.tool_privilege,
            "reversibility": action.reversibility,
            "external_impact": action.external_impact,
            "autonomy_context": action.autonomy_context,
        },
        composite_score=round(scored.composite_score, 3),
        max_dimension=scored.max_dimension,
        routing=scored.routing.to_dict() if scored.routing is not None else None,
        policy_version=scored.policy_version,
        scored_action=scored,
        trace={k: action.metadata[k] for k in _TRACE_FIELDS if k in action.metadata},
    )
