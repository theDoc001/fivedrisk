"""Native framework adapters — thin shims over the M0 verdict socket.

Each function returns a callback shaped for one framework's *pre-tool-execution*
hook. The callback scores the pending tool call with :func:`fivedrisk.adapters.to_verdict`
and translates the resulting sentinel into whatever that framework expects to STOP a
tool from running. The frameworks are optional dependencies: importing this module
never imports them; the framework symbols are looked up lazily only when a block is
actually raised, so `import fivedrisk` stays dependency-free.

The gate is fail-closed. BLOCK and ORANGE (APPROVE) both stop the tool. These hooks
have no per-call approval exchange; the deprecated ``has_approval_channel`` keyword
is accepted but ignored. Human review and any authorized continuation belong to the
host application. Invalid input or scorer errors resolve to BLOCK in ``to_verdict``.

VALIDATION STATUS (read before production): these shims are built against the
*documented* framework APIs current as of 2026-07 and their translation logic is unit
-tested against in-repo fakes, but they are NOT yet validated end-to-end against a live
install of each SDK. Pin your framework version and run a one-call smoke test (a known
RED tool call must not execute) before relying on one. Version notes per adapter below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .adapters import Verdict, sentinel_blocks, to_verdict
from .logger import DecisionLog
from .policy import Policy


@dataclass
class _GateDecision:
    """The framework-agnostic result of gating one tool call."""

    block: bool
    reason: str
    verdict: Verdict


def _gate_decision(
    tool_name: Optional[str],
    tool_input: Any,
    policy: Optional[Policy],
    session_id: Optional[str],
    has_approval_channel: bool,
    autonomy: Optional[int],
    source: str,
    log: Optional[DecisionLog] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    session_context: Any = None,
    require_session_id: bool = False,
) -> _GateDecision:
    """Score one tool call and decide whether the framework should stop it.

    This is the whole brain of every adapter; the per-framework wrappers only
    translate ``_GateDecision`` into the framework's own block shape. Kept
    separate so the decision is testable without importing any framework.

    A non-dict ``tool_input`` is NOT coerced here — it flows straight into
    ``to_verdict``, which fails CLOSED (BLOCK) on anything that is not a JSON
    object. Wrapping a hostile non-dict payload under a synthetic key would hide
    it from the classifier and demote a stop into a go (QA-M1 finding).
    """
    effective_policy = policy or Policy()

    def session_failure(reason: str, error_type: str) -> _GateDecision:
        effective_log = log or DecisionLog()
        logged_name = tool_name if isinstance(tool_name, str) and tool_name.strip() else "Unknown"
        row_id = effective_log.log_egress_block(
            logged_name,
            reason,
            None,
            source=f"{source}-session-error",
            config_hash=effective_policy.content_hash(),
            policy_preset=effective_policy.preset_name,
        )
        verdict = Verdict(
            band="RED", sentinel="block", blocked=True, reason=reason,
            decision_id=f"dec-{row_id}", audit_log_id=row_id,
            error_type=error_type,
        )
        return _GateDecision(block=True, reason=reason, verdict=verdict)

    resolved_session_id = session_id
    if session_id_resolver is not None:
        try:
            resolved_session_id = session_id_resolver(session_context)
        except Exception:
            return session_failure(
                "session id resolver failed", "SessionResolutionError"
            )
    if resolved_session_id is not None and (
        type(resolved_session_id) is not str or not resolved_session_id
    ):
        return session_failure(
            "session id resolver must return a non-empty string or null",
            "SessionResolutionError",
        )
    if require_session_id and resolved_session_id is None:
        return session_failure(
            "session id required for framework adapter", "SessionRequired"
        )

    verdict = to_verdict(
        tool_name, tool_input, effective_policy,
        session_id=resolved_session_id, log=log, autonomy=autonomy, source=source,
    )
    block = sentinel_blocks(verdict.sentinel, has_approval_channel=has_approval_channel)
    return _GateDecision(block=block, reason=verdict.reason if block else "", verdict=verdict)


def _info(verdict: Verdict) -> Dict[str, Any]:
    """Compact 5D evidence to attach to a framework's guardrail output_info."""
    return {
        "fivedrisk_band": verdict.band,
        "fivedrisk_sentinel": verdict.sentinel,
        "fivedrisk_decision_id": verdict.decision_id,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI — @on(InterceptionPoint.PRE_TOOL_CALL), ctx: ToolCallHookContext
# Block by raising HookAborted; allow by returning None. crewai v1.15.x (hooks ≥1.9.1).
# NOTE: the current @on API blocks via HookAborted — NOT the legacy `return False`.
# ─────────────────────────────────────────────────────────────────────────────
def _import_crewai_hook_aborted():
    try:
        from crewai.hooks import HookAborted
    except ImportError as exc:  # pragma: no cover - exercised only without crewai
        raise ImportError(
            "CrewAI is required for the CrewAI adapter. Install it with: pip install crewai"
        ) from exc
    return HookAborted


def make_crewai_pre_tool_hook(
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    require_session_id: bool = False,
    log: Optional[DecisionLog] = None,
    has_approval_channel: bool = False,
    autonomy: Optional[int] = None,
    source: str = "crewai",
    _hook_aborted: Optional[type] = None,
) -> Callable[[Any], None]:
    """Build a CrewAI PRE_TOOL_CALL hook that gates the tool with 5D.

    Wire it::

        from crewai.hooks import on, InterceptionPoint
        from fivedrisk.framework_adapters import make_crewai_pre_tool_hook

        gate = make_crewai_pre_tool_hook()
        on(InterceptionPoint.PRE_TOOL_CALL)(gate)   # or: @on(...) over your own wrapper

    ``_hook_aborted`` is a test seam (inject a stand-in exception class); leave it
    None in real use and CrewAI's ``HookAborted`` is imported lazily.
    """
    def hook(ctx: Any) -> None:
        decision = _gate_decision(
            getattr(ctx, "tool_name", None), getattr(ctx, "tool_input", {}),
            policy, session_id, has_approval_channel, autonomy, source,
            log, session_id_resolver, ctx, require_session_id,
        )
        if decision.block:
            hook_aborted = _hook_aborted or _import_crewai_hook_aborted()
            raise hook_aborted(reason=f"blocked by 5D: {decision.reason}", source="fivedrisk")
        return None

    return hook


# ─────────────────────────────────────────────────────────────────────────────
# Google ADK — before_tool_callback(tool, args, tool_context) -> Optional[dict]
# Block/override by returning a dict; allow by returning None. google-adk 2.0 GA.
# FOOTGUN: ADK calls these by keyword — the param names MUST be exactly
# tool / args / tool_context.
# ─────────────────────────────────────────────────────────────────────────────
def make_adk_before_tool_callback(
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    require_session_id: bool = False,
    log: Optional[DecisionLog] = None,
    has_approval_channel: bool = False,
    autonomy: Optional[int] = None,
    source: str = "adk",
) -> Callable[..., Optional[Dict[str, Any]]]:
    """Build a Google ADK ``before_tool_callback`` that gates the tool with 5D.

    Wire it: ``LlmAgent(..., before_tool_callback=make_adk_before_tool_callback())``.
    A block returns a dict tool-result the model sees instead of running the tool.
    """
    def before_tool_callback(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        decision = _gate_decision(
            getattr(tool, "name", None), args,
            policy, session_id, has_approval_channel, autonomy, source,
            log, session_id_resolver, tool_context, require_session_id,
        )
        if decision.block:
            return {
                "status": "blocked",
                "reason": f"blocked by 5D: {decision.reason}",
                "fivedrisk_band": decision.verdict.band,
            }
        return None

    return before_tool_callback


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI Agents SDK — tool-level input guardrail.
# gate(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput
# Read data.context.tool_name + data.context.tool_arguments (RAW JSON STRING).
# Block: .reject_content(message=...); allow: .allow(). Covers @function_tool only.
# Newest of the four APIs — pin openai-agents (~v0.16.x, 2026).
# ─────────────────────────────────────────────────────────────────────────────
def _import_openai_output_cls():
    try:
        from agents.tool_guardrails import ToolGuardrailFunctionOutput
    except ImportError as exc:  # pragma: no cover - exercised only without openai-agents
        raise ImportError(
            "openai-agents is required for the OpenAI adapter. Install it with: pip install openai-agents"
        ) from exc
    return ToolGuardrailFunctionOutput


def make_openai_tool_input_guardrail(
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    require_session_id: bool = False,
    log: Optional[DecisionLog] = None,
    has_approval_channel: bool = False,
    autonomy: Optional[int] = None,
    source: str = "openai_agents",
    _output_cls: Optional[type] = None,
) -> Callable[[Any], Any]:
    """Build an OpenAI Agents SDK tool-input guardrail that gates the tool with 5D.

    Wire it::

        from agents import function_tool
        from fivedrisk.framework_adapters import make_openai_tool_input_guardrail

        @function_tool(tool_input_guardrails=[make_openai_tool_input_guardrail()])
        def my_tool(...): ...

    ``data.context.tool_arguments`` is a raw JSON string; it is ``json.loads``-ed
    here. Anything that does not decode to a JSON OBJECT (unparseable text, or a
    JSON array/string/number/null) is passed through as-is to ``to_verdict``,
    which fails CLOSED (BLOCK) on a non-dict — a garbage or non-object args blob
    is never wrapped into a benign dict that would score as allow (QA-M1 finding).
    ``_output_cls`` is a test seam for ``ToolGuardrailFunctionOutput``.
    """
    def guardrail(data: Any) -> Any:
        output_cls = _output_cls or _import_openai_output_cls()
        context = getattr(data, "context", None)
        tool_name = getattr(context, "tool_name", None)
        raw_args = getattr(context, "tool_arguments", None)
        if isinstance(raw_args, str):
            if raw_args.strip() == "":
                tool_input: Any = {}  # no args supplied → benign empty call
            else:
                try:
                    tool_input = json.loads(raw_args)  # dict → scored; non-dict → fails closed
                except (ValueError, TypeError):
                    tool_input = raw_args  # unparseable → non-dict → BLOCK in to_verdict
        else:
            tool_input = {} if raw_args is None else raw_args

        decision = _gate_decision(
            tool_name, tool_input, policy, session_id, has_approval_channel, autonomy, source,
            log, session_id_resolver, data, require_session_id,
        )
        info = _info(decision.verdict)
        if decision.block:
            return output_cls.reject_content(
                message=f"blocked by 5D: {decision.reason}", output_info=info
            )
        return output_cls.allow(output_info=info)

    return guardrail


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic AI — MCPToolset process_tool_call.
# async def process_tool_call(ctx, call_tool, name, tool_args) -> ToolResult
# Allow: return await call_tool(name, tool_args); block: return a substitute str.
# NOTE: MCP-tools only — does NOT fire for native @agent.tool function tools.
# The callback itself must be async; the sync to_verdict() called inside is fine.
# ─────────────────────────────────────────────────────────────────────────────
def make_pydantic_process_tool_call(
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    require_session_id: bool = False,
    log: Optional[DecisionLog] = None,
    has_approval_channel: bool = False,
    autonomy: Optional[int] = None,
    source: str = "pydantic_ai",
) -> Callable[..., Any]:
    """Build a Pydantic AI ``process_tool_call`` that gates MCP tools with 5D.

    Wire it::

        from pydantic_ai.mcp import MCPToolset
        from fivedrisk.framework_adapters import make_pydantic_process_tool_call

        toolset = MCPToolset(<transport>, process_tool_call=make_pydantic_process_tool_call())

    A block returns a substitute ``ToolResult`` string instead of calling the tool.
    Applies to MCP tools only; native ``@agent.tool`` functions bypass this hook.
    """
    async def process_tool_call(ctx: Any, call_tool: Any, name: str, tool_args: Dict[str, Any]) -> Any:
        decision = _gate_decision(
            name, tool_args, policy, session_id, has_approval_channel, autonomy, source,
            log, session_id_resolver, ctx, require_session_id,
        )
        if decision.block:
            return f"blocked by 5D: {decision.reason}"
        return await call_tool(name, tool_args)

    return process_tool_call


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Agent Framework (agent-framework) — function-invocation middleware.
# async def middleware(context: FunctionInvocationContext, call_next) -> None
# Read context.function.name + context.arguments. Block by SHORT-CIRCUITING: set
# context.result to the substitute and return WITHOUT calling call_next() (the
# guardrail pattern in the MS docs); allow by `await call_next()`. The middleware
# is async; the sync to_verdict() called inside is fine.
# ─────────────────────────────────────────────────────────────────────────────
def make_ms_agent_framework_middleware(
    policy: Optional[Policy] = None,
    *,
    session_id: Optional[str] = None,
    session_id_resolver: Optional[Callable[[Any], Optional[str]]] = None,
    require_session_id: bool = False,
    log: Optional[DecisionLog] = None,
    has_approval_channel: bool = False,
    autonomy: Optional[int] = None,
    source: str = "ms_agent_framework",
) -> Callable[..., Any]:
    """Build a Microsoft Agent Framework function-invocation middleware gated by 5D.

    Wire it::

        from agent_framework import ChatAgent
        from fivedrisk.framework_adapters import make_ms_agent_framework_middleware

        agent = ChatAgent(chat_client=client, name="assistant",
                          middleware=make_ms_agent_framework_middleware())

    A block sets ``context.result`` to a substitute and short-circuits the chain
    (the tool never runs); the model sees the denial and can course-correct. We do
    NOT set ``context.terminate`` — a blocked tool should not kill the whole run.
    """
    async def middleware(context: Any, call_next: Any) -> None:
        function = getattr(context, "function", None)
        decision = _gate_decision(
            getattr(function, "name", None), getattr(context, "arguments", {}),
            policy, session_id, has_approval_channel, autonomy, source,
            log, session_id_resolver, context, require_session_id,
        )
        if decision.block:
            context.result = f"blocked by 5D: {decision.reason}"
            return  # short-circuit: the tool does not execute
        await call_next()

    return middleware
