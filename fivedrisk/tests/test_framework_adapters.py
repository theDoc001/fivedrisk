"""M1 native-adapter tests — the shim TRANSLATION logic, verified without any
framework installed. Real 5D scoring drives RED/GREEN; a monkeypatched synthetic
Verdict drives the ORANGE/approval-channel path so every branch is exercised.
"""

from __future__ import annotations

import asyncio

import pytest

from fivedrisk import framework_adapters as fa
from fivedrisk.adapters import APPROVE, BLOCK, EXECUTE, Verdict


# ── fakes that mimic each framework's minimal contract ───────────────────────
class _FakeHookAborted(Exception):
    """Stand-in for crewai.hooks.HookAborted."""

    def __init__(self, reason=None, source=None):
        super().__init__(reason)
        self.reason = reason
        self.source = source


class _FakeCtx:
    def __init__(self, tool_name, tool_input):
        self.tool_name = tool_name
        self.tool_input = tool_input


class _FakeTool:
    def __init__(self, name):
        self.name = name


class _FakeGuardrailOutput:
    """Stand-in for agents.tool_guardrails.ToolGuardrailFunctionOutput."""

    def __init__(self, kind, message=None, output_info=None):
        self.kind = kind
        self.message = message
        self.output_info = output_info

    @classmethod
    def reject_content(cls, message, output_info=None):
        return cls("reject", message, output_info)

    @classmethod
    def allow(cls, output_info=None):
        return cls("allow", None, output_info)


class _FakeGuardrailData:
    def __init__(self, tool_name, tool_arguments):
        self.context = type("Ctx", (), {"tool_name": tool_name, "tool_arguments": tool_arguments})()


class _CallToolRecorder:
    def __init__(self, result):
        self.result = result
        self.called = False
        self.seen = None

    async def __call__(self, name, tool_args, *a, **k):
        self.called = True
        self.seen = (name, tool_args)
        return self.result


RED = ("Bash", {"command": "rm -rf /data"})
GREEN = ("Read", {"file_path": "/tmp/a"})


def _synthetic(monkeypatch, band, sentinel):
    """Force _gate_decision's verdict so we can exercise ORANGE/APPROVE precisely."""
    v = Verdict(band=band, sentinel=sentinel, blocked=(sentinel != EXECUTE),
                reason=f"synthetic {band}", decision_id="dec-synthetic")
    monkeypatch.setattr(fa, "to_verdict", lambda *a, **k: v)


# ── CrewAI ───────────────────────────────────────────────────────────────────
class TestCrewAI:
    def test_red_raises_hook_aborted(self):
        hook = fa.make_crewai_pre_tool_hook(_hook_aborted=_FakeHookAborted)
        with pytest.raises(_FakeHookAborted) as ei:
            hook(_FakeCtx(*RED))
        assert ei.value.source == "fivedrisk"
        assert "blocked by 5D" in ei.value.reason

    def test_green_returns_none_no_raise(self):
        hook = fa.make_crewai_pre_tool_hook(_hook_aborted=_FakeHookAborted)
        assert hook(_FakeCtx(*GREEN)) is None

    def test_orange_blocks_without_channel_allows_with(self, monkeypatch):
        _synthetic(monkeypatch, "ORANGE", APPROVE)
        blocking = fa.make_crewai_pre_tool_hook(_hook_aborted=_FakeHookAborted)
        with pytest.raises(_FakeHookAborted):
            blocking(_FakeCtx(*GREEN))
        allowing = fa.make_crewai_pre_tool_hook(_hook_aborted=_FakeHookAborted, has_approval_channel=True)
        assert allowing(_FakeCtx(*GREEN)) is None

    def test_missing_crewai_raises_helpful_importerror(self):
        # real block path with no injected class and crewai absent → clear install hint
        hook = fa.make_crewai_pre_tool_hook()
        with pytest.raises(ImportError, match="pip install crewai"):
            hook(_FakeCtx(*RED))


# ── Google ADK ─────────────────────────────────────────────────────────────
class TestADK:
    def test_red_returns_block_dict(self):
        cb = fa.make_adk_before_tool_callback()
        # ADK calls by keyword — mirror that exactly.
        out = cb(tool=_FakeTool("Bash"), args={"command": "rm -rf /data"}, tool_context=None)
        assert out["status"] == "blocked"
        assert out["fivedrisk_band"] == "RED"
        assert "blocked by 5D" in out["reason"]

    def test_green_returns_none(self):
        cb = fa.make_adk_before_tool_callback()
        assert cb(tool=_FakeTool("Read"), args={"file_path": "/tmp/a"}, tool_context=None) is None

    def test_orange_blocks_without_channel(self, monkeypatch):
        _synthetic(monkeypatch, "ORANGE", APPROVE)
        cb = fa.make_adk_before_tool_callback()
        out = cb(tool=_FakeTool("X"), args={}, tool_context=None)
        assert out["status"] == "blocked"


# ── OpenAI Agents SDK ────────────────────────────────────────────────────────
class TestOpenAI:
    def test_red_rejects_content_parses_json_string(self):
        g = fa.make_openai_tool_input_guardrail(_output_cls=_FakeGuardrailOutput)
        # tool_arguments arrives as a RAW JSON STRING
        out = g(_FakeGuardrailData("Bash", '{"command": "rm -rf /data"}'))
        assert out.kind == "reject"
        assert "blocked by 5D" in out.message
        assert out.output_info["fivedrisk_band"] == "RED"

    def test_green_allows(self):
        g = fa.make_openai_tool_input_guardrail(_output_cls=_FakeGuardrailOutput)
        out = g(_FakeGuardrailData("Read", '{"file_path": "/tmp/a"}'))
        assert out.kind == "allow"
        assert out.output_info["fivedrisk_band"] == "GREEN"

    def test_unparseable_args_fail_closed_blocks(self):
        # garbage JSON must never silently pass: the raw non-dict string flows to
        # to_verdict, which fails CLOSED → the guardrail REJECTS (QA-M1).
        g = fa.make_openai_tool_input_guardrail(_output_cls=_FakeGuardrailOutput)
        out = g(_FakeGuardrailData("Bash", "not-json{{{"))
        assert out.kind == "reject"
        assert out.output_info["fivedrisk_band"] == "RED"

    def test_json_non_object_args_fail_closed_blocks(self):
        # valid JSON that is NOT an object (array/string/number) → non-dict → BLOCK
        g = fa.make_openai_tool_input_guardrail(_output_cls=_FakeGuardrailOutput)
        for raw in ('[1, 2]', '"hi"', '123', 'true'):
            out = g(_FakeGuardrailData("Bash", raw))
            assert out.kind == "reject", f"{raw!r} should fail closed"


# ── Pydantic AI (async, MCP) ─────────────────────────────────────────────────
class TestPydanticAI:
    def test_red_returns_substitute_and_does_not_call_tool(self):
        ptc = fa.make_pydantic_process_tool_call()
        rec = _CallToolRecorder(result="REAL")
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="Bash", tool_args={"command": "rm -rf /data"}))
        assert isinstance(out, str) and "blocked by 5D" in out
        assert rec.called is False  # the real tool must NOT run on a block

    def test_green_calls_real_tool(self):
        ptc = fa.make_pydantic_process_tool_call()
        rec = _CallToolRecorder(result="REAL")
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="Read", tool_args={"file_path": "/tmp/a"}))
        assert out == "REAL"
        assert rec.called is True
        assert rec.seen == ("Read", {"file_path": "/tmp/a"})

    def test_orange_blocks_without_channel(self, monkeypatch):
        _synthetic(monkeypatch, "ORANGE", APPROVE)
        ptc = fa.make_pydantic_process_tool_call()
        rec = _CallToolRecorder(result="REAL")
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="X", tool_args={}))
        assert "blocked by 5D" in out
        assert rec.called is False


# ── Microsoft Agent Framework (async function middleware) ────────────────────
class _FakeFunction:
    def __init__(self, name):
        self.name = name


class _FakeMSContext:
    def __init__(self, name, arguments):
        self.function = _FakeFunction(name)
        self.arguments = arguments
        self.result = None
        self.terminate = False


class _NextRecorder:
    def __init__(self):
        self.called = False

    async def __call__(self):
        self.called = True


class TestMSAgentFramework:
    def test_red_short_circuits_sets_result_does_not_call_next(self):
        mw = fa.make_ms_agent_framework_middleware()
        ctx = _FakeMSContext("Bash", {"command": "rm -rf /data"})
        nxt = _NextRecorder()
        asyncio.run(mw(ctx, nxt))
        assert isinstance(ctx.result, str) and "blocked by 5D" in ctx.result
        assert nxt.called is False       # the tool must NOT execute on a block
        assert ctx.terminate is False    # a blocked tool must not kill the whole run

    def test_green_calls_next(self):
        mw = fa.make_ms_agent_framework_middleware()
        ctx = _FakeMSContext("Read", {"file_path": "/tmp/a"})
        nxt = _NextRecorder()
        asyncio.run(mw(ctx, nxt))
        assert nxt.called is True
        assert ctx.result is None

    def test_orange_blocks_without_channel(self, monkeypatch):
        _synthetic(monkeypatch, "ORANGE", APPROVE)
        mw = fa.make_ms_agent_framework_middleware()
        ctx = _FakeMSContext("X", {})
        nxt = _NextRecorder()
        asyncio.run(mw(ctx, nxt))
        assert "blocked by 5D" in ctx.result
        assert nxt.called is False

    def test_non_dict_arguments_fail_closed(self):
        mw = fa.make_ms_agent_framework_middleware()
        ctx = _FakeMSContext("Bash", "rm -rf /data")  # non-dict → to_verdict blocks
        nxt = _NextRecorder()
        asyncio.run(mw(ctx, nxt))
        assert "blocked by 5D" in ctx.result
        assert nxt.called is False


# ── shared decision layer ────────────────────────────────────────────────────
class TestGateDecision:
    def test_non_dict_tool_input_fails_closed(self):
        # a hostile non-dict payload must NOT be coerced into a benign dict — it
        # flows to to_verdict, which fails CLOSED to BLOCK (QA-M1 fail-open fix).
        d = fa._gate_decision("Bash", "rm -rf /data", None, None, False, None, "t")
        assert d.verdict.band == "RED"
        assert d.block is True

    def test_block_carries_reason_allow_is_empty(self, monkeypatch):
        _synthetic(monkeypatch, "GREEN", EXECUTE)
        d = fa._gate_decision("Read", {}, None, None, False, None, "t")
        assert d.block is False and d.reason == ""
        _synthetic(monkeypatch, "RED", BLOCK)
        d = fa._gate_decision("Bash", {}, None, None, False, None, "t")
        assert d.block is True and "synthetic RED" in d.reason
