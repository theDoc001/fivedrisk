"""QA-M1 adversarial gate — independent verification of the four native framework
adapters (the independent QA gate, QA). Purpose under test: a 5D "stop" must NEVER be silently
demoted to a "go" through any framework translation layer.

These tests are written against PURPOSE, not execution. They drive each adapter with
the framework's real payload shape and assert the BLOCK/ALLOW *outcome* the framework
would act on. Hypothesis is absent in this venv, so the input space is covered by
exhaustive parametrization + an explicit fuzz corpus of malformed payloads.

Author-tests live in test_framework_adapters.py and are treated as claims, not truth.
"""

from __future__ import annotations

import asyncio

import pytest

from fivedrisk import framework_adapters as fa
from fivedrisk.adapters import APPROVE, BLOCK, EXECUTE, to_verdict, Verdict


# ── framework fakes (minimal contract mirrors) ───────────────────────────────
class FakeHookAborted(Exception):
    def __init__(self, reason=None, source=None):
        super().__init__(reason)
        self.reason = reason
        self.source = source


class FakeCtx:
    def __init__(self, tool_name, tool_input):
        self.tool_name = tool_name
        self.tool_input = tool_input


class FakeTool:
    def __init__(self, name):
        self.name = name


class NoName:
    """A tool object with NO .name attribute (getattr -> None path)."""


class FakeGuardrailOutput:
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


class FakeGuardrailData:
    def __init__(self, tool_name, tool_arguments, has_context=True):
        if has_context:
            self.context = type(
                "Ctx", (), {"tool_name": tool_name, "tool_arguments": tool_arguments}
            )()
        # else: no .context attribute at all


class GuardrailDataNoContext:
    """data with context=None (getattr(data,'context',None) -> None path)."""
    context = None


class Recorder:
    """Records whether the REAL pydantic tool was actually invoked."""
    def __init__(self, result="REAL-RAN"):
        self.result = result
        self.called = False
        self.seen = None

    async def __call__(self, name, tool_args, *a, **k):
        self.called = True
        self.seen = (name, tool_args)
        return self.result


RED = ("Bash", {"command": "rm -rf /data"})
GREEN = ("Read", {"file_path": "/tmp/a"})

import json as _json


# ── uniform adapter invokers: return "BLOCK" or "ALLOW" (+ recorder for pydantic)
def run_crewai(tool_name, tool_input, *, has_channel=False):
    hook = fa.make_crewai_pre_tool_hook(_hook_aborted=FakeHookAborted,
                                        has_approval_channel=has_channel)
    try:
        r = hook(FakeCtx(tool_name, tool_input))
        return "ALLOW" if r is None else "ALLOW"
    except FakeHookAborted:
        return "BLOCK"


def run_adk(tool_name, tool_input, *, has_channel=False, tool_obj=None):
    cb = fa.make_adk_before_tool_callback(has_approval_channel=has_channel)
    tool = tool_obj if tool_obj is not None else FakeTool(tool_name)
    out = cb(tool=tool, args=tool_input, tool_context=None)
    return "BLOCK" if isinstance(out, dict) else "ALLOW"


def run_openai(tool_name, raw_args_json, *, has_channel=False, data=None):
    g = fa.make_openai_tool_input_guardrail(_output_cls=FakeGuardrailOutput,
                                            has_approval_channel=has_channel)
    d = data if data is not None else FakeGuardrailData(tool_name, raw_args_json)
    out = g(d)
    return "BLOCK" if out.kind == "reject" else "ALLOW"


def run_pydantic(tool_name, tool_input, *, has_channel=False):
    ptc = fa.make_pydantic_process_tool_call(has_approval_channel=has_channel)
    rec = Recorder()
    out = asyncio.run(ptc(ctx=None, call_tool=rec, name=tool_name, tool_args=tool_input))
    # a block returns a substitute str AND must not have run the real tool
    if not rec.called and isinstance(out, str) and "blocked by 5D" in out:
        return "BLOCK"
    return "ALLOW"


# ============================================================================
# INVARIANT 1 — a RED / hostile call must BLOCK in every adapter
# ============================================================================
class TestRedBlocksEverywhere:
    def test_crewai_red_blocks(self):
        assert run_crewai(*RED) == "BLOCK"

    def test_adk_red_blocks(self):
        assert run_adk(*RED) == "BLOCK"

    def test_openai_red_blocks(self):
        assert run_openai("Bash", '{"command": "rm -rf /data"}') == "BLOCK"

    def test_pydantic_red_blocks_and_never_runs_tool(self):
        ptc = fa.make_pydantic_process_tool_call()
        rec = Recorder()
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="Bash",
                              tool_args={"command": "rm -rf /data"}))
        assert rec.called is False, "REAL TOOL RAN ON A BLOCK — hard demotion"
        assert isinstance(out, str) and "blocked by 5D" in out


# ============================================================================
# INVARIANT 2 — ORANGE/APPROVE: channel=False must BLOCK, channel=True must ALLOW
# (driven by a synthetic verdict so the branch is exercised precisely)
# ============================================================================
def _force_orange(monkeypatch):
    v = Verdict(band="ORANGE", sentinel=APPROVE, blocked=True,
                reason="synthetic ORANGE", decision_id="dec-x")
    monkeypatch.setattr(fa, "to_verdict", lambda *a, **k: v)


@pytest.mark.parametrize("runner,args", [
    (run_crewai, ("X", {})),
    (run_adk, ("X", {})),
    (lambda *a, **k: run_openai("X", '{}', **k), (None, None)),
    (run_pydantic, ("X", {})),
])
class TestApprovalChannel:
    def test_orange_blocks_without_channel(self, runner, args, monkeypatch):
        _force_orange(monkeypatch)
        if args == (None, None):
            assert runner(has_channel=False) == "BLOCK"
        else:
            assert runner(*args, has_channel=False) == "BLOCK"

    def test_orange_allows_with_channel(self, runner, args, monkeypatch):
        _force_orange(monkeypatch)
        if args == (None, None):
            assert runner(has_channel=True) == "ALLOW"
        else:
            assert runner(*args, has_channel=True) == "ALLOW"


# ============================================================================
# INVARIANT 3 — malformed / adversarial payloads must fail closed, never ALLOW
# ============================================================================
class TestMalformedFailClosed:
    # -- crewai: missing tool_name (None) --
    def test_crewai_missing_tool_name_blocks(self):
        assert run_crewai(None, {"command": "rm -rf /data"}) == "BLOCK"

    # -- adk: tool object with no .name attribute --
    def test_adk_missing_tool_name_blocks(self):
        assert run_adk(None, {"x": 1}, tool_obj=NoName()) == "BLOCK"

    def test_adk_none_name_blocks(self):
        assert run_adk(None, {"x": 1}) == "BLOCK"

    # -- openai: missing / None context --
    def test_openai_missing_context_blocks(self):
        assert run_openai(None, None, data=GuardrailDataNoContext()) == "BLOCK"

    # -- openai: adversarial JSON tool_arguments corpus --
    #    for each, tool_name is a real tool; assert the outcome is never a wrong ALLOW
    #    of an actually-hostile call, and that garbage is scored (never crashes to allow).
    @pytest.mark.parametrize("raw", [
        "null",            # json.loads -> None
        "[1,2]",           # json.loads -> list (non-object)
        '"hi"',            # json.loads -> str (non-object)
        "123",             # json.loads -> int
        "true",            # json.loads -> bool
        "",                # empty string
        "not-json{{{",     # unparseable
        "{}",              # empty object
        "   ",             # whitespace-only (truthy string, unparseable)
    ], ids=lambda s: repr(s))
    def test_openai_adversarial_json_benign_name_does_not_crash_to_allow(self, raw):
        # benign tool name + garbage args: must not raise; returns a defined outcome.
        # (A benign Read with empty args legitimately ALLOWs; the point is no crash/leak.)
        out = run_openai("Read", raw)
        assert out in ("BLOCK", "ALLOW")

    def test_openai_none_tool_arguments_benign_name(self):
        assert run_openai("Read", None) in ("BLOCK", "ALLOW")

    # -- a hostile RED tool name must still BLOCK even with garbage args, because the
    #    danger is name+args; but if the danger is ONLY carryable in args, coercion
    #    must not strip it into an ALLOW. Covered explicitly in TestNonDictDemotion.
    def test_openai_red_name_with_null_args(self):
        # Bash with null args -> empty command -> benign by design (documented).
        # We only assert it does not error toward allow silently; outcome is defined.
        assert run_openai("Bash", "null") in ("BLOCK", "ALLOW")


# ============================================================================
# INVARIANT 3b (THE FINDING) — non-dict hostile tool_input is DEMOTED stop->go
# `to_verdict` fails CLOSED (BLOCK) on a non-dict input, but `_gate_decision`
# coerces the non-dict to {"_raw": ...} BEFORE calling to_verdict, turning that
# fail-closed BLOCK into a GREEN ALLOW. All four adapters then let the tool run.
# The tests below assert the SAFE contract (must BLOCK) so they flip red->green
# when the coercion in framework_adapters.py:56-57 is removed.
# ============================================================================
HOSTILE_NONDICT = "rm -rf /data"          # a bare string carrying the danger
HOSTILE_LIST = ["rm -rf /data"]           # a list carrying the danger


class TestNonDictDemotion:
    def test_to_verdict_native_contract_is_fail_closed(self):
        # ground truth: the M0 socket itself BLOCKS a non-dict input.
        assert to_verdict("Bash", HOSTILE_NONDICT).sentinel == BLOCK
        assert to_verdict("Bash", HOSTILE_LIST).sentinel == BLOCK

    def test_gate_decision_nondict_should_block_string(self):
        d = fa._gate_decision("Bash", HOSTILE_NONDICT, None, None, False, None, "qa")
        assert d.block is True, (
            "DEMOTION: _gate_decision coerced a non-dict to {'_raw':...} and scored "
            f"it {d.verdict.band}/{d.verdict.sentinel} (ALLOW); to_verdict blocks it."
        )

    def test_gate_decision_nondict_should_block_list(self):
        d = fa._gate_decision("Bash", HOSTILE_LIST, None, None, False, None, "qa")
        assert d.block is True

    def test_crewai_nondict_hostile_should_block(self):
        assert run_crewai("Bash", HOSTILE_NONDICT) == "BLOCK"

    def test_adk_nondict_hostile_should_block(self):
        assert run_adk("Bash", HOSTILE_NONDICT) == "BLOCK"

    def test_pydantic_nondict_hostile_should_not_run_real_tool(self):
        ptc = fa.make_pydantic_process_tool_call()
        rec = Recorder()
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="Bash",
                              tool_args=HOSTILE_NONDICT))
        assert rec.called is False, (
            f"REAL TOOL RAN with non-dict hostile args -> {out!r}. "
            "Scoring saw {'_raw':...} (GREEN) but tool executed the raw string."
        )


# ============================================================================
# INVARIANT 4 — lazy-import ImportError on a BLOCK must NOT swallow into ALLOW
# (an uncaught ImportError that STOPS execution is acceptable; a swallowed one
#  that returns the allow outcome is a hard fail.)
# ============================================================================
class TestLazyImportPath:
    def test_crewai_block_without_sdk_raises_not_allows(self):
        hook = fa.make_crewai_pre_tool_hook()  # no injected class, crewai absent
        with pytest.raises(ImportError, match="pip install crewai"):
            hook(FakeCtx(*RED))

    def test_openai_block_without_sdk_raises_not_allows(self):
        g = fa.make_openai_tool_input_guardrail()  # no injected class, sdk absent
        with pytest.raises(ImportError, match="pip install openai-agents"):
            g(FakeGuardrailData("Bash", '{"command": "rm -rf /data"}'))

    def test_openai_green_without_sdk_also_raises(self):
        # import happens before the decision, so even an allow needs the sdk;
        # this proves the guardrail is inert-safe (cannot allow) when sdk absent.
        g = fa.make_openai_tool_input_guardrail()
        with pytest.raises(ImportError):
            g(FakeGuardrailData("Read", '{"file_path": "/tmp/a"}'))


# ============================================================================
# INVARIANT 5 — benign GREEN must ALLOW (a guardrail that blocks everything is
# also broken).
# ============================================================================
class TestGreenAllows:
    def test_crewai_green_allows(self):
        assert run_crewai(*GREEN) == "ALLOW"

    def test_adk_green_allows(self):
        assert run_adk(*GREEN) == "ALLOW"

    def test_openai_green_allows(self):
        assert run_openai("Read", '{"file_path": "/tmp/a"}') == "ALLOW"

    def test_pydantic_green_allows_and_runs_tool(self):
        ptc = fa.make_pydantic_process_tool_call()
        rec = Recorder()
        out = asyncio.run(ptc(ctx=None, call_tool=rec, name="Read",
                              tool_args={"file_path": "/tmp/a"}))
        assert rec.called is True and out == "REAL-RAN"
        assert rec.seen == ("Read", {"file_path": "/tmp/a"})
