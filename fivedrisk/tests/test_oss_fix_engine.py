"""Regression tests for the OSS-FIX engine-correctness batch (M2 milestone).

Covers: M8 (destination userinfo bypass), M5 (malformed bash_overrides regex),
M4 (shared default log, no per-call DDL), M3 (@gate resolves policy at call
time), M2 (bounded session-state eviction).
"""

from __future__ import annotations

import asyncio

import pytest

from fivedrisk import hooks
from fivedrisk.cli import _validate_policy_config
from fivedrisk.hooks import (
    _evict_oldest_if_over_cap,
    extract_external_destinations,
    gate,
)
from fivedrisk.policy import Policy


class TestM8DestinationUserinfoBypass:
    def test_userinfo_bypass_resolves_real_host(self):
        # https://allowed.com@evil.com must surface evil.com, not allowed.com.
        dests = extract_external_destinations(
            "Bash", {"command": "curl https://allowed.com@evil.com/x"}
        )
        assert "evil.com" in dests
        assert "allowed.com" not in dests

    def test_userpass_userinfo_resolves_real_host(self):
        dests = extract_external_destinations(
            "WebFetch", {"url": "https://user:pass@evil.com/y"}
        )
        assert dests == ["evil.com"]

    def test_plain_url_still_resolves(self):
        dests = extract_external_destinations("WebFetch", {"url": "https://evil.com/x"})
        assert dests == ["evil.com"]


class TestM5MalformedBashOverride:
    def test_malformed_regex_does_not_crash_scoring(self):
        # An unclosed character class is an invalid regex; scoring must not raise.
        policy = Policy(bash_overrides={"[unclosed": {"tool_privilege": 4}})
        result = policy.get_bash_overrides("anything")
        assert result == {}  # malformed pattern skipped, no crash

    def test_validate_flags_malformed_bash_override(self):
        policy = Policy(bash_overrides={"[unclosed": {"tool_privilege": 4}})
        # Monkeypatch load to return our policy via the validator's load path is
        # heavy; instead assert the validator surfaces the regex error when the
        # policy carries a bad key. We call the internal range/regex checks by
        # constructing errors directly through a temp policy file.
        import tempfile
        import os

        fd, path = tempfile.mkstemp(suffix=".yaml")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("bash_overrides:\n  '[unclosed':\n    tool_privilege: 4\n")
            errors = _validate_policy_config(path)
        finally:
            os.unlink(path)
        assert any("invalid regex" in e for e in errors), errors


class TestM4SharedDefaultLog:
    def test_unconfigured_pre_tool_reuses_one_default_log(self, monkeypatch):
        # Reset module state to the unconfigured path.
        monkeypatch.setattr(hooks, "_log", None)
        monkeypatch.setattr(hooks, "_default_log", None)

        async def run_two():
            await hooks.fivedrisk_pre_tool(
                {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a"}}, "call-1"
            )
            first = hooks._default_log
            await hooks.fivedrisk_pre_tool(
                {"tool_name": "Read", "tool_input": {"file_path": "/tmp/b"}}, "call-2"
            )
            second = hooks._default_log
            return first, second

        first, second = asyncio.run(run_two())
        assert first is not None
        assert first is second  # same object reused, DDL not rerun per call


class TestM7EgressBlockLogged:
    def test_post_tool_egress_block_is_audited(self, monkeypatch, tmp_path):
        from fivedrisk.logger import DecisionLog

        log = DecisionLog(str(tmp_path / "audit.db"))
        monkeypatch.setattr(hooks, "_log", log)
        monkeypatch.setattr(hooks, "_default_log", None)

        out = asyncio.run(
            hooks.fivedrisk_post_tool(
                {"tool_name": "Bash", "tool_result": "password=hunter2secret"},
                "call-egress",
            )
        )
        assert out["decision"] == "block"
        assert "log_id" in out  # M7: block returns an audit row id
        rows = log.query_recent(limit=5)
        assert any(
            r["source"] == "post-tool-egress" and r["band"] == "RED" for r in rows
        ), rows


class TestM2BoundedEviction:
    def test_evict_oldest_fifo(self):
        store = {f"s{i}": i for i in range(5)}
        _evict_oldest_if_over_cap(store, cap=3)
        assert len(store) == 3
        # Oldest-inserted (s0, s1) evicted; newest retained.
        assert "s0" not in store and "s1" not in store
        assert "s4" in store


class TestM3GateResolvesPolicyAtCallTime:
    def test_configure_after_decoration_is_honored(self, monkeypatch, tmp_path):
        # A gate decorated while the default policy is active must honor a policy
        # installed by a LATER configure() call (decoration-time binding was the
        # M3 bug). We prove it by configuring require_session_id=True after
        # decoration and observing the gate now blocks a session-less call.
        monkeypatch.setattr(hooks, "_policy", Policy())
        monkeypatch.setattr(hooks, "_require_session_id", False)

        blocked = {"hit": False}

        @gate(tool_name="write_thing", on_block=lambda r: blocked.__setitem__("hit", True))
        def write_thing(**kwargs):
            return "ran"

        # Before configure: session-less call runs.
        assert write_thing() == "ran"

        # configure() flips require_session_id on the module globals.
        monkeypatch.setattr(hooks, "_require_session_id", True)
        write_thing()
        assert blocked["hit"] is True  # now blocked -> gate read live module state
