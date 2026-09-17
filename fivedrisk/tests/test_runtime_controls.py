"""Runtime control tests for detector corpus, sessions, destinations, and fixtures."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from fivedrisk import hooks
from fivedrisk.detectors import DETECTOR_CORPUS_VERSION
from fivedrisk.hooks import (
    check_destination_policy,
    configure,
    extract_external_destinations,
    fivedrisk_post_tool,
    fivedrisk_pre_tool,
    scan_retrieved_content,
    scan_semantic_review,
    session_id_conventions,
)
from fivedrisk.langgraph_node import fivedrisk_gate_node
from fivedrisk.logger import DecisionLog


FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "attacker"


def _reset(tmp_path, **kwargs) -> None:
    configure(log_path=tmp_path / "runtime-controls.db", **kwargs)


class TestDetectorCorpus:
    def test_detector_corpus_version_is_exposed(self):
        assert DETECTOR_CORPUS_VERSION == session_id_conventions()["detector_corpus_version"]

    def test_session_conventions_publish_keys(self):
        conventions = session_id_conventions()
        assert conventions["accepted_keys"] == list(hooks.SESSION_ID_KEYS)


@pytest.mark.asi04_supply_chain
class TestDestinationPolicy:
    def test_extracts_http_destination_from_bash(self):
        destinations = extract_external_destinations(
            "Bash",
            {"command": "curl https://api.example.com/v1/data"},
        )
        assert destinations == ["api.example.com"]

    def test_extracts_ssh_destination(self):
        destinations = extract_external_destinations(
            "Bash",
            {"command": "ssh root@example.com"},
        )
        assert destinations == ["example.com"]

    def test_extracts_webfetch_destination(self):
        destinations = extract_external_destinations(
            "WebFetch",
            {"url": "https://docs.example.com/page"},
        )
        assert destinations == ["docs.example.com"]

    def test_structured_url_key_is_read_for_any_tool_name(self):
        """A destination control that only sees two hardcoded tool names is blind where it matters.

        Found by dogfooding (D2) on a real integration whose tool is named `speci.fetch_url`.
        The generic URL regex above the structured-key read requires an alphabetic TLD, so
        `https://evil.example.com` survived a custom tool name and `http://127.0.0.1` did not.
        Loopback and RFC1918 are precisely the class a destination control exists to catch, so
        the gap was widest exactly where the control matters most.
        """
        for tool_name in ("WebFetch", "speci.fetch_url", "my_company.http_get"):
            assert extract_external_destinations(
                tool_name, {"url": "http://127.0.0.1/admin"}
            ) == ["127.0.0.1"], f"loopback invisible to tool_name={tool_name}"
            assert extract_external_destinations(
                tool_name, {"url": "http://192.168.1.1/x"}
            ) == ["192.168.1.1"], f"rfc1918 invisible to tool_name={tool_name}"
            assert extract_external_destinations(
                tool_name, {"host": "10.0.0.5"}
            ) == ["10.0.0.5"], f"host key invisible to tool_name={tool_name}"

    def test_destination_policy_allows_allowlisted_destination(self, tmp_path):
        _reset(tmp_path, destination_allowlist=["api.example.com"])
        result = check_destination_policy("Bash", {"command": "curl https://api.example.com"})
        assert result is None

    def test_a_declared_allowlist_blocks_a_miss_and_cannot_be_downgraded(self, tmp_path):
        """Fail-open is not a setting.

        There used to be an `enforce_destination_policy` flag, default False, under which a
        destination missing from a DECLARED allowlist merely appended a note to the rationale
        and the verdict was unchanged. Declaring an allowlist IS the enforcement decision;
        a configuration that lets a non-allowlisted destination proceed is a fail-open.
        """
        _reset(tmp_path, destination_allowlist=["api.example.com"])
        result = check_destination_policy("Bash", {"command": "curl https://other.example.com"})
        assert result is not None
        assert result.decision == "block"

    def test_no_configure_parameter_can_reintroduce_the_fail_open(self, tmp_path):
        """The knob is gone from the signature, not merely defaulted to the safe value."""
        import inspect
        from fivedrisk import hooks
        assert "enforce_destination_policy" not in inspect.signature(hooks.configure).parameters
        assert not hasattr(hooks, "_enforce_destination_policy")

    def test_destination_policy_blocks_for_non_allowlisted_destination_when_enforced(self, tmp_path):
        _reset(tmp_path, destination_allowlist=["api.example.com"])
        result = check_destination_policy("Bash", {"command": "curl https://other.example.com"})
        assert result is not None
        assert result.decision == "block"

    def test_destination_policy_blocks_denylisted_destination(self, tmp_path):
        _reset(tmp_path, destination_denylist=["evil.example.com"])
        result = check_destination_policy("Bash", {"command": "curl https://evil.example.com"})
        assert result is not None
        assert result.decision == "block"


class TestSessionRequirements:
    def test_pre_tool_blocks_when_session_required_and_missing(self, tmp_path):
        _reset(tmp_path, require_session_id=True)
        result = asyncio.run(
            fivedrisk_pre_tool(
                {"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}},
                "tool-1",
            )
        )
        assert result["decision"] == "block"
        assert "session id required" in result["reason"]

    def test_pre_tool_allows_when_session_required_and_present(self, tmp_path):
        _reset(tmp_path, require_session_id=True)
        result = asyncio.run(
            fivedrisk_pre_tool(
                {
                    "tool_name": "Read",
                    "tool_input": {"file_path": "/tmp/a.txt"},
                    "session_id": "session-a",
                },
                "tool-1",
            )
        )
        assert result == {}

    def test_langgraph_blocks_when_session_required_and_missing(self, tmp_path):
        _reset(tmp_path, require_session_id=True)
        state = fivedrisk_gate_node({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}})
        assert state["fivedrisk_band"] == "RED"
        assert "session id required" in state["fivedrisk_rationale"]

    def test_langgraph_uses_session_when_present(self, tmp_path):
        log = DecisionLog(tmp_path / "runtime-controls.db")
        _reset(tmp_path, require_session_id=True)
        state = fivedrisk_gate_node(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/a.txt"},
                "session_id": "session-a",
            },
            log=log,
        )
        assert state["fivedrisk_band"] == "GREEN"
        assert log.query_recent(limit=1)[0]["session_id"] == "session-a"


class TestSemanticReview:
    def test_semantic_review_is_inactive_by_default(self):
        assert scan_semantic_review("Create a realistic fake arrest image") is None

    def test_semantic_review_detects_profile_pattern(self):
        result = scan_semantic_review(
            "Create a realistic fake arrest image",
            patterns=((r"(?i)\bfake\b.{0,30}\barrest\b", "impersonation"),),
        )
        assert result is not None
        assert "[impersonation]" in result

    def test_pre_tool_allows_semantic_content_without_profile(self, tmp_path):
        _reset(tmp_path)
        result = asyncio.run(
            fivedrisk_pre_tool(
                {
                    "tool_name": "ImageGenerate",
                    "tool_input": {
                        "prompt": "Create a realistic fake image of a public official being arrested",
                    },
                    "session_id": "session-a",
                },
                "tool-1",
            )
        )
        assert result == {}

    def test_pre_tool_escalates_semantic_profile_match(self, tmp_path):
        _reset(
            tmp_path,
            semantic_review_patterns={
                "impersonation": [r"(?i)\bfake\b.{0,60}\b(public official|arrested)\b"],
            },
        )
        result = asyncio.run(
            fivedrisk_pre_tool(
                {
                    "tool_name": "ImageGenerate",
                    "tool_input": {
                        "prompt": "Create a realistic fake image of a public official being arrested",
                    },
                    "session_id": "session-a",
                },
                "tool-1",
            )
        )
        assert result["decision"] == "block"
        assert result["semantic_review"] is True
        assert "semantic review required" in result["reason"]

    def test_post_tool_escalates_semantic_profile_match(self, tmp_path):
        _reset(
            tmp_path,
            semantic_review_patterns={
                "medical-claim": [r"(?i)\b(cures?|treats?)\s+cancer\b"],
            },
        )
        result = asyncio.run(
            fivedrisk_post_tool(
                {
                    "tool_name": "Write",
                    "tool_result": "This supplement cures cancer without medical supervision.",
                },
                "tool-1",
            )
        )
        assert result["decision"] == "block"
        assert result["semantic_review"] is True


@pytest.mark.asi06_context_manipulation
class TestRetrievedFixtures:
    def test_scan_retrieved_fixture_blocks_hidden_override(self):
        payload = (FIXTURE_DIR / "webfetch_hidden_override.html").read_text()
        assert scan_retrieved_content(payload) is not None

    def test_scan_retrieved_fixture_blocks_exfil_text(self):
        payload = (FIXTURE_DIR / "webfetch_prompt_exfil.txt").read_text()
        assert scan_retrieved_content(payload) is not None

    def test_scan_retrieved_fixture_allows_safe_article(self):
        payload = (FIXTURE_DIR / "safe_article.txt").read_text()
        assert scan_retrieved_content(payload) is None

    def test_post_tool_blocks_retrieved_injection_for_webfetch(self, tmp_path):
        _reset(tmp_path)
        payload = (FIXTURE_DIR / "webfetch_hidden_override.html").read_text()
        result = asyncio.run(
            fivedrisk_post_tool(
                {"tool_name": "WebFetch", "tool_result": payload},
                "tool-1",
            )
        )
        assert result["decision"] == "block"
        assert "retrieved-content block" in result["reason"]

    def test_post_tool_allows_safe_retrieved_fixture(self, tmp_path):
        _reset(tmp_path)
        payload = (FIXTURE_DIR / "safe_article.txt").read_text()
        result = asyncio.run(
            fivedrisk_post_tool(
                {"tool_name": "WebFetch", "tool_result": payload},
                "tool-1",
            )
        )
        assert result == {}
