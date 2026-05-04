"""Runtime control tests for detector corpus, sessions, destinations, and fixtures."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fivedrisk import hooks
from fivedrisk.detectors import DETECTOR_CORPUS_VERSION
from fivedrisk.hooks import (
    check_destination_policy,
    configure,
    extract_external_destinations,
    fivedrisk_post_tool,
    fivedrisk_pre_tool,
    scan_retrieved_content,
    session_id_conventions,
)
from fivedrisk.langgraph_node import fivedrisk_gate_node
from fivedrisk.logger import DecisionLog


FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "attacker"


def _reset(tmp_path, **kwargs) -> None:
    hooks._action_timestamps.clear()
    hooks._hitl_queue_depth = 0
    configure(log_path=tmp_path / "runtime-controls.db", **kwargs)


class TestDetectorCorpus:
    def test_detector_corpus_version_is_exposed(self):
        assert DETECTOR_CORPUS_VERSION == session_id_conventions()["detector_corpus_version"]

    def test_session_conventions_publish_keys(self):
        conventions = session_id_conventions()
        assert conventions["accepted_keys"] == list(hooks.SESSION_ID_KEYS)


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

    def test_destination_policy_allows_allowlisted_destination(self, tmp_path):
        _reset(tmp_path, destination_allowlist=["api.example.com"], enforce_destination_policy=True)
        result = check_destination_policy("Bash", {"command": "curl https://api.example.com"})
        assert result is None

    def test_destination_policy_warns_for_non_allowlisted_destination_when_not_enforced(self, tmp_path):
        _reset(tmp_path, destination_allowlist=["api.example.com"], enforce_destination_policy=False)
        result = check_destination_policy("Bash", {"command": "curl https://other.example.com"})
        assert result is not None
        assert result.decision == "warn"

    def test_destination_policy_blocks_for_non_allowlisted_destination_when_enforced(self, tmp_path):
        _reset(tmp_path, destination_allowlist=["api.example.com"], enforce_destination_policy=True)
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
