"""Tests for the 5D decision log + decision memory."""

import pytest

from fivedrisk.logger import DecisionLog
from fivedrisk.schema import Action, Band, ScoredAction, RoutingDecision, ModelClass


def _make_scored(band: Band = Band.GREEN, tool_name: str = "TestTool") -> ScoredAction:
    action = Action(tool_name=tool_name, tool_input={"test": True})
    return ScoredAction(
        action=action,
        band=band,
        composite_score=3.5,
        max_dimension=2,
        rationale=f"{band} — test rationale",
        policy_version="0.2.0",
        session_id="test-session-1",
        routing=RoutingDecision(
            data_class="D0",
            risk_band=band,
            task_class="execution",
            model_floor=ModelClass.M1,
            selected_model=ModelClass.M1,
        ),
    )


class TestDecisionLog:
    def test_log_returns_row_id(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        row_id = log.log(_make_scored())
        assert isinstance(row_id, int)
        assert row_id >= 1

    def test_log_sequential_ids(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        id1 = log.log(_make_scored())
        id2 = log.log(_make_scored(Band.ORANGE))
        id3 = log.log(_make_scored(Band.RED))
        assert id2 == id1 + 1
        assert id3 == id2 + 1

    def test_query_recent(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        for _ in range(5):
            log.log(_make_scored())
        entries = log.query_recent(limit=3)
        assert len(entries) == 3

    def test_query_recent_order(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.log(_make_scored(Band.GREEN, "First"))
        log.log(_make_scored(Band.ORANGE, "Second"))
        log.log(_make_scored(Band.RED, "Third"))
        entries = log.query_recent(limit=3)
        assert entries[0]["tool_name"] == "Third"
        assert entries[2]["tool_name"] == "First"

    def test_count_by_band(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.log(_make_scored(Band.GREEN))
        log.log(_make_scored(Band.GREEN))
        log.log(_make_scored(Band.ORANGE))
        log.log(_make_scored(Band.RED))
        counts = log.count_by_band()
        assert counts["GREEN"] == 2
        assert counts["ORANGE"] == 1
        assert counts["RED"] == 1

    def test_update_outcome(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        row_id = log.log(_make_scored(Band.ORANGE))
        log.update_outcome(row_id, "approved")
        entries = log.query_recent(limit=1)
        assert entries[0]["outcome"] == "approved"

    def test_empty_log_returns_empty(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        assert log.query_recent() == []
        assert log.count_by_band() == {}

    def test_routing_fields_logged(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.log(_make_scored(Band.RED))
        entries = log.query_recent(limit=1)
        assert entries[0]["routing_model"] == "M1"
        assert entries[0]["routing_floor"] == "M1"


class TestDecisionMemory:
    """Tests for the 'remember' adaptive learning feature."""

    def test_remember_and_check(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.remember(
            tool_name="Bash",
            input_pattern="docker compose restart",
            decision="approved",
            scope="global",
            band_override="GREEN",
        )
        mem = log.check_memory("Bash", "docker compose restart")
        assert mem is not None
        assert mem["decision"] == "approved"
        assert mem["band_override"] == "GREEN"

    def test_no_memory_returns_none(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        mem = log.check_memory("Bash", "rm -rf /")
        assert mem is None

    def test_project_scope_takes_priority(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.remember("Bash", "docker compose restart", "approved", "global", "GREEN")
        log.remember("Bash", "docker compose restart", "denied", "project:dotos-seed", None)
        mem = log.check_memory(
            "Bash", "docker compose restart",
            project_scope="project:dotos-seed",
        )
        assert mem["decision"] == "denied"

    def test_global_fallback(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.remember("Bash", "pip install requests", "approved", "global", "GREEN")
        mem = log.check_memory(
            "Bash", "pip install requests",
            project_scope="project:other",
        )
        assert mem is not None
        assert mem["scope"] == "global"

    def test_list_memories(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        log.remember("Bash", "docker restart", "approved", "global")
        log.remember("Edit", "vault file", "approved", "project:dotos")
        all_mems = log.list_memories()
        assert len(all_mems) == 2
        global_mems = log.list_memories(scope="global")
        assert len(global_mems) == 1

    def test_find_similar_decisions(self, tmp_path):
        log = DecisionLog(tmp_path / "test.db")
        scored = _make_scored(Band.ORANGE, "Bash")
        row_id = log.log(scored)
        log.update_outcome(row_id, "approved")
        similar = log.find_similar_decisions("Bash")
        assert len(similar) == 1
        assert similar[0]["outcome"] == "approved"

    def test_upsert_on_remember(self, tmp_path):
        """Remember replaces existing entry for same tool+pattern+scope."""
        log = DecisionLog(tmp_path / "test.db")
        log.remember("Bash", "docker restart", "denied", "global")
        log.remember("Bash", "docker restart", "approved", "global", "GREEN")
        mems = log.list_memories(scope="global")
        assert len(mems) == 1
        assert mems[0]["decision"] == "approved"
