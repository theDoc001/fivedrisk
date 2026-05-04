"""Expanded logger and decision-memory capability coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fivedrisk.logger import DecisionLog
from fivedrisk.schema import Action, Band, ModelClass, RoutingDecision, ScoredAction


def _scored(
    band: Band = Band.GREEN,
    tool_name: str = "Tool",
    metadata: dict | None = None,
    routing: bool = True,
    session_id: str = "session-1",
) -> ScoredAction:
    action = Action(
        tool_name=tool_name,
        tool_input={"value": 1},
        metadata=metadata or {},
    )
    routing_decision = None
    if routing:
        routing_decision = RoutingDecision(
            data_class="D1",
            risk_band=band,
            task_class="execution",
            model_floor=ModelClass.M1,
            selected_model=ModelClass.M2,
        )
    return ScoredAction(
        action=action,
        band=band,
        composite_score=1.5,
        max_dimension=2,
        rationale=f"{band} rationale",
        policy_version="0.3.0",
        routing=routing_decision,
        session_id=session_id,
    )


class TestLoggerCapability:
    def test_log_persists_session_id(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored(session_id="session-42"))
        assert log.query_recent(limit=1)[0]["session_id"] == "session-42"

    def test_log_persists_metadata_json(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored(metadata={"source": "unit"}))
        assert '"source": "unit"' in log.query_recent(limit=1)[0]["metadata"]

    def test_log_allows_missing_routing(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored(routing=False))
        row = log.query_recent(limit=1)[0]
        assert row["routing_model"] is None
        assert row["routing_floor"] is None

    def test_query_recent_respects_limit_one(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored(tool_name="first"))
        log.log(_scored(tool_name="second"))
        assert len(log.query_recent(limit=1)) == 1

    def test_count_by_band_returns_only_present_bands(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored(Band.YELLOW))
        counts = log.count_by_band()
        assert counts == {"YELLOW": 1}

    def test_update_outcome_on_missing_row_is_noop(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.update_outcome(999, "approved")
        assert log.query_recent() == []

    def test_remember_stores_source_decision_id(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        row_id = log.log(_scored(Band.ORANGE))
        log.remember("Bash", "docker restart", "approved", "global", source_decision_id=row_id)
        assert log.list_memories()[0]["source_decision_id"] == row_id

    def test_remember_stores_expiry(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        expires = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        log.remember("Bash", "docker restart", "approved", "global", expires_at=expires)
        assert log.list_memories()[0]["expires_at"] == expires

    def test_expired_memory_is_ignored_by_check_memory(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        log.remember("Bash", "docker restart", "approved", "global", expires_at=expired)
        assert log.check_memory("Bash", "docker restart") is None

    def test_list_memories_ignores_expired_entries(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        log.remember("Bash", "old", "approved", "global", expires_at=expired)
        log.remember("Bash", "new", "approved", "global", expires_at=future)
        memories = log.list_memories()
        assert len(memories) == 1
        assert memories[0]["input_pattern"] == "new"

    def test_project_scope_is_returned_when_exact_match_exists(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.remember("Bash", "deploy", "approved", "project:demo")
        mem = log.check_memory("Bash", "deploy", project_scope="project:demo")
        assert mem is not None
        assert mem["scope"] == "project:demo"

    def test_exact_pattern_match_is_required(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.remember("Bash", "deploy prod", "approved", "global")
        assert log.check_memory("Bash", "deploy") is None

    def test_find_similar_decisions_respects_limit(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        for idx in range(3):
            row_id = log.log(_scored(Band.ORANGE, tool_name="Bash"))
            log.update_outcome(row_id, f"approved-{idx}")
        assert len(log.find_similar_decisions("Bash", limit=2)) == 2

    def test_find_similar_decisions_returns_most_recent_first(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        first = log.log(_scored(Band.ORANGE, tool_name="Bash"))
        log.update_outcome(first, "approved")
        second = log.log(_scored(Band.RED, tool_name="Bash"))
        log.update_outcome(second, "denied")
        similar = log.find_similar_decisions("Bash", limit=2)
        assert similar[0]["outcome"] == "denied"

    def test_list_memories_can_filter_scope(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.remember("Bash", "global", "approved", "global")
        log.remember("Bash", "project", "approved", "project:demo")
        scoped = log.list_memories(scope="project:demo")
        assert len(scoped) == 1
        assert scoped[0]["scope"] == "project:demo"

    def test_remember_replace_keeps_single_row(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.remember("Bash", "deploy", "approved", "global")
        log.remember("Bash", "deploy", "denied", "global")
        memories = log.list_memories(scope="global")
        assert len(memories) == 1
        assert memories[0]["decision"] == "denied"

    def test_query_recent_returns_dict_rows(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored())
        assert isinstance(log.query_recent(limit=1)[0], dict)

    def test_log_persists_selected_model(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored())
        assert log.query_recent(limit=1)[0]["routing_model"] == "M2"

    def test_log_persists_model_floor(self, tmp_path):
        log = DecisionLog(tmp_path / "decisions.db")
        log.log(_scored())
        assert log.query_recent(limit=1)[0]["routing_floor"] == "M1"

    def test_decision_log_uses_custom_path(self, tmp_path):
        path = tmp_path / "custom.db"
        log = DecisionLog(path)
        log.log(_scored())
        assert path.exists()
