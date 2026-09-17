"""Tests for the NDJSON event emission layer.

Verifies risk_decision, budget_intervention, and identity_required_denial
events are written as one JSON object per line with the expected fields.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fivedrisk import classify_tool_call, score
from fivedrisk.events import (
    NDJSONEventChannel,
    REASON_BUDGET_CAP_EXCEEDED,
    REASON_IDENTITY_REQUIRED_NOT_SUPPLIED,
)
from fivedrisk.policy import Policy
from fivedrisk.schema import (
    ActingIdentity,
    AttestationSource,
    PrincipalType,
)


def _read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


class TestRiskDecisionEvent:
    def test_emits_one_line_per_event(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
            path = Path(tf.name)
        try:
            channel = NDJSONEventChannel(path=path)
            policy = Policy()
            action = classify_tool_call("Read", {"path": "/tmp/x"}, policy=policy)
            scored = score(action, policy)
            channel.emit_risk_decision(
                session_id="s1", scored_action=scored, acting_identity=None
            )
            channel.emit_risk_decision(
                session_id="s1", scored_action=scored, acting_identity=None
            )
            events = _read_events(path)
            assert len(events) == 2
            for e in events:
                assert e["event_type"] == "risk_decision"
                assert e["session_id"] == "s1"
                assert e["tool_name"] == "Read"
                assert "trace_id" in e
                assert "timestamp" in e
        finally:
            path.unlink()

    def test_includes_acting_identity_when_provided(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
            path = Path(tf.name)
        try:
            channel = NDJSONEventChannel(path=path)
            policy = Policy()
            action = classify_tool_call("Read", {"path": "/tmp/x"}, policy=policy)
            scored = score(action, policy)
            ai = ActingIdentity(
                principal_id="user-42",
                principal_type=PrincipalType.USER,
                attestation_source=AttestationSource.HTTP_HEADER,
            )
            channel.emit_risk_decision(
                session_id="s1", scored_action=scored, acting_identity=ai
            )
            events = _read_events(path)
            assert len(events) == 1
            assert events[0]["acting_identity"]["principal_id"] == "user-42"
            assert events[0]["acting_identity"]["principal_type"] == "USER"
        finally:
            path.unlink()


class TestBudgetInterventionEvent:
    def test_emits_with_required_fields(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
            path = Path(tf.name)
        try:
            channel = NDJSONEventChannel(path=path)
            channel.emit_budget_intervention(
                session_id="s1",
                reason_code=REASON_BUDGET_CAP_EXCEEDED,
                cumulative_token_spend=8500,
                max_session_budget_tokens=10000,
                pressure_ratio=0.85,
                tool_id="call-abc",
                tool_name="webfetch",
                reserved_tokens=2000,
            )
            events = _read_events(path)
            assert len(events) == 1
            e = events[0]
            assert e["event_type"] == "budget_intervention"
            assert e["reason_code"] == REASON_BUDGET_CAP_EXCEEDED
            assert e["cumulative_token_spend"] == 8500
            assert e["max_session_budget_tokens"] == 10000
            assert e["pressure_ratio"] == 0.85
            assert e["tool_id"] == "call-abc"
            assert e["tool_name"] == "webfetch"
            assert e["reserved_tokens"] == 2000
            # Architectural contract: no Score-modifier or amplifier-weight fields
            assert "amplifier_weight" not in e
            assert "modifier_value" not in e
            assert "score_modifier" not in e
        finally:
            path.unlink()


class TestIdentityDenialEvent:
    def test_emits_with_required_fields(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
            path = Path(tf.name)
        try:
            channel = NDJSONEventChannel(path=path)
            channel.emit_identity_required_denial(
                session_id="s1", tool_name="write_record"
            )
            events = _read_events(path)
            assert len(events) == 1
            e = events[0]
            assert e["event_type"] == "identity_required_denial"
            assert e["reason_code"] == REASON_IDENTITY_REQUIRED_NOT_SUPPLIED
            assert e["tool_name"] == "write_record"
        finally:
            path.unlink()


class TestDisabledChannel:
    def test_path_none_does_not_write(self) -> None:
        """A channel with path=None is a no-op."""
        channel = NDJSONEventChannel(path=None)
        channel.emit_budget_intervention(
            session_id="s1",
            reason_code=REASON_BUDGET_CAP_EXCEEDED,
            cumulative_token_spend=0,
            max_session_budget_tokens=None,
            pressure_ratio=0.0,
        )
        # No assertion needed; just confirming no exception is raised.
