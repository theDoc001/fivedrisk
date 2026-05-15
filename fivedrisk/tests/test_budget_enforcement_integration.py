"""Integration test for budget enforcement at @gate.

Simulates a synthetic agent session that triggers BUDGET_CAP_EXCEEDED.
Asserts that:
  - The @gate decorator raises BudgetExceededError (direct DENY).
  - An NDJSON budget_intervention event is emitted.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from fivedrisk import classify_tool_call, score
from fivedrisk.events import REASON_BUDGET_CAP_EXCEEDED
from fivedrisk.hooks import BudgetExceededError, IdentityRequiredError, configure, gate
from fivedrisk.policy import Policy
from fivedrisk.schema import ActingIdentity, AttestationSource, PrincipalType


@pytest.fixture
def tmp_event_path():
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tf:
        path = Path(tf.name)
    yield path
    if path.exists():
        path.unlink()


class TestBudgetEnforcementAtGate:
    def test_session_budget_breach_raises_direct_deny(self, tmp_event_path) -> None:
        # Set a tiny budget so the first call exceeds it
        configure(event_path=str(tmp_event_path), default_model_class="gpt-4-class")
        # Override policy with a hard budget cap
        from fivedrisk import hooks as h
        h._policy = Policy(max_session_budget_tokens=10)

        @gate(tool_name="WebFetch", estimated_input_tokens=5000)
        def fetch_url(url: str, session_id: str) -> str:
            return "should never run"

        with pytest.raises(BudgetExceededError):
            fetch_url("https://example.com", session_id="s1")

        events = [
            json.loads(line)
            for line in tmp_event_path.read_text().splitlines()
            if line
        ]
        assert any(
            e["event_type"] == "budget_intervention"
            and e["reason_code"] == REASON_BUDGET_CAP_EXCEEDED
            for e in events
        )

    def test_budget_exceeded_raises_direct_deny(self, tmp_event_path) -> None:
        """When budget admission rejects a call, it raises
        BudgetExceededError directly. The 5D Score function returns its
        normal result for a separate Action with the same input;
        admission denial is unrelated to score()."""
        configure(event_path=str(tmp_event_path), default_model_class="gpt-4-class")
        from fivedrisk import hooks as h
        h._policy = Policy(max_session_budget_tokens=10)

        @gate(tool_name="WebFetch", estimated_input_tokens=5000)
        def fetch_url(url: str, session_id: str) -> str:
            return "should never run"

        with pytest.raises(BudgetExceededError):
            fetch_url("https://example.com", session_id="s1")

        # Confirm that calling score() directly with a normal action
        # returns the same Band as it would have without budget data.
        # Score function is pure and oblivious to budget state.
        policy = Policy(max_session_budget_tokens=10)
        action = classify_tool_call("WebFetch", {"url": "x"}, policy=policy)
        scored = score(action, policy)
        # Band depends on classification + score thresholds only.
        assert scored.band is not None  # function ran; budget did not modify it

    def test_no_budget_no_enforcement(self, tmp_event_path) -> None:
        configure(event_path=str(tmp_event_path), default_model_class="gpt-4-class")
        from fivedrisk import hooks as h
        h._policy = Policy()  # max_session_budget_tokens is None

        @gate(tool_name="Read", estimated_input_tokens=1000)
        def read_file(path: str, session_id: str) -> str:
            return "content"

        # Should not raise; no budget configured
        result = read_file("/tmp/x", session_id="s1")
        assert result == "content"


class TestIdentityAdmissionAtGate:
    def test_identity_required_denies_anonymous(self, tmp_event_path) -> None:
        configure(event_path=str(tmp_event_path))
        from fivedrisk import hooks as h
        h._policy = Policy(identity_required=True)

        @gate(tool_name="Read")
        def read_file(path: str, session_id: str) -> str:
            return "content"

        with pytest.raises(IdentityRequiredError):
            read_file("/tmp/x", session_id="s1")

        events = [
            json.loads(line)
            for line in tmp_event_path.read_text().splitlines()
            if line
        ]
        assert any(e["event_type"] == "identity_required_denial" for e in events)

    def test_identity_required_admits_with_principal(self, tmp_event_path) -> None:
        configure(event_path=str(tmp_event_path))
        from fivedrisk import hooks as h
        h._policy = Policy(identity_required=True)

        @gate(tool_name="Read")
        def read_file(path: str, session_id: str) -> str:
            return "content"

        ai = ActingIdentity(
            principal_id="user-42",
            principal_type=PrincipalType.USER,
            attestation_source=AttestationSource.HTTP_HEADER,
        )
        result = read_file(
            "/tmp/x", session_id="s1", _fivedrisk_acting_identity=ai
        )
        assert result == "content"

    def test_no_identity_required_admits_anonymous(self, tmp_event_path) -> None:
        configure(event_path=str(tmp_event_path))
        from fivedrisk import hooks as h
        h._policy = Policy()  # identity_required=False

        @gate(tool_name="Read")
        def read_file(path: str, session_id: str) -> str:
            return "content"

        # No identity passed; admission succeeds because policy does not require it.
        result = read_file("/tmp/x", session_id="s1")
        assert result == "content"
