"""Tests for new Policy attributes (cost management + identity admission).

Verifies YAML parsing of:
  - max_session_budget_tokens
  - max_tool_call_budget_tokens
  - identity_required

Also pins down the architectural contract that Policy does not expose
a Score-multiplier knob: budget admission and risk scoring are
deliberately separate paths.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from fivedrisk.policy import Policy, load_policy


class TestPolicyBudgetAttributes:
    def test_defaults_are_none_and_false(self) -> None:
        p = Policy()
        assert p.max_session_budget_tokens is None
        assert p.max_tool_call_budget_tokens is None
        assert p.identity_required is False

    def test_yaml_parses_max_session_budget(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"max_session_budget_tokens": 50000}, f)
            path = f.name
        try:
            p = load_policy(path)
            assert p.max_session_budget_tokens == 50000
        finally:
            Path(path).unlink()

    def test_yaml_parses_max_tool_call_budget(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"max_tool_call_budget_tokens": 2048}, f)
            path = f.name
        try:
            p = load_policy(path)
            assert p.max_tool_call_budget_tokens == 2048
        finally:
            Path(path).unlink()

    def test_yaml_parses_identity_required(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"identity_required": True}, f)
            path = f.name
        try:
            p = load_policy(path)
            assert p.identity_required is True
        finally:
            Path(path).unlink()

    def test_policy_has_no_score_multiplier_knob(self) -> None:
        """Architectural contract: Policy does not expose a Score-side
        budget multiplier attribute.

        Budget admission and risk scoring are deliberately separate
        paths. If this test fails (someone added such an attribute),
        review with Loren before merging.
        """
        p = Policy()
        assert not hasattr(p, "budget_amplifier_weight"), (
            "Policy must not expose budget_amplifier_weight; budget "
            "admission and Score are separate paths."
        )


class TestAdmitSession:
    def test_admits_when_budget_configured(self) -> None:
        p = Policy(max_session_budget_tokens=10000)
        result = p.admit_session("workflow-a")
        assert result.admit
        assert result.max_session_budget_tokens == 10000
        assert result.warning is None

    def test_admits_with_warning_when_no_budget(self) -> None:
        p = Policy()  # max_session_budget_tokens is None
        result = p.admit_session("workflow-a")
        assert result.admit
        assert result.warning is not None
        assert "not configured" in result.warning
