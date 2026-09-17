"""Tests for the 5D classifier — tool-call to Action mapping."""

import pytest

from fivedrisk.classifier import classify_tool_call
from fivedrisk.policy import Policy


class TestToolBaselines:
    """Classifier uses policy baselines for known tools."""

    def test_read_is_zero_risk(self):
        action = classify_tool_call("Read", {"file_path": "/tmp/test.txt"})
        assert action.tool_privilege == 0
        assert action.reversibility == 0
        assert action.external_impact == 0

    def test_bash_has_baseline_risk(self):
        action = classify_tool_call("Bash", {"command": "ls -la"})
        assert action.tool_privilege >= 2
        assert action.reversibility >= 2

    def test_edit_has_moderate_risk(self):
        action = classify_tool_call("Edit", {"file_path": "/tmp/test.txt", "old_string": "a", "new_string": "b"})
        assert action.tool_privilege == 1
        assert action.reversibility == 1

    def test_unknown_tool_gets_zeros(self):
        action = classify_tool_call("CustomTool", {"foo": "bar"})
        assert action.tool_privilege == 0
        assert action.reversibility == 0


class TestBashOverrides:
    """Bash commands trigger pattern-based dimension overrides."""

    def test_rm_rf_triggers_stop_level(self):
        action = classify_tool_call("Bash", {"command": "rm -rf /important/data"})
        assert action.tool_privilege == 4
        assert action.reversibility == 4

    def test_docker_bumps_privilege(self):
        action = classify_tool_call("Bash", {"command": "docker compose up -d"})
        assert action.tool_privilege >= 3

    def test_git_push_force_is_irreversible(self):
        action = classify_tool_call("Bash", {"command": "git push --force origin main"})
        assert action.reversibility == 4

    def test_pip_install_moderate(self):
        action = classify_tool_call("Bash", {"command": "pip install requests"})
        assert action.tool_privilege >= 2

    def test_curl_post_external(self):
        action = classify_tool_call("Bash", {"command": "curl -X POST https://api.example.com"})
        assert action.external_impact >= 3


class TestContentHeuristics:
    """Sensitive content patterns bump dimensions."""

    def test_password_in_input_bumps_sensitivity(self):
        action = classify_tool_call("Bash", {"command": "echo password=secret123"})
        assert action.data_sensitivity >= 1

    def test_env_file_bumps_sensitivity(self):
        action = classify_tool_call("Read", {"file_path": "/app/.env"})
        assert action.data_sensitivity >= 1

    def test_email_keyword_bumps_external(self):
        action = classify_tool_call("Bash", {"command": "sendgrid send --to user@example.com"})
        assert action.external_impact >= 1

    def test_delete_keyword_bumps_reversibility(self):
        action = classify_tool_call("Bash", {"command": "delete all records"})
        assert action.reversibility >= 1

    def test_network_access_bumps_external(self):
        action = classify_tool_call("Bash", {"command": "curl https://example.com"})
        assert action.external_impact >= 2


class TestAutonomyContext:
    """Autonomy context is passed through from caller."""

    def test_autonomy_zero_default(self):
        action = classify_tool_call("Bash", {"command": "ls"})
        assert action.autonomy_context == 0

    def test_autonomy_set_by_caller(self):
        action = classify_tool_call("Bash", {"command": "ls"}, autonomy_context=3)
        assert action.autonomy_context == 3

    def test_autonomy_clamped_to_max(self):
        action = classify_tool_call("Bash", {"command": "ls"}, autonomy_context=10)
        assert action.autonomy_context == 4


class TestSource:
    """Source field is preserved."""

    def test_source_default(self):
        action = classify_tool_call("Bash", {"command": "ls"})
        assert action.source == "unknown"

    def test_source_set(self):
        action = classify_tool_call("Bash", {"command": "ls"}, source="planner")
        assert action.source == "planner"
