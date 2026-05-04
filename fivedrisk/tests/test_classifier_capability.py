"""Expanded classifier capability coverage."""

from __future__ import annotations

from fivedrisk.classifier import classify_tool_call
from fivedrisk.policy import Policy


class TestClassifierCapability:
    def test_policy_baselines_are_copied_per_call(self):
        policy = Policy()
        first = classify_tool_call("Read", {"file_path": "/tmp/a"}, policy=policy)
        second = classify_tool_call("Read", {"file_path": "/tmp/b"}, policy=policy)
        assert first.tool_privilege == second.tool_privilege == 0

    def test_custom_tool_baseline_is_used(self):
        policy = Policy(tool_defaults={"Deploy": {"tool_privilege": 3, "external_impact": 2}})
        action = classify_tool_call("Deploy", {"target": "prod"}, policy=policy)
        assert action.tool_privilege == 3
        assert action.external_impact == 2

    def test_custom_bash_override_is_applied(self):
        policy = Policy(bash_overrides={"terraform apply": {"tool_privilege": 4}})
        action = classify_tool_call("Bash", {"command": "terraform apply"}, policy=policy)
        assert action.tool_privilege == 4

    def test_multiple_bash_overrides_merge(self):
        policy = Policy(
            bash_overrides={
                "docker": {"tool_privilege": 3},
                "push": {"external_impact": 2},
            }
        )
        action = classify_tool_call("Bash", {"command": "docker push image"}, policy=policy)
        assert action.tool_privilege == 3
        assert action.external_impact >= 2

    def test_sensitive_ssn_pattern_bumps_data_sensitivity(self):
        action = classify_tool_call("Read", {"text": "ssn 123-45-6789"})
        assert action.data_sensitivity >= 1

    def test_sensitive_passport_pattern_bumps_data_sensitivity(self):
        action = classify_tool_call("Read", {"text": "passport data"})
        assert action.data_sensitivity >= 1

    def test_pem_file_pattern_bumps_data_sensitivity(self):
        action = classify_tool_call("Read", {"file_path": "/tmp/id_rsa.pem"})
        assert action.data_sensitivity >= 1

    def test_publish_keyword_bumps_external_impact(self):
        action = classify_tool_call("Bash", {"command": "publish release now"})
        assert action.external_impact >= 1

    def test_webhook_keyword_bumps_external_impact(self):
        action = classify_tool_call("Bash", {"command": "send to webhook"})
        assert action.external_impact >= 1

    def test_format_keyword_bumps_reversibility(self):
        action = classify_tool_call("Bash", {"command": "format disk"})
        assert action.reversibility >= 1

    def test_wipe_keyword_bumps_reversibility(self):
        action = classify_tool_call("Bash", {"command": "wipe device"})
        assert action.reversibility >= 1

    def test_ssh_counts_as_network_access(self):
        action = classify_tool_call("Bash", {"command": "ssh root@example.com"})
        assert action.external_impact >= 2

    def test_scp_counts_as_network_access(self):
        action = classify_tool_call("Bash", {"command": "scp file host:/tmp"})
        assert action.external_impact >= 2

    def test_rsync_counts_as_network_access(self):
        action = classify_tool_call("Bash", {"command": "rsync file host:/tmp"})
        assert action.external_impact >= 2

    def test_npm_publish_counts_as_network_access(self):
        action = classify_tool_call("Bash", {"command": "npm publish"})
        assert action.external_impact >= 2

    def test_negative_autonomy_is_clamped_to_zero(self):
        action = classify_tool_call("Read", {"file_path": "/tmp/a"}, autonomy_context=-4)
        assert action.autonomy_context == 0

    def test_unknown_tool_still_applies_content_heuristics(self):
        action = classify_tool_call("Custom", {"text": "delete password=secret"})
        assert action.data_sensitivity >= 1
        assert action.reversibility >= 1

    def test_command_missing_for_bash_uses_baseline_only(self):
        action = classify_tool_call("Bash", {})
        assert action.tool_privilege >= 2
        assert action.reversibility >= 2

    def test_multiple_sensitive_matches_are_clamped(self):
        action = classify_tool_call(
            "Bash",
            {"command": "password=secret token=abc passport .env api_key=x"},
        )
        assert 0 <= action.data_sensitivity <= 4

    def test_source_is_preserved_on_custom_policy_call(self):
        action = classify_tool_call(
            "Deploy",
            {"target": "prod"},
            policy=Policy(tool_defaults={"Deploy": {"tool_privilege": 2}}),
            source="planner",
        )
        assert action.source == "planner"
