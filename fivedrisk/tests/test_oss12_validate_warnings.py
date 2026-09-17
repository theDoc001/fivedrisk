"""OSS-12 — two `validate` warnings for authoring hazards that fail SILENTLY.

Both defects share a shape: the policy loads, `validate` reports it valid, and the control that
deploys is not the control the operator wrote. Nothing raises and nothing breaks, which is precisely
why neither is ever discovered in the field.

1. **An unrecognised key inside a floor rule is dropped.** A rule that also carries a recognised axis
   parses fine with the unknown key discarded. A near-miss on an axis name (`tool_names` for `tools`,
   `pattern` for `patterns`) therefore produces a rule that is WIDER than authored, because the axis
   meant to narrow it was never compiled.

2. **A spike threshold above `DIM_MAX` is unreachable.** Dimensions are clamped to [0, 4] and the
   band rule is `any dim >= threshold`, so `red_threshold: 5` does not harden the policy — it deletes
   the single-axis RED guarantee. `_validate_policy_config` checks the two thresholds against each
   OTHER and neither against the scale.

Each warning gets a POSITIVE case, a NEGATIVE case, and a reachability case, because a linter that
cannot stay quiet is as useless as one that cannot fire.
"""
from __future__ import annotations

import pytest

from fivedrisk.cli import (
    _floor_unknown_key_warnings,
    _spike_threshold_reachability_warnings,
    _validate_policy_config,
)


# ── 1. Unrecognised floor-rule keys ─────────────────────────────────────────────────────────────

class TestFloorUnknownKeyWarning:

    def test_warns_on_a_near_miss_axis_name(self, tmp_path):
        """`tool_names` is not an axis. `tools` is. The rule parses and the narrowing is gone."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - id: sanctions\n"
            "    patterns:\n"
            "      mode: block\n"
            "      values: ['SANCTIONED']\n"
            "    tool_names:\n"
            "      mode: block\n"
            "      values: ['Wire']\n"
        )
        warnings = _floor_unknown_key_warnings(str(p))
        assert any("'sanctions'" in w and "tool_names" in w and "IGNORED" in w for w in warnings), warnings

    def test_the_rule_really_does_load_clean_without_the_warning(self, tmp_path):
        """The premise: this is a SILENT drop, not a parse error. If it ever starts raising, this
        warning is redundant and this test says so."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - id: sanctions\n"
            "    patterns:\n"
            "      mode: block\n"
            "      values: ['SANCTIONED']\n"
            "    tool_names:\n"
            "      mode: block\n"
            "      values: ['Wire']\n"
        )
        assert _validate_policy_config(str(p)) == []

    def test_warns_on_an_unrecognised_key_nested_under_match(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - id: nested\n"
            "    match:\n"
            "      patterns:\n"
            "        mode: block\n"
            "        values: ['X']\n"
            "      data_class:\n"
            "        mode: block\n"
            "        values: ['CHD']\n"
        )
        warnings = _floor_unknown_key_warnings(str(p))
        assert any("data_class" in w and "under 'match:'" in w for w in warnings), warnings

    def test_silent_on_a_fully_recognised_rule(self, tmp_path):
        """A linter that always fires is indistinguishable from a broken one."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - id: ok\n"
            "    reason: 'a reason'\n"
            "    band: RED\n"
            "    tools:\n"
            "      mode: block\n"
            "      values: ['Wire']\n"
            "    patterns:\n"
            "      mode: block\n"
            "      values: ['SANCTIONED']\n"
        )
        assert _floor_unknown_key_warnings(str(p)) == []

    def test_silent_on_the_legacy_authoring_form(self, tmp_path):
        """The legacy tool_name/command_contains shape must not be linted into noise."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - tool_name: Bash\n"
            "    band: RED\n"
            "    command_contains: 'DROP TABLE'\n"
            "    reason: 'no schema drops'\n"
        )
        assert _floor_unknown_key_warnings(str(p)) == []

    def test_names_the_rule_by_id_then_tool_then_index(self, tmp_path):
        """An operator with thirty floor rules needs to know WHICH one."""
        p = tmp_path / "policy.yaml"
        p.write_text(
            "floor:\n"
            "  - tool_name: Bash\n"
            "    band: RED\n"
            "    bogus: 1\n"
            "  - patterns:\n"
            "      mode: block\n"
            "      values: ['X']\n"
            "    bogus: 2\n"
        )
        warnings = _floor_unknown_key_warnings(str(p))
        assert any("'Bash'" in w for w in warnings), warnings
        assert any("'#1'" in w for w in warnings), warnings

    def test_no_policy_and_no_floor_block_are_both_quiet(self, tmp_path):
        assert _floor_unknown_key_warnings(None) == []
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  red_threshold: 4\n")
        assert _floor_unknown_key_warnings(str(p)) == []

    def test_unreadable_policy_does_not_raise(self, tmp_path):
        """Load errors belong to `_validate_policy_config`; this must not double-report or crash."""
        p = tmp_path / "policy.yaml"
        p.write_text("floor: [oops\n")
        assert _floor_unknown_key_warnings(str(p)) == []


# ── 2. Unreachable spike thresholds ─────────────────────────────────────────────────────────────

class TestSpikeThresholdReachabilityWarning:

    def test_warns_when_red_threshold_is_above_the_scale(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  red_threshold: 5\n  orange_threshold: 3\n")
        warnings = _spike_threshold_reachability_warnings(str(p))
        assert any("red_threshold" in w and "single-axis RED guarantee" in w for w in warnings), warnings

    def test_the_existing_order_check_does_not_catch_it(self, tmp_path):
        """The gap, asserted directly: `orange <= red` holds, so nothing else reports this."""
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  red_threshold: 5\n  orange_threshold: 3\n")
        assert _validate_policy_config(str(p)) == []

    def test_warns_on_an_unreachable_orange_threshold_too(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  red_threshold: 9\n  orange_threshold: 7\n")
        warnings = _spike_threshold_reachability_warnings(str(p))
        assert any("orange_threshold" in w for w in warnings), warnings
        assert any("red_threshold" in w for w in warnings), warnings

    def test_silent_on_the_defaults(self, tmp_path):
        """red_threshold defaults to exactly DIM_MAX, which is reachable and must not warn --
        an off-by-one here would fire on every stock policy in existence."""
        p = tmp_path / "policy.yaml"
        p.write_text("thresholds:\n  red_threshold: 4\n  orange_threshold: 3\n")
        assert _spike_threshold_reachability_warnings(str(p)) == []

    def test_silent_on_an_empty_policy(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("version: '0.2.0'\n")
        assert _spike_threshold_reachability_warnings(str(p)) == []
        assert _spike_threshold_reachability_warnings(None) == []


# ── 3. Both are wired into the command, not merely defined ──────────────────────────────────────

class TestWarningsReachTheValidateCommand:
    """A warning function nothing calls is a dark control. This is the read site."""

    def test_cmd_validate_surfaces_both_new_warnings(self, tmp_path, capsys):
        import argparse

        from fivedrisk.cli import cmd_validate

        p = tmp_path / "policy.yaml"
        p.write_text(
            "thresholds:\n  red_threshold: 5\n  orange_threshold: 3\n"
            "floor:\n"
            "  - id: sanctions\n"
            "    patterns:\n"
            "      mode: block\n"
            "      values: ['SANCTIONED']\n"
            "    tool_names:\n"
            "      mode: block\n"
            "      values: ['Wire']\n"
        )
        with pytest.raises(SystemExit) as exc:
            cmd_validate(argparse.Namespace(input=str(p), format="json", audit=False))
        assert exc.value.code == 0, "warnings must not change the exit status; only errors do"

        import json

        payload = json.loads(capsys.readouterr().out)
        assert payload["valid"] is True, "the point is that it validates while being wrong"
        blob = " ".join(payload["warnings"])
        assert "tool_names" in blob
        assert "red_threshold" in blob
