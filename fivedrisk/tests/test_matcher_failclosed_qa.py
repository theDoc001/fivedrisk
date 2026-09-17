"""Regression locks for the two fail-opens QA found in the red-line FLOOR matcher
(structured-value + windowed-negation delta, 0.6.0). The floor is a HARD control —
it must fail CLOSED, never truncate-and-miss or let a shadow key hide a value.

F1 — the `_MAX_HAYSTACK_CHARS` cap on the `patterns` / `command_regex` axes was a
     truncate-and-scan (a dangerous token past the cap silently escaped the floor).
     Now: oversize input fails CLOSED (the axis fires), byte-identical within the cap.
F2 — `value_match` stopped at the first case-insensitive key, so a benign
     case-variant key could shadow the dangerous value. Now: ALL same-named
     fields are scanned; the axis fires if ANY of them would.
"""

from __future__ import annotations

from fivedrisk.policy import AxisPredicate, FieldValuePredicate, FloorRule, match_red_line
from fivedrisk.schema import Band


class TestF1OversizeFailsClosed:
    def test_patterns_axis_match_past_100k_still_fires(self):
        rule = FloorRule(id="f1a", patterns=AxisPredicate(values=(r"(?i)drop\s+table",), mode="block"), band=Band.RED)
        payload = "x " * 100_000 + " DROP TABLE users"   # match starts past the cap
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": payload}) is True

    def test_command_regex_match_past_100k_still_fires(self):
        rule = FloorRule(id="f1b", command_regex=r"(?i)rm\s+-rf\s+/", band=Band.RED)
        payload = "x " * 100_000 + " rm -rf /"
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": payload}) is True

    def test_oversize_benign_input_fails_closed_not_open(self):
        # An input too large to verify fires the floor (fail-closed) even with no
        # match — the intended tradeoff for a hard control; never a silent pass.
        rule = FloorRule(id="f1c", patterns=AxisPredicate(values=(r"(?i)drop\s+table",), mode="block"), band=Band.RED)
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": "a" * 200_000}) is True

    def test_within_cap_is_byte_identical(self):
        rule = FloorRule(id="f1d", patterns=AxisPredicate(values=(r"(?i)drop\s+table",), mode="block"), band=Band.RED)
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": "please DROP TABLE users"}) is True
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": "harmless echo"}) is False


class TestF2ValueMatchCaseShadow:
    def test_benign_case_variant_key_cannot_shadow_dangerous_value(self):
        rule = FloorRule(
            id="f2", band=Band.RED,
            value_match=FieldValuePredicate(field="amount", values=(r"\d{7,}",), mode="block", kind="regex"),
        )
        # benign "Amount":"0" placed FIRST must not hide the dangerous "amount":"9999999"
        assert match_red_line(rule, tool_name="Pay", tool_input={"Amount": "0", "amount": "9999999"}) is True
        assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "9999999", "Amount": "0"}) is True

    def test_all_matching_values_benign_does_not_fire(self):
        rule = FloorRule(
            id="f2b", band=Band.RED,
            value_match=FieldValuePredicate(field="amount", values=(r"\d{7,}",), mode="block", kind="regex"),
        )
        assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "5", "Amount": "0"}) is False
