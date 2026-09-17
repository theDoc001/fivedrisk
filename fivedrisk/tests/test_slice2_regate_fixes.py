"""Re-key fix wave for the canonical matcher (implementation pass, 2026-07-14).

Covers these canonical-matcher changes:
  * F-B — the iban_mod97 extractor now finds a LOWERCASE contiguous token (was uppercase-only),
    without the case-insensitive form bleeding across whitespace into adjacent prose.
  * F-C — a new ``fields`` axis scopes on the tool_input KEY name (case-insensitive), block/allow.
  * F-D — ``fivedrisk validate`` WARNS when a floor rule is keyed only on axes score() cannot
    supply (data_classes/list_ref) so an OSS deployer cannot author a silently-inert hard control.

Deterministic, offline. Patent-safe (boolean validators + membership axes, no fused score).
"""
from __future__ import annotations

import json

from fivedrisk.cli import _floor_unsupplyable_axis_warnings
from fivedrisk.policy import AxisPredicate, FloorRule, match_red_line


def _valid_iban(prefix: str, bban: str) -> str:
    r = bban + prefix + "00"
    num = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in r)
    chk = 98 - int(num) % 97
    return f"{prefix}{chk:02d}{bban}"


# ─────────────────── F-B: lowercase IBAN extraction ───────────────────
def test_checksum_axis_finds_lowercase_iban():
    rule = FloorRule(checksum=AxisPredicate(values=("iban_mod97",), mode="block"))
    iban = _valid_iban("IR", "0" + "1" * 21)
    assert match_red_line(rule, tool_name="IssueTransfer", tool_input={"acct": iban.lower()})


def test_checksum_axis_does_not_bleed_across_prose():
    """A valid IBAN adjacent to lowercase prose + a separate invalid prefix literal still validates
    the real IBAN — the any-case extractor is contiguous, so it does not gobble ' ref IR99…'."""
    rule = FloorRule(checksum=AxisPredicate(values=("iban_mod97",), mode="block"))
    de = _valid_iban("DE", "370400440532013000")
    assert match_red_line(rule, tool_name="Pay",
                          tool_input={"memo": f"pay {de} ref IR99{'1' * 22}"})


# ─────────────────── F-C: fields axis (KEY-name scope) ───────────────────
def test_fields_axis_block_mode_matches_key_name():
    rule = FloorRule(fields=AxisPredicate(values=("note", "memo"), mode="block"))
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"note": "hello"})
    assert not match_red_line(rule, tool_name="SendEmail", tool_input={"card_on_file": "hello"})


def test_fields_axis_is_case_insensitive():
    rule = FloorRule(fields=AxisPredicate(values=("note",), mode="block"))
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"Note": "x"})
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"NOTE": "x"})


def test_fields_axis_word_in_value_does_not_match():
    """The F-C invariant: 'note' appearing in a VALUE does not satisfy a field-NAME axis."""
    rule = FloorRule(fields=AxisPredicate(values=("note",), mode="block"))
    assert not match_red_line(rule, tool_name="SendEmail",
                              tool_input={"body": "please see the note below"})


def test_fields_axis_allow_mode_off_allowlist():
    """allow-mode: fires when a key is NOT in the permitted set (an off-allowlist field name)."""
    rule = FloorRule(fields=AxisPredicate(values=("subject", "to"), mode="allow"))
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"attachment": "x"})
    assert not match_red_line(rule, tool_name="SendEmail", tool_input={"subject": "x"})


def test_fields_axis_composes_and_with_checksum():
    """The re-keyed PAN shape: Luhn-valid PAN AND a non-CHD field name."""
    rule = FloorRule(
        fields=AxisPredicate(values=("note", "memo", "description", "body"), mode="block"),
        checksum=AxisPredicate(values=("luhn",), mode="block"),
    )
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"note": "4111 1111 1111 1111"})
    assert match_red_line(rule, tool_name="SendEmail", tool_input={"description": "4111111111111111"})
    # PAN in a designated CHD field name -> out of scope (fields axis False)
    assert not match_red_line(rule, tool_name="SendEmail",
                              tool_input={"card_on_file": "4111 1111 1111 1111"})
    # non-Luhn look-alike in a non-CHD field -> checksum axis False
    assert not match_red_line(rule, tool_name="SendEmail", tool_input={"note": "4111 1111 1111 1112"})


# ─────────────────── F-D: validate warns on a silently-inert floor ───────────────────
def _write_policy(tmp_path, floor):
    p = tmp_path / "policy.yaml"
    p.write_text(json.dumps({"floor": floor}))  # JSON is valid YAML; keeps the fixture terse
    return str(p)


def test_validate_warns_floor_keyed_only_on_unsupplyable_axes(tmp_path):
    path = _write_policy(tmp_path, [
        {"id": "inert-dataclass", "match": {"data_classes": {"mode": "allow", "values": ["public"]}}},
        {"id": "inert-list", "match": {"list_ref": {"mode": "block", "values": ["ofac"]}}},
    ])
    warns = _floor_unsupplyable_axis_warnings(path)
    joined = " ".join(warns)
    assert "inert-dataclass" in joined and "inert-list" in joined
    assert all("INERT" in w for w in warns)


def test_validate_no_warning_when_supplyable_axis_present(tmp_path):
    path = _write_policy(tmp_path, [
        {"id": "ok-fields", "match": {"fields": {"mode": "block", "values": ["note"]},
                                      "data_classes": {"mode": "allow", "values": ["public"]}}},
        {"id": "ok-tools", "match": {"tools": {"mode": "block", "values": ["Pay"]}}},
        {"id": "ok-legacy", "tool_name": "Bash", "band": "RED", "command_contains": "rm -rf"},
    ])
    assert _floor_unsupplyable_axis_warnings(path) == []
