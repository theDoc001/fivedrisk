"""OSS-4 — the ONE canonical red-line matcher (gate #6b, matcher level).

Additive to FloorRule: per-axis {mode, values} predicates (tools / destinations / patterns /
data_classes / list_ref) evaluated by ONE compiled deterministic matcher that REUSES the shipped
regex + destination machinery (no parallel engine). Covers:
  * allow-mode fires (contributes to a BLOCK) when the value is OFF the permitted set;
  * block-mode fires when the value is IN the set (the inverse);
  * the sanctions/blocklist axis is checked FIRST and BEATS an allowlist permit;
  * tools per-agent allowlist grant ⊕ group SEALED blocklist — a sealed-blocked tool is
    un-re-grantable by an allow rule;
  * patterns match_mode=all fires only when ALL required patterns co-occur; any = first hit.
"""
import pytest

from fivedrisk.policy import (
    AxisPredicate,
    FloorRule,
    first_red_line_hit,
    match_red_line,
)
from fivedrisk.schema import Band


# ── block-mode vs allow-mode membership ─────────────────────────────────────────
def test_block_mode_tools_fires_when_in_set():
    rule = FloorRule(tools=AxisPredicate(values=("InitiatePayment",), mode="block"))
    assert match_red_line(rule, tool_name="InitiatePayment", tool_input={}) is True
    assert match_red_line(rule, tool_name="ReadLedger", tool_input={}) is False


def test_allow_mode_destinations_fires_off_allowlist_permits_on_allowlist():
    rule = FloorRule(destinations=AxisPredicate(
        values=("corp-internal.example", "approved-partner.example"), mode="allow"))
    # Off the allowlist -> red-line hit.
    assert match_red_line(rule, tool_name="SendEmail",
                          tool_input={"to": "https://evil.example/x"}) is True
    # On the allowlist -> permitted, no hit.
    assert match_red_line(rule, tool_name="SendEmail",
                          tool_input={"to": "https://approved-partner.example/x"}) is False


# ── AND-within a rule ───────────────────────────────────────────────────────────
def test_and_within_rule_requires_all_axes():
    rule = FloorRule(
        tools=AxisPredicate(values=("ExportDataset",), mode="block"),
        destinations=AxisPredicate(values=("corp-internal.example",), mode="allow"),
    )
    # tool matches AND destination is off-allowlist -> fire.
    assert match_red_line(rule, tool_name="ExportDataset",
                          tool_input={"destination": "https://evil.example"}) is True
    # tool matches but destination IS on the allowlist -> allow axis false -> no fire.
    assert match_red_line(rule, tool_name="ExportDataset",
                          tool_input={"destination": "https://corp-internal.example"}) is False
    # destination off-allowlist but tool does not match -> no fire.
    assert match_red_line(rule, tool_name="ReadLedger",
                          tool_input={"destination": "https://evil.example"}) is False


# ── sanctions blocklist checked FIRST and BEATS an allowlist permit ─────────────
def test_sanctions_blocklist_beats_allowlist_permit_and_is_matched_first():
    sanctions = FloorRule(id="sanctions", destinations=AxisPredicate(
        values=("sanctioned-bank.example",), mode="block"))
    approved = FloorRule(id="approved", destinations=AxisPredicate(
        values=("sanctioned-bank.example", "other.example"), mode="allow"))
    # Same destination is BOTH sanctioned (block) and on the approved (allow) set.
    hit = first_red_line_hit([approved, sanctions], tool_name="IssueTransfer",
                             tool_input={"to": "https://sanctioned-bank.example/acct"})
    assert hit is not None
    assert hit.id == "sanctions"     # the blocklist axis won, evaluated first


# ── tools allowlist grant ⊕ group SEALED blocklist ──────────────────────────────
def test_sealed_blocklist_tool_un_re_grantable_by_allow_rule():
    sealed = FloorRule(id="group-sealed", tools=AxisPredicate(values=("WireToNewPayee",), mode="block"))
    subsidiary_grant = FloorRule(id="subsidiary-allow",
                                 tools=AxisPredicate(values=("WireToNewPayee", "ReadLedger"), mode="allow"))
    hit = first_red_line_hit([subsidiary_grant, sealed], tool_name="WireToNewPayee", tool_input={})
    assert hit is not None and hit.id == "group-sealed"


# ── patterns: match_mode any vs all ─────────────────────────────────────────────
def test_patterns_all_requires_every_pattern_present():
    rule = FloorRule(patterns=AxisPredicate(
        values=(r"(?i)\bIBAN\b", r"(?i)\bDE\d{2}"), mode="block", match_mode="all"))
    # both present -> fire
    assert match_red_line(rule, tool_name="InitiatePayment",
                          tool_input={"memo": "IBAN DE44 5001 ..."}) is True
    # only one present -> no fire (ALL required)
    assert match_red_line(rule, tool_name="InitiatePayment",
                          tool_input={"memo": "IBAN only, no country prefix"}) is False


def test_patterns_any_fires_on_first_hit():
    rule = FloorRule(patterns=AxisPredicate(
        values=(r"(?i)DROP\s+TABLE", r"(?i)rm\s+-rf"), mode="block", match_mode="any"))
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "rm -rf /"}) is True
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "ls -la"}) is False


# ── list_ref frozenset membership (lists = data) ────────────────────────────────
def test_list_ref_membership_block_mode():
    rule = FloorRule(list_ref=AxisPredicate(values=("ofac-sdn",), mode="block"))
    lookup = {"ofac-sdn": frozenset({"badcorp", "evilbank"})}
    assert match_red_line(rule, tool_name="IssueTransfer",
                          tool_input={"counterparty": "BadCorp"}, list_lookup=lookup) is True
    assert match_red_line(rule, tool_name="IssueTransfer",
                          tool_input={"counterparty": "GoodCorp"}, list_lookup=lookup) is False


# ── command_contains is a LITERAL substring; command_regex is the opt-in regex (F1) ───
def test_command_contains_literal_still_matches():
    rule = FloorRule(tool_name="Bash", band=Band.RED, command_contains="DROP TABLE")
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "sql: DROP TABLE users"}) is True


def test_command_contains_literal_metachar_still_fires_f1():
    # F1 regression: a metachar-bearing literal must fire like the pre-upgrade substring gate.
    # Under the old substring→regex behaviour '$' anchored and '(' opened a group, silently
    # WEAKENING the floor (the unsafe direction). command_contains is now a plain literal.
    for needle, hay in [
        ("rm -rf $HOME", "rm -rf $HOME/data"),
        ("cmd(x)", "run cmd(x) now"),
        ("cost$5", "the cost$5 line"),
        ("a+b", "a+b=c"),
    ]:
        rule = FloorRule(tool_name="Bash", band=Band.RED, command_contains=needle)
        assert match_red_line(rule, tool_name="Bash", tool_input={"command": hay}) is True, needle


def test_command_regex_enables_case_insensitive_control():
    # The opt-in: an operator writes command_regex to close the documented casing/whitespace evasion.
    rule = FloorRule(tool_name="Bash", band=Band.RED, command_regex=r"(?i)drop\s+table")
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "drop   table x"}) is True
    # And a literal-looking metachar in command_regex behaves as a regex (operator's explicit choice).
    rule2 = FloorRule(tool_name="Bash", band=Band.RED, command_regex=r"rm -rf \$HOME")
    assert match_red_line(rule2, tool_name="Bash", tool_input={"command": "rm -rf $HOME/data"}) is True
