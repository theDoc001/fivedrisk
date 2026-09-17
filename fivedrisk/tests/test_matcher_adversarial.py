"""Independent adversarial suite for the OSS red-line matcher (priority #5).

Folded in as PERMANENT regression (F5) — mutation-catches the matcher block/allow/order/any-all
class. Two F1 migrations applied at fold-in (SUITE_NEXT_STEPS §E4):
  * `test_command_regex_closes_casing_whitespace_evasion` now keys the casing/whitespace closure on
    the opt-in `command_regex` field (regex semantics), because `command_contains` is now a LITERAL.
  * the former strict-xfail `..._metachar_literal_still_fires...` is now a PASSING assertion — the F1
    fix makes a metachar-bearing literal fire like the pre-upgrade substring gate (the bug is gone).
€0 offline."""
import pytest
from fivedrisk.policy import (
    AxisPredicate, FloorRule, match_red_line, first_red_line_hit, _regex_search,
)


def RL(**kw):
    return FloorRule(**kw)

# ── block vs allow mode ──────────────────────────────────────────────────────
def test_block_mode_tools_fires_on_membership():
    r = RL(id="t", tools=AxisPredicate(values=("Danger",), mode="block"))
    assert match_red_line(r, tool_name="Danger", tool_input={})
    assert not match_red_line(r, tool_name="Safe", tool_input={})

def test_allow_mode_destinations_blocks_off_list_permits_on_list():
    r = RL(id="d", destinations=AxisPredicate(values=("approved.example",), mode="allow"))
    # on-allowlist -> not a hit (permitted)
    assert not match_red_line(r, tool_name="Send", tool_input={"destination": "approved.example"})
    # off-allowlist -> hit (red line)
    assert match_red_line(r, tool_name="Send", tool_input={"destination": "evil.example"})

def test_allow_mode_no_candidate_is_deny():
    # unknown/absent value under allow-mode = deny (fail-safe). data_classes allow-mode.
    r = RL(id="dc", data_classes=AxisPredicate(values=("public",), mode="allow"))
    assert match_red_line(r, tool_name="X", tool_input={}, data_classes=())        # no label -> deny
    assert not match_red_line(r, tool_name="X", tool_input={}, data_classes=("public",))
    assert match_red_line(r, tool_name="X", tool_input={}, data_classes=("pii",))    # off-list -> deny

# ── the sealed-blocklist invariant: an allow rule can NEVER re-grant a block hit ──
def test_sealed_blocklist_not_regrantable_by_allow_rule():
    sealed = RL(id="sealed", tools=AxisPredicate(values=("ProhibitedTool",), mode="block"))
    permissive = RL(id="permit", tools=AxisPredicate(values=("ProhibitedTool",), mode="allow"))
    rules = [permissive, sealed]  # even with the allow rule listed first in input
    hit = first_red_line_hit(rules, tool_name="ProhibitedTool", tool_input={})
    assert hit is not None                       # STILL blocked
    assert hit.id == "sealed"                    # block-dominant reported first

def test_sanctions_blocklist_beats_allowlist_permit_same_action():
    # An on-allowlist destination that is ALSO on a sanctions blocklist must still BLOCK.
    allow_rule = RL(id="dest-allow", destinations=AxisPredicate(values=("wire.bank",), mode="allow"))
    sanctions = RL(id="sanctions", list_ref=AxisPredicate(values=("ofac",), mode="block"))
    rules = [allow_rule, sanctions]
    lists = {"ofac": ["acme-sanctioned"]}
    hit = first_red_line_hit(rules, tool_name="Wire",
                             tool_input={"destination": "wire.bank", "counterparty": "acme-sanctioned"},
                             list_lookup=lists)
    assert hit is not None and hit.id == "sanctions"   # sanctions evaluated first, blocks

# ── patterns any vs all ──────────────────────────────────────────────────────
def test_patterns_any_fires_on_first_hit():
    r = RL(id="p", patterns=AxisPredicate(values=(r"iban", r"swift"), mode="block", match_mode="any"))
    assert match_red_line(r, tool_name="X", tool_input={"m": "has iban only"})

def test_patterns_all_requires_cooccurrence():
    r = RL(id="p", patterns=AxisPredicate(values=(r"iban", r"sanctioned"), mode="block", match_mode="all"))
    assert not match_red_line(r, tool_name="X", tool_input={"m": "iban present"})       # only one
    assert match_red_line(r, tool_name="X", tool_input={"m": "iban to sanctioned party"})  # both

# ── F1: command_regex is the OPT-IN regex; command_contains is a LITERAL substring ──
def test_command_regex_closes_casing_whitespace_evasion():
    # MIGRATED at fold-in: the casing/whitespace closure is a real regex -> command_regex.
    r = RL(id="c", tool_name="Bash", command_regex=r"(?i)drop\s+table")
    assert match_red_line(r, tool_name="Bash", tool_input={"cmd": "DROP    TABLE x"})   # was evadable
    assert match_red_line(r, tool_name="Bash", tool_input={"cmd": "drop table y"})

def test_command_contains_literal_dropTABLE_byte_compat():
    r = RL(id="c", tool_name="Bash", command_contains="DROP TABLE")
    assert match_red_line(r, tool_name="Bash", tool_input={"cmd": "please DROP TABLE"})

def test_command_contains_metachar_literal_still_fires_like_substring():
    # F1 FIXED (was strict-xfail): a metachar-bearing literal fires like the pre-upgrade substring
    # gate. Under the substring->regex upgrade '$HOME' -> '$' anchored and under-matched (unsafe).
    r = RL(id="shell", tool_name="Bash", command_contains="rm -rf $HOME")
    assert match_red_line(r, tool_name="Bash", tool_input={"cmd": "rm -rf $HOME/data"})
    # A few more literals that regex would have silently weakened:
    for needle, hay in [("cmd(x)", "run cmd(x)"), ("cost$5", "cost$5 total"), ("1+1", "1+1=2")]:
        assert match_red_line(RL(id="l", tool_name="Bash", command_contains=needle),
                              tool_name="Bash", tool_input={"cmd": hay}), needle

# ── metamorphic: same-meaning red-line input -> same verdict ──────────────────
def test_metamorphic_same_meaning_tool_input_key_order():
    r = RL(id="p", patterns=AxisPredicate(values=(r"(?i)sanctioned",), mode="block"))
    a = match_red_line(r, tool_name="X", tool_input={"a": "1", "note": "SANCTIONED entity"})
    b = match_red_line(r, tool_name="X", tool_input={"note": "SANCTIONED entity", "a": "1"})
    assert a == b == True

def test_metamorphic_destination_normalization_equivalence():
    # https://Host/path and host should normalize equivalently for an allow-list red line.
    r = RL(id="d", destinations=AxisPredicate(values=("approved.example",), mode="allow"))
    v1 = match_red_line(r, tool_name="Send", tool_input={"destination": "https://approved.example/x"})
    v2 = match_red_line(r, tool_name="Send", tool_input={"destination": "approved.example"})
    assert v1 == v2  # both permitted (not a hit)
