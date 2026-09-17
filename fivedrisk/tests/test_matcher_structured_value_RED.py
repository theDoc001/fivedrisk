"""RED baseline (test-first) for the structured-value + windowed-negation matcher axes.

Authored test-first as a scoping artifact; the GREEN implementation follows separately.
Two queued OSS capabilities:
  * OSS-STRUCTURED-VALUE-AXIS-001 — bind a value predicate to a NAMED field's VALUE
    (today `patterns`/`checksum` match over the JOINED haystack of ALL values, and
    `fields` scopes only KEY names — neither can say "the VALUE of field `amount`
    matches this pattern").
  * OSS-WINDOWED-NEGATION-001 — suppress a pattern hit when a negation cue occurs
    within a TOKEN WINDOW of the match (NOT lookbehind — both RE2 and the Rust
    `regex` crate drop lookbehind; this is a token-window negator).

The `_RED_*` tests were authored strict-xfail (RED); the GREEN axes have LANDED, so the
strict-xfail markers were dropped (an XPASS under strict=True is a suite FAILURE) — a clean
RED->GREEN handshake. They now stand as permanent regression assertions of the value-scope
and token-window-negation behavior. (Kept in this file name for provenance.)

The `_GUARD_*` tests are PERMANENT regression locks: they assert the EXISTING axis semantics
are byte-identical before and after the new axes landed — the never-perturb-existing-rules
invariant independent QA gates. They passed before GREEN and keep passing after.

Empirical gap proof captured at authoring (shipped matcher, 2026-07-20):
  GAP-A structured-value  match_red_line(patterns=r"\\d{7,}", {"amount":"5","reference":"INV-1000000"}) -> True  (want False)
  GAP-B windowed-negation match_red_line(patterns=r"(?i)transfer", {"command":"reversal of the disputed transfer to vendor"}) -> True (want False)
  fields axis fires on KEY presence only, VALUE ignored -> True regardless of value
"""

from __future__ import annotations

from fivedrisk.policy import FloorRule, AxisPredicate, match_red_line
from fivedrisk.schema import Band


# ─────────────────────────────────────────────────────────────────────────────
# PERMANENT GUARD tests — existing axis semantics must NOT change (independent QA gate).
# These pass today and must keep passing after the new axes land. They lock the
# byte-identity of the shipped `patterns` and `fields` axes so the new axis is
# proven ADDITIVE, never a silent change to an existing rule's outcome.
# ─────────────────────────────────────────────────────────────────────────────

def test_GUARD_patterns_axis_still_matches_over_joined_haystack():
    """The `patterns` axis scans the JOINED values (all fields). Unchanged."""
    rule = FloorRule(id="g1", patterns=AxisPredicate(values=(r"(?i)transfer",), mode="block"), band=Band.RED)
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "wire transfer"}) is True
    assert match_red_line(rule, tool_name="Bash", tool_input={"note": "a transfer note"}) is True  # any field


def test_GUARD_fields_axis_still_scopes_key_names_only():
    """The `fields` axis fires on presence of a KEY name, independent of its value."""
    rule = FloorRule(id="g2", fields=AxisPredicate(values=("amount",), mode="block"), band=Band.RED)
    assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "5"}) is True
    assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "999999999"}) is True
    assert match_red_line(rule, tool_name="Pay", tool_input={"reference": "amount"}) is False  # value != key


def test_GUARD_unspecified_rule_never_fires():
    """A rule with no specified axis still never fires (fail-safe by construction)."""
    assert match_red_line(FloorRule(id="g3", band=Band.RED), tool_name="X", tool_input={"a": "b"}) is False


# ─────────────────────────────────────────────────────────────────────────────
# RED — OSS-STRUCTURED-VALUE-AXIS-001 : bind a predicate to a NAMED field's VALUE
# Target contract (builder implements): FloorRule.value_match = FieldValuePredicate(
#     field="amount", values=(...), mode="block", kind="regex"|"literal"|"checksum",
#     match_mode="any"|"all"). The matcher scopes the predicate to str(tool_input[field]).
# ─────────────────────────────────────────────────────────────────────────────

def test_RED_structured_value_scopes_to_named_field_value():
    """A value predicate on field `amount` must NOT fire when the pattern only
    appears in a DIFFERENT field's value (the false-fire the joined haystack causes)."""
    from fivedrisk.policy import FieldValuePredicate  # noqa: symbol lands with GREEN
    rule = FloorRule(
        id="r1",
        value_match=FieldValuePredicate(field="amount", values=(r"\d{7,}",), mode="block", kind="regex"),
        band=Band.RED,
    )
    # amount is small; a 7-digit token lives only in `reference` -> must NOT fire.
    assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "5", "reference": "INV-1000000"}) is False
    # the 7-digit value IS in amount -> must fire.
    assert match_red_line(rule, tool_name="Pay", tool_input={"amount": "1000000", "reference": "x"}) is True


def test_RED_structured_value_checksum_scoped_to_field():
    """A checksum predicate scoped to field `iban` must validate THAT field's value,
    not any IBAN-looking token elsewhere in the payload."""
    from fivedrisk.policy import FieldValuePredicate
    rule = FloorRule(
        id="r2",
        value_match=FieldValuePredicate(field="iban", values=("iban_mod97",), mode="block", kind="checksum"),
        band=Band.RED,
    )
    # valid IBAN in a memo, but the iban field is empty/benign -> must NOT fire.
    assert match_red_line(
        rule, tool_name="Pay",
        tool_input={"iban": "n/a", "memo": "old account GB82 WEST 1234 5698 7654 32"},
    ) is False


def test_RED_structured_value_absent_field_allow_mode_denies():
    """allow-mode on a missing field = unknown => deny (fail-safe direction), consistent
    with the shipped AxisPredicate allow semantics."""
    from fivedrisk.policy import FieldValuePredicate
    rule = FloorRule(
        id="r3",
        value_match=FieldValuePredicate(field="destination", values=("approved-hub",), mode="allow", kind="literal"),
        band=Band.RED,
    )
    # field absent -> unknown -> allow-mode denies (rule fires).
    assert match_red_line(rule, tool_name="Ship", tool_input={"item": "x"}) is True
    # on-allowlist value -> does NOT fire.
    assert match_red_line(rule, tool_name="Ship", tool_input={"destination": "approved-hub"}) is False


# ─────────────────────────────────────────────────────────────────────────────
# RED — OSS-WINDOWED-NEGATION-001 : suppress a pattern hit when a negation cue
# occurs within a token window. Target contract (builder implements): AxisPredicate
# gains negate_within:int=0 (0=off) + negate_cues:tuple[str,...]=(). A `patterns`
# hit is suppressed when any cue is within negate_within tokens of the match span.
# NOT lookbehind.
# ─────────────────────────────────────────────────────────────────────────────

def test_RED_windowed_negation_suppresses_near_cue():
    rule = FloorRule(
        id="w1",
        patterns=AxisPredicate(values=(r"(?i)transfer",), mode="block",
                               negate_within=3, negate_cues=("reversal", "refund", "simulated")),
        band=Band.RED,
    )
    # cue within window -> suppressed -> must NOT fire.
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "reversal of the disputed transfer"}) is False
    # cue absent -> fires.
    assert match_red_line(rule, tool_name="Bash", tool_input={"command": "execute wire transfer now"}) is True


def test_RED_windowed_negation_respects_window_distance():
    """A cue OUTSIDE the token window must NOT suppress the hit (window is bounded)."""
    rule = FloorRule(
        id="w2",
        patterns=AxisPredicate(values=(r"(?i)transfer",), mode="block",
                               negate_within=2, negate_cues=("reversal",)),
        band=Band.RED,
    )
    # cue is >2 tokens from `transfer` -> NOT suppressed -> fires.
    ti = {"command": "reversal note filed yesterday please also perform the transfer"}
    assert match_red_line(rule, tool_name="Bash", tool_input=ti) is True
