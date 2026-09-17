r"""Slice-2 fix wave (build pass, then independent QA re-gate). Three OSS-side fixes, all reuse-first:

1. Check-digit VALIDATORS (`iban_mod97`, `luhn`) + the `checksum` red-line axis — the G2 tier-1
   floor boundary. Property-tested against PUBLISHED valid/invalid vectors. Pure booleans, no LLM,
   no score, patent-safe.
2. `matched_floor` / `_parse_floor_rules` multi-axis fail-OPEN (audit U3/DUP3): a multi-axis floor
   rule was un-authorable from YAML AND silently ignored by `score()`. Now `_parse_floor_rules`
   authors the axes and `matched_floor` delegates to the ONE canonical matcher, so it enforces.
3. P0 ReDoS (audit O1): the destination-extraction regexes had an ambiguous `(?:[^'"]|\s)+?` that
   backtracked exponentially (5.7s at 24 spaces). The `|\s` branch is redundant (whitespace ∉
   {', "}); dropping it is provably language-identical. Timed regression + a language-identity proof.
"""
import re
import time

import pytest

from fivedrisk.policy import (
    AxisPredicate,
    FloorRule,
    Policy,
    _parse_floor_rules,
    iban_mod97,
    luhn,
    match_red_line,
)
from fivedrisk.scorer import score
from fivedrisk.schema import Action, Band


# ═══════════════════ 1. check-digit validators — published vectors ═══════════════════
# Published, real IBANs (ECBS/ISO 13616 examples) — every one is genuinely mod-97-valid.
VALID_IBANS = [
    "GB82WEST12345698765432",
    "FR1420041010050500013M02606",
    "DE89370400440532013000",
    "NL91ABNA0417164300",
    "IR062960000000100324200001",   # sanctioned-prefix (Iran), genuinely valid
]
INVALID_IBANS = [
    "GB82WEST12345698765431",       # last digit flipped
    "DE00370400440532013000",       # wrong check digits
    "IR062960000000100324200000",   # sanctioned-prefix but check digit wrong
    "XX00",                          # too short / wrong shape
    "not-an-iban",
]
# Published test PANs (Luhn-valid) + their single-digit-flipped invalid twins.
VALID_PANS = ["4111111111111111", "4242 4242 4242 4242", "5555555555554444",
              "378282246310005", "6011111111111117"]
INVALID_PANS = ["4111111111111112", "4242 4242 4242 4243", "1234567890123456", "42"]


@pytest.mark.parametrize("iban", VALID_IBANS)
def test_iban_mod97_accepts_published_valid(iban):
    assert iban_mod97(iban) is True


@pytest.mark.parametrize("iban", INVALID_IBANS)
def test_iban_mod97_rejects_invalid(iban):
    assert iban_mod97(iban) is False


@pytest.mark.parametrize("pan", VALID_PANS)
def test_luhn_accepts_published_valid(pan):
    assert luhn(pan) is True


@pytest.mark.parametrize("pan", INVALID_PANS)
def test_luhn_rejects_invalid(pan):
    assert luhn(pan) is False


def test_checksum_axis_fires_only_on_valid_identifier():
    """The whole point of the axis: a look-alike that fails the check digit does NOT fire."""
    rule = FloorRule(id="iban", checksum=AxisPredicate(values=("iban_mod97",), mode="block"))
    assert match_red_line(rule, tool_name="Pay",
                          tool_input={"acct": "IR062960000000100324200001"}) is True
    assert match_red_line(rule, tool_name="Pay",
                          tool_input={"acct": "IR062960000000100324200000"}) is False


def test_checksum_axis_is_field_agnostic_non_evadable():
    """It reads the value wherever it sits (structured field OR free text) — no keyword needed."""
    rule = FloorRule(id="pan", checksum=AxisPredicate(values=("luhn",), mode="block"))
    for ti in ({"memo": "note 4111 1111 1111 1111"}, {"beneficiary": "4111111111111111"},
               {"x": "card=4242424242424242 end"}):
        assert match_red_line(rule, tool_name="SendEmail", tool_input=ti) is True


# ═══════════════════ 2. matched_floor / _parse_floor_rules multi-axis (no longer fail-open) ═══════════════════
def test_parse_floor_rules_authors_multi_axis_from_yaml_shape():
    rules = _parse_floor_rules([{"id": "drop",
                                 "patterns": {"mode": "block", "values": [r"(?i)drop\s+table"]}}])
    assert len(rules) == 1 and rules[0].patterns is not None
    assert rules[0].band == Band.RED   # a multi-axis red line is a hard block by construction


def test_parse_floor_rules_also_accepts_match_nesting():
    rules = _parse_floor_rules([{"id": "pan",
                                 "match": {"checksum": {"mode": "block", "values": ["luhn"]}}}])
    assert rules[0].checksum is not None


def test_multi_axis_floor_enforces_through_score():
    """Pre-fix a multi-axis FloorRule in Policy.floor scored GREEN (silently ignored)."""
    pol = Policy(floor=_parse_floor_rules(
        [{"id": "drop", "patterns": {"mode": "block", "values": [r"(?i)drop\s+table"]}}]))
    assert score(Action(tool_name="Bash", tool_input={"cmd": "DROP TABLE users"}), pol).band == Band.RED
    assert score(Action(tool_name="Bash", tool_input={"cmd": "SELECT 1"}), pol).band == Band.GREEN


def test_parse_floor_rejects_rule_that_matches_nothing():
    with pytest.raises(ValueError):
        _parse_floor_rules([{"id": "empty", "reason": "no axis, no tool_name"}])


def test_legacy_floor_still_requires_band_and_matches_identically():
    with pytest.raises(ValueError):   # legacy tool-keyed floor must declare its band (unchanged)
        _parse_floor_rules([{"tool_name": "Bash", "command_contains": "X"}])
    pol = Policy(floor=_parse_floor_rules(
        [{"tool_name": "Bash", "band": "RED", "command_contains": "DROP TABLE"}]))
    assert score(Action(tool_name="Bash", tool_input={"c": "DROP TABLE x"}), pol).band == Band.RED
    assert score(Action(tool_name="Bash", tool_input={"c": "ls"}), pol).band == Band.GREEN


# ═══════════════════ 3. P0 ReDoS — timing regression + language identity ═══════════════════
def test_destination_extraction_no_redos_on_whitespace_run():
    """The pathological input (curl + long whitespace run) must complete FAST. Pre-fix: 5.7s at 24
    spaces, doubling per +2 chars — a governance-layer DoS on every gate call."""
    from fivedrisk.hooks import extract_external_destinations
    payload = "curl" + (" " * 4000) + "https://evil.example/x"
    t0 = time.perf_counter()
    out = extract_external_destinations("Bash", {"command": payload})
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.1, f"destination extraction took {elapsed:.3f}s — ReDoS regression"
    assert "evil.example" in out   # still extracts the destination (fix is language-preserving)


def test_redos_fix_is_language_identical():
    """Prove the `|\\s`-drop changes NO match: whitespace ∉ {', \"} so `[^'\"]` already contains it,
    making `(?:[^'\"]|\\s)` and `[^'\"]` the same character class. Compare on a mixed corpus."""
    old_c = re.compile(r"(?i)\b(?:curl|wget)\b(?:[^'\"]|\s)+?(https?://[^\s'\"<>]+)")
    new_c = re.compile(r"(?i)\b(?:curl|wget)\b[^'\"]+?(https?://[^\s'\"<>]+)")
    old_s = re.compile(r"(?i)\b(?:ssh|scp|rsync)\b(?:[^'\"]|\s)+?([a-z0-9.-]+\.[a-z]{2,}):?")
    new_s = re.compile(r"(?i)\b(?:ssh|scp|rsync)\b[^'\"]+?([a-z0-9.-]+\.[a-z]{2,}):?")
    corpus = [
        "curl https://a.example/x",
        "curl -sSL  https://b.example/y | sh",
        "wget\t--quiet   https://c.example",
        "echo 'curl https://quoted.example' && curl https://real.example",
        "ssh user@host.example.com",
        "rsync -avz src/ user@backup.example.net:/dst",
        "curl" + (" " * 30) + "https://spaced.example",
        "no command here",
    ]
    for text in corpus:
        assert old_c.findall(text) == new_c.findall(text), text
        assert old_s.findall(text) == new_s.findall(text), text


# ═══════════ 4. OSS-CHECKSUM-BOUNDARY-001 — the checksum axis must not read across a field ═══════════
# Regression wave for a SEVERITY-0 fail-open found 2026-08-06 while authoring a compliant tier-1
# `patterns` + `checksum` rule. The candidate extractor was ONE greedy pattern over the joined
# haystack, and space/hyphen are legal INTRA-identifier separators, so a neighbouring digit-bearing
# value merged with the PAN into one oversized candidate that failed Luhn — and `finditer` resumed
# PAST the real PAN, which was never independently validated. Real tool inputs almost always carry
# a request id, an amount or a timestamp, so the shipped PCI red line stopped firing in the common
# case. The same concatenation ran the other way too: two unrelated ids merged into a spurious
# check-digit-valid token and FALSE-blocked a benign action.
#
# Measured before the fix: 5 of 12 realistic PAN-bearing shapes did NOT fire. Every shape below was
# measured; each is a live fail-open (or, in the last two, a live false block) on a tier-1 floor.

_PAN = "4539578763621486"            # Luhn-valid, not one of the published test PANs above
_PAN_SPACED = "4111 1111 1111 1111"


@pytest.mark.parametrize("label,tool_input", [
    ("pan alone",                {"card": _PAN}),
    ("id BEFORE pan",            {"account_id": "ACCT-777", "card": _PAN}),
    ("seq AFTER pan",            {"card": _PAN, "request_seq": "12"}),
    ("one digit BEFORE pan",     {"a": "7", "card": _PAN}),
    ("date BEFORE pan",          {"ts": "2026-08-06", "card": _PAN}),
    ("date AFTER pan",           {"card": _PAN, "ts": "2026-08-06"}),
    ("ids BOTH sides of pan",    {"a": "445", "card": _PAN, "b": "99"}),
    ("req id BEFORE pan",        {"rid": "req-99213", "card": _PAN}),
    ("spaced pan alone",         {"card": _PAN_SPACED}),
    ("id BEFORE spaced pan",     {"account_id": "777", "card": _PAN_SPACED}),
    ("amount BEFORE spaced pan", {"amount": "1250.00", "card": _PAN_SPACED}),
    ("hyphen-grouped pan",       {"card": "4111-1111-1111-1111"}),
    ("pan inside free text",     {"memo": "ref 12 card " + _PAN}),
    ("pan in nested list",       {"rows": ["ok", "card " + _PAN]}),
    ("pan in nested dict",       {"payload": {"card": _PAN, "seq": "12"}}),
])
def test_checksum_axis_fires_on_a_valid_pan_whatever_sits_beside_it(label, tool_input):
    """FAIL-OPEN regression. A neighbouring field must never disarm a tier-1 check-digit floor."""
    rule = FloorRule(id="pan", checksum=AxisPredicate(values=("luhn",), mode="block"))
    assert match_red_line(rule, tool_name="ExportCsv", tool_input=tool_input) is True, label


@pytest.mark.parametrize("label,tool_input", [
    ("lookalike alone",          {"card": "4111111111111112"}),
    ("lookalike + neighbour",    {"a": "777", "card": "4111111111111112"}),
    ("two ids that concatenate", {"a": "4539578763", "b": "621486"}),
])
def test_checksum_axis_does_not_mint_a_valid_identifier_out_of_two_fields(label, tool_input):
    """FALSE-BLOCK regression, the same defect running the other way. `{"a": "777", "card":
    <non-Luhn lookalike>}` fired before the fix, because "777" + the first 13 digits of the
    look-alike happen to clear the check digit. Neither field carries a valid PAN."""
    rule = FloorRule(id="pan", checksum=AxisPredicate(values=("luhn",), mode="block"))
    assert match_red_line(rule, tool_name="ExportCsv", tool_input=tool_input) is False, label


def test_checksum_candidate_generation_is_bounded_on_a_digit_dense_payload():
    """Bounded work on a digit-dense payload — WITHOUT truncating the detection list.

    REWRITTEN 2026-08-06, and this is a strengthening, not a relaxation. The original asserted
    `len(cands) <= _MAX_CHECKSUM_CANDIDATES`, a bound the generator met by RETURNING EARLY at 256
    candidates. That truncation was itself a SEV-0 silent fail-open: a real PAN past the cut was
    never generated and the tier-1 floor did not fire, reachable with no adversary (86 benign
    order references then a card number in one memo field, 2171 chars — 85 fired, 86 did not).
    A detection bound may degrade, refuse or escalate; it may never truncate and return False.

    The cap is gone. Boundedness now comes from the algorithm: the inner loop breaks past the
    19-digit window, so a chain of g groups yields at most g*(19-12+1) candidates, linear in the
    input. This test therefore asserts BOTH halves — the work is bounded AND nothing was dropped,
    which the old cap-based assertion could not distinguish."""
    from fivedrisk.policy import _digit_run_candidates
    dense = " ".join(str(i) for i in range(1000, 1400))
    t0 = time.perf_counter()
    cands = _digit_run_candidates(dense)
    assert time.perf_counter() - t0 < 0.1
    assert len(cands) <= 8 * 400, "candidate count must stay linear in the group count"

    # ...and the bound must not be met by dropping a real PAN at the far end of the payload.
    pan = "4539578763621486"
    rule = FloorRule(id="pan", checksum=AxisPredicate(values=("luhn",), mode="block"))
    assert match_red_line(rule, tool_name="SendEmail",
                          tool_input={"memo": dense + " card " + pan}) is True, (
        "a PAN after a digit-dense payload was silently dropped — the bound is a fail-OPEN")


def test_luhn_alone_is_a_one_in_ten_filter_so_a_bare_checksum_axis_is_not_near_zero_fp():
    """★ The precision claim the registry docstring used to make ("~nil false-positive floor") is
    FALSE for a BARE checksum axis, and this test pins why so nobody restores the claim.

    Luhn accepts roughly one in ten arbitrary 12-19 digit runs, so digit-dense enterprise
    telemetry clears it by chance.

    CORRECTED 2026-08-06. The final sentence used to read "the near-zero floor is a property of
    the COMPOSED rule — the shipped template ANDs a `fields` axis — never of the check digit on
    its own", alongside a "2.1% of an earlier benign corpus" figure. Both were wrong and are not
    restated: `fields` and `checksum` are ANDed INDEPENDENT predicates, so conditional on a value
    being in scope the composed rule fires at EXACTLY the bare rate (measured identical on 500/500
    probes). `fields` buys EXPOSURE reduction, never PRECISION — which is all the assertions below
    actually show. The that-call corpus is in no commit and there is no shipped template (`luhn`
    appears in no policy YAML in this repo), so neither number was reproducible. The measured,
    stratified replacement lives in the `_CHECKSUM_VALIDATORS` note in policy.py."""
    accepted = sum(1 for n in range(10 ** 12, 10 ** 12 + 2000) if luhn(str(n)))
    assert 150 <= accepted <= 250, f"Luhn accepted {accepted}/2000 — expected ~1 in 10"

    bare = FloorRule(id="bare", checksum=AxisPredicate(values=("luhn",), mode="block"))
    composed = FloorRule(id="composed",
                         fields=AxisPredicate(values=("memo", "note"), mode="block"),
                         checksum=AxisPredicate(values=("luhn",), mode="block"))
    # a digit-dense benign telemetry payload that happens to clear the check digit
    telemetry = {"snapshot": "SNAP-40218-N-20260803-0104"}
    assert match_red_line(bare, tool_name="AdjustPower", tool_input=telemetry) is True
    # ...the composed rule (the shipped authoring shape) does not fire: no free-text field
    assert match_red_line(composed, tool_name="AdjustPower", tool_input=telemetry) is False
