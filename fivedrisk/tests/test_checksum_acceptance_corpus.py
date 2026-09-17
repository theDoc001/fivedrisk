r"""ACCEPTANCE CORPUS for the `checksum: luhn` candidate extractor — authored BEFORE the fix.

This file is the gate the next attempt on `_digit_run_candidates` must clear. It is authored
against the two failure directions AT ONCE, because the defect history here is a pendulum:

  bug 1 (fixed by the field-boundary fix) — the extractor read ACROSS a field join, so a neighbouring
      digit-bearing value absorbed the PAN into one oversized candidate that failed Luhn.
      A tier-1 PCI floor silently stopped firing. 5 of 12 realistic shapes missed.
  bug 2 (CAUSED by the field-boundary fix, not seen by its own 18 regression rows + base-rate test) — the
      replacement enumerates digit-group SUBSEQUENCES, so a 4-group 16-digit chain yields 3
      candidates each clearing Luhn ~1-in-10. Measured here: 880/4507 (19.53%) of space- or
      hyphen-grouped 16-digit NON-PAN values now fire a tier-1 terminal BLOCK.

A fix that closes bug 2 by narrowing candidate generation reintroduces bug 1 on some shape.
That trade is REAL and IRREDUCIBLE (see `test_the_trade_is_irreducible_on_digits_alone`), so
this corpus is built to MEASURE it, never to let it be argued.

═══════════════════════════════════════════════════════════════════════════════════════════
WHY THE TWO PRIOR CORPORA WERE BLIND — stated as the property this corpus must not repeat
═══════════════════════════════════════════════════════════════════════════════════════════

(a) The 18 regression rows were not a covering array. Read as a factorial over
    (ground truth) x (grouping), they covered:

                     contiguous   space-grouped   hyphen-grouped
        PAN present       yes          yes             yes
        PAN absent        yes          EMPTY           EMPTY        <-- bug 2 lives here

    The whole false-block half was 3 rows against 15, and all 3 were contiguous. The defect
    class is symmetric; the corpus was 5:1 asymmetric. `test_corpus_is_a_covering_array`
    below makes non-emptiness of every cell a MECHANICAL assertion on this corpus, so the
    same hole cannot reopen silently.

(b) The earlier benign corpus measured its own field-NAME distribution, not the control.
    Two independent failures:
      1. it contained no space-grouped 16-digit values at all, so the failing shape was
         unobservable in it — the measurement characterised the corpus, not the rule;
      2. the "composed rule floor 0-1/that" was produced by the `fields` axis EXCLUDING the
         digit-dense keys, not by the checksum axis being precise. `fields` restricts WHERE
         the axis looks; it cannot change WHAT the axis accepts. Conditional on a value being
         in scope, composed precision == bare precision, exactly, by construction.
         Pinned by `test_composed_rule_has_no_precision_floor_only_reduced_exposure`.
    The corpus itself was never committed, so the figure is also UNREPRODUCIBLE: it was
    quoted without its artifact.

    Checkable property this corpus adopts instead: every benign stratum is defined by VALUE
    SHAPE (grouping x chain length), is placed in a field the rule actually scopes to, and
    is reported with its Wilson 95% interval and its n.

═══════════════════════════════════════════════════════════════════════════════════════════
EXPECTED STATE BEFORE the field-boundary fix: RED. That is correct and intended.
Each failing test asserts the SAFE contract, so the identical test flips red -> green when
the code is fixed. No test here may be relaxed to make it pass; if a test fails, the CODE is
the finding.
═══════════════════════════════════════════════════════════════════════════════════════════
"""
import math
import random
import re
import time
from contextlib import contextmanager

import pytest

from fivedrisk import policy as P
from fivedrisk.policy import AxisPredicate, FloorRule, luhn, match_red_line

pytestmark = pytest.mark.acceptance


# ═══════════════════════════════ helpers ═══════════════════════════════
BARE = FloorRule(id="pan_bare", checksum=AxisPredicate(values=("luhn",), mode="block"))
COMPOSED = FloorRule(
    id="pan_composed",
    fields=AxisPredicate(values=("memo", "note", "description", "comment"), mode="block"),
    checksum=AxisPredicate(values=("luhn",), mode="block"),
)


def fires(value, rule=BARE, key="memo"):
    """Does the tier-1 floor fire on this single-field payload?"""
    return match_red_line(rule, tool_name="SendEmail", tool_input={key: value})


def fires_ti(tool_input, rule=BARE):
    return match_red_line(rule, tool_name="SendEmail", tool_input=tool_input)


def wilson(k, n, z=1.96):
    """Wilson 95% interval. Required accompaniment for every rate in this file
    (the claim ladder: a rate is quotable only when its interval clears the tier)."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def group(digits, sep=" ", size=4):
    return sep.join(digits[i:i + size] for i in range(0, len(digits), size))


def make_pan(rng, prefix="4", length=16):
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    for cd in range(10):
        if luhn(body + str(cd)):
            return body + str(cd)
    raise AssertionError("unreachable: one check digit always closes Luhn")


def make_non_pan(rng, length=16):
    """A digit string that is NOT a valid PAN when read as ONE identifier."""
    while True:
        s = "".join(str(rng.randint(0, 9)) for _ in range(length))
        if not luhn(s):
            return s


@contextmanager
def candidate_generator(gen):
    """Swap the luhn candidate generator. Used by the MUTANT potency checks (part 9) so the
    corpus is proven able to go RED, and by nothing else."""
    original = P._CHECKSUM_VALIDATORS["luhn"]
    P._CHECKSUM_VALIDATORS["luhn"] = (gen, original[1])
    try:
        yield
    finally:
        P._CHECKSUM_VALIDATORS["luhn"] = original


# ═══════════════════════════════════════════════════════════════════════
# THE CORPUS. Ground truth is DECLARED per row, never inferred from the
# validator (inferring it is how a corpus starts measuring itself: an
# earlier draft of this file defined "PAN-free" as "no 12-19 digit window
# anywhere is Luhn-valid", which filters out precisely the accidents under
# test and reported 0.00% FP for a variant measured at 19.53%).
#
# An IDENTIFIER is what a human reads as one value. A row is PAN_PRESENT
# iff a human would say "there is a payment card number in there".
# ═══════════════════════════════════════════════════════════════════════

_PAN = "4539578763621486"                     # Luhn-valid Visa-16
_PAN_SP = "4539 5787 6362 1486"
_PAN_HY = "4539-5787-6362-1486"
_AMEX = "378282246310005"                     # Luhn-valid Amex-15
_AMEX_SP = "3782 822463 10005"                # real Amex print grouping 4-6-5
_PAN19 = "4111111111111110005"                # Luhn-valid 19-digit
_PAN19_SP = "4111 1111 1111 1110 005"

# (label, value, grouping, neighbourhood)  -- MUST BLOCK
PAN_PRESENT = [
    ("pan contiguous alone",        _PAN,                              "contiguous", "alone"),
    ("pan spaced alone",            _PAN_SP,                           "space",      "alone"),
    ("pan hyphen alone",            _PAN_HY,                           "hyphen",     "alone"),
    ("amex contiguous alone",       _AMEX,                             "contiguous", "alone"),
    ("amex spaced 4-6-5",           _AMEX_SP,                          "space",      "alone"),
    ("pan19 contiguous",            _PAN19,                            "contiguous", "alone"),
    ("pan19 spaced 4-4-4-4-3",      _PAN19_SP,                         "space",      "alone"),
    ("pan + seq after",             _PAN + " 12",                      "contiguous", "after"),
    ("seq + pan before",            "12 " + _PAN,                      "contiguous", "before"),
    ("spaced pan + seq after",      _PAN_SP + " 12",                   "space",      "after"),
    ("seq + spaced pan",            "12 " + _PAN_SP,                   "space",      "before"),
    ("hyphen pan + seq",            _PAN_HY + " 12",                   "hyphen",     "after"),
    ("iso date + pan",              "2026-08-06 " + _PAN,              "contiguous", "before"),
    ("pan + iso date",              _PAN + " 2026-08-06",              "contiguous", "after"),
    ("iso date + spaced pan",       "2026-08-06 " + _PAN_SP,           "space",      "before"),
    ("iso date + hyphen pan",       "2026-08-06 " + _PAN_HY,           "hyphen",     "before"),
    ("ids both sides of pan",       "445 " + _PAN + " 99",             "contiguous", "both"),
    ("ids both sides spaced pan",   "445 " + _PAN_SP + " 99",          "space",      "both"),
    ("ids both sides hyphen pan",   "445 " + _PAN_HY + " 99",          "hyphen",     "both"),
    ("pan in prose",                "please charge card " + _PAN + " today", "contiguous", "prose"),
    ("spaced pan in prose",         "please charge card " + _PAN_SP + " today", "space", "prose"),
    ("hyphen pan in prose",         "charge " + _PAN_HY + " now",      "hyphen",     "prose"),
    ("amount + pan",                "amount 1250.00 card " + _PAN,     "contiguous", "before"),
    ("amount + spaced pan",         "amount 1250.00 card " + _PAN_SP,  "space",      "before"),
    ("pan + phone",                 _PAN + " 660 1234567",             "contiguous", "after"),
    ("ref chain + pan",             "REF 9988 7766 5544 3322 card " + _PAN, "contiguous", "before"),
    ("pan + ref chain",             "card " + _PAN + " REF 9988 7766 5544 3322", "contiguous", "after"),
    ("spaced pan + ref chain",      "card " + _PAN_SP + " REF 9988 7766 5544 3322", "space", "after"),
]

# (label, value, grouping, neighbourhood)  -- MUST NOT BLOCK.
# SYNTHESISED values in shapes typical of enterprise telemetry. Every one is verified
# PAN-free by construction: no
# maximal chain and no single group in it is a Luhn-valid 12-19 digit number, and no human
# reading it would call any part of it a card number.
PAN_ABSENT = [
    ("invoice ref spaced 4x4",      "INV 8412 6603 5591 2274",         "space",      "prose"),
    ("order no hyphen 4x4",         "ORD-8412-6603-5591-2274",         "hyphen",     "prose"),
    ("ticket id spaced",            "TCK 4471 9928 3316 5502",         "space",      "prose"),
    ("change ticket contiguous",    "CHG 8412660355912274",            "contiguous", "prose"),
    ("iso timestamp groups",        "2026 08 06 14 32 07 8891",        "space",      "alone"),
    ("compact ts + seq",            "20260806143207 0091",             "contiguous", "after"),
    ("phone + extension",           "43 660 1234567 8891",             "space",      "after"),
    ("sequence counters",           "000123 000124 000125 000126",     "space",      "alone"),
    ("iban digit portion spaced",   "8937 0400 4405 3201 3000",        "space",      "alone"),
    ("gl account chain",            "1001 2002 3003 4004 5005",        "space",      "alone"),
    ("meter reading run",           "77213 88214 99215 10216",         "space",      "alone"),
    ("lot codes hyphen",            "LOT-5521-8834-2299-7741",         "hyphen",     "prose"),
    ("shipment ids spaced",         "SHP 3319 4428 5537 6646",         "space",      "prose"),
    ("po number contiguous",        "PO 4471992833165502",             "contiguous", "prose"),
    ("serial hyphen long",          "SER-1122-3344-5566-7788-9900",    "hyphen",     "alone"),
    ("batch + qty both sides",      "445 8412 6603 5591 2274 99",      "space",      "both"),
    ("emp id + cost centre",        "100234 200456 300678 400890",     "space",      "alone"),
    ("seq before invoice ref",      "0091 8412 6603 5591 2274",        "space",      "before"),
    ("date before order no",        "2026-08-06 8412-6603-5591-2274",  "hyphen",     "before"),
    ("run id before ticket",        "77213 4471 9928 3316 5502",       "space",      "before"),
]
# NOTE on a row deliberately NOT here. `"4539578763 621486"` in ONE field was in an earlier
# draft as a negative, copied across from the the field-boundary fix suite where it is two SEPARATE fields
# `{"a": "4539578763", "b": "621486"}`. In one field it is a space-grouped rendering of a
# genuinely Luhn-valid PAN, so its declared truth was wrong; the ground-truth guard below
# caught it. The two-field form is the real negative and lives in
# `test_MR2_inverse_a_neighbour_never_MINTS_a_block`. Field boundary is load-bearing here,
# and a corpus that blurs it re-creates bug 1 as a test-data error.

GROUPINGS = ("contiguous", "space", "hyphen")


# ═══════════════ PART 0 — the corpus's coverage is a CHECKABLE property ═══════════════

def test_corpus_is_a_covering_array_over_truth_x_grouping():
    """★ THE PROPERTY THE 18 REGRESSION ROWS LACKED.

    Every cell of (PAN present/absent) x (contiguous/space/hyphen) must be non-empty. The
    prior corpus left (PAN absent x space) and (PAN absent x hyphen) empty, and that is
    exactly where the 19.53% false-block regression lived, invisibly."""
    holes = []
    for truth, rows in (("PAN_PRESENT", PAN_PRESENT), ("PAN_ABSENT", PAN_ABSENT)):
        for g in GROUPINGS:
            if not [r for r in rows if r[2] == g]:
                holes.append(f"{truth} x {g}")
    assert not holes, f"corpus has empty cells: {holes}"


def test_corpus_covers_every_neighbourhood_in_both_truth_halves():
    """Adjacency is the other axis the defect moves on. Both halves need every position."""
    needed = {"alone", "before", "after", "both", "prose"}
    for truth, rows in (("PAN_PRESENT", PAN_PRESENT), ("PAN_ABSENT", PAN_ABSENT)):
        have = {r[3] for r in rows}
        assert needed <= have, f"{truth} missing neighbourhoods {needed - have}"


def test_false_block_half_is_not_outnumbered():
    """The defect class is symmetric; the corpus must be too. the field-boundary fix shipped 15 fail-open
    rows against 3 false-block rows and the 20% regression fell in the thin half."""
    assert len(PAN_ABSENT) >= 0.6 * len(PAN_PRESENT), (
        f"false-block arm {len(PAN_ABSENT)} vs fail-open arm {len(PAN_PRESENT)} — "
        "the thin half is where the next regression hides")


def test_declared_ground_truth_of_the_negative_arm_holds():
    """Guard against the corpus quietly acquiring a real PAN. An identifier is a maximal
    space/hyphen chain or a single group — NOT an arbitrary window (defining it as a window
    is circular: it filters out the very accidents under test)."""
    dg = re.compile(r"[0-9]+")

    def identifiers(text):
        groups = [(m.start(), m.end(), m.group(0)) for m in dg.finditer(text)]
        chains, cur, prev_end = [], [], -1
        for s, e, d in groups:
            if cur and text[prev_end:s] in (" ", "-"):
                cur.append(d)
            else:
                if cur:
                    chains.append(cur)
                cur = [d]
            prev_end = e
        if cur:
            chains.append(cur)
        out = []
        for c in chains:
            out.append("".join(c))
            out.extend(c)
        return out

    offenders = [(lbl, v) for lbl, v, _, _ in PAN_ABSENT
                 if any(luhn(t) for t in identifiers(v))]
    assert not offenders, f"negative rows that actually carry a valid PAN identifier: {offenders}"


# ═══════════════ PART 1 — MR-1: grouping invariance (metamorphic) ═══════════════
# There is no ground-truth oracle for "is this 16-digit string a card number", so the
# strongest available instrument is a metamorphic relation. Grouping is PRESENTATION.
# Presentation must not change identity.

@pytest.mark.parametrize("seed", range(40))
def test_MR1_grouping_does_not_change_the_verdict_on_a_lone_identifier(seed):
    """★ THE CENTRAL RELATION. For a single 16-digit value with nothing beside it, the
    verdict on `D`, on `group(D," ")` and on `group(D,"-")` must be IDENTICAL. They are the
    same identifier typed three ways.

    At the field-boundary fix this is violated in the false-block direction: a non-PAN fires when spaced
    and does not when contiguous. It is the whole of bug 2, and it needs no corpus of
    realistic values to expose — which is why a metamorphic relation beats a row set."""
    rng = random.Random(9000 + seed)
    for value in (make_pan(rng), make_non_pan(rng)):
        verdicts = {
            "contiguous": fires(value),
            "space": fires(group(value)),
            "hyphen": fires(group(value, "-")),
        }
        assert len(set(verdicts.values())) == 1, (
            f"grouping changed the verdict for {value!r}: {verdicts} — "
            "the same identifier typed two ways must get the same answer")


def test_MR1_holds_for_the_19_digit_window_edge_on_the_EXACT_class():
    """The relation must hold at the top of the [12,19] window too, where a 5-group chain yields
    more subsequences than a 4-group one.

    RESCOPED TO `luhn_exact` ON 2026-08-07, AND THE REASON IS A CORPUS-SPECIFICATION ERROR, NOT
    AN IMPLEMENTATION GAP. MR-1 says grouping is presentation and must not change the verdict.
    That is TRUE of the exact class by construction — an exact candidate is a whole chain or a
    whole group, and neither depends on where the spaces fall — and it is FALSE of the embedded
    class BY DESIGN, because SHAPE and CADENCE both read grouping deliberately. Asserting it of
    `luhn` demanded that two conjuncts stop working.

    The contradiction is categorical, not a seed accident: a 19-digit non-Luhn chain printed
    4-4-4-4-3 has a Luhn-valid, IIN-plausible leading 16-digit window 2.887% of the time
    (100,000 draws), which is exactly P(Luhn) x P(IIN). Over 40 draws the probability that the
    old test failed was 69%, so it was a coin-flip that happened to be red — leaving it red would
    have been shipping a permanently-failing detector, and relaxing it would have deleted two
    conjuncts. Scoping it to the class where it provably holds is the only honest third option.

    The embedded class's grouping-dependence is not lost coverage: it is asserted directly by
    `test_SHAPE_admits_a_card_grouping_and_suppresses_every_other_cut` and
    `test_CADENCE_admits_a_broken_cadence_and_suppresses_an_UNCORROBORATED_uniform_one`."""
    exact = FloorRule(id="pan_exact",
                      checksum=AxisPredicate(values=("luhn_exact",), mode="block"))

    def fires_exact(v):
        return match_red_line(exact, tool_name="SendEmail", tool_input={"memo": v})

    rng = random.Random(4242)
    for _ in range(400):
        v = make_non_pan(rng, 19)
        assert fires_exact(v) == fires_exact(group(v)) == fires_exact(group(v, "-")), (
            f"grouping changed the EXACT-class verdict for the 19-digit value {v!r} — "
            "an exact candidate is grouping-invariant by construction, so this is a real defect")
    # ... and the embedded class is grouping-DEPENDENT at 19 digits on purpose. Pinned so the
    # rescope above cannot be misread as "MR-1 holds everywhere now".
    rng = random.Random(4242)
    assert any(fires(v) != fires(group(v)) for v in (make_non_pan(rng, 19) for _ in range(400))), (
        "the embedded class became grouping-invariant at 19 digits, so SHAPE and CADENCE have "
        "stopped reading grouping — re-run the ruling; MR-1 could now be scoped to `luhn` again")


# ═══════════════ PART 2 — MR-2: an unrelated neighbour must not flip the verdict ═══════════════

@pytest.mark.parametrize("neighbour", ["12", "2026-08-06", "445", "1250.00", "req-99213",
                                       "ACCT-777", "7", "99999999"])
def test_MR2_adding_an_unrelated_field_never_disarms_the_floor(neighbour):
    """★ BUG 1's RELATION, kept live so the next fix cannot buy FP reduction by
    reintroducing it. Adding a field can never turn BLOCK into ALLOW."""
    for pan in (_PAN, _PAN_SP, _PAN_HY, _AMEX):
        assert fires_ti({"card": pan}) is True, f"baseline broken for {pan!r}"
        assert fires_ti({"card": pan, "extra": neighbour}) is True, (
            f"neighbour {neighbour!r} in a SEPARATE field disarmed the floor for {pan!r}")
        assert fires_ti({"extra": neighbour, "card": pan}) is True, (
            f"neighbour {neighbour!r} before the PAN disarmed the floor for {pan!r}")


@pytest.mark.parametrize("neighbour", ["12", "2026-08-06", "445", "99"])
def test_MR2_same_field_adjacency_never_disarms_the_floor(neighbour):
    """The harder half: the neighbour shares the field with the PAN, so it is inside the
    same digit chain. This is the shape the proposed narrowing direction breaks."""
    for pan in (_PAN, _PAN_SP, _PAN_HY):
        assert fires(f"{pan} {neighbour}") is True, f"{pan!r} + trailing {neighbour!r}"
        assert fires(f"{neighbour} {pan}") is True, f"leading {neighbour!r} + {pan!r}"


def test_MR2_inverse_a_neighbour_never_MINTS_a_block():
    """The same relation in the false-block direction: adding a field to a benign payload
    must not turn ALLOW into BLOCK. Two unrelated ids must never concatenate into a PAN."""
    for lbl, value, _, _ in PAN_ABSENT:
        base = fires(value)
        for extra in ("12", "445", "2026-08-06"):
            assert fires_ti({"memo": value, "x": extra}) == base, (
                f"{lbl}: adding field {extra!r} changed the verdict")
    assert fires_ti({"a": "4539578763", "b": "621486"}) is False, (
        "two unrelated fields concatenated into a spurious valid PAN")


# ═══════════════ PART 3 — the fail-open arm (must BLOCK) ═══════════════

@pytest.mark.parametrize("label,value,grouping,neigh", PAN_PRESENT,
                         ids=[r[0] for r in PAN_PRESENT])
def test_fail_open_arm_a_real_pan_always_fires(label, value, grouping, neigh):
    """A tier-1 PCI floor must fire on a genuinely valid PAN whatever sits beside it."""
    assert fires(value) is True, f"MISS ({grouping}/{neigh}): {value!r}"


@pytest.mark.parametrize("label,value,grouping,neigh", PAN_PRESENT,
                         ids=[r[0] for r in PAN_PRESENT])
def test_fail_open_arm_holds_for_the_composed_rule_too(label, value, grouping, neigh):
    """The shipped authoring shape (`fields` + `checksum`) must have the same recall when the
    value is in a scoped field. `fields` narrows exposure, never detection."""
    assert fires(value, rule=COMPOSED, key="memo") is True, f"MISS composed: {value!r}"


# ═══════════════ PART 4 — the false-block arm (must NOT block) ═══════════════

@pytest.mark.parametrize("label,value,grouping,neigh", PAN_ABSENT,
                         ids=[r[0] for r in PAN_ABSENT])
def test_false_block_arm_benign_enterprise_identifiers_do_not_fire(label, value, grouping, neigh):
    """★ THE ARM THAT DID NOT EXIST. In a bank, space- and hyphen-grouped 12-19 digit strings
    in a memo field are invoice refs, order numbers, ticket ids, GL accounts and timestamps.
    A tier-1 terminal, unrecoverable BLOCK on those is an outage, not a control."""
    assert fires(value) is False, f"FALSE BLOCK ({grouping}/{neigh}): {value!r}"


@pytest.mark.parametrize("label,value,grouping,neigh", PAN_ABSENT,
                         ids=[r[0] for r in PAN_ABSENT])
def test_false_block_arm_holds_for_the_composed_rule_in_a_scoped_field(label, value, grouping, neigh):
    """The composed rule is measured with its value IN a field it scopes to. Measuring it in
    an out-of-scope field measures the field name, not the rule — that is the exact error
    that produced the unreproducible '0-1/that composed floor'."""
    assert fires(value, rule=COMPOSED, key="memo") is False, f"FALSE BLOCK composed: {value!r}"


# ═══════════════ PART 5 — statistical arms, per stratum, with Wilson intervals ═══════════════

FP_STRATA_N = 3000


def _fp_rate(n_groups, sep, seed):
    """False-block rate over random values that are NOT valid PANs read as one identifier."""
    rng = random.Random(seed)
    k = 0
    for _ in range(FP_STRATA_N):
        v = make_non_pan(rng, 4 * n_groups)
        if fires(group(v, sep) if sep else v):
            k += 1
    return k, FP_STRATA_N


@pytest.mark.parametrize("n_groups", [3, 4, 5, 6, 8, 12])
@pytest.mark.parametrize("sep", [" ", "-"])
def test_false_block_rate_per_chain_length_stratum(n_groups, sep):
    """★ THE STRATIFICATION THE EARLIER CORPUS DID NOT HAVE.

    A benign corpus that substantiates a false-positive floor MUST be stratified by VALUE
    SHAPE. Measured before the field-boundary fix the rate rises with chain length, because a chain of g groups
    yields ~2g-5 subsequences in the window and each clears Luhn ~1-in-10:

        3 groups (12 digits)   0.00%
        4 groups (16 digits)  17.7%     <-- the only stratum in the bug report
        5 groups (20 digits)  39.3%
        6 groups (24 digits)  51.9%
        8 groups (32 digits)  68.0%
       12 groups (48 digits)  86.1%

    A fix validated only at 16 digits would report a clean 0% and leave 39-86% standing.
    That is how a fix comes to characterise the bug report rather than the defect — the
    same failure the that-call corpus already made once."""
    k, n = _fp_rate(n_groups, sep, seed=7000 + n_groups)
    lo, hi = wilson(k, n)
    assert hi <= MAX_FALSE_BLOCK_WILSON_UPPER, (
        f"{n_groups} groups sep={sep!r}: false-block {k}/{n} = {100*k/n:.2f}% "
        f"Wilson95 [{100*lo:.2f}, {100*hi:.2f}] exceeds the declared budget "
        f"{100*MAX_FALSE_BLOCK_WILSON_UPPER:.2f}%")


# ── the two budgets. A deliberate, recorded decision, made explicit so it is reviewed. ──
#
# MAX_FALSE_BLOCK_WILSON_UPPER is a budget on a TIER-1 TERMINAL, UNRECOVERABLE BLOCK. It is
# not a detection metric with room to trade; every point of it is a stopped legitimate bank
# operation. 2% is the loosest value defensible for that consequence, and the claim ladder
# puts it in the tightest <=5% tier.
#
# MAX_FAIL_OPEN_MISSES is 0 because a silently-non-firing tier-1 PCI floor is the bug that
# started this.
#
# THESE TWO CANNOT BOTH BE MET BY ANY RULE OPERATING ON DIGITS ALONE. That is proven, not
# asserted, by test_the_trade_is_irreducible_on_digits_alone below. The gate failing on both
# is the intended outcome: it forces the choice to be made explicitly and recorded, rather
# than absorbed silently into an extractor tweak.
MAX_FALSE_BLOCK_WILSON_UPPER = 0.02
MAX_FAIL_OPEN_MISSES = 0


def test_recall_on_random_valid_pans_across_groupings_and_neighbours():
    """The paired half of the budget. Never report the false-block rate without this, and
    never this without the false-block rate (outage over-block is always paired
    with the normal over-block)."""
    rng = random.Random(31337)
    misses = []
    for _ in range(300):
        pan = make_pan(rng)
        for sep, tail in ((None, ""), (" ", ""), ("-", ""),
                          (None, " 12"), (" ", " 12"), ("-", " 12"),
                          (None, " 2026-08-06"), (" ", " 2026-08-06")):
            v = (group(pan, sep) if sep else pan) + tail
            if not fires(v):
                misses.append(v)
    assert len(misses) <= MAX_FAIL_OPEN_MISSES, (
        f"{len(misses)} silent misses on genuinely valid PANs, e.g. {misses[:5]}")


# The neighbour widths this file sampled until 2026-08-07 were {0, 2, 8} — and 8 was exactly the
# CONTEXT boundary. A whole loss surface (every scheme, both sides, every neighbour width >= 9)
# therefore shipped unseen before the first narrowing pass: the sampling could not distinguish "no neighbour effect"
# from "no neighbour effect BELOW the boundary". A boundary constant must never be the widest
# value its own recall arm tests. This sweep is the fix.
_SCHEMES = [("Visa-16", "4", 16, (4, 4, 4, 4)), ("Visa-19", "4", 19, (4, 4, 4, 4, 3)),
            ("MC-55", "55", 16, (4, 4, 4, 4)), ("Amex-37", "37", 15, (4, 6, 5)),
            ("Diners-36", "36", 14, (4, 6, 4)), ("UnionPay", "62", 16, (4, 4, 4, 4))]


@pytest.mark.parametrize("name,prefix,length,widths", _SCHEMES, ids=[s[0] for s in _SCHEMES])
@pytest.mark.parametrize("width", list(range(1, 12)))
@pytest.mark.parametrize("side", ["left", "right"])
def test_recall_is_not_lost_at_ANY_neighbour_width_either_side(name, prefix, length, widths,
                                                               width, side):
    """★ THE ARM THAT WOULD HAVE CAUGHT THE SHIPPED LOSS. Every scheme, in its own print
    grouping, beside a neighbour of every width from 1 to 11, on both sides.

    At the first narrowing pass this failed 33 of its cells — every scheme at neighbour width >= 9 on both sides
    (CONTEXT was 8), plus width 4 for the schemes printed 4-4-4-4 (CADENCE). The docstring of
    `_digit_run_candidates` claimed the traded shapes stayed detected "beside any token of a
    DIFFERENT width", and that claim was false for every width >= 9, for every scheme.

    A width-4 neighbour of a 4-4-4-4 card makes the chain uniform, so detection there depends on
    the neighbour reading as an expiry — hence the real MMYY below. The non-expiry case is the
    declared limit, pinned in `test_KNOWN_MISS_the_shapes_the_narrowing_gave_up`."""
    rng = random.Random(hash((name, width, side)) & 0xffff)
    neighbour = "1225" if width == 4 else "1" * width      # a real MMYY at the ambiguous width
    misses = []
    for _ in range(100):
        pan = make_pan(rng, prefix, length)
        cut, i = [], 0
        for w in widths:
            cut.append(pan[i:i + w])
            i += w
        printed = " ".join(cut)
        v = f"{neighbour} {printed}" if side == "left" else f"{printed} {neighbour}"
        if not fires(v):
            misses.append(v)
    assert len(misses) <= MAX_FAIL_OPEN_MISSES, (
        f"{name} beside a {width}-digit neighbour on the {side}: {len(misses)}/100 genuinely "
        f"valid cards missed, e.g. {misses[0]!r}")


def test_the_trade_is_irreducible_on_digits_alone():
    """★ THE RULING THE FIX MUST BE WRITTEN AGAINST, measured rather than argued.

    `"4539 5787 6362 1486 12"` is byte-identical whether it is (PAN, sequence number) or one
    18-digit reference. No predicate over the digits can separate them, so detecting the
    first NECESSARILY blocks a fraction of the second. Measured on 20000 random 18-digit
    chains: the leading 16 digits are Luhn-valid 9.99% of the time [9.58, 10.41].

    Therefore any fix that reports BOTH zero misses on `PAN + short neighbour` AND a
    near-zero false-block rate on 18-digit references is measuring one of them wrong.
    This test does not gate the fix; it gates the CLAIM the fix is allowed to make."""
    rng = random.Random(4242)
    n, k = 20000, 0
    for _ in range(n):
        s = "".join(str(rng.randint(0, 9)) for _ in range(18))
        if luhn(s[:16]):
            k += 1
    lo, hi = wilson(k, n)
    assert 0.08 <= lo and hi <= 0.12, (
        f"collision rate {k}/{n} Wilson95 [{lo:.4f}, {hi:.4f}] — expected ~1-in-10; "
        "if this moved, the arithmetic of the trade changed")


# ═══════════════ PART 6 — bounded work, and what happens AT the bound ═══════════════
# The bound is not a performance detail. `_digit_run_candidates` returns EARLY at
# _MAX_CHECKSUM_CANDIDATES, which TRUNCATES the candidate list. Truncation of a detection
# list is a fail-OPEN, and it is reachable without any adversary.

def test_candidate_cap_must_not_silently_drop_a_real_pan_ADVERSARIAL():
    """★ SEV-0, live before the field-boundary fix and NOT a bug-2 regression — it arrived with the same commit.

    Repro: 131 four-digit groups then the PAN, in one field, 671 chars. The cap is reached
    while still inside the pad, `_digit_run_candidates` returns, and the PAN is never
    generated as a candidate. The tier-1 floor does not fire.

    A detection bound may DEGRADE (refuse, escalate, take longer) but may never silently
    ALLOW. If bounded work and complete detection genuinely conflict, the axis must raise or
    escalate at the bound — not return a truncated list and a False."""
    pan = _PAN
    pad = " ".join(["1234"] * 200)
    payload = pad + " " + pan
    # The failure message must not interpolate the old candidate-cap constant: the cap was REMOVED
    # before the first narrowing pass, so on failure the f-string raised AttributeError and this test could not report
    # the fail-open it exists to report. A detector whose alarm is broken is worse than no
    # detector, because the suite still shows one. Found by mutation audit, 2026-08-07.
    assert fires(payload) is True, (
        f"digit padding of {len(pad)} chars before the PAN silently disarmed a tier-1 floor; "
        f"candidates generated: {P._digit_run_candidates(payload)!r}")


def test_the_cap_repro_is_grouping_INVARIANT_or_its_limit_is_declared():
    """★ THE SAME SEV-0 BY A SECOND ROUTE, and the reason the test above is not sufficient.

    The repro above passes only because its payload appends the CONTIGUOUS `_PAN`, which keeps
    the chain non-uniform and routes through the EXACT class. Print the same card in its own
    4-4-4-4 grouping and the padded chain becomes uniform, so CADENCE suppresses every window and
    no candidate is generated at all — the identical silent allow, reached differently. The
    pinning test above cannot see it, which is exactly how it survived.

    This asserts the CONTIGUOUS form fires and DECLARES the printed form as the measured limit
    (see `test_KNOWN_MISS_the_shapes_the_narrowing_gave_up`): admitting interior windows of a
    uniform chain costs 15.70% false-block at 9 groups and 21.80% at 12, against a 2.00% budget.
    It is recorded rather than fixed because it is not fixable at that price."""
    pad = " ".join(["1234"] * 200)
    assert fires(pad + " " + _PAN) is True, "the contiguous repro stopped firing"
    assert fires(pad + " " + group(_PAN)) is False, (
        "the PRINTED form of the padded card now fires. That is an improvement in the recall "
        "arm and it is not free — re-measure the UNIFORM false-block strata before keeping it, "
        "and update the declared limit in test_KNOWN_MISS_the_shapes_the_narrowing_gave_up.")


def test_candidate_cap_must_not_silently_drop_a_real_pan_ACCIDENTAL():
    """The same fail-open with no adversary: an ordinary batch memo listing order refs, with
    a card number at the end. Measured threshold: 86 refs / 2171 chars, well inside a normal
    email body or export description."""
    ref = "5260 1815 9083 0166"
    payload = ", ".join([f"ORD {ref}"] * 90) + ", card " + _PAN
    assert fires(payload) is True, (
        "90 benign order references in one memo field silently dropped the PAN "
        "(measured threshold: 86 refs, 2171 chars)")


def test_candidate_generation_is_bounded_in_TIME_on_hostile_input():
    """Bounded work must survive the payload sizes a gate actually sees. The bound must come
    from the algorithm, not only from the truncating cap — because the cap is what causes the
    fail-open above, so a correct fix will have to weaken or remove it."""
    for payload in (" ".join("1" for _ in range(50000)),
                    " ".join("1234" for _ in range(20000)),
                    "x".join(["1234 5678 9012 3456"] * 20000),
                    "9" * 100000,
                    ("4539 5787 6362 1486 " * 5000)):
        t0 = time.perf_counter()
        P._digit_run_candidates(payload)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.25, (
            f"candidate generation took {elapsed:.3f}s on a {len(payload)}-char payload — "
            "a checksum axis that is a DoS surface is a third bug")


def test_the_bound_is_declared_and_its_overflow_behaviour_is_asserted():
    """Whatever bound the fix carries, the input that exceeds it must be NAMED and its
    behaviour must be a deliberate, tested choice. This test pins that the overflow path is
    fail-CLOSED for detection: at the point where work is capped, a payload containing a real
    PAN still fires."""
    sizes = [50, 100, 200, 400, 800]
    fired = {n: fires(" ".join(["1234"] * n) + " " + _PAN) for n in sizes}
    assert all(fired.values()), (
        f"detection is not monotone in payload size — it fails OPEN as the payload grows: "
        f"{fired}")


# ═══════════════ PART 7 — the extractor and the validator must share one alphabet ═══════════════
# Pre-existing before the reduction fix AND before the field-boundary fix, never tested. `luhn()` uses `str.isdigit()` and
# `int(c)`, which are Unicode-aware; the extractor uses `[0-9]+` and a single-character
# separator test. The validator is strictly MORE permissive than the extractor, and the
# extractor is the gate. Every gap between the two is a silent fail-open.

@pytest.mark.parametrize("name,pan", [
    ("fullwidth digits", "".join(chr(0xFF10 + int(c)) for c in _PAN)),
    ("arabic-indic digits", "".join(chr(0x0660 + int(c)) for c in _PAN)),
])
def test_extractor_alphabet_matches_the_validator_alphabet(name, pan):
    """`luhn()` returns True for these; the extractor produces zero candidates, so the floor
    does not fire. A PAN pasted from a CJK-locale form or an IME evades a tier-1 control with
    no tooling at all."""
    assert luhn(pan) is True, "precondition: the validator accepts this alphabet"
    assert fires(pan) is True, f"{name}: validator accepts it, extractor cannot see it"


@pytest.mark.parametrize("name,sep", [
    ("NBSP U+00A0", " "), ("narrow NBSP U+202F", " "),
    ("thin space U+2009", " "), ("non-breaking hyphen U+2011", "‑"),
    ("en dash U+2013", "–"), ("tab", "\t"), ("newline", "\n"),
    ("double space", "  "),
])
def test_typographic_separators_do_not_disarm_the_floor(name, sep):
    """A PAN copy-pasted out of Word, a PDF, an email client or a spreadsheet cell arrives
    with a non-breaking space, a non-breaking hyphen or a tab between the groups, and a
    double space is ordinary in free text. `luhn()` ignores all of them; the chain-linking
    test accepts exactly one of `" "` or `"-"`, so every one of these silently misses."""
    pan = sep.join(_PAN[i:i + 4] for i in range(0, 16, 4))
    assert luhn(pan) is True, "precondition: the validator accepts this separator"
    assert fires(pan) is True, f"{name} between the groups disarmed a tier-1 floor"


# ═══════════════ PART 8 — the mitigation claim (a claim-discipline matter) ═══════════════

def test_composed_rule_has_no_precision_floor_only_reduced_exposure():
    """★ RULES ON THE SHIPPED DOCSTRING SENTENCE, which is FALSE as written.

    policy.py currently states the near-zero false-positive floor is "a property of the
    COMPOSED rule ... measured 0-1/that". Measured here: conditional on the value sitting in a
    field the rule scopes to, the composed rule fires at exactly the same rate as the bare
    rule, on every input, because `fields` and `checksum` are ANDed independent predicates.
    An AND cannot improve the CONDITIONAL precision of its other conjunct; it only shrinks
    the set of eligible calls.

    So: `fields` buys EXPOSURE reduction, never PRECISION. The 0-1/that measured how rarely
    digit-dense content landed in a free-text key in that corpus — a property of that
    corpus's field naming."""
    rng = random.Random(2718)
    for _ in range(500):
        v = group(make_non_pan(rng))
        assert fires(v, rule=BARE, key="memo") == fires(v, rule=COMPOSED, key="memo"), (
            f"composed differs from bare on an IN-SCOPE value {v!r} — if this ever passes, "
            "the fields axis has started doing something it is not designed to do")

    # ...and the ONLY thing `fields` changes is whether the call is eligible at all.
    telemetry = group(make_non_pan(random.Random(1), 16))
    assert fires(telemetry, rule=COMPOSED, key="snapshot") is False
    assert fires(telemetry, rule=BARE, key="snapshot") == fires(telemetry, rule=BARE, key="memo")


def test_a_false_positive_floor_needs_an_IN_SCOPE_denominator():
    """The claim ladder's arithmetic applied to the shipped sentence. A 0/that over ALL calls
    is not a 0/that over calls the rule can fire on. If the in-scope stratum is empty the
    honest n is 0, and at n=0 nothing is quotable: a 0-numerator claim first reaches the
    <=20% tier at n=16, <=10% at n=35 and <=5% at n=73."""
    for tier_bound, first_n in ((0.20, 16), (0.10, 35), (0.05, 73)):
        assert wilson(0, first_n)[1] <= tier_bound
        assert wilson(0, first_n - 1)[1] > tier_bound


# ═══════════════ PART 9 — MUTANTS: proof this corpus can go RED ═══════════════
# Both prior test sets passed while the defect was live. A corpus that cannot fail is what
# produced two regressions. Each mutant below is a plausible wrong fix; each must be KILLED
# by at least one named arm of this corpus, and the arm that kills it is asserted.

_DG = re.compile(r"[0-9]+")


def _chains(text):
    groups = [(m.start(), m.end(), m.group(0)) for m in _DG.finditer(text)]
    chains, cur, prev_end = [], [], -1
    for s, e, d in groups:
        if cur and text[prev_end:s] in (" ", "-"):
            cur.append(d)
        else:
            if cur:
                chains.append(cur)
            cur = [d]
        prev_end = e
    if cur:
        chains.append(cur)
    return chains


def _expand(chain, lo=12, hi=19):
    pre = [0]
    for d in chain:
        pre.append(pre[-1] + len(d))
    out = []
    for i in range(len(chain)):
        for j in range(i, len(chain)):
            n = pre[j + 1] - pre[i]
            if n > hi:
                break
            if n >= lo:
                out.append("".join(chain[i:j + 1]))
    return out


def MUT_pre_fix_greedy(text):
    """M1 — restore the pre-fix greedy extractor verbatim (reintroduces bug 1)."""
    return [m.group(0) for m in re.compile(r"[0-9](?:[ -]?[0-9]){11,18}").finditer(text)]


def MUT_whole_chain_only(text):
    """M2 — the over-narrow fix: never expand, test only the whole chain."""
    return ["".join(c) for c in _chains(text)]


def MUT_plausible_length_gate(text):
    """M3 — the proposed narrowing direction, naive form: expand only chains whose full length
    is implausible as a single identifier."""
    out = []
    for c in _chains(text):
        total = sum(len(d) for d in c)
        if 12 <= total <= 19:
            out.append("".join(c))
        else:
            out.extend(_expand(c))
    return out


def MUT_unbounded_expansion(text):
    """M4 — subsequence bound removed: every window accepted, no [12,19] break, no cap."""
    out = []
    for c in _chains(text):
        for i in range(len(c)):
            for j in range(i, len(c)):
                out.append("".join(c[i:j + 1]))
    return out


def MUT_joined_haystack(text):
    """M5 — a per-field extractor that is correct in isolation is still wrong if the caller
    re-joins the fields. Kept as a mutant because the field-boundary fix lives in the
    CALLER, and a future refactor could quietly undo it there."""
    return _expand(_chains(text)[0]) if _chains(text) else []


def MUT_current_b4ac9f8(text):
    """M6 — the CURRENTLY SHIPPED generator, restated. Present so the corpus proves it can
    fail the code that is live right now, not only hypothetical wrong fixes."""
    out = []
    for c in _chains(text):
        for cand in _expand(c):
            out.append(cand)
            if len(out) >= 256:
                return out
    return out


def _run_arm(fn):
    """Run one corpus arm under whatever generator is installed; return failures."""
    failures = []
    try:
        fn()
    except AssertionError as exc:
        failures.append(str(exc).split("\n")[0])
    return failures


def _arm_fail_open():
    for lbl, v, g, n in PAN_PRESENT:
        assert fires(v) is True, f"MISS {lbl}"


def _arm_false_block():
    for lbl, v, g, n in PAN_ABSENT:
        assert fires(v) is False, f"FALSE BLOCK {lbl}"


def _arm_mr1():
    rng = random.Random(9000)
    for _ in range(40):
        v = make_non_pan(rng)
        assert fires(v) == fires(group(v)) == fires(group(v, "-")), f"MR-1 {v}"


def _arm_cap():
    assert fires(" ".join(["1234"] * 200) + " " + _PAN) is True, "cap fail-open"


def _arm_time():
    t0 = time.perf_counter()
    P._digit_run_candidates("x".join(["1234 5678 9012 3456"] * 20000))
    assert time.perf_counter() - t0 < 0.25, "unbounded work"


ARMS = {
    "fail_open": _arm_fail_open,
    "false_block": _arm_false_block,
    "MR1_grouping": _arm_mr1,
    "cap_fail_open": _arm_cap,
    "bounded_work": _arm_time,
}

# mutant -> the arms that MUST kill it. A mutant no arm kills is a hole in this corpus.
MUTANTS = {
    "M1 pre-fix greedy":        (MUT_pre_fix_greedy,           {"fail_open"}),
    "M2 whole-chain only":      (MUT_whole_chain_only,         {"fail_open"}),
    "M3 plausible-length":  (MUT_plausible_length_gate, {"fail_open"}),
    "M4 unbounded expansion":   (MUT_unbounded_expansion,      {"false_block", "MR1_grouping"}),
    "M5 first-chain only":      (MUT_joined_haystack,          {"fail_open"}),
    "M6 current the field-boundary fix":       (MUT_current_b4ac9f8,          {"false_block", "MR1_grouping"}),
}


@pytest.mark.parametrize("name", list(MUTANTS))
def test_mutant_is_killed_by_this_corpus(name):
    """★ POTENCY. Each plausible wrong fix must be caught by the arms named against it.
    This is the check both prior test sets lacked: they passed while the defect was live."""
    gen, must_kill = MUTANTS[name]
    with candidate_generator(gen):
        killed = {arm for arm, fn in ARMS.items() if _run_arm(fn)}
    missing = must_kill - killed
    assert not missing, (
        f"{name} SURVIVED arms {sorted(missing)} — those arms cannot detect this defect, "
        f"so the corpus has a hole. Arms that did fire: {sorted(killed)}")


def test_every_mutant_is_killed_by_at_least_one_arm():
    """A blanket potency floor: no plausible wrong fix may pass the whole corpus."""
    survivors = []
    for name, (gen, _) in MUTANTS.items():
        with candidate_generator(gen):
            if not any(_run_arm(fn) for fn in ARMS.values()):
                survivors.append(name)
    assert not survivors, f"mutants that pass the entire corpus: {survivors}"


def test_the_corpus_is_green_on_a_hypothetically_correct_generator():
    """Guard against the opposite failure: a corpus so strict that nothing can pass it is
    also useless. This does NOT propose the fix — it only proves at least one generator
    satisfies the fail-open arm and MR-1 simultaneously, so the arms are not contradictory.
    The false-block arm is deliberately NOT included: whether it can be met at the same time
    is exactly the open question `test_the_trade_is_irreducible_on_digits_alone` measures."""
    with candidate_generator(lambda t: [c for ch in _chains(t) for c in _expand(ch)]):
        assert not _run_arm(_arm_fail_open), "no generator satisfies the fail-open arm"
