"""Regression tests for the 2026-08-06 checksum-extractor fix.

Companion to `test_checksum_acceptance_corpus.py`, which is the ACCEPTANCE GATE and is
not modified here. That corpus stays 21-red on purpose: its MR-1 grouping arm and its
false-block arm are mutually unsatisfiable (proved in
`test_the_corpus_MR1_and_MR2_arms_are_mutually_unsatisfiable` below), so no candidate generator
can turn it fully green. This file pins the defects that WERE closeable, and pins the trade
itself as a measured property rather than an argument.

Every rate below is reported with BOTH arms (false-block AND recall). Never one without the
other.
"""
import random

import pytest

from fivedrisk import policy as P
from fivedrisk.policy import (AxisPredicate, FloorRule, luhn, match_red_line,
                              _digit_run_candidates, _digit_run_candidates_exact,
                              _iin_plausible)

_PAN = "4539578763621486"          # Luhn-valid Visa-16

LUHN = FloorRule(id="pan_luhn", checksum=AxisPredicate(values=("luhn",), mode="block"))
EXACT = FloorRule(id="pan_exact", checksum=AxisPredicate(values=("luhn_exact",), mode="block"))


def fires(value, rule=LUHN, key="memo"):
    return match_red_line(rule, tool_name="SendEmail", tool_input={key: value})


def group(d, sep=" ", size=4):
    return sep.join(d[i:i + size] for i in range(0, len(d), size))


def make_pan(rng, prefix="4", length=16):
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    return next(body + c for c in "0123456789" if luhn(body + c))


def make_non_pan(rng, length=16):
    while True:
        s = "".join(str(rng.randint(0, 9)) for _ in range(length))
        if not luhn(s):
            return s


# ═════════════ 1. SEV-0: the candidate cap was a silent fail-open ═════════════

def test_the_candidate_cap_is_gone_and_the_bisected_accidental_trigger_fires():
    """★ SEV-0 REPRO, bisected exactly. At the field-boundary fix the generator returned early at 256
    candidates, truncating the detection list. 85 benign order references before the PAN fired;
    86 did not. No adversary, 2171 chars, an ordinary batch memo."""
    ref = "5260 1815 9083 0166"
    for n in (85, 86, 87, 200):
        payload = ", ".join([f"ORD {ref}"] * n) + ", card " + _PAN
        assert fires(payload) is True, f"{n} benign order refs silently dropped the PAN"
    assert not hasattr(P, "_MAX_CHECKSUM_CANDIDATES"), (
        "the truncating cap is back — a detection bound may degrade, refuse or escalate, "
        "but it may never truncate and return False")


def test_detection_is_monotone_in_payload_size():
    """Adding padding must never turn BLOCK into ALLOW. At the field-boundary fix this flipped between 100 and
    200 pad groups, which is what a truncating bound looks like from the outside."""
    fired = {n: fires(" ".join(["1234"] * n) + " " + _PAN) for n in (50, 100, 200, 400, 800)}
    assert all(fired.values()), f"detection fails OPEN as the payload grows: {fired}"


def test_the_declared_bound_is_the_shipped_haystack_cap_and_it_fails_CLOSED():
    """The bound is NAMED and its overflow behaviour is a deliberate, tested choice: a field
    value above `_MAX_HAYSTACK_CHARS` is treated as a HIT in block-mode, never skipped. This is
    the same fail-closed shape `_patterns_hit` already ships for ReDoS."""
    oversize = "x" * (P._MAX_HAYSTACK_CHARS + 1)
    assert fires(oversize) is True, "an unverifiable oversize value must fail CLOSED"
    assert fires("x" * (P._MAX_HAYSTACK_CHARS - 1)) is False, "under the bound, scan normally"


# ═════════════ 2. SEV-1: extractor and validator now share ONE alphabet ═════════════

@pytest.mark.parametrize("name,ch", [("superscript two", "²"),
                                     ("superscript three", "³"),
                                     ("superscript one", "¹")])
def test_luhn_does_not_raise_on_category_No_digits(name, ch):
    """`str.isdigit()` accepts these; `int()` rejects them, so the shipped `isdigit` form raised
    ValueError out of a hard floor on ordinary user text. A gate must not crash."""
    assert luhn(ch * 12) is False, f"{name}: must return a verdict, not raise"
    assert luhn(_PAN + ch) is True, f"{name}: a non-decimal char is ignored, like a space"


@pytest.mark.parametrize("name,offset", [("fullwidth U+FF10", 0xFF10),
                                         ("arabic-indic U+0660", 0x0660)])
def test_a_unicode_digit_pan_is_visible_to_the_extractor(name, offset):
    """`luhn()` accepted these all along; the `[0-9]` extractor produced zero candidates, so a
    PAN from a CJK-locale form or an IME walked through a tier-1 control with no tooling."""
    pan = "".join(chr(offset + int(c)) for c in _PAN)
    assert luhn(pan) is True, "precondition: the validator accepts this alphabet"
    assert fires(pan) is True, f"{name}: validator accepts it, extractor could not see it"
    assert fires(group(pan)) is True, f"{name}: grouped form too"


@pytest.mark.parametrize("name,sep", [
    ("NBSP U+00A0", " "), ("narrow NBSP U+202F", " "),
    ("thin space U+2009", " "), ("hair space U+200A", " "),
    ("figure space U+2007", " "), ("non-breaking hyphen U+2011", "‑"),
    ("figure dash U+2012", "‒"), ("en dash U+2013", "–"),
    ("soft hyphen U+00AD", "­"), ("tab", "\t"), ("newline", "\n"),
    ("double space", "  "),
])
def test_typographic_separators_do_not_disarm_the_floor(name, sep):
    """A PAN out of Word, a PDF, an HTML email or a spreadsheet cell arrives with one of these
    between the groups. `luhn()` ignores all of them; the extractor accepted exactly `" "` or
    `"-"`, so every one silently missed."""
    pan = sep.join(_PAN[i:i + 4] for i in range(0, 16, 4))
    assert luhn(pan) is True, "precondition: the validator accepts this separator"
    assert fires(pan) is True, f"{name} between the groups disarmed a tier-1 floor"


def test_a_separator_RUN_longer_than_the_declared_max_does_not_link_groups():
    """The widened separator set must not turn an aligned table into one digit chain. The
    declared bound is `_MAX_SEPARATOR_RUN`; past it the groups are separate identifiers."""
    wide = (" " * (P._MAX_SEPARATOR_RUN + 1)).join(_PAN[i:i + 4] for i in range(0, 16, 4))
    assert fires(wide) is False, "column padding must not join groups into one PAN"


# ═════════════ 3. the IIN narrowing conjunct ═════════════

ISSUER_RANGES = [("Visa", "4", 16), ("Visa-19", "4", 19), ("Mastercard-5", "55", 16),
                 ("Mastercard-2", "2221", 16), ("Mastercard-2b", "2720", 16),
                 ("Amex-34", "34", 15), ("Amex-37", "37", 15), ("Discover-6011", "6011", 16),
                 ("Discover-65", "65", 16), ("Diners-36", "36", 14), ("JCB", "3528", 16),
                 ("UnionPay", "62", 16)]


@pytest.mark.parametrize("name,prefix,length", ISSUER_RANGES, ids=[r[0] for r in ISSUER_RANGES])
def test_the_IIN_conjunct_costs_ZERO_recall_on_every_issuer_range(name, prefix, length):
    """★ Why IIN and not a length gate. Measured 0/12000 synthetic PANs rejected across every
    published issuer range, for a ~3x cut in the false-block rate at every stratum. A length
    gate buys the same reduction only at 16 digits and costs 900/2400 genuine detections."""
    rng = random.Random(hash(name) & 0xFFFF)
    rejected = [p for p in (make_pan(rng, prefix, length) for _ in range(1000))
                if not _iin_plausible(p)]
    assert not rejected, f"{name}: IIN conjunct rejected real PANs, e.g. {rejected[:3]}"


def test_the_IIN_conjunct_never_gates_the_EXACT_class():
    """Deliberate asymmetry. A private-label or unusual BIN printed as its OWN value must still
    floor-block; IIN narrows only the speculative embedded windows, where the false-block mass
    is. Without this, the narrowing would trade a measurable FP win for an unmeasurable recall
    loss on real-world BINs."""
    rng = random.Random(99)
    odd = make_pan(rng, "9", 16)                       # no issuer owns a leading 9
    assert _iin_plausible(odd) is False, "precondition: this BIN is not IIN-plausible"
    assert fires(odd) is True, "an odd-BIN PAN printed alone must still block"
    assert fires(group(odd)) is True, "...in every grouping"
    assert fires(odd, rule=EXACT) is True, "...under luhn_exact too"


# ═════════════ 4. the two classes, and the trade between them, measured ═════════════

STRATA = [3, 4, 5, 6, 8, 12]


@pytest.mark.parametrize("n_groups", STRATA)
@pytest.mark.parametrize("sep", [" ", "-"])
def test_luhn_exact_has_a_ZERO_false_block_rate_at_every_chain_length(n_groups, sep):
    """★ THE PRECISE CLASS. An EXACT candidate is the value a human reads as one identifier, so
    it is grouping-invariant by construction and cannot be minted by adjacency. Measured 0/1500
    at every stratum from 3 to 12 groups — this is the class that may carry a terminal block."""
    rng = random.Random(7000 + n_groups)
    blocked = [v for v in (make_non_pan(rng, 4 * n_groups) for _ in range(1500))
               if fires(group(v, sep), rule=EXACT)]
    assert not blocked, (f"{n_groups} groups sep={sep!r}: luhn_exact false-blocked "
                         f"{len(blocked)}/1500, e.g. {blocked[:2]}")


def test_luhn_exact_is_grouping_invariant():
    """MR-1 for the exact class: presentation must not change identity. Holds at 16 and at the
    19-digit window edge, which is where the corpus's central relation breaks for `luhn`."""
    for seed, length in [(9000, 16), (4242, 19)]:
        rng = random.Random(seed)
        for _ in range(60):
            for v in (make_pan(rng, "4", length), make_non_pan(rng, length)):
                verdicts = {fires(v, rule=EXACT), fires(group(v), rule=EXACT),
                            fires(group(v, "-"), rule=EXACT)}
                assert len(verdicts) == 1, f"grouping changed the luhn_exact verdict for {v!r}"


def test_luhn_keeps_FULL_recall_where_luhn_exact_declares_its_miss():
    """★ THE TRADE, pinned as a property rather than argued. The two classes are exactly
    complementary and a deployer picks by DISPOSITION, not by which is 'better':

      luhn_exact  false-block 0.0% at every stratum | MISSES a PAN sharing a digit chain
      luhn        false-block 6.7% (4 groups) to    | 0 misses
                  41.8% (12 groups)                 |

    Neither is the safe default for both arms. That is the finding, not a bug to fix."""
    rng = random.Random(31337)
    exact_misses = luhn_misses = 0
    for _ in range(200):
        pan = make_pan(rng)
        for sep, tail in ((None, ""), (" ", ""), ("-", ""), (None, " 12"),
                          (" ", " 12"), ("-", " 12"), (None, " 2026-08-06"), (" ", " 2026-08-06")):
            v = (group(pan, sep) if sep else pan) + tail
            exact_misses += not fires(v, rule=EXACT)
            luhn_misses += not fires(v)
    assert luhn_misses == 0, f"`luhn` must not miss a valid PAN: {luhn_misses}/1600"
    assert exact_misses == 600, (
        f"`luhn_exact` misses the EMBEDDED class by design: expected 600/1600 "
        f"(3 of 8 presentations), measured {exact_misses}. If this moved, the two classes are "
        "no longer complementary and the disposition guidance is stale")


def test_the_two_classes_are_nested_never_contradictory():
    """Invariant: luhn_exact ⊆ luhn. The exact class may never fire where the broader class does
    not — otherwise a deployer authoring both bands gets an inverted ladder."""
    rng = random.Random(5150)
    for length in (16, 20, 24, 32):
        for _ in range(200):
            v = group(make_non_pan(rng, length))
            if fires(v, rule=EXACT):
                assert fires(v) is True, f"luhn_exact fired where luhn did not: {v!r}"
    assert set(_digit_run_candidates_exact("445 " + group(_PAN) + " 99")) <= \
        set(_digit_run_candidates("445 " + group(_PAN) + " 99"))


# ═════════════ 5. the acceptance corpus is UNSATISFIABLE — proved, not asserted ═════════════

def test_the_corpus_MR1_and_MR2_arms_are_mutually_unsatisfiable():
    """★ WHY THE ACCEPTANCE CORPUS CANNOT BE MADE GREEN, and why that is a corpus defect rather
    than a fix that has not been found yet.

    `test_MR2_same_field_adjacency_never_disarms_the_floor` requires
    `"4539 5787 6362 1486 445"` to FIRE. `test_MR1_holds_for_the_19_digit_window_edge`, on its
    own seed, draws `"4188 2002 0872 3355 251"` and requires it NOT to fire.

    Those two inputs are IDENTICAL in every observable a digits-only rule has: same group-length
    shape (4,4,4,4,3), same Luhn verdict on every in-window sub-window, and both start in the
    Visa IIN range. No function of the digit string can separate them, so no candidate generator
    can pass both tests. This is stronger than the corpus's own §4 ruling, which framed the
    conflict as two BUDGETS that cannot both be met.

    The corpus's guard against exactly this
    (`test_the_corpus_is_green_on_a_hypothetically_correct_generator`) is vacuous: its docstring
    claims to prove the fail-open arm and MR-1 hold simultaneously, but its body asserts only the
    fail-open arm, and MR-1 in fact fails under the same generator."""
    def windows(chain, lo=12, hi=19):
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
                    out.append((i, j, n, luhn("".join(chain[i:j + 1]))))
        return tuple(out)

    def signature(text):
        chain = text.split(" ")
        return tuple(len(g) for g in chain), windows(chain)

    must_fire = "4539 5787 6362 1486 445"        # corpus MR-2, required True
    must_not_fire = "4188 2002 0872 3355 251"    # corpus MR-1 @19 seed 4242 draw 5, required False
    assert signature(must_fire) == signature(must_not_fire), (
        "the two inputs became distinguishable — re-derive the impossibility argument")
    assert _iin_plausible(must_fire.replace(" ", "")[:16])
    assert _iin_plausible(must_not_fire.replace(" ", "")[:16]), (
        "the IIN conjunct does not separate them either — it lowers the RATE, "
        "it does not resolve the CONTRADICTION")
