r"""The three structural narrowing conjuncts on the `checksum: luhn` embedded class, and the
residual that survives all of them.

Companion to `test_checksum_acceptance_corpus.py` (the gate) and
`test_checksum_exact_class.py` (the two-class trade). This file exists for the four things
NEITHER of those can do, and it deliberately duplicates nothing they already assert.

  1. THE CORPUS GENERATOR ONLY EMITS UNIFORM CHAINS. `_fp_rate` renders every stratum as
     `group(v, sep)` — fixed 4-digit groups, all the way down. The CADENCE conjunct suppresses
     exactly that shape, so a fix could take all twelve stratum tests to 0.00% while changing
     nothing about a chain whose groups are not all the same width. Measuring only there would
     characterise the generator, which is the failure the field-boundary fix already made once. Part 2 re-runs
     the same arms on NON-uniform chains.

  2. A CONJUNCT THAT CHANGES NOTHING IS A CONJUNCT THAT SHOULD BE DELETED, and a test that
     passes for a reason unrelated to the code under test is not a test. Part 3 ABLATES each
     conjunct in turn -- against the real shipped function, never a re-implementation of it --
     and asserts a named measured failure reopens. If a conjunct is ever quietly removed, the
     ablation for it starts passing with the conjunct still gone, so part 3 also asserts the
     ablated rate differs from the shipped rate.

  3. THE RESIDUAL IS ABOVE BUDGET AND NO NARROWING REMOVES IT. Part 4 measures it and asserts
     it is over 2.00%, so no future reading of this suite can produce the claim "the false-block
     budget is met" for the embedded class. It is not met and it is not reachable.

  4. TWO RECALL SHAPES WERE TRADED AWAY ON PURPOSE. Part 5 pins them. They are fail-opens, they
     were chosen, and a silent fail-open that nobody wrote down is how this defect started.
"""
import math
import random

import pytest

from fivedrisk import policy as P
from fivedrisk.policy import AxisPredicate, FloorRule, luhn, match_red_line

BARE = FloorRule(id="pan_bare", checksum=AxisPredicate(values=("luhn",), mode="block"))

# The budget under test, restated from the acceptance corpus rather than re-decided here.
MAX_FALSE_BLOCK_WILSON_UPPER = 0.02
N = 3000


def fires(value):
    return match_red_line(BARE, tool_name="SendEmail", tool_input={"memo": value})


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def make_pan(rng, prefix="4", length=16):
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    for cd in range(10):
        if luhn(body + str(cd)):
            return body + str(cd)
    raise AssertionError("unreachable: one check digit always closes Luhn")


def group(digits, sep=" ", size=4):
    return sep.join(digits[i:i + size] for i in range(0, len(digits), size))


def pan_free(value):
    """The acceptance corpus's OWN ground-truth definition (its `test_declared_ground_truth_of
    _the_negative_arm_holds`): an identifier is a maximal chain or a single group -- NOT an
    arbitrary window. Defining it as a window would filter out precisely the accidents under
    test and report 0.00% for a rule measured well above it."""
    groups = value.split(" ")
    return not luhn(value.replace(" ", "")) and not any(luhn(g) for g in groups)


# ═══════════ PART 1 — the conjuncts, one measurable difference each ═══════════
# Each case is a PAIR: a negative that the conjunct suppresses and a positive that it admits.
# The positive is what stops the negative from passing vacuously -- without it, a generator that
# returned [] unconditionally would satisfy every negative in this part.

def embedded(text):
    """Embedded-only candidates: what `luhn` generates beyond what `luhn_exact` does."""
    return set(P._digit_run_candidates(text)) - set(P._digit_run_candidates_exact(text))


def test_SHAPE_admits_a_card_grouping_and_suppresses_every_other_cut():
    """A window is a claim that a card is PRINTED there, so its group widths must be a grouping
    a card is printed in. `4539 5787 6362 1486 12` offers the printed 4-4-4-4; the same digits
    cut 5-5-6 offer a 12-digit window that no scheme prints."""
    assert embedded("4539 5787 6362 1486 12") == {"4539578763621486"}
    assert embedded("45395 78763 62148 6 12") == set(), (
        "a 5-5-6 cut is not a grouping any card is printed in")
    assert (4, 4, 4, 4) in P._PAN_PRINT_GROUPINGS
    assert (5, 5, 6) not in P._PAN_PRINT_GROUPINGS


def test_CONTEXT_admits_a_card_beside_a_date_and_suppresses_a_ledger_run():
    """11 digits of context, RAISED FROM 8 on 2026-08-07. 8 was set to the width of an ISO date
    on the assumption that a date was the widest token a card is printed beside. That assumption
    was wrong: a 9-digit bank account and a 10-digit phone number are both commoner neighbours
    than a date, and at 8 both were silently undetected for every scheme on both sides."""
    assert embedded("4539 5787 6362 1486 2026 08 06") == {"4539578763621486"}, (
        "a card beside a date is the shape the embedded class exists for")
    assert embedded("4539 5787 6362 1486 123456789") == {"4539578763621486"}, (
        "a 9-digit account number is the commonest wide neighbour, not a ledger run")
    assert embedded("4539 5787 6362 1486 4155550123") == {"4539578763621486"}, (
        "a 10-digit phone number likewise")
    assert embedded("4539 5787 6362 1486 2026 08 06 1234") == set(), (
        "12 digits of context is a ledger run, not adjacency")
    assert P._MAX_EMBEDDED_CONTEXT_DIGITS == 11


def test_CADENCE_admits_a_broken_cadence_and_suppresses_an_UNCORROBORATED_uniform_one():
    """The conjunct that removes the scaling with chain length, AND its one exception.

    Identical digits, identical windows, identical Luhn verdicts -- the only difference is
    whether the neighbouring group repeats the cadence. What changed on 2026-08-07 is that a
    repeated cadence is no longer sufficient on its own: a card printed with its EXPIRY is
    uniform by coincidence, because an expiry is 4 digits and so is a card's group. The suppressor
    and the corroborating signal were the same feature (see `_card_plus_expiry`)."""
    assert embedded("4539 5787 6362 1486 123") == {"4539578763621486"}
    assert embedded("4539 5787 6362 1486 0912") == {"4539578763621486"}, (
        "0912 reads as MMYY, so this is a card printed with its expiry, not a serial number")
    assert embedded("4539 5787 6362 1486 5678") == set(), (
        "month 56 does not exist, so five identical-width groups is one formatted reference")
    assert P._is_single_cadence([4, 4, 4, 4, 4]) is True
    assert P._is_single_cadence([4, 4, 4, 4, 3]) is False
    # The corroboration is the ONLY thing separating the two assertions above: same shape, same
    # length, same cadence, same conjuncts -- one neighbour is a month and the other is not.
    assert P._expiry_shaped("0912") is True
    assert P._expiry_shaped("5678") is False
    # DEAD CODE GUARD. (4,4,4,4,4) is unreachable: a 20-digit window exceeds `hi`=19, so adding it
    # "for completeness" would ship a grouping no window can ever match. QA proved this before the first narrowing pass.
    assert (4, 4, 4, 4, 4) not in P._PAN_PRINT_GROUPINGS


def test_SEPARATOR_RUN_a_layout_gap_does_not_link_two_identifiers():
    """`_MAX_SEPARATOR_RUN` had no coverage in any of the four checksum files: the mutant that
    raises it 2 -> 4 survived the whole suite. 2 admits an ordinary double space; a wider run is
    column padding in an aligned table, and linking across it fuses two unrelated identifiers
    into one chain."""
    assert P._separator_links(" ") is True
    assert P._separator_links("  ") is True
    assert P._separator_links("    ") is False, "a 4-space run is column padding, not a grouping"
    assert P._MAX_SEPARATOR_RUN == 2
    # ... and the consequence at the generator, which is what actually matters: a card is still
    # found across a double space, and two aligned columns do not become one 20-digit chain.
    assert "4539578763621486" in P._digit_run_candidates("4539  5787  6362  1486")
    assert P._digit_run_candidates("4539    5787    6362    1486") == [], (
        "column-aligned digits fused into one chain")


# ═══════════ PART 2 — the arms re-run on chains the corpus generator cannot produce ═══════════

def mixed_widths(rng, n):
    while True:
        w = [rng.choice([2, 3, 4, 4, 4, 5, 6]) for _ in range(n)]
        if len(set(w)) > 1:
            return w


def _fp_mixed(n_groups, seed):
    rng = random.Random(seed)
    k = 0
    for _ in range(N):
        while True:
            v = " ".join("".join(str(rng.randint(0, 9)) for _ in range(w))
                         for w in mixed_widths(rng, n_groups))
            if pan_free(v):
                break
        if fires(v):
            k += 1
    return k, N


@pytest.mark.parametrize("n_groups", [5, 6, 12])
def test_false_block_rate_on_NON_uniform_chains_meets_the_budget(n_groups):
    """★ THE ANTI-SELF-FLATTERY ARM. The acceptance corpus renders every stratum in fixed
    4-digit groups, and CADENCE suppresses exactly that. So the twelve stratum tests going green
    is necessary but nowhere near sufficient: it is consistent with a fix that does nothing at
    all to a chain whose groups differ in width. These strata are that chain."""
    k, n = _fp_mixed(n_groups, seed=11000 + n_groups)
    lo, hi = wilson(k, n)
    assert hi <= MAX_FALSE_BLOCK_WILSON_UPPER, (
        f"{n_groups} mixed-width groups: false-block {k}/{n} = {100*k/n:.2f}% "
        f"Wilson95 [{100*lo:.2f}, {100*hi:.2f}] exceeds the declared budget "
        f"{100*MAX_FALSE_BLOCK_WILSON_UPPER:.2f}%")


@pytest.mark.parametrize("n_groups", [5, 6, 7, 9, 12])
def test_false_block_rate_on_UNIFORM_chains_meets_the_budget(n_groups):
    """★ THE NEW EXPOSURE SURFACE, added 2026-08-07 with the CADENCE exception.

    Before the exception, CADENCE suppressed EVERY window in a uniform chain, so this arm was
    0.00% everywhere by construction and measured nothing. It is now the only arm that can see
    `_card_plus_expiry`, and it replaces the 8-mixed-group cell that a mutation audit showed
    could not move (CONTEXT had already suppressed every window there, so it saw neither SHAPE
    nor CADENCE and survived all 20 mutants).

    The load-bearing property is that the exception does NOT scale with chain length: it is
    admitted only from a 5-group chain, so 6 groups and up must stay at zero."""
    k, n = _fp_uniform(n_groups, seed=7000 + n_groups)
    lo, hi = wilson(k, n)
    assert hi <= MAX_FALSE_BLOCK_WILSON_UPPER, (
        f"{n_groups} uniform groups: false-block {k}/{n} = {100*k/n:.2f}% "
        f"Wilson95 [{100*lo:.2f}, {100*hi:.2f}] exceeds the declared budget "
        f"{100*MAX_FALSE_BLOCK_WILSON_UPPER:.2f}%")
    if n_groups > 5:
        assert k == 0, (
            f"{n_groups} uniform groups yielded {k}/{n} — the CADENCE exception is supposed to be "
            "reachable only from a 5-group chain (card + one expiry). If it now fires on longer "
            "uniform chains it has started scaling with chain length, which is the defect CADENCE "
            "was added to remove.")


# ═══════════ PART 3 — ABLATION: every conjunct must be load-bearing ═══════════
# Each ablation neutralises ONE conjunct in the REAL shipped generator (by substituting the
# constant or predicate it consults) and re-runs a stratum that is green with it. A conjunct
# whose removal changes nothing is dead weight and should be deleted rather than documented.


class _AlwaysIn(frozenset):
    def __contains__(self, item):
        return True


# The stratum per conjunct is chosen so the ablation is NOT masked by a different conjunct --
# SHAPE at 12 groups measures nothing, because CONTEXT has already suppressed every window there
# (the first draft of this test made exactly that mistake and this suite caught it).
@pytest.mark.parametrize("conjunct,attr,neutral,kind,n_groups", [
    ("SHAPE",   "_PAN_PRINT_GROUPINGS",         _AlwaysIn(),               "mixed",   5),
    # CONTEXT moved 12 -> 16 groups on 2026-08-07. It was decisive at 12 before Lever A shipped;
    # Lever A absorbed enough of its precision that ablating CONTEXT at 12 now measures 0.87%
    # [Wilson95 1.27%], INSIDE budget. That is a real reduction in what CONTEXT buys, and the
    # honest response is to measure it where it is still decisive rather than to keep asserting
    # a breach that no longer happens. It breaches from 16 groups up (16: 1.57% [2.08%];
    # 26: 2.60% [3.23%]), so the conjunct is load-bearing against LONG chains, which is its job.
    ("CONTEXT", "_MAX_EMBEDDED_CONTEXT_DIGITS", 10 ** 9,                   "mixed",  16),
    ("CADENCE", "_is_single_cadence",           lambda w: False,           "uniform", 6),
    # Lever B is the CADENCE exception. Neutralising it means "a uniform chain needs no
    # corroboration", which is the pre-2026-08-07 behaviour of admitting any window there.
    ("LEVER_B", "_card_plus_expiry",            lambda w, g, i, j: True,   "uniform", 6),
])
def test_each_narrowing_conjunct_is_LOAD_BEARING(monkeypatch, conjunct, attr, neutral, kind,
                                                 n_groups):
    """★ PROOF THESE TESTS CAN FAIL. Part 2 and the corpus strata are green; this asserts they
    are green BECAUSE of the code and not for some unrelated reason. Neutralise one conjunct and
    a measured stratum must go over budget again.

    Uses the shipped `_digit_run_candidates` throughout -- ablation by substitution, never by
    re-implementing the generator, because a re-implementation would be measuring itself."""
    measure = ((lambda: _fp_mixed(n_groups, seed=11000 + n_groups)) if kind == "mixed"
               else (lambda: _fp_uniform(n_groups, seed=7000 + n_groups)))
    shipped_k, n = measure()
    assert wilson(shipped_k, n)[1] <= MAX_FALSE_BLOCK_WILSON_UPPER, "precondition: shipped is green"

    monkeypatch.setattr(P, attr, neutral)
    ablated_k, n = measure()
    lo, hi = wilson(ablated_k, n)
    assert hi > MAX_FALSE_BLOCK_WILSON_UPPER, (
        f"removing {conjunct} left the false-block rate at {ablated_k}/{n} = "
        f"{100*ablated_k/n:.2f}% Wilson95 [{100*lo:.2f}, {100*hi:.2f}], still inside budget — "
        f"so {conjunct} buys nothing on this stratum and is dead weight, OR this stratum cannot "
        f"see it and the ablation is vacuous. Either way it must not ship as written.")
    assert ablated_k > shipped_k


def _fp_uniform(n_groups, seed):
    """The corpus's own stratum shape, restated so the CADENCE ablation has somewhere to show up
    (CADENCE only ever acts on uniform chains, so a mixed stratum cannot see it)."""
    rng = random.Random(seed)
    k = 0
    for _ in range(N):
        while True:
            v = "".join(str(rng.randint(0, 9)) for _ in range(4 * n_groups))
            if not luhn(v):
                break
        if fires(group(v)):
            k += 1
    return k, N


# ═══════════ PART 4 — the residual, which is ABOVE budget and is not removable ═══════════

def test_the_irreducible_shape_is_OVER_budget_and_that_is_the_finding():
    """★ THE RULING, MEASURED. `445 8412 6603 5591 2274 99` is byte-identical whether it is one
    21-digit reference or (batch 445, PAN, qty 99). Every conjunct above is already satisfied by
    it: the window is printed 4-4-4-4, the context is 5 digits, and the cadence breaks on both
    sides. Exactly one window survives, and one window carries

        P(Luhn) x P(IIN-plausible) = 10% x 29% = 2.9%

    which is ABOVE the 2.00% terminal-block budget. So the budget is not reachable by narrowing
    the embedded class -- only by admitting zero embedded windows, which is `luhn_exact`.

    This test asserts the OVERRUN. If a later change takes this stratum under budget, one of two
    things is true: the embedded class stopped detecting a card printed between two short ids
    (a fail-open), or the arithmetic above changed. Both require a new ruling, so both should
    turn this red rather than quietly bank an improvement."""
    rng = random.Random(22000)
    k = 0
    for _ in range(N):
        while True:
            mid = "".join(str(rng.randint(0, 9)) for _ in range(16))
            v = f"{rng.randint(100, 999)} {group(mid)} {rng.randint(10, 99)}"
            if pan_free(v):
                break
        if fires(v):
            k += 1
    lo, hi = wilson(k, N)
    assert lo > MAX_FALSE_BLOCK_WILSON_UPPER, (
        f"the irreducible shape measured {k}/{N} = {100*k/N:.2f}% Wilson95 "
        f"[{100*lo:.2f}, {100*hi:.2f}], no longer provably above the {100*MAX_FALSE_BLOCK_WILSON_UPPER:.2f}% "
        "budget — re-run the ruling, do not relax this test")
    assert 0.02 < lo and hi < 0.05, (
        f"expected the ~2.9% collision floor, measured Wilson95 [{lo:.4f}, {hi:.4f}]")


# ═══════════ PART 5 — the recall that was traded away, on purpose, in writing ═══════════

@pytest.mark.parametrize("label,render", [
    ("card in a 5-5-6 cut inside a chain",   lambda p: f"{p[:5]} {p[5:10]} {p[10:]} 12"),
    ("card padded BOTH sides, width 4",      lambda p: "1234 " + group(p) + " 5678"),
    ("card inside a longer uniform 4-run",   lambda p: "1234 5678 9012 " + group(p) + " 3456"),
    ("card between a label and its expiry",  lambda p: "1111 " + group(p) + " 1225"),
])
def test_KNOWN_MISS_the_shapes_the_narrowing_gave_up(label, render):
    """★ A CHOSEN FAIL-OPEN, WRITTEN DOWN, WITH THE PRICE OF CLOSING IT MEASURED.

    Every narrowing of a candidate space is also an evasion path. Two of the four originally
    recorded here were CLOSED on 2026-08-07 by the CADENCE exception (`card + same-width
    neighbour` before and after, now detected 200/200 each, because the same-width neighbour is
    usually an expiry). What remains is the ADVERSARIAL residue, and it is not closable:

      * padding on BOTH sides, or into a longer uniform run, leaves no single-group context for
        the expiry corroboration to read. Admitting interior windows of a uniform chain instead
        measures a false-block rate of 5.63% at 5 groups, 8.00% at 6, 10.73% at 7, 15.70% at 9
        and 21.80% at 12 (n=3000/stratum) — 3x to 11x over the 2.00% budget. There is no
        digits-only conjunct that separates these, because there is nothing left to read.
      * `1111 <card> 1225` (label, card, expiry) is the one non-adversarial member of this set.
        Widening the exception from one context group to two recovers it 200/200, and costs
        2.23% [Wilson95 2.83%] at 6 uniform groups — OVER budget, so it is withdrawn on the
        measurement rather than on an argument.
      * the 5-5-6 cut is SHAPE, unchanged: no scheme prints a card that way.

    So this is a DECLARED LIMIT, not a bug queued for a later fix: `luhn` is an accidental-egress
    backstop and is not, and cannot be, an anti-evasion control. If a later change starts
    detecting these, this test goes red and the ruling gets revisited with the false-block cost
    measured — which is the point. Do not delete it to make a fix look free."""
    rng = random.Random(555)
    detected = sum(1 for _ in range(200) if fires(render(make_pan(rng))))
    assert detected == 0, (
        f"{label}: now detected {detected}/200. This is an IMPROVEMENT in the recall arm and it "
        "is not free — re-measure the false-block arms in part 2, the UNIFORM arm, and part 4 "
        "before keeping it.")


def test_LEVER_A_costs_zero_recall_on_every_issuer_range():
    """Lever A's falsifier, from the pre-registration: any recall loss on a generated PAN arm
    means the length table is wrong, not the lever. A real card is issued at one of its own
    scheme's lengths, so this is zero BY CONSTRUCTION and a non-zero reading is an implementation
    bug to fix rather than a trade to declare."""
    rejected = []
    for name, prefix, length in [("Visa", "4", 16), ("Visa-19", "4", 19),
                                 ("Mastercard-5", "55", 16), ("Mastercard-2", "2221", 16),
                                 ("Mastercard-2b", "2720", 16), ("Amex-34", "34", 15),
                                 ("Amex-37", "37", 15), ("Discover-6011", "6011", 16),
                                 ("Discover-65", "65", 16), ("Diners-36", "36", 14),
                                 ("JCB", "3528", 16), ("UnionPay", "62", 16)]:
        rng = random.Random(4242)
        for _ in range(1000):
            pan = make_pan(rng, prefix, length)
            if not P._length_consistent(pan):
                rejected.append((name, pan))
    assert not rejected, f"Lever A rejected {len(rejected)}/12000 real cards: {rejected[:3]}"


def test_LEVER_A_precision_gain_is_REAL_BUT_SMALL_and_misses_its_prediction():
    """★ A PRE-REGISTERED PREDICTION THAT FAILED, PINNED SO IT CANNOT BE RE-READ AS A SUCCESS.

    The pre-registration predicted issuer-length consistency would take IIN plausibility from
    29% to 10-15% and the floor from 2.90% to 1.0-1.5%, CLEARING the 2.00% budget and returning
    `luhn` to terminal-block grade. Enumerated over all 10^6 six-digit prefixes — not sampled —
    it does not:

        length   IIN mass   floor (x P(Luhn)=10.006%)
          13      10.00%      1.00%
          14       3.61%      0.36%
          15       2.00%      0.20%
          16      26.84%      2.69%   <- the shape that carries the false-block mass
          19      16.84%      1.68%

    16 digits is what Visa, Mastercard, Discover, JCB and UnionPay ALL print, so the only ranges a
    16-digit window can exclude are Amex (2.00%) and Diners (3.61%). Even on the narrowest
    defensible table that leaves 23.23%, i.e. a floor of 2.33% — so NO length table clears 2.00%
    at 16 digits. The lever is genuine and free, and it is not sufficient. Decision 1 is NOT
    reversed; `luhn` stays escalation-grade."""
    at16 = sum(1 for p in range(1000000) if P._length_consistent(f"{p:06d}" + "0" * 10))
    assert at16 == 268400, f"16-digit IIN-and-length mass moved: {at16}/1000000"
    assert 0.10006 * at16 / 1e6 > MAX_FALSE_BLOCK_WILSON_UPPER, (
        "the 16-digit floor now clears the budget — if this is real, decision 1 (luhn is "
        "escalation-grade, not terminal-block) must be re-run, not silently banked")
    # ... and the whole IIN table is UNCHANGED by the lever: Lever A adds a length test, it does
    # not touch membership. QA enumerated membership at 28.84% and that must not have moved.
    assert sum(1 for p in range(1000000)
               if P._iin_plausible(f"{p:06d}" + "0" * 10)) == 288400


def test_the_traded_shapes_are_still_detected_in_every_canonical_presentation():
    """The other half of part 5, and the reason it is a trade rather than a hole: the same card
    that goes undetected above is detected in every way it is normally printed."""
    rng = random.Random(556)
    for _ in range(200):
        pan = make_pan(rng)
        for v in (pan, group(pan), group(pan, "-"), f"{pan} 1234", f"445 {group(pan)} 99",
                  f"{group(pan)} 12", f"{group(pan)} 2026-08-06", f"charge {group(pan)} today"):
            assert fires(v) is True, f"canonical presentation stopped firing: {v!r}"
