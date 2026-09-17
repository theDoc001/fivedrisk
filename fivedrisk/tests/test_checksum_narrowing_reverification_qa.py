r"""INDEPENDENT RE-VERIFICATION of the second narrowing pass (branch `wip/checksum-candidate-narrowing`).

Written by the verifier after the author edited the verifier's previous file
(`test_checksum_narrowing_evasion_qa.py`) while shipping the build it grades. Everything here
runs the SHIPPED `_digit_run_candidates` / `match_red_line`; ablation is by substitution on the
real function, never by re-implementing it (defect class 7).

Every test below was confirmed to FAIL under a named mutant of `policy.py` before it shipped, so
none of them is vacuous. The mutant that each one kills is named in its docstring.

Run: cd <dev> && PYTHONPATH=<dev> ./.venv/bin/python -m pytest \
     fivedrisk/tests/test_checksum_narrowing_reverification_qa.py -q -p no:randomly
"""
import math
import random

import pytest

from fivedrisk import policy as P
from fivedrisk.policy import AxisPredicate, FloorRule, luhn, match_red_line

BARE = FloorRule(id="pan_bare", checksum=AxisPredicate(values=("luhn",), mode="block"))
BUDGET = 0.02
N = 1500


def fires(value):
    return match_red_line(BARE, tool_name="SendEmail", tool_input={"memo": value})


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def make_luhn(prefix, length, rng):
    """A Luhn-valid run of `length` digits starting with `prefix`. Ground truth is CONSTRUCTED."""
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    for cd in range(10):
        if luhn(body + str(cd)):
            return body + str(cd)
    raise AssertionError("unreachable: one check digit always closes Luhn")


def group(digits, sep=" ", size=4):
    return sep.join(digits[i:i + size] for i in range(0, len(digits), size))


def uniform_stratum(n_groups, seed, neighbour=None, where="tail"):
    """The shipped `_fp_uniform` shape. `neighbour` optionally forces one group's value, which is
    how a benign month-shaped lot code is introduced without changing anything else."""
    rng = random.Random(seed)
    k = 0
    for _ in range(N):
        while True:
            gs = ["".join(str(rng.randint(0, 9)) for _ in range(4)) for _ in range(n_groups)]
            if neighbour is not None:
                gs[-1 if where == "tail" else 0] = neighbour(rng)
            if not luhn("".join(gs)):
                break
        if fires(" ".join(gs)):
            k += 1
    return k, N


# ══════════ 1. LEVER A IS UNTESTED AT THE GENERATOR (kills mutant M20) ══════════

def test_FINDING_the_generator_must_actually_CONSULT_the_issuer_length_table():
    """UNCOVERED CODE PATH. Deleting `_length_consistent` from the gate in
    `_digit_run_candidates` kills NO test in the shipped suite (421 passed under that mutant).
    Lever A, the headline conjunct of the second narrowing pass, is asserted only as a standalone predicate by
    `test_LEVER_A_costs_zero_recall_*` and `test_LEVER_A_precision_gain_*`; nothing asserted
    that the extractor calls it.

    The pair below is the missing integration assertion. Both payloads are 16 digits printed
    4-4-4-4 beside a 2-digit token, so IIN, SHAPE, CONTEXT and CADENCE all reach the same verdict
    on both. The ONLY conjunct that can separate them is LENGTH: Amex prints 15 digits, so a
    16-digit Amex-prefixed window is not a card; Visa prints 16, so it is.

    Kills mutant M20 (`if _iin_plausible(candidate) and _length_consistent(candidate)` ->
    `if _iin_plausible(candidate)`)."""
    rng = random.Random(11)
    amex16 = make_luhn("37", 16, rng)                 # Amex range, a length Amex never prints
    visa16 = make_luhn("4", 16, rng)                  # Visa range at a length Visa does print

    # Precondition: every OTHER conjunct is satisfied by the rejected window, so the rejection
    # cannot be credited to IIN, SHAPE, CONTEXT or CADENCE.
    assert P._iin_plausible(amex16) is True, "probe broken: IIN must admit this prefix"
    assert P._iin_schemes(amex16) == ("amex",)
    assert (4, 4, 4, 4) in P._PAN_PRINT_GROUPINGS
    assert P._length_consistent(amex16) is False, "Amex does not print 16 digits"
    assert P._length_consistent(visa16) is True

    assert amex16 not in P._digit_run_candidates(group(amex16) + " 12"), (
        "a 16-digit window inside a published Amex range reached the checksum as a candidate. "
        "Amex prints 15 digits, so LENGTH must reject it -- the generator is not consulting "
        "`_length_consistent`, and Lever A is not actually wired in.")
    assert visa16 in P._digit_run_candidates(group(visa16) + " 12"), (
        "the positive half: a length-consistent window must still be emitted, otherwise the "
        "assertion above would pass for a generator that emits nothing at all")


def test_FINDING_the_issuer_length_table_is_unpinned_at_a_REACHABLE_length():
    """UNCOVERED TABLE ENTRY. `policy.py:203` documents an equivalent-mutant argument for the
    17- and 18-digit entries: no grouping in `_PAN_PRINT_GROUPINGS` sums to 17 or 18, so those
    are unreachable. That argument is correct (verified below) but it covers only the
    UNREACHABLE entries. Adding a REACHABLE wrong length survives the whole suite: widening
    Mastercard from (16,) to (16, 15) kills no test, and 15 is reachable because it is the Amex
    4-6-5 grouping.

    Kills mutant M16 (`("mastercard", (16,))` -> `("mastercard", (16, 15))`)."""
    rng = random.Random(12)
    mc15 = make_luhn("5412", 15, rng)
    assert P._iin_schemes(mc15) == ("mastercard",)
    assert P._length_consistent(mc15) is False, (
        "Mastercard prints 16 digits, so a 15-digit window in its range is not a card")
    assert P._length_consistent(make_luhn("5412", 16, random.Random(12))) is True

    # ... and the shape is genuinely reachable, which is what makes the entry load-bearing.
    assert sum((4, 6, 5)) == 15 and (4, 6, 5) in P._PAN_PRINT_GROUPINGS
    assert mc15 not in P._digit_run_candidates(f"{mc15[:4]} {mc15[4:10]} {mc15[10:]} 12")


def test_VERIFIED_both_documented_equivalent_mutant_arguments_still_hold():
    """The two EQUIVALENT-MUTANT notes in `policy.py` (:203 `_ISSUER_LENGTHS` 17/18, :284
    `_expiry_shaped`'s `len(group) == 4`) each rest on one structural fact about
    `_PAN_PRINT_GROUPINGS`. Both facts are pinned here, because an equivalence argument that
    silently stops being true converts a documented survivor into an uncovered code path.

    I independently confirmed both survivors and both arguments. This is the guard, not the
    finding."""
    sums = {sum(g) for g in P._PAN_PRINT_GROUPINGS}
    assert 17 not in sums and 18 not in sums, (
        "a grouping now sums to 17 or 18, so the _ISSUER_LENGTHS 17/18 entries became reachable "
        "and the equivalent-mutant note at policy.py:203 is no longer true")

    all_equal = [g for g in P._PAN_PRINT_GROUPINGS if len(set(g)) == 1]
    assert all_equal == [(4, 4, 4, 4)], (
        f"all-equal groupings are now {all_equal}. `_expiry_shaped`'s `len(group) == 4` test is "
        "unreachable ONLY because (4,4,4,4) is the sole all-equal grouping, so a uniform chain "
        "reaching `_card_plus_expiry` always has 4-wide groups. The note at policy.py:284 is no "
        "longer true and that mutant is now a live uncovered path.")
    assert not [g for g in P._PAN_PRINT_GROUPINGS if len(g) == 1], (
        "a single-group grouping would let a uniform chain of any width reach _expiry_shaped")


# ══════════ 2. _MAX_MONTH, THE COST BASIS OF THE 0.67% (kills mutants M02, M05) ══════════

def test_FINDING_the_MAX_MONTH_boundary_is_unpinned_at_BOTH_edges():
    """UNCOVERED OFF-BY-ONE, on the constant the author calls the entire cost basis of the new
    Lever B exposure. The shipped suite asserts `_expiry_shaped("0912") is True` and
    `_expiry_shaped("5678") is False`. 56 is 44 months past the bound, so neither edge is tested:
    moving `_MAX_MONTH` 12 -> 13, or the lower bound 1 -> 0, changes the admitted mass from 12%
    to 13% of all 4-digit groups and survives all 421 tests.

    Kills mutants M02 (`_MAX_MONTH = 13`) and M05 (`0 <= int(group[:2])`)."""
    assert P._expiry_shaped("1201") is True, "December is a month"
    assert P._expiry_shaped("1301") is False, "there is no month 13"
    assert P._expiry_shaped("0101") is True, "January is a month"
    assert P._expiry_shaped("0012") is False, "there is no month 0"
    assert P._MAX_MONTH == 12

    # ... and the same two edges at the generator, which is where the exposure actually lives.
    pan = make_luhn("4", 16, random.Random(13))
    assert fires(f"{group(pan)} 1201") is True, "a card printed with a December expiry"
    assert fires(f"{group(pan)} 1301") is False, (
        "month 13 does not exist, so a 5th same-width group is one formatted reference and the "
        "CADENCE exception must not read it as an expiry")
    assert fires(f"{group(pan)} 0012") is False, "month 00 likewise"


def test_FINDING_the_admitted_month_mass_is_exactly_12_percent_by_enumeration():
    """The multiplier behind the 0.67% uniform stratum, enumerated over all 10^4 four-digit
    groups rather than sampled. Pinned because the whole false-block reading of Lever B scales
    linearly in it, and because a change here moves a published number silently."""
    admitted = sum(1 for x in range(10000) if P._expiry_shaped(f"{x:04d}"))
    assert admitted == 1200, f"_expiry_shaped now admits {admitted}/10000 of 4-digit groups"


# ══════════ 3. THE 0.67% IS CORPUS-DEPENDENT AND BREACHES ON A REALISTIC ONE ══════════

def test_FINDING_the_uniform_exposure_is_OVER_BUDGET_on_a_month_shaped_corpus():
    """THE NUMBER THAT GOT WORSE, RE-READ ON A REALISTIC CORPUS.

    The published exposure is 0.67% [Wilson95 0.43, 1.03] at 5 uniform groups, measured with
    UNIFORMLY RANDOM 4-digit groups, where only 12% of neighbours read as a month. That
    assumption is wrong in the direction that matters: the chains this rule meets are invoice
    lines, receipts, ledger exports and lot codes, and 4-digit tokens there are heavily
    date-derived (MMYY, MMDD). Force a single month-shaped neighbour, change nothing else, and
    the stratum breaches the 2.00% budget.

    This is a PRECISION finding, not a fail-open. It is asserted as a measured breach, in the
    same style as `test_the_irreducible_shape_is_OVER_budget_and_that_is_the_finding`, so that
    no future reading of this suite can report 0.67% as the exposure without its cost basis."""
    def month(rng):
        return f"{rng.randint(1, 12):02d}{rng.randint(0, 9)}{rng.randint(0, 9)}"

    base_k, n = uniform_stratum(5, seed=7005)
    assert wilson(base_k, n)[1] <= BUDGET, (
        f"precondition: the published random-neighbour stratum is inside budget "
        f"({base_k}/{n} = {100 * base_k / n:.2f}%)")

    worst = 0
    for where in ("tail", "head"):
        k, n = uniform_stratum(5, seed=7005, neighbour=month, where=where)
        worst = max(worst, wilson(k, n)[0])
        assert k > base_k, (
            f"a month-shaped {where} neighbour measured {k}/{n}, no worse than the {base_k}/{n} "
            "random-neighbour reading. If `_card_plus_expiry` has stopped keying on the month "
            "the 0.67% cost basis has changed and the Lever B ruling must be re-run.")
    assert worst > BUDGET, (
        f"the month-shaped strata now measure a Wilson95 LOWER bound of {100 * worst:.2f}%, "
        f"inside the {100 * BUDGET:.2f}% budget. That would be a genuine improvement in Lever B "
        "and it must be banked deliberately: re-measure both arms and re-run the ruling.")


# ══════════ 4. THE DECLARED-LIMIT COST BASIS (the numbers the ruling rests on) ══════════

@pytest.mark.parametrize("n_groups", [5, 6, 7, 9, 12])
def test_FINDING_relaxing_CADENCE_costs_NOTHING_from_seven_uniform_groups_up(monkeypatch,
                                                                            n_groups):
    """THE COST BASIS OF THE 'UNCLOSABLE' RULING, MEASURED ON THE SHIPPED GENERATOR.

    The padding evasion is declared unclosable and priced at "5.63% at 5 groups, 8.00% at 6,
    10.73% at 7, 15.70% at 9 and 21.80% at 12, rising with chain length". The last three are
    wrong. A chain of n 4-digit groups is 4n digits; a 16-digit window leaves 4n-16 outside;
    CONTEXT rejects once 4n-16 > 11, i.e. from n = 7. So from 7 groups up, CONTEXT has already
    suppressed every window and relaxing CADENCE costs exactly nothing.

    Those three figures come from a probe that enumerates group-boundary windows with Luhn, IIN
    and LENGTH but no CONTEXT check, so it measures a counterfactual the shipped extractor
    cannot produce. Ablation by substitution on the real generator is the correct instrument and
    it is what this test uses.

    The ruling SURVIVES at 5 and 6 groups, where the price is genuinely 2.7x to 3.9x over
    budget. It is the "rises with chain length" framing, and the pricing of the 200-group
    the field-boundary fix case in particular, that the measurement does not support."""
    shipped_k, n = uniform_stratum(n_groups, seed=7000 + n_groups)
    monkeypatch.setattr(P, "_is_single_cadence", lambda widths: False)
    ablated_k, n = uniform_stratum(n_groups, seed=7000 + n_groups)
    lo, hi = wilson(ablated_k, n)

    if n_groups <= 6:
        assert lo > BUDGET, (
            f"{n_groups} uniform groups: relaxing CADENCE measured {ablated_k}/{n} = "
            f"{100 * ablated_k / n:.2f}% Wilson95 [{100 * lo:.2f}, {100 * hi:.2f}], no longer "
            f"clearly over the {100 * BUDGET:.2f}% budget. The declared limit on padding rests "
            "on this price; if it has moved, the ruling must be re-run rather than inherited.")
        assert ablated_k > shipped_k, "precondition: the ablation must be visible at all"
    else:
        assert ablated_k == 0, (
            f"{n_groups} uniform groups: relaxing CADENCE measured {ablated_k}/{n}. It must be "
            "exactly 0, because CONTEXT already suppresses every 16-digit window once the chain "
            f"exceeds 16 + {P._MAX_EMBEDDED_CONTEXT_DIGITS} digits. A non-zero reading means "
            "CONTEXT has been widened, and the published cost basis must be re-derived.")
        assert shipped_k == 0


def test_FINDING_the_200_group_padding_limit_is_attributed_to_the_WRONG_conjunct(monkeypatch):
    """DOC-vs-CODE, on a named SEV-0's declared limit.

    `test_DECLARED_LIMIT_the_padding_fail_open_fixed_at_b4ac9f8_is_reachable_again` and
    `test_the_cap_repro_is_grouping_INVARIANT_or_its_limit_is_declared` both justify leaving the
    200-group padding case open with "CADENCE suppresses every window", priced at "15.70% false
    block at 9 groups and 21.80% at 12".

    Neither is true of that payload. Relax CADENCE alone and the payload still does not fire, so
    CADENCE is not what blocks it. CONTEXT is: 204 groups of 4 digits leave 800 digits outside a
    16-digit window, against a limit of 11.

    The case is genuinely still open, so this is not a regression. What is wrong is the reason
    given for leaving it open and the price attached to it, and a limit justified by a number
    that does not apply to it is a limit nobody can re-litigate."""
    pad = " ".join(["1234"] * 200)
    printed = pad + " 4539 5787 6362 1486"
    assert fires(printed) is False, "precondition: this is the declared limit, still open"

    monkeypatch.setattr(P, "_is_single_cadence", lambda widths: False)
    assert fires(printed) is False, (
        "relaxing CADENCE alone now makes the 200-group padded card fire, so CADENCE really was "
        "the blocking conjunct and the declared limit's attribution was right after all")

    monkeypatch.setattr(P, "_MAX_EMBEDDED_CONTEXT_DIGITS", 10 ** 9)
    assert fires(printed) is True, (
        "with CADENCE and CONTEXT both relaxed the payload still does not fire, so a third "
        "conjunct is involved and the attribution must be re-derived from scratch")


# ══════════ 5. THE RECALL ARM PINS ITS OWN PASSING VALUE ══════════

def test_FINDING_the_recall_arm_hard_codes_the_only_neighbour_that_passes_at_width_4():
    """TEST-DESIGN DEFECT, and a repeat of the exact failure the second narrowing pass was written to correct.

    `test_recall_is_not_lost_at_ANY_neighbour_width_either_side` sweeps neighbour widths 1..11
    and reports 132/132 cells green. At width 4, and only at width 4, it substitutes a
    hand-picked neighbour:

        neighbour = "1225" if width == 4 else "1" * width

    Width 4 is the single width where the CADENCE exception is load-bearing, and 1225 is chosen
    because it reads as December 2025. With a 4-digit neighbour that is not month-shaped, the
    three 16-digit 4-4-4-4 schemes lose the cell outright on BOTH sides: 6 of 132 cells, 0/100.

    the second narrowing pass's own commit message states the principle this violates: "a boundary constant must
    never be the widest value its own recall arm tests." The arm cannot distinguish "no loss at
    width 4" from "no loss at width 4 GIVEN the neighbour is an expiry".

    This asserts the real, declared shape of the width-4 cell so the arm's 100% cannot be read
    as unconditional."""
    schemes = [("Visa-16", "4", 16, (4, 4, 4, 4)), ("MC-55", "55", 16, (4, 4, 4, 4)),
               ("UnionPay", "62", 16, (4, 4, 4, 4))]
    for name, prefix, length, widths in schemes:
        rng = random.Random(hash(name) & 0xffff)
        month_hits = plain_hits = 0
        for _ in range(100):
            pan = make_luhn(prefix, length, rng)
            cut, i = [], 0
            for w in widths:
                cut.append(pan[i:i + w])
                i += w
            printed = " ".join(cut)
            month_hits += fires(f"{printed} 1225")
            plain_hits += fires(f"{printed} 5678")
        assert month_hits == 100, (
            f"{name}: the arm's own configuration lost {100 - month_hits}/100 -- the shipped "
            "recall claim has regressed")
        assert plain_hits == 0, (
            f"{name}: a NON-month 4-digit neighbour now recovers {plain_hits}/100. That is an "
            "improvement in the recall arm and it is not free: re-measure the uniform "
            "false-block strata, which key on exactly this predicate, before banking it.")
