r"""INDEPENDENT QA of the checksum candidate narrowing before the first narrowing pass (branch
`wip/checksum-candidate-narrowing`). Written by the verifier, not the author.

Scope: the four narrowing conjuncts on the `checksum: luhn` embedded class (IIN, SHAPE,
CONTEXT, CADENCE) and the recall they cost. Everything here runs the SHIPPED
`match_red_line` / `_digit_run_candidates`; nothing is re-implemented (defect class 7).

TWO KINDS OF TEST LIVE HERE AND THEY ARE LABELLED.

  * `test_FINDING_*` assert the SAFE contract and are RED before the first narrowing pass. Each is a reproduced
    fail-open: a genuinely Luhn-valid, IIN-plausible payment card that the axis does not see.
    They are written so the IDENTICAL test flips red -> green when the code is fixed; none of
    them asserts on a swallowed value, and none of them relaxes a guardrail.
  * `test_VERIFIED_*` are GREEN and pin claims of the author's that I independently reproduced,
    so a later change cannot quietly move them.

Run: cd <dev> && PYTHONPATH=<dev> ./.venv/bin/python -m pytest \
     fivedrisk/tests/test_checksum_narrowing_evasion_qa.py -q -p no:randomly
"""
import random
import re

import pytest

from fivedrisk import policy as P
from fivedrisk.policy import (AxisPredicate, FloorRule, luhn, match_red_line,
                              _iin_plausible)

# Author both classes. A deployer who wants a terminal block authors `luhn_exact`; one who
# wants an escalation authors `luhn`. Naming BOTH is the most generous configuration the
# library offers, so an evasion that survives this rule survives every authoring of the axis.
BOTH = FloorRule(id="pan_both",
                 checksum=AxisPredicate(values=("luhn", "luhn_exact"), mode="block"))
LUHN = FloorRule(id="pan_luhn", checksum=AxisPredicate(values=("luhn",), mode="block"))
EXACT = FloorRule(id="pan_exact", checksum=AxisPredicate(values=("luhn_exact",), mode="block"))

N_TRIALS = 300


def fires(value, rule=BOTH):
    return match_red_line(rule, tool_name="SendEmail", tool_input={"memo": value})


def make_pan(rng, prefix="4", length=16):
    """A genuinely Luhn-valid, IIN-plausible card number. Ground truth is CONSTRUCTED, never
    inferred from the validator under test."""
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    for cd in range(10):
        if luhn(body + str(cd)):
            assert _iin_plausible(body + str(cd))
            return body + str(cd)
    raise AssertionError("unreachable: one check digit always closes Luhn")


def group(digits, sep=" ", size=4):
    return sep.join(digits[i:i + size] for i in range(0, len(digits), size))


def recover(text):
    """A 4-line attacker-side recovery: the PAN is still trivially extractable from every
    evasion string below. This is what makes them EVASIONS and not merely losses of a signal —
    the payload a human or a script reads is unchanged."""
    d = "".join(c for c in text if c.isdecimal())
    return [d[i:i + 16] for i in range(len(d) - 15)
            if luhn(d[i:i + 16]) and _iin_plausible(d[i:i + 16])]


# ══════════════ FINDINGS — RED before the first narrowing pass, each a reproduced fail-open ══════════════

# CLOSED at 2026-08-07 by the CADENCE exception (`_card_plus_expiry`) and the CONTEXT raise
# 8 -> 11. These were RED when this file was written and are GREEN now, unchanged — which is what
# makes them evidence rather than decoration.
EVASIONS = [
    # label, transform, cost in characters added to the canonically-printed card
    ("CADENCE: one 4-digit group appended",
     lambda p: group(p) + " 1234", 5),
    ("CADENCE: one 4-digit group prepended",
     lambda p: "1234 " + group(p), 5),
    ("CONTEXT: 9-digit neighbour (ACH/account-shaped)",
     lambda p: group(p) + " 123456789", 10),
    ("CONTEXT: 10-digit neighbour (phone-shaped)",
     lambda p: group(p) + " 4155550123", 11),
    ("CONTEXT: 9-digit neighbour leading",
     lambda p: "123456789 " + group(p), 10),
]

# NOT CLOSED, and the recorded re-scope declares them unclosable at the 2.00% false-block budget.
# Kept as measured limits rather than as permanently-red tests — the same remedy this file
# prescribed for MR-1 ("scope it to where it provably holds rather than leave a red test").
DECLARED_LIMITS = [
    ("CADENCE: padded both sides into a uniform run",
     lambda p: "1234 " + group(p) + " 5678", 10),
    ("CADENCE: card inside a longer uniform 4-group run",
     lambda p: "1234 5678 9012 " + group(p) + " 3456 7890", 30),
    ("SHAPE: one space moved, plus a 4-digit neighbour",
     lambda p: f"{p[:5]} {p[5:9]} {p[9:13]} {p[13:]} 1234", 5),
]


@pytest.mark.parametrize("label,render,cost", EVASIONS, ids=[e[0] for e in EVASIONS])
def test_FINDING_a_padded_card_must_still_reach_the_checksum_floor(label, render, cost):
    """FAIL-OPEN. A single appended token disarms the axis on a genuinely valid card.

    The safe contract is asserted: the floor MUST fire. This test is RED before the first narrowing pass and goes
    GREEN when the narrowing stops suppressing the window; it does not assert on the swallowed
    verdict, so it cannot invert on the fix.

    `recover()` in this file extracts the card from every one of these strings in four lines,
    so the transformation costs the attacker `cost` characters and costs the recipient nothing.
    """
    rng = random.Random(90210)
    missed = []
    for _ in range(N_TRIALS):
        pan = make_pan(rng)
        payload = render(pan)
        assert pan in recover(payload), "probe is broken: the card is not recoverable"
        if not fires(payload):
            missed.append(payload)
    assert not missed, (
        f"{label}: {len(missed)}/{N_TRIALS} genuinely valid cards walked a checksum floor for "
        f"{cost} added characters. Example: {missed[0]!r}")


@pytest.mark.parametrize("label,render,cost", DECLARED_LIMITS,
                         ids=[e[0] for e in DECLARED_LIMITS])
def test_DECLARED_LIMIT_adversarial_padding_is_not_closable_at_the_budget(label, render, cost):
    """★ A FAIL-OPEN THAT IS RECORDED RATHER THAN FIXED, WITH THE PRICE MEASURED IN THIS TEST.

    These three survive the 2026-08-07 re-scope. They are real: `recover()` still extracts the
    card in four lines, so the payload a human reads is unchanged. They are not closable:

      * both-sides padding and the longer uniform run leave no single-group context, so there is
        nothing for the expiry corroboration to read. The only remaining option is to admit
        INTERIOR windows of a uniform chain, and the assertion below measures what that costs.
      * the 5-4-4-3 re-cut is SHAPE. No card scheme prints a card that way, so admitting it means
        admitting every arbitrary cut, which is the 42.2%-at-12-groups defect this work started
        from.

    This is the difference between an accidental-egress backstop and an anti-evasion control.
    `luhn` is the former and the docstring now says so without qualification. A deployer who
    needs the latter cannot get it from digits alone — that is the finding, not a TODO."""
    rng = random.Random(90210)
    still_missed = sum(1 for _ in range(N_TRIALS) if not fires(render(make_pan(rng))))
    assert still_missed == N_TRIALS, (
        f"{label}: now detected {N_TRIALS - still_missed}/{N_TRIALS}. That is an improvement in "
        "the recall arm and it is NOT free — re-measure the uniform false-block strata (the "
        "price of admitting these was 5.63% at 5 groups rising to 21.80% at 12, against a 2.00% "
        "budget) and re-run the ruling before banking it.")


def test_DECLARED_LIMIT_the_price_of_closing_the_padding_evasion_is_over_budget():
    """The measurement the test above rests on, run here rather than cited, so the declared limit
    cannot drift away from the number that justifies it.

    Admitting every length-consistent 16-digit window cut on a group boundary of a uniform chain
    is exactly what "closing the padding evasion" means. On benign, PAN-free uniform chains it
    costs far more than the 2.00% budget, and the cost RISES with chain length — which is the
    original defect, not a new one."""
    rng = random.Random(50000)
    for n_groups, floor in ((5, 0.03), (9, 0.10)):
        k = 0
        for _ in range(1000):
            while True:
                v = " ".join("".join(str(rng.randint(0, 9)) for _ in range(4))
                             for _ in range(n_groups))
                if not luhn(v.replace(" ", "")) and not any(luhn(g) for g in v.split(" ")):
                    break
            d = v.replace(" ", "")
            if any(luhn(d[s:s + 16]) and _iin_plausible(d[s:s + 16])
                   and P._length_consistent(d[s:s + 16])
                   for s in range(0, len(d) - 15, 4)):
                k += 1
        assert k / 1000 > floor, (
            f"{n_groups} uniform groups: admitting interior windows measured {k}/1000 = "
            f"{100*k/1000:.2f}%, below the {100*floor:.0f}% this limit was declared against. "
            "If the collision arithmetic has genuinely moved, the padding ruling must be re-run.")


def test_DECLARED_LIMIT_the_padding_fail_open_fixed_at_b4ac9f8_is_reachable_again():
    """FAIL-OPEN, a REGRESSION of a named SEV-0 by a second route, and the same declared limit as
    the two tests above — the 200-group pad is the "longer uniform run" case at scale.

    `test_candidate_cap_must_not_silently_drop_a_real_pan_ADVERSARIAL` in the acceptance corpus
    pins that digit padding before a card cannot disarm the floor. It passes only because its
    payload appends the CONTIGUOUS `_PAN`, which keeps the chain non-uniform and routes through
    the EXACT class. Print the same card in its own 4-4-4-4 grouping and the chain becomes
    uniform, CADENCE suppresses every window, and no candidate is generated at all.

    The corpus now pins BOTH halves directly (`test_the_cap_repro_is_grouping_INVARIANT_or_its_
    limit_is_declared`), so the blind spot that let this survive is closed even though the
    fail-open itself is not. What is asserted here is the ASYMMETRY, because that is the part a
    deployer must know: the contiguous rendering blocks and the printed one does not."""
    pad = " ".join(["1234"] * 200)
    contiguous = pad + " " + "4539578763621486"
    printed = pad + " " + "4539 5787 6362 1486"
    assert fires(contiguous) is True, "the shipped test's own payload stopped firing"
    assert "4539578763621486" in recover(printed), "probe broken"
    assert fires(printed) is False, (
        "the PRINTED form of the padded card now fires. Improvement in the recall arm, not free "
        "— re-measure the uniform false-block strata and re-run the padding ruling.")


def test_FINDING_the_traded_recall_is_not_limited_to_a_same_width_neighbour():
    """DOC-vs-CODE. `_digit_run_candidates.__doc__` states the traded shapes "remain detected
    whenever the card is printed ALONE, contiguously, in prose, or beside any token of a
    DIFFERENT width". Measured across neighbour widths 1..10 on both sides, that is false for
    widths 9 and 10 (CONTEXT), for every scheme.

    Asserting the documented contract, so this goes green if either the code or the doc is
    corrected — but the doc is the load-bearing claim a deployer reads."""
    rng = random.Random(4242)
    broken = []
    for label, prefix, length, widths in [("Visa-16", "4", 16, (4, 4, 4, 4)),
                                          ("Amex", "37", 15, (4, 6, 5)),
                                          ("Diners", "36", 14, (4, 6, 4)),
                                          ("Visa-19", "4", 19, (4, 4, 4, 4, 3))]:
        for w in range(1, 11):
            if w == len(str(widths[-1])) or w in {x for x in widths}:
                continue                      # same-width neighbour: a DECLARED trade, skip
            pan = make_pan(rng, prefix, length)
            cut, i = [], 0
            for g in widths:
                cut.append(pan[i:i + g])
                i += g
            payload = " ".join(cut) + " " + "1" * w
            if not fires(payload):
                broken.append((label, w, payload))
    assert not broken, (
        "the docstring's 'beside any token of a DIFFERENT width' is false for "
        f"{sorted({(b[0], b[1]) for b in broken})}; e.g. {broken[0][2]!r}")


ACCIDENTAL = [
    ("card then 4-digit expiry MMYY", "4539 5787 6362 1486 0912"),
    ("card then 4-digit expiry, hyphens", "4539-5787-6362-1486-0912"),
    ("card, date, then a 2-digit sequence", "4539 5787 6362 1486 2026-08-06 12"),
    ("card then a 9-digit account number", "4539 5787 6362 1486 123456789"),
    ("card then a 10-digit phone", "4539 5787 6362 1486 4155550123"),
]


@pytest.mark.parametrize("label,payload", ACCIDENTAL, ids=[a[0] for a in ACCIDENTAL])
def test_FINDING_the_modal_accidental_egress_shapes_are_the_blind_spot(label, payload):
    """FAIL-OPEN, and the one that undercuts the stated justification.

    `_digit_run_candidates.__doc__` justifies the embedded class as "a backstop against
    ACCIDENTAL card egress, which is printed canonically" and prices the CADENCE trade as
    costing only "a card sharing a uniform-cadence chain with a same-width neighbour" —
    framed as a narrow, chosen loss.

    But the modal same-width neighbour of a printed card is its 4-digit EXPIRY (MMYY), and the
    modal wide neighbour is a 9-digit account or a 10-digit phone. Those are not adversarial
    shapes; they are what accidental egress actually looks like. Every string below carries a
    Luhn-valid, IIN-plausible Visa in its printed 4-4-4-4 grouping and none of them fires."""
    assert "4539578763621486" in recover(payload), "probe broken"
    assert fires(payload) is True, (
        f"{label}: {payload!r} — the shape the embedded class exists to catch is not caught. "
        f"Candidates generated: {P._digit_run_candidates(payload)!r}")


def test_FINDING_a_failing_cap_test_raises_instead_of_reporting():
    """TEST DEFECT. `test_candidate_cap_must_not_silently_drop_a_real_pan_ADVERSARIAL` builds its
    failure message from `P._MAX_CHECKSUM_CANDIDATES`, which this change REMOVED. On failure the
    test raises AttributeError from the f-string instead of reporting the fail-open it exists to
    report — a detector whose alarm is itself broken. Confirmed by mutation: under a mutant that
    deletes the EXACT single-group emit, that test errors rather than failing cleanly.

    ASSERTION CORRECTED 2026-08-07. As written this asserted `hasattr(P,
    "_MAX_CHECKSUM_CANDIDATES")`, which could only be satisfied by re-adding a dead constant to
    `policy.py` — the opposite of the fix its own message prescribes ("Fix the test, not
    policy.py"). It now asserts the actual contract: no acceptance-corpus failure message may
    interpolate an attribute that does not exist. That is general, so it also catches the next
    one rather than only this one."""
    import pathlib
    corpus = (pathlib.Path(__file__).parent / "test_checksum_acceptance_corpus.py")
    src = corpus.read_text()
    dangling = sorted({name for name in re.findall(r"\bP\.(_[A-Za-z_]+)", src)
                       if not hasattr(P, name)})
    assert not dangling, (
        f"{corpus.name} interpolates policy attributes that no longer exist: {dangling}. "
        "A test that raises AttributeError from its own f-string cannot report the fail-open it "
        "exists to report — fix the test, not policy.py.")


# ══════════════ VERIFIED — green, pinning claims I independently reproduced ══════════════

def test_VERIFIED_luhn_exact_candidates_are_a_subset_of_luhn_candidates():
    """Structural consequence of the shared branch, so ANY evasion of `luhn` is automatically an
    evasion of `luhn_exact`. This is why naming both validators buys a deployer nothing against
    the shapes above. 0 counterexamples in 4000 random chains."""
    rng = random.Random(31415)
    for _ in range(4000):
        v = " ".join("".join(str(rng.randint(0, 9)) for _ in range(rng.randint(1, 8)))
                     for _ in range(rng.randint(1, 7)))
        assert set(P._digit_run_candidates_exact(v)) <= set(P._digit_run_candidates(v))
    # The invariant, stated as an implication rather than as a pinned verdict, so a FIX to the
    # embedded class cannot turn this test red: exact must never fire where luhn does not.
    for _, render, _c in EVASIONS:
        payload = render(make_pan(random.Random(1)))
        if fires(payload, rule=EXACT):
            assert fires(payload, rule=LUHN), f"inverted ladder on {payload!r}"


def test_VERIFIED_the_IIN_plausibility_mass_of_the_shipped_table_is_28_84_percent():
    """The author's 2.90% residual is derived as P(Luhn) x P(IIN) = 10% x 29%. The IIN factor is
    EXACTLY 28.84% for the shipped table, by enumeration over all 10^6 six-digit prefixes — not
    a sample. 10.00% x 28.84% = 2.884%, inside the author's measured Wilson95 [2.36, 3.56] on
    87/3000. The derivation is sound and the figure is right."""
    hits = sum(1 for p in range(1000000)
               if _iin_plausible(f"{p:06d}" + "0" * 10))
    assert hits == 288400, f"IIN mass moved: {hits}/1000000"


def test_VERIFIED_the_residual_probe_cannot_disagree_with_its_own_formula():
    """EVAL HYGIENE, not a defect. The residual probe filters its samples with `pan_free()`, and
    on the shape `<3 digits> <16 in 4-4-4-4> <2 digits>` that filter rejects NOTHING (0/20000):
    the 21-digit chain is out of luhn's [12,19] range and every group is under 12. Exactly one
    window survives the conjuncts, so the measured rate is definitionally P(Luhn & IIN) — the
    same quantity the formula computes. The agreement is arithmetic self-consistency, and it is
    NOT independent evidence that the conjuncts behave as described on that shape."""
    def pan_free(value):
        groups = value.split(" ")
        return not luhn(value.replace(" ", "")) and not any(luhn(g) for g in groups)

    rng = random.Random(22000)
    rejected = 0
    for _ in range(20000):
        mid = "".join(str(rng.randint(0, 9)) for _ in range(16))
        v = f"{rng.randint(100, 999)} {group(mid)} {rng.randint(10, 99)}"
        rejected += not pan_free(v)
    assert rejected == 0, (
        f"pan_free() now rejects {rejected}/20000 on the residual shape — it used to be a no-op, "
        "so the probe's sampling has changed and the 2.90% reading must be re-derived")


def test_VERIFIED_the_MR1_at_19_contradiction_is_categorical_not_a_seed_accident():
    """The author claims `test_MR1_holds_for_the_19_digit_window_edge` is unsatisfiable. It is.
    The per-draw violation rate is exactly the residual: a 19-digit non-Luhn chain printed
    4-4-4-4-3 has a Luhn-valid, IIN-plausible leading 16-digit window 2.88% of the time, and MR-2
    requires that same shape to fire. Measured 2.887% over 100k draws here at n=20000. So the
    red test is a corpus-specification defect (MR-1 does not hold for the embedded class BY
    DESIGN, since SHAPE and CADENCE both read grouping), not an unfixed bug — but the honest
    remedy is to SCOPE MR-1 to `luhn_exact`, where it does hold, rather than leave a red test."""
    rng = random.Random(999)
    n, k = 20000, 0
    for _ in range(n):
        while True:
            s = "".join(str(rng.randint(0, 9)) for _ in range(19))
            if not luhn(s):
                break
        if fires(s, rule=LUHN) != fires(group(s), rule=LUHN):
            k += 1
    assert 0.02 < k / n < 0.04, (
        f"MR-1@19 violation rate {k}/{n} = {100*k/n:.3f}% left the ~2.88% P(Luhn & IIN) band; "
        "the impossibility argument must be re-derived")
    # and MR-1 holds at 16 digits only because SHAPE rejects every sub-window cut of a 4-group
    # chain -- not, as the commit message implies, because of CADENCE.
    rng = random.Random(999)
    for _ in range(3000):
        while True:
            s = "".join(str(rng.randint(0, 9)) for _ in range(16))
            if not luhn(s):
                break
        assert fires(s, rule=LUHN) == fires(group(s), rule=LUHN)


def test_VERIFIED_no_shipped_policy_authors_the_luhn_axis():
    """Severity context. `luhn`/`luhn_exact` appear in no YAML in this repo, so nothing ships
    pre-authored against the evasions above; a deployer has to opt in. This is stated so the
    finding is not over-read, and pinned so it stops being true loudly."""
    import pathlib
    root = pathlib.Path(P.__file__).resolve().parent.parent
    authored = [p for p in list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
                if ".venv" not in p.parts and "luhn" in p.read_text(errors="ignore")]
    assert not authored, f"a shipped policy now authors the luhn axis: {authored}"
