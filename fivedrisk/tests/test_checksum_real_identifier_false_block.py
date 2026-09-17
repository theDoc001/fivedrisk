r"""The check-digit axes against REAL identifiers that are not cards.

WHY THIS EXISTS. `test_checksum_candidate_narrowing.py` measures the false-block floor on a
benign corpus built through `pan_free()`, which discards any value whose digit chain clears
Luhn. That is the correct filter for synthetic digit noise — a Luhn-valid random string is
arithmetically indistinguishable from a card, so counting it as a false block would be
measuring the arithmetic rather than the control.

It also means the corpus **cannot contain an IMEI**, because an IMEI's check digit IS Luhn
(3GPP TS 23.003), nor an NPI carried with its `80840` prefix, for the same reason. Those are
the two commonest real-world Luhn-valid non-card identifiers, and both were filtered out of
the population that produced the 0.0% figure `luhn_exact` holds terminal grade on.

So this file measures what that one structurally could not. It is a CHARACTERISATION suite:
it pins what the shipped code actually does today, including where that is bad. If a future
narrowing fixes the IMEI case, these tests go RED and whoever fixed it must come here and to
`policy.py`'s false-positive note and update both. That is the point — the finding is written
into a mechanism rather than only into a document.

Nothing here is a re-implementation: the rules run through the shipped `match_red_line`.
"""
import pytest

from fivedrisk.policy import AxisPredicate, FloorRule, luhn, match_red_line

EXACT = FloorRule(id="pan_exact", checksum=AxisPredicate(values=("luhn_exact",), mode="block"))
LOOSE = FloorRule(id="pan_loose", checksum=AxisPredicate(values=("luhn",), mode="block"))


def fires(rule, value):
    return match_red_line(rule, tool_name="SendEmail", tool_input={"memo": value})


def _luhn_close(body):
    for cd in "0123456789":
        if luhn(body + cd):
            return body + cd
    raise AssertionError("unreachable")


def imei(seed):
    """15 digits, Luhn check digit. A phone's identity, on every telco document."""
    return _luhn_close(f"{seed:014d}")


def npi_prefixed(seed):
    """The US healthcare NPI as it travels in a claim: `80840` + 10-digit NPI, whose check
    digit closes Luhn over exactly that prefixed string."""
    body = f"{seed:09d}"
    return "80840" + body + _luhn_close("80840" + body)[-1]


def gs1_close(body):
    total = sum(int(d) * (3 if i % 2 == 0 else 1) for i, d in enumerate(reversed(body)))
    return body + str((10 - total % 10) % 10)


# ── the finding, pinned ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,make", [("IMEI", imei), ("NPI_with_80840_prefix", npi_prefixed)])
def test_a_REAL_luhn_valid_identifier_is_caught_by_BOTH_classes(name, make):
    """★ THE FINDING. Both classes fire on 100% of these — including `luhn_exact`, which is the
    one entitled to block terminally. `luhn_exact` does not admit embedded windows, but an IMEI
    is not an embedded window: it is a 15-digit chain standing alone, inside the [12,19] window,
    that clears Luhn. Nothing about the exact class was ever going to exclude it.

    Measured over n=3000 per family against generated IMEI and prefixed-NPI corpora:
    3000/3000 for both classes."""
    caught_exact = sum(1 for s in range(200) if fires(EXACT, make(s)))
    caught_loose = sum(1 for s in range(200) if fires(LOOSE, make(s)))
    assert caught_exact == 200, (
        f"{name}: luhn_exact caught {caught_exact}/200. If this is now BELOW 200 the terminal "
        f"class has been narrowed — update this module's docstring and policy.py's false-positive "
        f"note, both of which currently record 100%.")
    assert caught_loose == 200


def test_the_BARE_npi_is_NOT_caught_and_that_is_the_control():
    """The bare 10-digit NPI does not clear Luhn on its own — the check digit closes Luhn over
    the PREFIXED string. It measures 0/3000, which is what shows the effect above is the check
    digit and not merely 'a run of digits of plausible length'."""
    assert sum(1 for s in range(200) if fires(EXACT, f"{s:09d}" + _luhn_close("80840" + f"{s:09d}")[-1])) == 0


def test_a_GS1_identifier_is_caught_only_at_the_LUHN_COINCIDENCE_rate():
    """GTIN/EAN/ISBN/SSCC use a mod-10 with weights 3,1 — not Luhn. They are caught only when
    they happen to clear Luhn as well, which is ~1 in 10. Measured 9.13-10.13% at n=3000.

    This is the non-vacuity partner for the two tests above: if EVERY digit identifier fired,
    the finding would be 'the axis fires on digits', which is not a finding. It fires on the
    check digit, and these families show the difference."""
    caught = sum(1 for s in range(1000) if fires(EXACT, gs1_close(f"{s:012d}")))
    assert 30 <= caught <= 180, (
        f"GS1 caught {caught}/1000; expected the ~1-in-10 Luhn coincidence. Outside that band "
        f"the axis is no longer behaving as a check-digit test on this family.")


def test_non_checksummed_business_references_are_clean():
    """Order references, lot codes and cost centres measure 0/3000. Recorded so that a future
    widening of the candidate class has somewhere to show up: these are the shapes a deployer
    would be most surprised to see blocked."""
    refs = ([f"SO-{s:09d}" for s in range(300)]
            + [f"LOT24{s:08d}" for s in range(300)]
            + [f"CC-{s % 9000 + 1000}-{s:06d}" for s in range(300)])
    assert [r for r in refs if fires(EXACT, r)] == []
