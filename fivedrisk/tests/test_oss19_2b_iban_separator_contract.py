r"""OSS-19 2B — the `iban_mod97` contract covers printed separators and zero-width characters.

**The defect, and why it is a fail-open rather than a strictness.** `iban_mod97` stripped `\s` and
nothing else, so an IBAN printed with a HYPHEN — the ordinary way an IBAN is grouped for human
transcription outside the "space every four" convention — was reported INVALID. So was one carrying
a zero-width character picked up from a copy-paste out of a web page or a PDF.

The caller's question is *"is this a valid IBAN"*. Answering "no" for a value that a human can see is
a valid IBAN does not make the library stricter, it makes it wrong in the direction where nothing
complains: whatever the caller does with valid IBANs simply does not happen.

**The zero-width half is the load-bearing one.** ZWSP, ZWNJ, ZWJ, the word joiner and the BOM survive
copy-paste, render as nothing, and are therefore invisible in any review that would otherwise catch
the problem. A validator that fails open on a character no human can see fails open by construction.

**Extractor and validator move together, and that is the whole shape of OSS-19.** The original gap
was that the validator stripped a class the extractor could not produce; 2A closed that for
whitespace and was measured INERT on its own; 2B closes it for the remaining two forms. Both sides
are built from ONE frozenset here so they cannot drift apart again, and this file asserts that
property directly rather than trusting it.

Offline, deterministic, no API calls.
"""
from __future__ import annotations

import pytest

from fivedrisk.policy import (
    _CHECKSUM_VALIDATORS,
    _IBAN_SEPARATORS_BEYOND_WHITESPACE,
    iban_mod97,
)

#: A real Iranian IBAN (Sheba, 26 chars). IR is the one prefix in the shipped sanctions rule that
#: has a published national IBAN format at all.
IBAN = "IR062960000000100324200001"


def _grouped(sep: str, value: str = IBAN) -> str:
    return sep.join(value[i:i + 4] for i in range(0, len(value), 4))


# ── the validator contract ──────────────────────────────────────────────────────────────────────

WHITESPACE_FORMS = {
    "single space": " ",
    "double space": "  ",
    "tab": "\t",
    "NBSP": " ",
    "thin space": " ",
    "narrow NBSP": " ",
    "em space": " ",
    # These reach the validator through `\s` and NOT through the explicit set. They are here to pin
    # that `\s` was KEPT rather than replaced -- swapping a broad class for an explicit one while
    # calling it a widening is the trade nobody notices.
    "en quad (U+2000)": " ",
    "ideographic space (U+3000)": "　",
    "ogham space mark (U+1680)": " ",
}

PRINTED_SEPARATOR_FORMS = {
    "hyphen-minus": "-",
    "soft hyphen": "­",
    "non-breaking hyphen": "‑",
    "figure dash": "‒",
    "en dash": "–",
}

ZERO_WIDTH_FORMS = {
    "ZWSP": "​",
    "ZWNJ": "‌",
    "ZWJ": "‍",
    "word joiner": "⁠",
    "BOM / ZWNBSP": "﻿",
}


@pytest.mark.parametrize("name,sep", sorted(WHITESPACE_FORMS.items()))
def test_whitespace_forms_still_validate(name, sep):
    """Non-perturbation: everything that worked before 2B must still work."""
    assert iban_mod97(_grouped(sep)), f"{name} regressed"


@pytest.mark.parametrize("name,sep", sorted(PRINTED_SEPARATOR_FORMS.items()))
def test_printed_separator_forms_now_validate(name, sep):
    assert iban_mod97(_grouped(sep)), f"{name} still rejected"


@pytest.mark.parametrize("name,sep", sorted(ZERO_WIDTH_FORMS.items()))
def test_zero_width_forms_now_validate(name, sep):
    assert iban_mod97(_grouped(sep)), f"{name} still rejected"


def test_the_contiguous_form_is_unchanged():
    assert iban_mod97(IBAN)


# ── what widening must NOT have cost ────────────────────────────────────────────────────────────

def test_a_wrong_check_digit_is_still_rejected_in_every_separator_form():
    """The one that matters. A widening that also started accepting invalid IBANs would be a
    fail-open wearing a fix's clothes -- and every form must be checked, not just the plain one,
    because the stripping happens before the checksum."""
    bad = "IR062960000000100324200000"          # last digit changed; mod-97 != 1
    assert not iban_mod97(bad)
    for name, sep in {**WHITESPACE_FORMS, **PRINTED_SEPARATOR_FORMS, **ZERO_WIDTH_FORMS}.items():
        assert not iban_mod97(_grouped(sep, bad)), f"{name} now accepts a bad check digit"


def test_separators_alone_are_not_an_IBAN():
    for sep in sorted(_IBAN_SEPARATORS_BEYOND_WHITESPACE):
        assert not iban_mod97(sep * 30)


def test_a_malformed_shape_is_still_rejected():
    assert not iban_mod97("not-an-iban")
    assert not iban_mod97("")
    assert not iban_mod97("--------")
    assert not iban_mod97("IR-06")                       # too short once stripped


def test_stripping_cannot_MANUFACTURE_a_valid_iban_from_a_shorter_one():
    """Removing characters shortens the value, so the shape check is what stops a truncated or
    padded token from clearing. Asserted because 'strip more characters' is exactly the kind of
    change that can widen a shape check by accident."""
    assert not iban_mod97("IR06296000000010032420")      # a real prefix, wrong length
    assert not iban_mod97("-".join("IR06296000000010032420"))


# ── extractor / validator parity, asserted rather than trusted ──────────────────────────────────

def test_the_extractor_produces_a_candidate_for_every_form_the_validator_accepts():
    """The property OSS-19 is actually about.

    A validator more permissive than its extractor is not a safe asymmetry: the extractor is the
    gate, so a form the extractor cannot see is a form the validator never gets asked about. That
    asymmetry is the original defect, and it is the reason 2A alone was measured inert.
    """
    generator, validator = _CHECKSUM_VALIDATORS["iban_mod97"]
    every_form = {**WHITESPACE_FORMS, **PRINTED_SEPARATOR_FORMS, **ZERO_WIDTH_FORMS}
    missed = []
    for name, sep in sorted(every_form.items()):
        value = _grouped(sep)
        assert validator(value), f"fixture error: {name} does not validate"
        if not any(validator(c) for c in generator(value)):
            missed.append(name)
    assert not missed, (
        f"{len(missed)} of {len(every_form)} forms validate but yield NO extractor candidate, so "
        f"the rule can never fire on them: {missed}")


def test_the_two_sides_are_built_from_ONE_alphabet():
    """Structural, not behavioural: the extractor class is composed from the same frozenset the
    validator strips. Two hand-maintained copies of one alphabet is how this gap opened."""
    from fivedrisk.policy import _IBAN_CANDIDATE_UPPER, _IBAN_SEP_CLASS

    for ch in _IBAN_SEPARATORS_BEYOND_WHITESPACE:
        assert ch in _IBAN_SEP_CLASS, f"{ch!r} is stripped by the validator but absent from the class"
    assert _IBAN_SEP_CLASS in _IBAN_CANDIDATE_UPPER


def test_line_breaks_are_still_excluded_from_the_extractor_class():
    """Deliberate and load-bearing. An IBAN ending a line, joined across the break to an uppercase
    token starting the next, is the bleed the uppercase/contiguous split exists to prevent."""
    generator, validator = _CHECKSUM_VALIDATORS["iban_mod97"]
    across_a_break = IBAN[:12] + "\n" + IBAN[12:]
    assert not any(validator(c) for c in generator(across_a_break)), (
        "a line break now joins two halves into one candidate")
