"""5D Risk Governance Engine — Policy definition and YAML loader.

4-band thresholds, dimension weights, tool defaults, bash overrides,
and risk-based model routing floors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .schema import Band, DIMENSION_NAMES


# Low→high band ordering, used to compare floor bands against computed bands.
_FLOOR_BAND_ORDER = (Band.GREEN, Band.YELLOW, Band.ORANGE, Band.RED)

# ReDoS hygiene (OSS-REDOS-HYGIENE-001): a per-scan input-length cap that bounds the worst-case
# backtracking window BEFORE a regex axis scans. This is the tunable knob (module default; a
# deployment may lower it). A truncated haystack still scans the LITERAL (``command_contains``) and
# membership (``fields``/``list_ref``) axes fully — only the regex axes (``patterns``/``command_regex``)
# read the capped text. The default is generous enough that no shipped preset / test input is
# affected (never-perturb-existing holds): it exists to defang a crafted megabyte-scale backtracking
# payload, not to change any real floor outcome. NOTE the engine is NOT swapped (RE2/rust deferred
# per the tech-scout); this is the €0 hygiene that makes an eventual linear-time swap a half-day.
_MAX_HAYSTACK_CHARS = 100_000


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> "re.Pattern[str] | None":
    """Compile-cache a pattern; None if it does not compile (fail-safe, caught at validate)."""
    try:
        return re.compile(pattern)
    except re.error:
        return None


# ReDoS pattern-linter (OSS-REDOS-HYGIENE-001). Authoring-time WARNING only — it never rejects a
# pattern (a reviewed pattern may legitimately trip a heuristic). It flags the classic catastrophic
# shapes an eventual RE2/Rust swap would have to rewrite. Called from ``fivedrisk validate``.
_REDOS_LINTS: "tuple[tuple[re.Pattern[str], str], ...]" = (
    (re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]"),
     "nested quantifier: a quantified group under another quantifier — exponential backtracking risk"),
    (re.compile(r"\.\*.*\.\*"),
     "multiple unbounded '.*' runs — polynomial backtracking on a crafted input"),
    (re.compile(r"\([^)]*\|[^)]*\)\s*[+*]"),
     "quantified alternation group — overlapping alternatives with a quantified tail can blow up"),
)

# Constructs a linear-time engine (RE2 / Rust `regex`) does NOT support — the corpus-audit inventory.
_NONLINEAR_CONSTRUCTS: "tuple[tuple[re.Pattern[str], str], ...]" = (
    (re.compile(r"\\[1-9]"), "backreference"),
    (re.compile(r"\(\?="), "lookahead"),
    (re.compile(r"\(\?!"), "negative lookahead"),
    (re.compile(r"\(\?<"), "lookbehind"),
)


def lint_redos_pattern(pattern: str) -> list[str]:
    """Return authoring-time ReDoS warnings for one regex pattern (never rejects; warn-only)."""
    return [msg for rx, msg in _REDOS_LINTS if rx.search(pattern)]


def audit_pattern_construct(pattern: str) -> list[str]:
    """Return the non-linear constructs (backref/lookaround) a linear-time engine could not run.

    The pre-work inventory for a deferred RE2/Rust swap — reported by ``fivedrisk validate --audit``.
    """
    return [name for rx, name in _NONLINEAR_CONSTRUCTS if rx.search(pattern)]


def _regex_search(pattern: str, haystack: str) -> bool:
    """Compiled-regex membership for the OPT-IN ``command_regex`` axis. Falls back to a literal
    substring test only when the pattern does not compile (defense-in-depth; `validate` rejects an
    uncompilable ``command_regex`` before deploy). NOTE: ``command_contains`` does NOT route here —
    it is a plain LITERAL match (see ``_literal_contains``) so a metachar-bearing literal such as
    ``"rm -rf $HOME"`` fires exactly like the pre-upgrade substring gate rather than silently
    under-matching because ``$``/``(`` acquire regex meaning (F1)."""
    rx = _compiled(pattern)
    if rx is None:
        return pattern in haystack
    return rx.search(haystack) is not None


def _literal_contains(needle: str, haystack: str) -> bool:
    """Plain substring membership — byte-compatible with the pre-upgrade ``command_contains`` gate.
    No regex meaning is given to metacharacters, so a floor keyed on ``"rm -rf $HOME"`` or ``"cmd(x)"``
    still fires (the F1 fix: substring→regex on ``command_contains`` had silently WEAKENED such
    literals). For real-regex semantics operators opt in via the separate ``command_regex`` field."""
    return needle in haystack


# ─── Deterministic check-digit validators (patent-safe: pure booleans, no score, no fusion) ───
# The G2 pattern-floor boundary: a structural pattern may be a tier-1 hard block ONLY when a
# check digit confirms the identifier is genuinely valid — otherwise a format-only match false-
# blocks ~90-99% of look-alikes (measured). These validate; they never classify or score.

def luhn(number: str) -> bool:
    """Luhn (mod-10) check-digit validity for a candidate PAN. Non-digits (spaces/dashes) are
    ignored; a sequence outside the 12-19 digit PAN range is rejected so a short/long number
    never floor-blocks.

    Digit test is ``str.isdecimal`` (Unicode category Nd), NOT ``str.isdigit``. The two differ on
    category-No characters — ``"²".isdigit()`` is True but ``int("²")`` raises, so the shipped
    ``isdigit`` form raised ValueError out of a hard floor on any superscript-bearing input (a
    crash in a gate, reachable from user text). Nd is also exactly what the ``\\d`` extractor
    matches, so validator and extractor now share ONE alphabet by construction — the property
    whose absence made every non-ASCII PAN invisible to the extractor while ``luhn`` accepted it.
    """
    digits = [int(c) for c in number if c.isdecimal()]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_IBAN_SHAPE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")


# The separators a PRINTED IBAN is actually broken on, beyond whitespace. ISO 13616 groups an IBAN
# in fours for human transcription, and what sits between the groups is whatever the source document
# used — which is very often not a space.
#
# OSS-19 2B. ``iban_mod97`` stripped ``\s`` alone, so an IBAN printed with a HYPHEN, or one carrying
# a ZERO-WIDTH character from a copy-paste out of a web page or a PDF, was rejected as malformed.
# That is a FAIL-OPEN and not a strictness: the caller's question is "is this a valid IBAN", and
# answering "no" to a valid IBAN with an invisible character in it means a value the operator can
# see is an IBAN is treated as though it were not one.
#
# The zero-width set is the load-bearing half. ZWSP/ZWNJ/ZWJ/word-joiner/BOM survive copy-paste,
# render as nothing, and are therefore invisible in every review that would otherwise catch them.
# A validator that fails open on a character no human can see fails open silently by construction.
#
# DELIBERATELY SCOPED TO THIS VALIDATOR. The PAN separator set (``_GROUP_SEPARATORS`` below) carries
# the same zero-width gap, and closing it there changes measured card false-block rates — that is
# its own pre-registered piece of work and is not smuggled in here.
_IBAN_SEPARATORS_BEYOND_WHITESPACE = frozenset(
    "-"                     # ASCII hyphen-minus, the ordinary printed grouping
    "­‑‒–"   # soft hyphen, non-breaking hyphen, figure dash, en dash
    "​‌‍⁠﻿"  # ZWSP, ZWNJ, ZWJ, word-joiner, ZWNBSP/BOM
)
# ``\s`` is KEPT as well as, never instead of: it reaches Unicode spaces (U+2000-2006, U+205F,
# U+3000, U+1680) that an explicit set would quietly drop, and narrowing the validator while
# widening it is exactly the kind of trade nobody notices.
_IBAN_STRIP = re.compile(
    "[\\s" + re.escape("".join(sorted(_IBAN_SEPARATORS_BEYOND_WHITESPACE))) + "]")

# The same alphabet, as an EXTRACTOR class. One character run between printed groups, horizontal
# whitespace OR one of the separators above. Line breaks stay excluded: an IBAN ending a line and
# joined to an uppercase token on the next is the bleed the uppercase/contiguous split exists to
# prevent. Run capped at ``_MAX_SEPARATOR_RUN`` (2) — longer is column padding in a laid-out table,
# not a printed IBAN's grouping.
_IBAN_SEP_CLASS = ("(?:[^\\S\\r\\n]|["
                   + re.escape("".join(sorted(_IBAN_SEPARATORS_BEYOND_WHITESPACE))) + "])")
_IBAN_CANDIDATE_UPPER = r"[A-Z]{2}[0-9]{2}(?:" + _IBAN_SEP_CLASS + r"{0,2}[A-Z0-9]){10,30}"


def iban_mod97(iban: str) -> bool:
    """ISO 13616 IBAN mod-97 validity.

    Whitespace, printed group separators (hyphen and dash forms) and zero-width characters are
    stripped, and the value is case folded; a value whose shape is not a well-formed IBAN (or whose
    mod-97 remainder != 1) is rejected.
    """
    s = _IBAN_STRIP.sub("", iban).upper()
    if not _IBAN_SHAPE.fullmatch(s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


# Unicode decimal digits (Nd), NOT ``[0-9]`` — the validator's alphabet. An ASCII-only extractor
# in front of a Unicode-aware validator is a silent fail-open: a PAN typed on a CJK-locale form or
# an IME (fullwidth U+FF10-19, Arabic-Indic U+0660-69) yielded ZERO candidates and walked through a
# tier-1 floor with no tooling at all.
_DIGIT_GROUP = re.compile(r"\d+")

# A printed PAN's group separator is whatever the source document used. ``luhn`` ignores every
# one of these; the extractor previously linked groups on exactly one of ``" "`` or ``"-"``, so a
# PAN pasted out of Word, a PDF, an HTML email or a spreadsheet cell (NBSP, thin space,
# non-breaking hyphen, en dash, tab, newline) or merely typed with a double space silently missed.
# Same root class as the alphabet gap: the validator was strictly more permissive than the
# extractor, and the extractor is the gate.
_GROUP_SEPARATORS = frozenset(
    " -"                                            # ASCII space / hyphen-minus
    "\t\n\r\f\v"                                    # spreadsheet cell, wrapped line, email body
    "     ⁠"          # NBSP, figure/thin/hair/narrow-NBSP, word-joiner
    "­‑‒–"                      # soft hyphen, non-breaking hyphen, figure/en dash
)
# A separator RUN longer than this is a layout gap (column padding), not a printed PAN's grouping.
# 2 admits the ordinary double space without letting an aligned table become one digit chain.
_MAX_SEPARATOR_RUN = 2

# Cheap first-character prune for :func:`_iin_plausible` — every issuer range below starts 2-6.
_IIN_LEAD = frozenset("23456")

# The group widths a payment card is actually PRINTED in. Card-scheme print grouping is a CLOSED
# set, and that closure is the structural fact this module had not been using: an EMBEDDED window
# asserts "a card number is typed here, next to something else", so the window must be SHAPED like
# a printed card — not merely be a Luhn-valid run of digits. The old form accepted every
# group-subsequence in [12,19], which is why the false-block rate scaled with chain length: a
# 12-group chain offers 19 windows, each clearing Luhn ~1-in-10.
_PAN_PRINT_GROUPINGS = frozenset({
    (4, 4, 4, 4),        # 16 — Visa, Mastercard, Discover, JCB, UnionPay-16
    (4, 4, 4, 4, 3),     # 19 — Visa-19, UnionPay-19
    (4, 6, 5),           # 15 — American Express
    (4, 6, 4),           # 14 — Diners Club
})

# Digits of the chain lying OUTSIDE the window. The embedded class exists to catch ONE printed
# card standing beside a short token in the same separator run — a sequence number, a batch id, an
# ISO date, a bank account number, a phone number. Past that the chain is a ledger run and a
# window cut out of its middle is not an identifier anybody printed.
#
# RAISED 8 -> 11 (2026-08-07). 8 was set to the width of an ISO date and was assumed to be the
# widest adjacent token; that assumption was wrong, and the two commonest identifiers a card is
# accidentally printed next to are both wider — a 9-digit bank account / ABA routing number and a
# 10-digit phone number. At 8 those were silently undetected for EVERY card scheme, on both
# sides, which is the shape the embedded class exists to catch. Measured cost of the raise on the
# mixed-width strata: 5 groups 0.57%, 6 groups 0.53%, 8 groups 0.17%, 12 groups 0.00% —
# Wilson95 upper 0.91%, inside the 2.00% budget. 11 is the widest token that keeps that true.
_MAX_EMBEDDED_CONTEXT_DIGITS = 11

# Lever A — ISSUER-LENGTH CONSISTENCY. IIN membership says a window starts in a published issuer
# range; it does not enforce what that range IMPLIES. Visa prints 13/16/19, Mastercard 16, Amex
# 15, Diners 14 (16/19 for the extended 36 range), JCB and UnionPay 16-19. A window whose IIN says
# Amex and whose length is 16 is not a card, and rejecting it costs no recall BY CONSTRUCTION —
# a real card satisfies its own scheme's length by definition.
#
# Deliberately a SUPERSET where a scheme's length is disputed (Diners 14/16/19, Discover 16/19,
# JCB/UnionPay 16-19). The falsifier for this lever is any recall loss on a generated PAN arm, so
# the table errs toward admitting: a narrower table would buy precision by rejecting real cards.
#
# EQUIVALENT-MUTANT NOTE (mutation audit 2026-08-07). Widening any entry to 17 or 18 kills no
# test, and cannot: no grouping in `_PAN_PRINT_GROUPINGS` sums to 17 or 18, so no embedded window
# is ever that long and those entries are unreachable. They stay because this table is a
# statement about what card SCHEMES print, not about what the extractor currently reaches — SHAPE
# owns reachability. Trimming it to the reachable lengths would silently start rejecting real
# cards the day a 17- or 18-digit grouping is added.
_ISSUER_LENGTHS: "tuple[tuple[str, tuple[int, ...]], ...]" = (
    ("visa", (13, 16, 19)),
    ("mastercard", (16,)),
    ("amex", (15,)),
    ("discover", (16, 19)),
    ("diners", (14, 16, 19)),
    ("jcb", (16, 17, 18, 19)),
    ("unionpay", (16, 17, 18, 19)),
)

# A printed card's expiry is MMYY, and it is the ONE token that corroborates rather than
# contradicts a card reading — see the CADENCE exception in :func:`_digit_run_candidates`. Only
# the month is constrained: a year range would be a threshold picked to hit a false-block number,
# and an expiry in the past is exactly what a leaked historical record contains.
_MAX_MONTH = 12


def _iin_schemes(digits: str) -> "tuple[str, ...]":
    """Which published issuer ranges a candidate's leading digits fall inside (possibly several).

    Sole owner of the IIN table. :func:`_iin_plausible` and :func:`_length_consistent` are both
    thin readings of this, so the membership test and the length test can never disagree about
    what scheme a prefix belongs to.
    """
    if len(digits) < 6:
        return ()
    p2, p3, p4, p6 = int(digits[:2]), int(digits[:3]), int(digits[:4]), int(digits[:6])
    hit = []
    if digits[0] == "4":
        hit.append("visa")
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        hit.append("mastercard")
    if p2 in (34, 37):
        hit.append("amex")
    if p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925:
        hit.append("discover")
    if 300 <= p3 <= 305 or p4 == 3095 or p2 == 36 or p2 in (38, 39):
        hit.append("diners")
    if 3528 <= p4 <= 3589:
        hit.append("jcb")
    if p2 == 62:
        hit.append("unionpay")
    return tuple(hit)


def _length_consistent(digits: str) -> bool:
    """Lever A. Does the candidate's LENGTH match what its own issuer range prints?

    A NARROWING CONJUNCT with zero recall cost by construction: a real card is issued at one of
    its scheme's lengths, so this can only reject windows that were never cards. Where a prefix
    falls in several ranges the union is taken, so an ambiguous prefix is never punished for the
    ambiguity.

    MEASURED PRECISION GAIN, AND IT IS SMALL — this is stated because it falsifies the
    prediction that motivated the lever. Over all 10^6 six-digit prefixes, IIN mass falls from
    28.84% to 26.84% at 16 digits: the only ranges 16 excludes are Amex (2.00%) and, on the
    narrowest defensible Diners table, Diners (3.61%). Sixteen digits is what Visa, Mastercard,
    Discover, JCB and UnionPay ALL print, so no length table can take 16-digit windows below
    23.23% and no length table can take the 16-digit floor below 10.006% x 23.23% = 2.33%. The
    lever is real and free at 13/14/15/17/18/19 digits; at 16 it cannot reach the 2.00% budget,
    and 16 is where the false-block mass lives.
    """
    lengths: "set[int]" = set()
    table = dict(_ISSUER_LENGTHS)
    for scheme in _iin_schemes(digits):
        lengths |= set(table[scheme])
    return len(digits) in lengths


def _expiry_shaped(group: str) -> bool:
    """Is this 4-digit group readable as a printed card expiry, MMYY?

    Month only (see :data:`_MAX_MONTH`). Used solely to corroborate a card reading in a
    uniform-cadence chain; never to reject one.

    EQUIVALENT-MUTANT NOTE (mutation audit 2026-08-07). Deleting the ``len(group) == 4`` test
    kills no test, and cannot: the only caller is :func:`_card_plus_expiry`, which runs only on a
    uniform chain whose window already passed SHAPE, and ``(4, 4, 4, 4)`` is the sole all-equal
    grouping in :data:`_PAN_PRINT_GROUPINGS` — so every group reaching here is 4 wide. The check
    is kept because MMYY is four digits BY DEFINITION and this predicate is named for that, not
    for its caller: without it ``"12"`` would read as a December.
    """
    return len(group) == 4 and 1 <= int(group[:2]) <= _MAX_MONTH


def _iin_plausible(digits: str) -> bool:
    """True when a candidate starts inside a published card-issuer (IIN/BIN) range.

    A NARROWING CONJUNCT, not a classifier: pure boolean, no score, no fusion (patent-safe).
    Luhn alone accepts ~1 in 10 arbitrary digit runs; requiring a real issuer prefix cuts that
    by ~3x. Measured recall cost: 0/12000 synthetic PANs rejected across Visa, Mastercard (both
    51-55 and the 2221-2720 2-series), Amex, Discover, Diners, JCB and UnionPay — so it is
    strictly dominant over a length gate, which buys the same FP reduction only at 16 digits and
    costs 900/2400 genuine detections.

    Deliberately NOT applied to EXACT candidates (see :func:`_digit_run_candidates`): a
    private-label or unusual BIN printed as its own value must still floor-block. This gates only
    the speculative embedded windows, where the false-block mass actually lives.
    """
    return bool(_iin_schemes(digits))


def _rx_candidates(*patterns: "re.Pattern[str]") -> "Any":
    """Candidate generator built from bounded extractor patterns (no catastrophic backtracking)."""
    def _gen(text: str) -> "list[str]":
        return [m.group(0) for rx in patterns for m in rx.finditer(text)]
    return _gen


def _is_single_cadence(widths: "list[int]") -> bool:
    """Is this chain printed in ONE uniform group width, i.e. is it a single formatted reference?

    A NARROWING CONJUNCT for the embedded class (see :func:`_digit_run_candidates`), and the one
    that removes the false-block rate's scaling with chain length. Lot codes, serial numbers, GL
    account chains and employee-id runs are printed as a repeated fixed-width group; a payment
    card is printed in a grouping that TERMINATES at the card. So a window cut out of a uniform
    run is a cut through the middle of one reference, not a card standing next to something.

    NOT sufficient on its own — see :func:`_card_plus_expiry` for the one uniform chain that IS a
    card, and :func:`_digit_run_candidates` for what this conjunct cannot do.
    """
    return len(set(widths)) == 1


def _card_plus_expiry(widths: "list[int]", groups: "list[str]", i: int, j: int) -> bool:
    """Lever B. Is this uniform-cadence chain a card printed WITH ITS EXPIRY, not a reference?

    The corroborating-context lever and the CADENCE conjunct are the same problem with the sign
    flipped, and that is why they are one function. CADENCE discards a window because its
    neighbour repeats the cadence — but the strongest evidence that a digit window really is a
    printed card, the expiry date beside it, is a 4-digit token, which is exactly the card's own
    group width. So the commonest accidental card egress there is, ``4539 5787 6362 1486 0912``,
    makes the chain uniform and CADENCE throws it away. The signal and the suppressor were the
    same feature; this is the sign flip.

    The exception is a POSITIVE description of one artefact rather than a threshold: the chain is
    exactly one card grouping PLUS ONE further group, and that group reads as MMYY. Card-then-
    expiry and expiry-then-card both qualify; nothing else in a uniform chain does.

    Bounded by construction, which is the property CADENCE existed to protect. At most two windows
    are admitted and only from a 5-group chain, so this cannot reintroduce the scaling with chain
    length — a 12-group ledger run still yields nothing at all.
    """
    if len(widths) != (j - i + 1) + 1:
        return False                      # more than one group of context: a run, not an expiry
    return _expiry_shaped(groups[0] if i else groups[-1])


def _separator_links(gap: str) -> bool:
    """Do these characters BETWEEN two digit groups join them into one printed identifier?"""
    return 0 < len(gap) <= _MAX_SEPARATOR_RUN and all(c in _GROUP_SEPARATORS for c in gap)


def _digit_chains(text: str) -> "list[tuple[str, list[int]]]":
    """Separator-linked digit runs, each as (ASCII-normalised digits, group-boundary offsets).

    Normalisation is 1:1 per character, so the offsets index the normalised string directly.
    """
    chains: "list[tuple[str, list[int]]]" = []
    current: "list[str]" = []
    prev_end = -1
    for m in _DIGIT_GROUP.finditer(text):
        if current and _separator_links(text[prev_end:m.start()]):
            current.append(m.group(0))
        else:
            if current:
                chains.append(_normalise(current))
            current = [m.group(0)]
        prev_end = m.end()
    if current:
        chains.append(_normalise(current))
    return chains


def _normalise(groups: "list[str]") -> "tuple[str, list[int]]":
    raw = "".join(groups)
    whole = raw if raw.isascii() else "".join(str(int(c)) for c in raw)
    offsets = [0]
    for g in groups:
        offsets.append(offsets[-1] + len(g))
    return whole, offsets


def _digit_run_candidates(text: str, lo: int = 12, hi: int = 19,
                          *, embedded: bool = True) -> "list[str]":
    """Candidate identifiers from one field's text, length-windowed to [lo, hi].

    TWO CLASSES, and the distinction is the whole design:

    * EXACT — the value a human reads as ONE identifier: a whole separator-linked chain
      (``4111 1111 1111 1111``), or a single digit group inside a longer chain
      (``4111111111111111`` in ``"445 4111111111111111 99"``). Grouping is presentation, so an
      exact candidate is grouping-INVARIANT by construction: the contiguous and the spaced
      rendering of one value produce the identical candidate. Measured false-block rate 0.0% at
      every chain-length stratum from 3 to 12 groups (n=1500/stratum), 0 misses on lone PANs.
    * EMBEDDED — a Luhn window spanning SOME of a longer chain (the PAN in
      ``"4111 1111 1111 1111 12"``). This is the only way to catch a PAN printed next to a
      sequence number, and it is where 100% of the false-block mass lives, because
      ``"4539 5787 6362 1486 12"`` is byte-identical whether it is (PAN, sequence) or one
      18-digit reference.

      FIVE NARROWING CONJUNCTS, all structural, all pure booleans. The first shipped already;
      the rest closed the length-scaling defect (42.2% at 12 groups -> 0.0%). The defect was
      never a threshold to tune: the rate was a function of HOW MANY windows the chain offers,
      so it had to be cut by admitting fewer windows, not by accepting fewer of them.

      1. IIN — the window starts inside a published issuer range (:func:`_iin_plausible`).
         ~3x fewer windows, 0/12000 recall cost.
      2. LENGTH — the window's length is one its own issuer range actually prints
         (:func:`_length_consistent`). Zero recall cost by construction, 0/12000 measured. Real
         but SMALL: at 16 digits it moves IIN mass only 28.84% -> 26.84%, because 16 is what
         Visa, Mastercard, Discover, JCB and UnionPay all print. See that function for why no
         length table can bring the 16-digit floor under the 2.00% budget.
      3. SHAPE — the window's group widths are a grouping a card is actually PRINTED in
         (:data:`_PAN_PRINT_GROUPINGS`). Kills every window cut at a non-card boundary; this
         alone takes 4 groups to 0.0% and 12 groups to 24.5%.
      4. CONTEXT — at most :data:`_MAX_EMBEDDED_CONTEXT_DIGITS` digits of the chain lie outside
         the window. A card printed beside a date, an account number or a phone number, not a
         window carved out of a ledger run.
      5. CADENCE — a chain whose groups ALL have the same width yields no embedded windows
         UNLESS the chain is one card grouping plus a single MMYY group
         (:func:`_card_plus_expiry`). One uniform cadence is normally one printed reference: lot
         codes, serial numbers, GL account chains and employee-id runs are formatted that way and
         cards are not. The exception exists because a card printed with its expiry is uniform by
         coincidence — an expiry is 4 digits and so is a card's group — so the unqualified rule
         discarded the commonest accidental egress there is.

      MEASURED COST, stated because every one of these is also an evasion path (a narrowing
      always is). What is NOT detected, and it is a declared limit rather than a queued fix:

      * a card in a NON-canonical grouping inside a longer chain (``"45395 78763 62148 6 12"``),
        SHAPE. The realistic instance is a 15- or 14-digit card re-cut into 4s — ``"3782 8224
        6310 005 12"`` rather than the printed ``"3782 822463 10005 12"``. In their OWN print
        groupings Amex 4-6-5, Diners 4-6-4 and Visa-19 4-4-4-4-3 miss 0/800 each, beside a
        neighbour included.
      * a card padded into the INTERIOR of a uniform-cadence chain — both sides, or a longer run
        (``"1234 4539 5787 6362 1486 5678"``). Closing this means admitting interior windows of a
        uniform chain, measured at 5.63% false-block for 5 groups, 8.00% at 6, 10.73% at 7,
        15.70% at 9 and 21.80% at 12 (n=3000/stratum) against a 2.00% budget. It is not closable
        at any price the budget allows.
      * a card between a label and its expiry, all one width (``"1111 <card> 1225"``). Widening
        the CADENCE exception from one context group to two recovers this 200/200 and costs 2.23%
        [Wilson95 2.83%] at 6 uniform groups — over budget, so it is withdrawn on the
        measurement.

      A card IS detected printed alone, contiguously, in prose, hyphenated, or beside a single
      neighbour of ANY width from 1 to 11 on either side — 132 scheme x width x side cells at
      200/200 each, which is the arm that governs. That claim was previously written as "beside
      any token of a DIFFERENT width" and it was FALSE: at ``_MAX_EMBEDDED_CONTEXT_DIGITS`` = 8
      every scheme missed every neighbour of width 9 or more, on both sides, and the recall arm
      sampled only widths 2 and 8 so it could not see it. The constant is now 11 and the arm
      sweeps 1..11.

      The embedded class is a backstop against ACCIDENTAL card egress, which is printed
      canonically. It is not, and cannot be, an anti-evasion control — an attacker who pads a
      card into a uniform run defeats it for 10 added characters, and the arithmetic above is why
      that cannot be fixed rather than an admission that it has not been.

    ``embedded=False`` yields the exact class alone — registered as ``luhn_exact`` so a deployer
    can author the precise class as a terminal block and the speculative class as an escalation,
    using the shipped per-rule :attr:`FloorRule.band`. Nothing here scores or fuses; both classes
    are independent booleans and the disposition is config, not code.

    BOUNDED WORK, WITHOUT TRUNCATION. The previous form returned early at a 256-candidate cap,
    which TRUNCATED the candidate list — a silent fail-OPEN reachable with no adversary (86
    benign order references before a PAN in one memo field, 2171 chars: 85 fired, 86 did not).
    A detection bound may degrade, refuse or escalate; it may never truncate and return False.
    The cap is gone. Work is now linear in the input: a chain of g groups yields at most
    g*(hi-lo+1) windows because the inner loop breaks past ``hi``, so no cap is needed for
    boundedness. The declared bound is the SHIPPED ``_MAX_HAYSTACK_CHARS`` (100,000 chars per
    field value), enforced fail-CLOSED in :func:`_checksum_hit` exactly as :func:`_patterns_hit`
    already does for ReDoS. Named overflow input: any single field value above that length —
    the axis fires rather than skipping the check.
    """
    out: "list[str]" = []
    for whole, offsets in _digit_chains(text):
        last = len(offsets) - 2                      # index of the final group
        widths = [offsets[k + 1] - offsets[k] for k in range(last + 1)]
        if lo <= len(whole) <= hi:
            out.append(whole)
        if last:                                     # multi-group chain: each group on its own
            for k in range(last + 1):
                if lo <= widths[k] <= hi:
                    out.append(whole[offsets[k]:offsets[k + 1]])
        if not embedded or not last:
            continue
        uniform = _is_single_cadence(widths)
        groups = [whole[offsets[k]:offsets[k + 1]] for k in range(last + 1)]
        for i in range(last + 1):
            a = offsets[i]
            if whole[a] not in _IIN_LEAD:            # cheap prune before any slicing
                continue
            for j in range(i, last + 1):
                length = offsets[j + 1] - a
                if length > hi:
                    break
                if length < lo or i == j or (i, j) == (0, last):
                    continue                         # already emitted as EXACT
                if tuple(widths[i:j + 1]) not in _PAN_PRINT_GROUPINGS:
                    continue                         # SHAPE
                if len(whole) - length > _MAX_EMBEDDED_CONTEXT_DIGITS:
                    continue                         # CONTEXT
                if uniform and not _card_plus_expiry(widths, groups, i, j):
                    continue                         # CADENCE, less its corroborated exception
                candidate = whole[a:offsets[j + 1]]
                if _iin_plausible(candidate) and _length_consistent(candidate):
                    out.append(candidate)
    return out


def _digit_run_candidates_exact(text: str, lo: int = 12, hi: int = 19) -> "list[str]":
    """The EXACT class only — see :func:`_digit_run_candidates`. Registered as ``luhn_exact``."""
    return _digit_run_candidates(text, lo, hi, embedded=False)


# Registry: validator name -> (candidate generator, boolean validator). The generator pulls
# plausibly-shaped tokens from ONE field's text; the validator confirms the check digit — so a
# ``checksum`` axis fires only on a genuinely-valid identifier. Two IBAN extractors so a
# candidate is found whether the IBAN is UPPERCASE (spaced OR contiguous — the standard printed
# form) or lowercase/contiguous, WITHOUT a case-insensitive space-tolerant pattern bleeding across
# whitespace into adjacent lowercase prose and corrupting an otherwise-valid neighbouring token
# (that bleed silently dropped the DE-corner token). iban_mod97 case-folds + strips spaces, so
# validation is case-agnostic; the split is purely about clean tokenisation (F-B: a lowercase IBAN
# now yields a candidate; the uppercase space-tolerant branch keeps spaced/cornered tokens clean).
# A lowercase-AND-spaced IBAN is out of scope (not required; documented).
#
# FALSE-POSITIVE NOTE — REWRITTEN 2026-08-06. The previous text claimed the near-zero floor was
# "a property of the COMPOSED rule (the shipped template ANDs a ``fields`` axis ..., measured
# 0-1/that)". That sentence was FALSE in three independent ways and is retained here only as the
# defect it was:
#   1. ``fields`` and ``checksum`` are ANDed INDEPENDENT predicates. An AND cannot improve the
#      conditional precision of its other conjunct. Conditional on a value sitting in a field the
#      rule scopes to, the composed rule fires at EXACTLY the bare rate — measured identical on
#      500/500 probes. ``fields`` buys EXPOSURE reduction, never PRECISION.
#   2. The denominator was wrong. 0/that was over ALL calls, not over calls the rule can fire on.
#      A 0-numerator claim over an in-scope stratum of n=0 is not quotable at all; it first
#      reaches the <=20% tier at n=16, <=10% at n=35, <=5% at n=73.
#   3. The corpus behind that figure was never committed anywhere, so the number was also
#      unreproducible: it was quoted without its artifact.
#      There is likewise no "shipped template" — ``luhn`` appears in no policy YAML in this repo.
#
# WHAT IS ACTUALLY MEASURED (2026-08-07, n=3000 per stratum, non-PAN values in a scoped field,
# report both arms or neither):
#
#   validator      4 groups  5 groups  6 groups  8 groups  12 groups | misses on valid PANs
#   luhn_exact         0.0%      0.0%      0.0%      0.0%       0.0% | 900/2400 (PAN sharing a
#                                                                    | digit chain with a neighbour)
#   luhn (before)      6.6%     13.4%     18.0%     26.4%      42.2% | 0/2400
#   luhn (now)         0.0%      0.0%      0.0%      0.0%       0.0% | 0/2400
#
# Uniform-cadence strata alone would be a self-flattering measurement (the corpus generator emits
# only those, and CADENCE targets exactly them), so the same arms were re-run on NON-uniform chains
# with widths drawn from {2,3,4,5,6}: 0.40% at 5 groups, 0.23% at 6, 0.00% at 8 and 12 (n=3000).
#
# THE RESIDUAL, which no narrowing removes. On the shape ``<3-digit id> <16 digits printed 4-4-4-4>
# <2-digit id>`` the rate is 87/3000 = 2.90% [Wilson95 2.35-3.56]. That value is byte-identical to
# (batch, PAN, qty); it is the collision the corpus proves irreducible, and 2.90% is simply
# P(Luhn) x P(IIN-plausible) = 10% x 29% for the ONE window such a chain offers. Any candidate
# class that admits even one PAN-shaped embedded window therefore has a ~2.9% false-block floor,
# which is ABOVE the 2.00% terminal-block budget. The budget is not reachable by narrowing; it is
# reachable only by admitting zero embedded windows, i.e. by ``luhn_exact``.
#
# So the two classes are a DISPOSITION choice and neither is "better":
#   luhn_exact — 0.0% everywhere. The only class that meets a terminal-block budget. Misses a
#                PAN that shares a digit chain with a neighbour (900/2400).
#   luhn       — 0.0% on uniform chains, <=0.40% on mixed chains, 2.90% on the irreducible shape.
#                0/2400 misses. Correct disposition is ESCALATION (``band:`` is per-rule).
# Authoring ``luhn`` at RED on digit-dense free text is still an outage, now a 2.9% one.
_CHECKSUM_VALIDATORS: "Dict[str, tuple[Any, Any]]" = {
    "iban_mod97": (
        _rx_candidates(
            # OSS-19 2A (2026-08-12) — EXTRACTOR/VALIDATOR PARITY. **INERT ON ITS OWN.**
            #
            # The extractor admitted exactly one ASCII space while ``iban_mod97`` strips every
            # Unicode whitespace character, so the VALIDATOR was strictly more permissive than the
            # EXTRACTOR and the extractor is the gate. Measured: an IBAN printed with a double
            # space, a tab, or an NBSP produced no candidate at all — the same root class as the
            # PAN separator gap fixed above, and a rule that cannot see its identifier does not
            # fail loudly, it simply never fires.
            #
            # WHAT THIS DOES NOT DO, AND THE MEASUREMENT THAT SAYS SO. A composed rule ANDs a
            # ``patterns`` axis with this ``checksum`` axis, and the shipped sanctions-IBAN template
            # carries the SAME single-space restriction in its pattern. So widening the extractor
            # alone changes NOTHING observable — the other conjunct still gates. 2x2 over a 20,000
            # value benign population of payment-document identifiers (EORI, MRN, VAT, tracking):
            #
            #                        pattern shipped   pattern widened
            #     extractor shipped          0.050%            0.050%
            #     extractor widened          0.050%          **0.175%**
            #
            # THE ABSOLUTE RATES ABOVE ARE NOT QUOTABLE AND ARE RECORDED HERE ONLY AS THE
            # MEASUREMENT THAT JUSTIFIED THIS CHANGE. The benign corpus that produced them no
            # longer exists and cannot be reproduced, so they are not a standing figure and must
            # not be cited outside this comment. What survives reproduction is the RATIO, 3.5x.
            # A rebuilt corpus would be authored after the result was already known, which is a
            # rationale and not a pre-registration, so rebuilding does not make these quotable
            # either; it changes what they can honestly say. A number whose corpus cannot be re-run
            # is evidence for the decision that was taken, not a property of the shipped code.
            #
            # **Neither widening alone moves the benign-fire rate; only both together** — and both
            # together is 3.5x the baseline. The pre-registered withdrawal threshold for this work
            # is *"if widening the separator class moves any existing stratum, withdraw and
            # re-scope"*, and every re-scope tried moves it too (run<=1 horizontal whitespace:
            # 0.130%, closing 6 of 7 forms; run<=2: 0.175%, closing 7 of 7). **There is no free
            # version.**
            #
            # So the TEMPLATE half is withheld pending a ruling on the trade — closing a total
            # evasion on a sanctions rule against +0.125pp benign escalation, on a rule that is now
            # tier-3 routed and therefore recoverable. This half lands because it is measured inert,
            # it removes a real validator/extractor inconsistency, and it is a precondition for both
            # the ruling and for 2B.
            #
            # ``[^\S\r\n]`` is horizontal whitespace: space, double space, tab, NBSP, thin/narrow
            # spaces. Line breaks are DELIBERATELY excluded. An IBAN ending a line, joined across
            # the break to an uppercase token starting the next, is precisely the bleed the
            # uppercase/contiguous split above exists to prevent, and admitting ``\n`` here would
            # reintroduce it on the widest branch.
            #
            # Run capped at 2, matching ``_MAX_SEPARATOR_RUN``: a longer run is column padding in a
            # laid-out table, not a printed IBAN's grouping.
            #
            # OSS-19 2B (2026-08-16) — ZWSP AND HYPHEN, the two forms 2A left open.
            #
            # They were left open on purpose, not missed: neither is whitespace, so ``\s`` matched
            # neither and ``[^\S\r\n]`` could not reach them, and admitting a candidate the validator
            # would then reject buys nothing. ``iban_mod97``'s contract is widened first (see
            # ``_IBAN_SEPARATORS_BEYOND_WHITESPACE`` above) and this class follows it, so extractor
            # and validator move together — the parity 2A was about in the first place.
            #
            # The separator class is BUILT FROM THE SAME FROZENSET the validator strips, rather than
            # written out again here. Two hand-maintained copies of one alphabet is precisely how the
            # original gap opened: the validator stripped a class the extractor could not produce.
            #
            # The extras need ALTERNATION, not insertion. ``[^\S\r\n]`` is a NEGATED class, so adding
            # a hyphen inside it would EXCLUDE the hyphen — the exact opposite of the intent, and it
            # would have read as correct.
            re.compile(_IBAN_CANDIDATE_UPPER),   # uppercase, separator-tolerant (run <= 2)
            re.compile(r"(?i)[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")),      # any case, contiguous
        iban_mod97,
    ),
    "luhn": (_digit_run_candidates, luhn),
    "luhn_exact": (_digit_run_candidates_exact, luhn),
}


# ─── Default weights (§12.3) ───────────────────────────────────
# Spec recommends: DS=0.30, TP=0.20, R=0.20, EI=0.15, AC=0.15
# We use absolute weights that produce a 0-3 normalized score range
DEFAULT_WEIGHTS = {
    "data_sensitivity": 1.2,     # DS: highest weight (0.30 relative)
    "tool_privilege": 1.0,       # TP: privilege escalation
    "reversibility": 1.5,        # R: irreversible is always worse
    "external_impact": 0.8,      # EI: external blast radius
    "autonomy_context": 0.8,     # AC: oversight modifies, doesn't dominate
}

# ─── Default tool classification baselines ──────────────────────
DEFAULT_TOOL_DEFAULTS: Dict[str, Dict[str, int]] = {
    "Read":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Glob":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Grep":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Edit":      {"tool_privilege": 1, "reversibility": 1, "external_impact": 0},
    "Write":     {"tool_privilege": 1, "reversibility": 1, "external_impact": 0},
    "Bash":      {"tool_privilege": 2, "reversibility": 2, "external_impact": 1},
    "WebFetch":  {"tool_privilege": 1, "reversibility": 0, "external_impact": 1},
    "WebSearch": {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
}

# ─── Bash command overrides ─────────────────────────────────────
DEFAULT_BASH_OVERRIDES: Dict[str, Dict[str, int]] = {
    "rm -rf":           {"tool_privilege": 4, "reversibility": 4},
    "docker":           {"tool_privilege": 3, "reversibility": 2},
    "git push --force": {"tool_privilege": 3, "reversibility": 4},
    r"curl.*POST":      {"tool_privilege": 2, "external_impact": 3},
    "pip install":      {"tool_privilege": 2, "reversibility": 1},
}


@dataclass(frozen=True)
class AxisPredicate:
    """One predicate axis of a floor / red-line rule: a value set + a match mode.

    ``mode="block"`` — the axis is TRUE (contributes to a match) when the action's value
        IS IN ``values`` (block THESE: sanctions, prohibited tools).
    ``mode="allow"`` — the axis is TRUE when the action's value is NOT in the permitted
        ``values`` (an off-allowlist value is the red-line hit), or when the action carries
        no value at all (unknown = deny, the fail-safe direction for asserted-label axes).
    ``match_mode`` applies to the ``patterns`` axis only: ``"any"`` fires on the first hit;
        ``"all"`` fires only when EVERY listed pattern co-occurs (the structurally-unambiguous
        multi-signal red line — e.g. a mod-97-valid IBAN AND a sanctioned prefix).
    ``negate_within`` / ``negate_cues`` add a TOKEN-WINDOW negator to the ``patterns`` axis
        (0 = off, the default → byte-identical to the pre-negation matcher). When ``negate_within
        > 0`` and cues are given, a pattern hit is SUPPRESSED if any cue token separates from the
        match span by at most ``negate_within`` intervening whitespace tokens. This is NOT lookbehind
        (both RE2 and the Rust ``regex`` crate drop lookbehind) — a forward+backward token-window
        scan over the already-matched span, so it is deterministic and backtracking-free. Negation
        only ever SUPPRESSES this axis's own ``patterns`` hit; it never touches a co-firing block-mode
        axis (AND-within — a multi-axis rule that also matches on tools/checksum/… still fires).
    """

    values: tuple[str, ...] = ()
    mode: str = "block"          # "block" | "allow"
    match_mode: str = "any"      # patterns axis: "any" | "all"
    negate_within: int = 0       # patterns axis: token-window negator radius (0 = off)
    negate_cues: tuple[str, ...] = ()  # cue tokens that suppress a nearby pattern hit


@dataclass(frozen=True)
class FieldValuePredicate:
    """Bind a predicate to a NAMED field's VALUE (not its key-name, not the joined haystack).

    The one missing composition: ``fields`` scopes KEY names, ``patterns``/``checksum`` scan the
    WHOLE joined haystack — neither can say "the VALUE of field ``amount`` matches this pattern".
    ``value_match`` resolves ``field`` case-insensitively on the tool_input KEY, then runs the
    predicate scoped to THAT field's value ONLY, reusing the shipped predicate helpers
    (``_patterns_hit`` for ``kind="regex"``, ``_literal_contains`` for ``"literal"``,
    ``_checksum_hit`` for ``"checksum"``). Pure boolean — no score, no fusion (patent-safe).

    ``mode`` mirrors :class:`AxisPredicate`: ``"block"`` fires when the value IS in/matches
    ``values``; ``"allow"`` fires when it is NOT (off-allowlist), OR when the field is ABSENT
    (unknown = deny, the fail-safe direction).
    """

    field: str                          # tool_input KEY name (case-insensitive)
    values: tuple[str, ...] = ()
    mode: str = "block"                 # block | allow  (AxisPredicate semantics)
    kind: str = "regex"                 # regex | literal | checksum
    match_mode: str = "any"             # regex/kind: any | all


@dataclass(frozen=True)
class FloorRule:
    """A policy floor / red-line rule: a hard minimum band for a matching action.

    A floored action is ALWAYS scored at least ``band`` regardless of its
    computed 5D score, and the floor cannot be lowered at runtime (drift and
    routing only escalate; nothing in the engine demotes below a floor). Use it
    for controls that must never depend on tuning — e.g. "any Bash command
    containing DROP TABLE is RED".

    Two authoring forms, ONE canonical matcher (``match_red_line`` / ``first_red_line_hit``):

    * Legacy single-tool floor — ``tool_name`` (+ optional ``command_contains`` / ``command_regex``).
      A rule matches when ``tool_name`` equals the action's tool and, if set, the command predicate
      is found in the action's input. ``command_contains`` is a plain LITERAL substring (byte-compatible
      with the pre-upgrade gate — a metachar-bearing literal like ``"rm -rf $HOME"`` or ``"cmd(x)"``
      still fires; F1). To close the documented casing/whitespace evasions an operator OPTS IN to real
      regex via the separate ``command_regex`` field (e.g. ``command_regex: '(?i)drop\\s+table'``);
      an uncompilable ``command_regex`` is rejected by ``fivedrisk validate`` before deploy.
    * Multi-axis red line — any of ``tools`` / ``destinations`` / ``patterns`` /
      ``data_classes`` / ``list_ref`` / ``checksum`` / ``fields`` (each an :class:`AxisPredicate`
      with its own ``mode``; ``fields`` scopes on the tool_input KEY names, case-insensitive).
      A rule matches when ALL of its specified axes are TRUE (AND-within); any
      matching rule in a set fires (OR-across). This is the ONE primitive over the shipped
      regex + destination machinery — no parallel matcher.

    ``fivedrisk validate`` warns when a RED/ORANGE floor is gated on ``command_contains``.
    """

    tool_name: Optional[str] = None
    band: Band = Band.RED
    command_contains: Optional[str] = None   # LITERAL substring (byte-compat, evadable — see validate)
    command_regex: Optional[str] = None      # OPT-IN real regex (closes casing/whitespace evasion)
    reason: str = ""
    # ── Multi-axis red-line predicates (additive; each honours its own allow/block mode) ──
    id: str = ""
    tools: Optional[AxisPredicate] = None
    destinations: Optional[AxisPredicate] = None
    patterns: Optional[AxisPredicate] = None
    data_classes: Optional[AxisPredicate] = None
    list_ref: Optional[AxisPredicate] = None
    checksum: Optional[AxisPredicate] = None   # check-digit-validated identifier (iban_mod97|luhn)
    fields: Optional[AxisPredicate] = None     # tool_input KEY-name scope (case-insensitive)
    value_match: Optional["FieldValuePredicate"] = None  # scope a predicate to a NAMED field's VALUE


@dataclass
class Policy:
    """Scoring policy for the 5D Risk Governance Engine.

    4-band system per governance spec v0.3 §12.4:
      GREEN  (normalized 0.0-0.9)  → Low risk
      YELLOW (normalized 1.0-1.7)  → Moderate risk
      ORANGE (normalized 1.8-2.4)  → High risk
      RED    (normalized 2.5+)     → Critical
    """

    version: str = "0.2.0"

    # ── 4-Band normalized score thresholds (§12.4) ──
    green_score: float = 0.0       # everything below yellow
    yellow_score: float = 1.0      # moderate risk
    orange_score: float = 1.8      # high risk
    red_score: float = 2.5         # critical

    # ── Single-axis spike thresholds ──
    red_threshold: int = 4         # any dim >= this → RED
    orange_threshold: int = 3      # any dim >= this → ORANGE (minimum)

    # ── Dimension weights ──
    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    # ── Tool baselines ──
    tool_defaults: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_TOOL_DEFAULTS.items()}
    )

    # ── Bash overrides ──
    bash_overrides: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_BASH_OVERRIDES.items()}
    )

    # ── Provenance ──
    # The packaged preset this policy was loaded from, if any. A preset is a
    # defensible posture ("we run read_only") where a bag of numbers is not, so
    # the NAME has to survive adoption and reach the decision record. Loading a
    # preset by path leaves this None, which is correct: a copied file is no
    # longer the preset, whatever it started as.
    preset_name: Optional[str] = None

    # ── Retry budget (per task) ──
    # ── Retry budget ──
    # How many times ONE action may be attempted within ONE session before it is denied.
    # OPT-IN: None enforces nothing. The right number is per action class, and depends on
    # whether this interception point sits below the caller's own retry policy, so it is not
    # a value to choose on a deployment's behalf.
    retry_budget: Optional[int] = None

    # ── Cost-management attributes ──
    # Budget breach triggers a direct DENY at the @gate reservation gate.
    max_session_budget_tokens: Optional[int] = None    # session-level token cap
    max_tool_call_budget_tokens: Optional[int] = None  # per-call output cap

    # ── Identity admission ──
    identity_required: bool = False                    # deny ANONYMOUS at admission

    # ── YELLOW band behavior ──
    # Default: 3-band experience (GREEN / ORANGE / RED). Scores that
    # would land in the YELLOW range are returned as GREEN. Simpler
    # mental model for OSS users who do not need a moderate tier.
    # Set enable_yellow_band=True for the 4-band compliance model:
    # adds a stable moderate-risk label for audit queries and dashboards
    # that need to track moderate-risk actions over time.
    enable_yellow_band: bool = False
    # When YELLOW is enabled, opt in to model-class promotion for D2/D3
    # data via yellow_model_escalation=True. The caller's stack still
    # decides whether to honour the routing recommendation.
    yellow_model_escalation: bool = False

    # ── Profile-scoped semantic review hints ──
    # Empty by default. Deployment profiles can define regex cues for content
    # classes that require observer/HITL review for that agent's mission.
    semantic_review_patterns: Dict[str, list[str]] = field(default_factory=dict)

    # ── Policy floors ──
    # Hard minimum bands for matching actions. A floored action is always at
    # least its floor band regardless of score, and cannot be lowered at
    # runtime. Empty by default. See FloorRule.
    floor: list[FloorRule] = field(default_factory=list)

    @property
    def weight_vector(self) -> tuple[float, ...]:
        return tuple(self.weights.get(name, 1.0) for name in DIMENSION_NAMES)

    def content_hash(self) -> str:
        """A stable digest of the policy CONTENT that decides an action.

        Public since 0.7.0, to answer a question `version` cannot: **which policy actually made
        this decision?** `version` is a string the author types. Two deployments can both say
        ``0.2.0`` with different thresholds, weights and floor rules, and an audit record carrying
        only the version cannot tell them apart — nor can it show that the policy changed under a
        version that stayed the same, which is the case that matters when someone asks why an
        action scored differently last month.

        Covers every field that can change a verdict: thresholds, weights, tool defaults, bash
        overrides, destination and admission settings, and the compiled floor rules. It is a
        content digest, **not** a signature: it proves two policies are the same policy, not that
        either is authentic. Anyone can compute it, which is what makes it useful for comparison
        and useless as an authenticity claim — stated so nobody mistakes it for one.

        Stable across processes and across dict ordering (keys are sorted). Changing this
        function's output for an unchanged policy would break every stored comparison, so it is
        treated as a compatibility surface.
        """
        import dataclasses
        import hashlib
        import json

        def _plain(value: Any) -> Any:
            if dataclasses.is_dataclass(value) and not isinstance(value, type):
                return {f.name: _plain(getattr(value, f.name))
                        for f in dataclasses.fields(value)}
            if isinstance(value, dict):
                return {str(k): _plain(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
            if isinstance(value, (list, tuple)):
                return [_plain(v) for v in value]
            if isinstance(value, (str, int, float, bool)) or value is None:
                return value
            return str(value)

        blob = json.dumps(_plain(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def get_tool_baseline(self, tool_name: str) -> Dict[str, int]:
        return dict(self.tool_defaults.get(tool_name, {}))

    def get_bash_overrides(self, command: str) -> Dict[str, int]:
        # Per-dimension MAX across all matching patterns. A command that matches
        # several overrides must never score LOWER than any single match — taking
        # the max prevents a weaker pattern (e.g. "docker") from overwriting the
        # per-dimension spike of a stronger one (e.g. "rm -rf") via last-write.
        #
        # M5: `bash_overrides` keys are case-SENSITIVE regexes (unlike the built-in
        # classifier patterns, which are all `(?i)`). A malformed regex in a user
        # policy is skipped here rather than crashing scoring at runtime — a
        # DEFINED best-effort fallback; `fivedrisk validate` compiles these keys so
        # operators catch a bad pattern before deploy.
        merged: Dict[str, int] = {}
        for pattern, overrides in self.bash_overrides.items():
            try:
                matched = re.search(pattern, command)
            except re.error:
                continue
            if matched:
                for dim, val in overrides.items():
                    merged[dim] = max(merged.get(dim, val), val)
        return merged

    def matched_floor(self, tool_name: str, tool_input: Dict[str, Any]) -> Optional[FloorRule]:
        """Return the highest-band floor rule matching this action, or None.

        Delegates per-rule matching to the ONE canonical matcher (:func:`match_red_line`) so a
        multi-axis floor rule (``tools`` / ``patterns`` / ``checksum`` / …) actually enforces
        through ``score()`` instead of being silently ignored (the pre-fix fail-open by API shape);
        a legacy ``tool_name`` (+ ``command_contains`` / ``command_regex``) rule matches byte-
        identically as before. When several rules match, the highest band wins (a floor only raises).

        Note: the axes ``score()`` cannot supply here (asserted ``data_classes``, ``list_ref``
        lookups) simply do not match on this path; a caller that supplies full context drives those.
        """
        matched: Optional[FloorRule] = None
        for rule in self.floor:
            if not match_red_line(rule, tool_name=tool_name, tool_input=tool_input):
                continue
            if matched is None or (
                _FLOOR_BAND_ORDER.index(rule.band) > _FLOOR_BAND_ORDER.index(matched.band)
            ):
                matched = rule
        return matched

    def admit_session(self, workflow_type: str = "default") -> "AdmissionResult":
        """Admission check L1: validate policy is configured for the workflow.

        Returns an AdmissionResult with admit=True in either of these cases:
          - max_session_budget_tokens is configured (the workflow has an
            explicit budget cap)
          - max_session_budget_tokens is None (the workflow opts out of
            budget enforcement; admission succeeds with a warning)

        Additional Operational FinOps admission layers (Tool Manifest
        validation, historical P95 baselines, post-step reconciliation)
        are on the project roadmap.
        """
        if self.max_session_budget_tokens is None:
            return AdmissionResult(
                admit=True,
                workflow_type=workflow_type,
                warning="max_session_budget_tokens not configured; admitting without budget enforcement",
            )
        return AdmissionResult(
            admit=True,
            workflow_type=workflow_type,
            max_session_budget_tokens=self.max_session_budget_tokens,
        )


@dataclass
class AdmissionResult:
    """Outcome of policy.admit_session()."""

    admit: bool
    workflow_type: str
    max_session_budget_tokens: Optional[int] = None
    warning: Optional[str] = None
    deny_reason: Optional[str] = None


# ─── The ONE canonical red-line matcher (reuses shipped regex + destination machinery) ───
# ANY-of / ALL-of pattern matching reuses classifier._scan_content (the collect-all aggregator)
# and the first-hit re.search scanners; destination normalization reuses hooks. No parallel engine.

_RED_LINE_AXES = ("tools", "destinations", "patterns", "data_classes", "list_ref", "checksum", "fields")


def _haystack(tool_input: Dict[str, Any]) -> str:
    if isinstance(tool_input, dict):
        return " ".join(str(v) for v in tool_input.values())
    return str(tool_input)


def _haystack_parts(tool_input: Dict[str, Any]) -> "list[str]":
    """The per-FIELD text units of an action, for axes that must not read across a field boundary.

    ``_haystack`` joins every value with a space, which is correct for the free-text axes
    (``command_contains`` / ``patterns``) but wrong for the check-digit axis: the joiner is also a
    legal intra-identifier separator, so one field's digits silently merge with the next. Used by
    the ``checksum`` axis only."""
    if isinstance(tool_input, dict):
        return [str(v) for v in tool_input.values()]
    return [str(tool_input)]


def _axis_hit(pred: AxisPredicate, candidates: list[str],
              normalize: "Optional[Any]" = None) -> bool:
    """Membership axis truth honouring allow/block mode.

    block: TRUE when any candidate ∈ values.  allow: TRUE when any candidate ∉ values
    (off-allowlist) OR there is no candidate at all (unknown = deny)."""
    vals = {normalize(v) if normalize else v for v in pred.values}
    cands = [normalize(c) if normalize else c for c in candidates]
    if pred.mode == "allow":
        return (len(cands) == 0) or any(c not in vals for c in cands)
    return any(c in vals for c in cands)


def _destination_candidates(tool_name: str, tool_input: Dict[str, Any]) -> list[str]:
    """Reuse the shipped destination extraction + normalization (hooks)."""
    from .hooks import _normalize_destination, extract_external_destinations
    cands = list(extract_external_destinations(tool_name, tool_input))
    if isinstance(tool_input, dict):
        for k in ("destination", "url", "recipient", "to", "host", "domain"):
            v = tool_input.get(k)
            if isinstance(v, str) and v:
                cands.append(_normalize_destination(v))
    return cands


def _patterns_matched_with_negation(pred: AxisPredicate, text: str) -> set[str]:
    """Indices (as ``str(i)``, matching ``_scan_content`` keys) of patterns that hit AND are NOT
    suppressed by a nearby negation cue. A pattern's hit is suppressed when a cue token is within
    ``negate_within`` intervening whitespace tokens of the match span (forward+backward, over the
    already-matched span — NOT lookbehind). If a pattern has an unsuppressed occurrence anywhere,
    it counts as matched (a cue near one occurrence never hides a far, un-cued occurrence)."""
    # Tokenize by whitespace, recording each token's char span + lowered surface.
    tokens = [(m.start(), m.end(), m.group(0).lower()) for m in re.finditer(r"\S+", text)]
    cues = {c.strip().lower() for c in pred.negate_cues}
    cue_token_idxs = [i for i, (_, _, tok) in enumerate(tokens) if tok in cues]
    matched: set[str] = set()
    for i, pat in enumerate(pred.values):
        rx = _compiled(pat)
        if rx is None:                       # uncompilable → literal fallback (defense-in-depth)
            if pat in text:
                matched.add(str(i))
            continue
        for mm in rx.finditer(text):
            span_toks = [ti for ti, (s, e, _) in enumerate(tokens) if s < mm.end() and e > mm.start()]
            if not span_toks:                # match landed off any token (e.g. empty match) → keep
                matched.add(str(i))
                break
            # Suppress when a cue is within negate_within INTERVENING tokens of the span (a cue
            # exactly ADJACENT to the span is 0 intervening tokens; abs(diff) - 1 == intervening).
            suppressed = any(
                (abs(cti - sti) - 1) <= pred.negate_within
                for sti in span_toks for cti in cue_token_idxs
            )
            if not suppressed:
                matched.add(str(i))
                break
    return matched


def _patterns_hit(pred: AxisPredicate, text: str) -> bool:
    """Reuse classifier._scan_content (collect-all, no short-circuit) for BOTH match modes:
    any = ≥1 label matched; all = the required labels ⊆ the matched set.

    When ``negate_within > 0`` with cues, a span-aware token-window negator (``_patterns_matched_
    with_negation``) replaces the aggregator so a cue-suppressed hit does NOT count toward any/all.
    Negation is off (byte-identical to the shipped matcher) for every existing rule (default 0)."""
    if len(text) > _MAX_HAYSTACK_CHARS:
        # ReDoS hygiene: never run the regex on an oversize haystack. Fail CLOSED —
        # an input too large to verify is treated as a HIT in BOTH modes (block:
        # assume the dangerous pattern is present; allow: assume the required-safe
        # token is absent). Truncate-and-scan would be a fail-OPEN — a dangerous
        # token past the cap would silently escape this hard floor.
        return True
    if pred.negate_within > 0 and pred.negate_cues:
        nmatched = len(_patterns_matched_with_negation(pred, text))
    else:
        from .classifier import _scan_content
        pairs = [(p, str(i)) for i, p in enumerate(pred.values)]
        nmatched = len(_scan_content(text, pairs))
    if pred.match_mode == "all":
        hit = nmatched == len(pred.values) and len(pred.values) > 0
    else:
        hit = nmatched >= 1
    return hit if pred.mode == "block" else (not hit)


def _value_match_hit(pred: "FieldValuePredicate", tool_input: Dict[str, Any]) -> bool:
    """Scope a predicate to a NAMED field's VALUE only, reusing the shipped predicate helpers.

    Resolve ``field`` case-insensitively on the tool_input KEY; run the predicate on THAT value
    alone. An ABSENT field is unknown = deny (block-mode: no match / does not fire; allow-mode:
    fires) — the fail-safe direction, mirroring the shipped :func:`_axis_hit` allow-semantics."""
    target = str(pred.field).strip().lower()
    vals: list[str] = []
    if isinstance(tool_input, dict):
        # Collect EVERY value whose key matches case-insensitively — NOT just the
        # first. Stopping at the first key lets an attacker plant a benign
        # case-variant key ("Amount":"0") ahead of the dangerous one
        # ("amount":"9999999") to shadow it — a fail-open on this hard floor.
        vals = [str(v) for k, v in tool_input.items() if str(k).strip().lower() == target]
    if not vals:                             # absent field = unknown
        return pred.mode == "allow"          # allow → deny (fires); block → no match (no fire)
    shim = AxisPredicate(values=pred.values, mode=pred.mode, match_mode=pred.match_mode)

    def _one(val: str) -> bool:
        if pred.kind == "checksum":
            return _checksum_hit(shim, val)
        if pred.kind == "literal":
            hit = any(_literal_contains(v, val) for v in pred.values)
            return hit if pred.mode == "block" else (not hit)
        return _patterns_hit(shim, val)      # kind == "regex" (default)

    # Fire if ANY same-named field would independently fire the axis (block: any
    # dangerous value; allow: any value missing the required-safe token).
    return any(_one(v) for v in vals)


def _checksum_hit(pred: AxisPredicate, text: "str | list[str]") -> bool:
    """A checksum axis is TRUE (block-mode) when the action carries a token that PASSES one of the
    named check-digit validators (``iban_mod97`` / ``luhn``). Pure boolean validation — no LLM,
    no score, patent-safe. Unknown validator names contribute nothing (fail-safe: they are
    rejected at config-load, so this is only reached for a known set).

    ``text`` is a LIST of per-field values, each scanned on its own. A single joined haystack let
    one field's digits run into the next and produced errors in BOTH directions — a real PAN
    absorbed into an oversized candidate stopped firing, and two unrelated ids concatenated into a
    spurious valid one started firing. A bare string is still accepted (the ``value_match``
    checksum kind scopes to one field's value already).

    THE DECLARED BOUND. A field value above ``_MAX_HAYSTACK_CHARS`` fails CLOSED — the axis is
    treated as a HIT (block-mode: assume the identifier is present) rather than scanned. This
    mirrors the shipped :func:`_patterns_hit` ReDoS guard exactly. It replaces the previous
    256-candidate TRUNCATION inside the generator, which was a silent fail-OPEN: a real PAN past
    the cut was never generated and the tier-1 floor did not fire, with no adversary needed."""
    units = [text] if isinstance(text, str) else list(text)
    if any(len(u) > _MAX_HAYSTACK_CHARS for u in units):
        return pred.mode == "block"
    hit = False
    for name in pred.values:
        spec = _CHECKSUM_VALIDATORS.get(name)
        if spec is None:
            continue
        candidates, validator = spec
        if any(validator(c) for unit in units for c in candidates(unit)):
            hit = True
            break
    return hit if pred.mode == "block" else (not hit)


def match_red_line(
    rule: FloorRule,
    *,
    tool_name: str,
    tool_input: Dict[str, Any],
    data_classes: "tuple[str, ...] | list[str]" = (),
    list_lookup: "Optional[Dict[str, Any]]" = None,
) -> bool:
    """Return True iff this rule fires (AND-within: every SPECIFIED axis is TRUE).

    A rule with no specified axis never fires. Reuses shipped machinery for every axis."""
    specified = False

    if rule.tools is not None:
        specified = True
        if not _axis_hit(rule.tools, [tool_name]):
            return False
    elif rule.tool_name is not None:
        specified = True
        if tool_name != rule.tool_name:
            return False

    if rule.command_contains is not None:
        specified = True
        if not _literal_contains(rule.command_contains, _haystack(tool_input)):
            return False

    if rule.command_regex is not None:
        specified = True
        _hay = _haystack(tool_input)
        # ReDoS hygiene: never run the regex on an oversize haystack. Fail CLOSED —
        # an oversize input is treated as a MATCH (we do NOT `return False`), so a
        # dangerous command past the cap cannot silently escape this floor. Within
        # the cap, behaviour is byte-identical to the uncapped scan.
        if len(_hay) <= _MAX_HAYSTACK_CHARS and not _regex_search(rule.command_regex, _hay):
            return False

    if rule.destinations is not None:
        specified = True
        from .hooks import _normalize_destination
        if not _axis_hit(rule.destinations, _destination_candidates(tool_name, tool_input),
                         normalize=_normalize_destination):
            return False

    if rule.patterns is not None:
        specified = True
        if not _patterns_hit(rule.patterns, _haystack(tool_input)):
            return False

    if rule.data_classes is not None:
        specified = True
        if not _axis_hit(rule.data_classes, list(data_classes)):
            return False

    if rule.checksum is not None:
        specified = True
        if not _checksum_hit(rule.checksum, _haystack_parts(tool_input)):
            return False

    if rule.fields is not None:
        specified = True
        # Field-NAME scope: keyed on the tool_input KEY names (case-insensitive), NOT on the
        # word appearing in a value (the F-C fix — the prior rule matched the literal word
        # "memo"/"note" in the joined VALUES via a patterns axis, so a PAN in a field literally
        # NAMED `note` was missed and a `body` value carrying the word "memo" false-fired).
        # block-mode: fires when the action touches one of the listed field names (e.g. a
        # free-text memo/note/description that must never hold CHD). This is the deterministic
        # stand-in for the fuller future form (data-class asserted-label scoping).
        keys = list(tool_input.keys()) if isinstance(tool_input, dict) else []
        if not _axis_hit(rule.fields, keys, normalize=lambda s: str(s).strip().lower()):
            return False

    if rule.value_match is not None:
        specified = True
        # Scope a predicate to a NAMED field's VALUE (case-insensitive KEY resolve), the one
        # composition the joined-haystack axes cannot express. AND-within: this suppresses only
        # itself — a co-firing block-mode axis above already `return`ed on its own miss.
        if not _value_match_hit(rule.value_match, tool_input):
            return False

    if rule.list_ref is not None:
        specified = True
        entries: set[str] = set()
        for lid in rule.list_ref.values:
            entries |= {str(e).strip().lower() for e in (list_lookup or {}).get(lid, ())}
        tokens = [str(v).strip().lower() for v in tool_input.values()] if isinstance(tool_input, dict) else []
        present = any(t in entries for t in tokens)
        if rule.list_ref.mode == "allow":
            if present:
                return False
        elif not present:
            return False

    return specified


def _is_block_dominant(rule: FloorRule) -> bool:
    """A rule with any block-mode axis (or a bare tool/command floor) is evaluated FIRST, so a
    sanctions/blocklist hit BEATS an allowlist permit (architect's hard ordering rule)."""
    axes = [getattr(rule, a) for a in _RED_LINE_AXES if getattr(rule, a) is not None]
    if not axes:
        return True
    return any(a.mode == "block" for a in axes)


def first_red_line_hit(
    rules: "list[FloorRule]",
    *,
    tool_name: str,
    tool_input: Dict[str, Any],
    data_classes: "tuple[str, ...] | list[str]" = (),
    list_lookup: "Optional[Dict[str, Any]]" = None,
) -> Optional[FloorRule]:
    """Return the STRICTEST firing rule — highest band first, block-dominant first within a band.

    A reduction over a rule set must never let authoring order decide the verdict. Ordering on
    block-dominance alone (the pre-fix behaviour) meant a soft floor listed earlier swallowed a hard
    red line firing on the same action, so ``first_red_line_hit`` could report YELLOW — or GREEN —
    where :meth:`Policy.matched_floor` over the identical rules floored the action at RED. Two
    reductions over one rule set with opposite answers is a fail-open by list position.

    Band is therefore the primary key and ``_is_block_dominant`` the tiebreak WITHIN a band, which is
    where the sealed-blocklist attribution rule was always meant to apply (a sanctions hit is reported
    ahead of an allowlist violation of the same severity). Sorting descending by band keeps the
    short-circuit: the first rule that matches is already the strictest one that can.

    Behaviour is unchanged for any rule set whose floors share one band, and for any action matched by
    a single rule. Where it differs it can only return a rule of band >= the pre-fix answer — the
    invariant asserted in ``tests/test_red_line_reduction_strictest.py``.
    """
    ordered = sorted(
        rules,
        key=lambda r: (-_FLOOR_BAND_ORDER.index(r.band), 0 if _is_block_dominant(r) else 1),
    )
    for rule in ordered:
        if match_red_line(rule, tool_name=tool_name, tool_input=tool_input,
                          data_classes=data_classes, list_lookup=list_lookup):
            return rule
    return None


def parse_axis_predicate(spec: Any) -> Optional[AxisPredicate]:
    """Compile one axis spec ``{mode, values, match_mode[, negate_within, negate_cues]}`` into an
    :class:`AxisPredicate`, or ``None`` when ``spec`` is ``None``.

    Public since 0.7.0. :func:`load_policy` compiles the ``floor:`` block for you when your policy
    lives in a YAML file. If it lives anywhere else — a database, a service config, an API payload,
    a different YAML shape — this is the supported way to build the same predicate from the same
    spec, and it applies the same validation:

    * ``values`` must be present and non-empty;
    * ``negate_within`` must be an integer ``>= 0``;
    * a non-zero ``negate_within`` must come with at least one ``negate_cues`` entry.

    :class:`AxisPredicate` is a plain dataclass, so it has always been possible to construct one
    directly — but doing so **skips every check above**, and a hand-built predicate can therefore
    match differently from the identical spec loaded through ``load_policy``. Two paths that
    compile the same spec and disagree is the failure this export exists to remove.

    Raises ``ValueError`` on a malformed spec so ``validate`` reports it rather than a rule
    silently matching more, or less, than it was written to.
    """
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise ValueError(f"floor axis must be a mapping, got {spec!r}")
    values = spec.get("values")
    if not values:
        raise ValueError(f"floor axis needs non-empty 'values': {spec!r}")
    try:
        negate_within = int(spec.get("negate_within", 0))
    except (TypeError, ValueError):
        raise ValueError(f"floor axis 'negate_within' must be an integer: {spec!r}")
    if negate_within < 0:
        raise ValueError(f"floor axis 'negate_within' must be >= 0: {spec!r}")
    negate_cues = tuple(str(c) for c in (spec.get("negate_cues") or ()))
    if negate_within > 0 and not negate_cues:
        raise ValueError(f"floor axis sets 'negate_within' but no 'negate_cues': {spec!r}")
    return AxisPredicate(
        values=tuple(str(v) for v in values),
        mode=str(spec.get("mode", "block")),
        match_mode=str(spec.get("match_mode", "any")),
        negate_within=negate_within,
        negate_cues=negate_cues,
    )


#: Pre-0.7.0 internal name. Kept so existing callers keep working; prefer the public name.
_parse_axis_pred = parse_axis_predicate


def parse_value_match(spec: Any) -> Optional[FieldValuePredicate]:
    """Compile a ``value_match`` spec ``{field, values, mode, kind, match_mode}`` into a
    :class:`FieldValuePredicate`, or ``None`` when ``spec`` is ``None``.

    Public since 0.7.0, for the same reason as :func:`parse_axis_predicate`: it is the supported
    way to compile the field-scoped half of a floor rule when your policy does not come from a
    YAML file. Fail-closed on a missing ``field``, an empty ``values``, or an unknown ``kind`` —
    never silently dropped, because a ``value_match`` that quietly disappears turns a rule scoped
    to one named field into a rule scoped to none.
    """
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise ValueError(f"value_match must be a mapping, got {spec!r}")
    field_name = spec.get("field")
    if not field_name:
        raise ValueError(f"value_match needs a 'field': {spec!r}")
    values = spec.get("values")
    if not values:
        raise ValueError(f"value_match needs non-empty 'values': {spec!r}")
    kind = str(spec.get("kind", "regex"))
    if kind not in ("regex", "literal", "checksum"):
        raise ValueError(f"value_match has unknown kind {kind!r} (regex|literal|checksum): {spec!r}")
    return FieldValuePredicate(
        field=str(field_name),
        values=tuple(str(v) for v in values),
        mode=str(spec.get("mode", "block")),
        kind=kind,
        match_mode=str(spec.get("match_mode", "any")),
    )


#: Pre-0.7.0 internal name. Kept so existing callers keep working; prefer the public name.
_parse_value_match = parse_value_match


def _parse_floor_rules(raw_floor: Any) -> list[FloorRule]:
    """Parse the ``floor:`` block into FloorRule objects — legacy AND multi-axis forms.

    Two authoring shapes, ONE canonical matcher:
      * legacy — ``tool_name`` (+ optional ``command_contains`` / ``command_regex`` / ``band``);
      * multi-axis red line — any of ``tools`` / ``destinations`` / ``patterns`` /
        ``data_classes`` / ``list_ref`` / ``checksum`` (each ``{mode, values[, match_mode]}``),
        given top-level or nested under a ``match:`` key. A multi-axis floor defaults to band RED
        (a hard block by construction) so it enforces via ``score()`` instead of being silently
        dropped (the pre-fix fail-open: ``_parse_floor_rules`` required ``tool_name`` and could not
        author these axes at all).

    Raises ValueError on a malformed block so `fivedrisk validate` (and startup configure()) fail
    closed rather than silently dropping a control.
    """
    if not raw_floor:
        return []
    if not isinstance(raw_floor, list):
        raise ValueError("policy 'floor' must be a list of floor rules")
    rules: list[FloorRule] = []
    for entry in raw_floor:
        if not isinstance(entry, dict):
            raise ValueError(f"floor rule must be a mapping, got {entry!r}")
        axis_src = entry.get("match") if isinstance(entry.get("match"), dict) else entry
        axes = {a: _parse_axis_pred(axis_src.get(a)) for a in _RED_LINE_AXES if axis_src.get(a)}
        value_match = _parse_value_match(axis_src.get("value_match"))
        tool_name = entry.get("tool_name")
        command_contains = entry.get("command_contains")
        command_regex = entry.get("command_regex")
        if not tool_name and not axes and not command_contains and not command_regex and not value_match:
            raise ValueError(
                f"floor rule matches nothing (needs 'tool_name' or a red-line axis): {entry!r}")
        band_raw = entry.get("band")
        if tool_name and not band_raw:
            # A legacy tool-keyed floor must declare its band (unchanged, fail-closed).
            raise ValueError(f"floor rule missing 'band': {entry!r}")
        if band_raw:
            try:
                band = Band(str(band_raw).upper())
            except ValueError:
                raise ValueError(
                    f"floor rule has invalid band {band_raw!r}; "
                    "must be one of GREEN/YELLOW/ORANGE/RED"
                )
        else:
            band = Band.RED   # a multi-axis red line is a hard block by construction
        rules.append(
            FloorRule(
                id=str(entry.get("id", "")),
                tool_name=str(tool_name) if tool_name else None,
                band=band,
                command_contains=str(command_contains) if command_contains else None,
                command_regex=str(command_regex) if command_regex else None,
                reason=str(entry.get("reason", "")),
                value_match=value_match,
                **axes,
            )
        )
    return rules


PRESET_DIR = Path(__file__).resolve().parent / "policies" / "presets"


def list_presets() -> list[str]:
    """Names of the packaged policy presets, without the .yaml suffix."""
    if not PRESET_DIR.is_dir():
        return []
    return sorted(p.stem for p in PRESET_DIR.glob("*.yaml"))


def load_policy(path: Optional[str | Path] = None) -> Policy:
    """Load a Policy from a YAML file, a packaged preset name, or return defaults.

    A bare name that matches a packaged preset (`load_policy("read_only")`) loads
    that preset AND records `preset_name` on the result, so the posture survives
    into the decision record. A path loads the file and leaves `preset_name` None.
    """
    if path is None:
        return Policy()

    preset_name: Optional[str] = None
    if isinstance(path, str) and path in list_presets():
        preset_name = path
        path = PRESET_DIR / f"{path}.yaml"

    path = Path(path)
    if not path.exists():
        known = ", ".join(list_presets())
        raise FileNotFoundError(
            f"Policy file not found: {path}. Packaged presets, loadable by name: {known}"
        )

    with open(path) as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    thresholds = raw.get("thresholds", {})
    bands = raw.get("bands", {})
    raw_semantic_patterns = raw.get("semantic_review_patterns", {})
    floor_rules = _parse_floor_rules(raw.get("floor", []))

    return Policy(
        preset_name=preset_name,
        version=raw.get("version", "0.2.0"),
        # 4-band score thresholds
        yellow_score=float(bands.get("yellow_score", 1.0)),
        orange_score=float(bands.get("orange_score", 1.8)),
        red_score=float(bands.get("red_score", 2.5)),
        # Spike thresholds
        red_threshold=thresholds.get("red_threshold", 4),
        orange_threshold=thresholds.get("orange_threshold", 3),
        # Weights
        weights={**DEFAULT_WEIGHTS, **raw.get("weights", {})},
        # Tools
        tool_defaults={
            **{k: dict(v) for k, v in DEFAULT_TOOL_DEFAULTS.items()},
            **{k: dict(v) for k, v in raw.get("tool_defaults", {}).items()},
        },
        bash_overrides={
            **{k: dict(v) for k, v in DEFAULT_BASH_OVERRIDES.items()},
            **{k: dict(v) for k, v in raw.get("bash_overrides", {}).items()},
        },
        retry_budget=raw.get("retry_budget"),
        # Cost-management attributes (OSS-COST-MVP-001)
        max_session_budget_tokens=raw.get("max_session_budget_tokens"),
        max_tool_call_budget_tokens=raw.get("max_tool_call_budget_tokens"),
        # Identity admission
        identity_required=bool(raw.get("identity_required", False)),
        # YELLOW band behavior
        enable_yellow_band=bool(raw.get("enable_yellow_band", False)),
        yellow_model_escalation=bool(raw.get("yellow_model_escalation", False)),
        # Profile-scoped semantic review hints
        semantic_review_patterns={
            str(label): [str(pattern) for pattern in patterns]
            if isinstance(patterns, list)
            else patterns
            for label, patterns in raw_semantic_patterns.items()
        },
        # Policy floors
        floor=floor_rules,
    )
