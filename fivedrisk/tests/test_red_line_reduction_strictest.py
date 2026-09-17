"""Regression suite for the red-line REDUCTION — how a set of firing rules collapses to one verdict.

Backlog OSS-01. Two fail-open shapes were checked against this matcher; each test below is written so
that it FAILS if the shape is present, not so that it documents the current behaviour.

  * **Inertness asymmetry** — a rule shape that does nothing under one typing and fires on everything
    under another. Verified absent: a rule with no specified axis is inert on *every* path
    (`match_red_line`, `first_red_line_hit`, `Policy.matched_floor`), and the YAML loader rejects it
    outright, so it can never reach a runtime where the two disagree.
  * **Weak-pre-empts-strong reduction** — a reduction that returns the FIRST firing rule rather than
    the STRICTEST one, so a soft floor authored earlier in the list swallows a hard red line firing on
    the same action. This one was real: `first_red_line_hit` ordered only on block-dominance and
    ignored `band`, while `Policy.matched_floor` over the identical rule set took the highest band.
    Two reductions over one rule set with opposite answers is a fail-open by authoring order.

The binding invariant is `test_reduction_agreement_*`: whatever `matched_floor` floors an action at,
`first_red_line_hit` must report a rule of at least that band. It is the check that would have caught
the defect, so it is the one that stays. €0 offline.
"""
import itertools

import pytest

from fivedrisk.policy import (
    AxisPredicate,
    Band,
    FloorRule,
    Policy,
    _FLOOR_BAND_ORDER,
    _parse_floor_rules,
    first_red_line_hit,
    match_red_line,
)


def _strength(band: "Band") -> int:
    return _FLOOR_BAND_ORDER.index(band)


# ── Shape 1: inertness asymmetry ─────────────────────────────────────────────

def test_axis_less_rule_is_inert_on_every_path_not_just_one():
    """A rule specifying no axis must be inert EVERYWHERE. The asymmetry is the defect: inert on one
    path and universally-firing on another is how a degraded sentinel silently allows or blocks all."""
    bare = FloorRule(id="sentinel", band=Band.RED, reason="carries no axis")
    probes = [
        ("Bash", {"command": "rm -rf /"}),
        ("Wire", {"amount": "9999999", "destination": "evil.example"}),
        ("Read", {}),
    ]
    for tool_name, tool_input in probes:
        assert match_red_line(bare, tool_name=tool_name, tool_input=tool_input) is False
        assert first_red_line_hit([bare], tool_name=tool_name, tool_input=tool_input) is None
        assert Policy(floor=[bare]).matched_floor(tool_name, tool_input) is None


def test_axis_less_rule_is_rejected_at_load_so_it_never_reaches_a_matcher():
    """An authoring shape the loader does not understand (here: pluralised/unknown keys carrying no
    recognised axis) must fail closed at parse, not compile to a rule that matches nothing."""
    with pytest.raises(ValueError, match="matches nothing"):
        _parse_floor_rules([{
            "id": "degrade-sentinel",
            "tool_names": ["Pay"],              # not an axis — the axis is `tools`
            "value_thresholds": {"amount": 10_000},   # not an axis at all
            "band": "RED",
        }])


def test_dropping_a_conjunct_can_only_widen_never_narrow():
    """AND-within semantics mean an axis that fails to compile can only make a rule fire MORE often.
    That is the fail-safe direction; assert it so a future change to OR-within is caught here."""
    both = FloorRule(id="both", band=Band.RED,
                     tools=AxisPredicate(values=("Pay",), mode="block"),
                     patterns=AxisPredicate(values=(r"(?i)urgent",), mode="block"))
    one = FloorRule(id="one", band=Band.RED,
                    tools=AxisPredicate(values=("Pay",), mode="block"))
    action = dict(tool_name="Pay", tool_input={"amount": "1"})
    assert match_red_line(both, **action) is False
    assert match_red_line(one, **action) is True


# ── Shape 2: the reduction must take the strictest firing rule ───────────────

_SOFT = FloorRule(id="soft", band=Band.YELLOW,
                  fields=AxisPredicate(values=("memo",), mode="block"))
_HARD = FloorRule(id="hard", band=Band.RED,
                  patterns=AxisPredicate(values=(r"(?i)drop\s+table",), mode="block"))
_NOOP = FloorRule(id="noop", band=Band.GREEN,
                  tools=AxisPredicate(values=("Bash",), mode="block"))
_DANGER = dict(tool_name="Bash", tool_input={"memo": "please DROP TABLE users"})


@pytest.mark.parametrize("order", list(itertools.permutations([_SOFT, _HARD, _NOOP])))
def test_strictest_firing_rule_wins_regardless_of_declaration_order(order):
    """All three fire on the same action. Authoring order must not decide the verdict."""
    for rule in order:
        assert match_red_line(rule, **_DANGER) is True, rule.id
    hit = first_red_line_hit(list(order), **_DANGER)
    assert hit is not None
    assert hit.band is Band.RED and hit.id == "hard"


def test_green_floor_declared_first_cannot_swallow_a_red_red_line():
    """The sharpest form: a GREEN floor is a no-op on the scoring path, so letting it pre-empt a RED
    red line on the reduction path sends a must-stop action to auto-allow."""
    hit = first_red_line_hit([_NOOP, _HARD], **_DANGER)
    assert hit is not None and hit.band is Band.RED


@pytest.mark.parametrize("order", [(_SOFT, _HARD), (_HARD, _SOFT), (_NOOP, _HARD), (_HARD, _NOOP)])
def test_reduction_agreement_first_hit_never_softer_than_matched_floor(order):
    """THE invariant. `Policy.matched_floor` and `first_red_line_hit` reduce the same rule set; the
    reported band must never be softer than the enforced floor, in any authoring order."""
    rules = list(order)
    floored = Policy(floor=rules).matched_floor(_DANGER["tool_name"], _DANGER["tool_input"])
    hit = first_red_line_hit(rules, **_DANGER)
    assert floored is not None and hit is not None
    assert _strength(hit.band) >= _strength(floored.band)


def test_reduction_agreement_holds_across_a_mixed_rule_population():
    """Same invariant swept over every subset/order of a mixed-band, mixed-mode population."""
    population = [
        FloorRule(id="p-green", band=Band.GREEN, tools=AxisPredicate(values=("Wire",), mode="block")),
        FloorRule(id="p-yellow", band=Band.YELLOW, fields=AxisPredicate(values=("memo",), mode="block")),
        FloorRule(id="p-orange", band=Band.ORANGE,
                  patterns=AxisPredicate(values=(r"(?i)sanction",), mode="block")),
        FloorRule(id="p-red", band=Band.RED,
                  destinations=AxisPredicate(values=("approved.example",), mode="allow")),
    ]
    action = dict(tool_name="Wire",
                  tool_input={"memo": "sanctioned party", "destination": "evil.example"})
    for size in range(1, len(population) + 1):
        for combo in itertools.permutations(population, size):
            rules = list(combo)
            floored = Policy(floor=rules).matched_floor(action["tool_name"], action["tool_input"])
            hit = first_red_line_hit(rules, **action)
            if floored is None:
                continue
            assert hit is not None, rules
            assert _strength(hit.band) >= _strength(floored.band), [r.id for r in rules]


# ── the ordering rule the strictest-wins fix must not break ──────────────────

def test_block_dominance_still_decides_within_a_band():
    """A blocklist hit is reported ahead of an allowlist violation of the SAME band — the sealed-
    blocklist attribution rule. Band decides first; block-dominance is the tiebreak inside a band."""
    allow_side = FloorRule(id="off-allowlist", band=Band.RED,
                           destinations=AxisPredicate(values=("approved.example",), mode="allow"))
    block_side = FloorRule(id="sanctions", band=Band.RED,
                           list_ref=AxisPredicate(values=("ofac",), mode="block"))
    action = dict(tool_name="Wire",
                  tool_input={"destination": "evil.example", "counterparty": "acme-sanctioned"},
                  list_lookup={"ofac": ["acme-sanctioned"]})
    for order in ([allow_side, block_side], [block_side, allow_side]):
        hit = first_red_line_hit(order, **action)
        assert hit is not None and hit.id == "sanctions"


def test_single_firing_rule_is_returned_unchanged():
    """Byte-compat guard: with one firing rule the reduction is the identity, whatever else is listed."""
    hit = first_red_line_hit([_NOOP, _SOFT, _HARD], tool_name="Bash",
                             tool_input={"command": "drop table x"})
    assert hit is not None and hit.id == "hard"
