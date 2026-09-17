"""Public floor-rule compilers: `parse_axis_predicate` and `parse_value_match`.

WHY THESE ARE PUBLIC (0.7.0). `load_policy` compiles the `floor:` block for you when your policy
lives in a YAML file on disk. Plenty of deployments keep policy somewhere else — a database, a
service config, an API payload, a YAML shape of their own — and those callers had no supported way
to turn one axis spec into an `AxisPredicate`.

`AxisPredicate` and `FieldValuePredicate` are public dataclasses, so a caller could always build
one by hand. **That is the trap this export closes**: hand-construction skips every check the
loader performs, so the same spec can compile two ways and match differently depending on which
path it took. Two compilers over one spec that disagree is a policy bug nobody can see in their
config file.

These tests pin both halves: the public names exist and are exported, and the validation they carry
is the same validation `load_policy` applies.
"""
from __future__ import annotations

import pytest

import fivedrisk
from fivedrisk import parse_axis_predicate, parse_value_match
from fivedrisk.policy import (
    AxisPredicate, FieldValuePredicate, _parse_axis_pred, _parse_floor_rules, _parse_value_match,
    match_red_line,
)


# ── the export itself ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    "parse_axis_predicate", "parse_value_match", "AxisPredicate", "FieldValuePredicate",
])
def test_the_compiler_surface_is_importable_from_the_package_root(name):
    assert hasattr(fivedrisk, name)
    assert name in fivedrisk.__all__, f"{name} is importable but missing from __all__"


def test_the_pre_0_6_1_private_names_still_work():
    """Renaming a symbol people already import is a breaking change. These stay as aliases."""
    assert _parse_axis_pred is parse_axis_predicate
    assert _parse_value_match is parse_value_match


# ── the point of the export: one spec, one result, whichever path compiled it ───────────────────

AXIS = {"values": ["transfer"], "mode": "block", "match_mode": "any",
        "negate_within": 2, "negate_cues": ["simulated"]}


def test_the_public_compiler_and_load_policy_agree_on_the_same_spec():
    direct = parse_axis_predicate(AXIS)
    via_loader = _parse_floor_rules([{"band": "RED", "patterns": AXIS}])[0].patterns
    assert direct == via_loader, (
        "the same axis spec compiled two ways produced two different predicates")


def test_a_compiled_predicate_matches_the_same_way_the_loader_would():
    rule_direct = _parse_floor_rules([{"band": "RED", "patterns": AXIS}])[0]
    cued = {"body": "simulated transfer to the test account"}
    uncued = {"body": "transfer to the beneficiary account"}
    assert match_red_line(rule_direct, tool_name="Pay", tool_input=uncued) is True
    assert match_red_line(rule_direct, tool_name="Pay", tool_input=cued) is False
    assert parse_axis_predicate(AXIS).negate_within == 2


def test_hand_construction_skips_the_validation_the_compiler_applies():
    """The reason to export a compiler rather than tell people to build the dataclass.

    `AxisPredicate(values=())` is a perfectly constructible object and a rule that can never fire.
    The compiler refuses it; the constructor does not.
    """
    assert AxisPredicate(values=()) is not None          # constructible, and inert
    with pytest.raises(ValueError):
        parse_axis_predicate({"values": []})


# ── validation, which is the substance of the export ────────────────────────────────────────────

@pytest.mark.parametrize("spec,why", [
    ({"values": []}, "empty values"),
    ({"mode": "block"}, "no values key"),
    ({"values": ["x"], "negate_within": 2}, "negator with no cues"),
    ({"values": ["x"], "negate_within": -1, "negate_cues": ["c"]}, "negative window"),
    ({"values": ["x"], "negate_within": "two", "negate_cues": ["c"]}, "non-integer window"),
    ("not-a-mapping", "wrong type"),
])
def test_parse_axis_predicate_refuses_a_malformed_spec(spec, why):
    with pytest.raises(ValueError):
        parse_axis_predicate(spec)


@pytest.mark.parametrize("spec,why", [
    ({"values": ["^DE"]}, "no field"),
    ({"field": "iban", "values": []}, "empty values"),
    ({"field": "iban", "values": ["^DE"], "kind": "nonsense"}, "unknown kind"),
    ("not-a-mapping", "wrong type"),
])
def test_parse_value_match_refuses_a_malformed_spec(spec, why):
    with pytest.raises(ValueError):
        parse_value_match(spec)


def test_none_compiles_to_none_on_both():
    """An absent axis is absent, not an error — that is how an unspecified axis is authored."""
    assert parse_axis_predicate(None) is None
    assert parse_value_match(None) is None


def test_defaults_match_the_documented_shape():
    p = parse_axis_predicate({"values": ["a", 1]})
    assert p.values == ("a", "1"), "values are normalised to strings"
    assert p.mode == "block" and p.match_mode == "any"
    assert p.negate_within == 0 and p.negate_cues == ()

    v = parse_value_match({"field": "iban", "values": ["^DE"]})
    assert isinstance(v, FieldValuePredicate)
    assert v.field == "iban" and v.kind == "regex" and v.match_mode == "any"
