"""A policy key the loader ignores must not pass `validate` in silence.

The defect these guard: `max_sesion_budget_tokens` (one letter short of the real
key) validated clean, so an operator could set a budget cap, have it reviewed and
approved, and ship with no cap at all. A silently ignored key is worse than a
rejected one, because everyone in the approval chain believes the control exists.
"""
import re
from pathlib import Path

import pytest

from fivedrisk.cli import (
    _KNOWN_TOP_LEVEL_KEYS,
    _ACCEPTED_BUT_UNENFORCED_KEYS,
    _unknown_key_warnings,
)


def _write(tmp_path, body: str) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_a_near_miss_of_a_real_key_is_named_with_a_suggestion(tmp_path):
    """The original defect, by name."""
    w = _unknown_key_warnings(_write(tmp_path, "version: 1\nmax_sesion_budget_tokens: 50000\n"))
    assert len(w) == 1
    assert "max_sesion_budget_tokens" in w[0]
    assert "IGNORED" in w[0]
    assert "max_session_budget_tokens" in w[0], "the suggestion is the whole value of the warning"


def test_an_unrelated_unknown_key_warns_without_a_bogus_suggestion(tmp_path):
    w = _unknown_key_warnings(_write(tmp_path, "version: 1\ntotally_made_up_key: true\n"))
    assert len(w) == 1
    assert "IGNORED" in w[0]
    assert "Did you mean" not in w[0], "a far-off key must not get a misleading suggestion"


def test_retry_budget_no_longer_warns_because_it_is_now_ENFORCED(tmp_path):
    """This test asserted the OPPOSITE until 2026-08-24, and the inversion is the record.

    `retry_budget` was parsed onto the Policy object and read by nothing. It is now enforced
    (`hooks.check_retry_budget`), so the warning was removed rather than reworded.
    """
    assert _unknown_key_warnings(_write(tmp_path, "version: 1\nretry_budget: 3\n")) == []


def test_the_unenforced_key_mechanism_still_exists_for_the_next_one(tmp_path):
    """🔴 The dict is empty, not deleted. This defect class recurs -- a key the loader accepts
    and nothing enforces -- and the next one should be declared the day it is found rather than
    after someone trips over it. Deleting the mechanism would guarantee the next one is silent.
    """
    from fivedrisk import cli
    assert isinstance(cli._ACCEPTED_BUT_UNENFORCED_KEYS, dict)
    fake = dict(cli._ACCEPTED_BUT_UNENFORCED_KEYS, version="pretend this did nothing")
    orig = cli._ACCEPTED_BUT_UNENFORCED_KEYS
    try:
        cli._ACCEPTED_BUT_UNENFORCED_KEYS = fake
        w = cli._unknown_key_warnings(_write(tmp_path, "version: 1\n"))
        assert any("NOT ENFORCED" in x for x in w), "the mechanism must still fire"
    finally:
        cli._ACCEPTED_BUT_UNENFORCED_KEYS = orig


def test_a_clean_policy_produces_no_noise(tmp_path):
    """False positives here would train operators to ignore the warnings."""
    body = "version: 1\nbands:\n  yellow_score: 1.0\nweights:\n  blast_radius: 1.0\n"
    assert _unknown_key_warnings(_write(tmp_path, body)) == []


def test_a_non_mapping_or_unreadable_file_does_not_crash_validate(tmp_path):
    """Load errors belong to the validator, not to this warning pass."""
    assert _unknown_key_warnings(_write(tmp_path, "- just\n- a list\n")) == []
    assert _unknown_key_warnings(str(tmp_path / "does_not_exist.yaml")) == []
    assert _unknown_key_warnings(None) == []


def test_every_unenforced_key_is_also_a_known_key():
    """Otherwise it would warn twice, as unknown AND as unenforced."""
    assert set(_ACCEPTED_BUT_UNENFORCED_KEYS) <= _KNOWN_TOP_LEVEL_KEYS


def test_the_known_key_set_matches_what_load_policy_actually_reads():
    """🔴 The anti-rot guard, and the reason this is a test and not a comment.

    A hand-maintained list of valid keys is the same defect class as a
    hand-maintained configuration map: it is correct on the day it is written and
    wrong two releases later. Adding a `raw.get("...")` to `load_policy` without
    adding it here would make the new key warn as unknown, which is exactly the
    silent-misconfiguration failure inverted. Fail the build instead.
    """
    src = Path(__file__).resolve().parents[1] / "policy.py"
    text = src.read_text(encoding="utf-8")
    start = text.index("def load_policy(")
    body = text[start:start + 6000]
    read = set(re.findall(r'raw\.get\(\s*"([a-z_]+)"', body))
    assert read, "could not parse load_policy; this guard must not pass vacuously"
    missing = read - _KNOWN_TOP_LEVEL_KEYS
    assert not missing, (
        f"load_policy reads {sorted(missing)} but _KNOWN_TOP_LEVEL_KEYS omits them, "
        f"so a valid policy would warn as unknown"
    )
