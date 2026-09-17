"""The policy that decided must be identifiable FROM the decision record.

Two columns existed for this and neither was ever populated by a production path:
`config_hash` had 2 call sites, both tests, and `policy_preset` did not exist. A
column nothing writes is not provenance, it is a schema comment — and the record
cannot then answer "which policy was in force, under which declared posture",
which is the first question asked after an incident.

These are end-to-end: they gate a real action and read the row back.
"""
import tempfile
from pathlib import Path

import pytest

from fivedrisk import hooks as H
from fivedrisk.logger import DecisionLog
from fivedrisk.policy import list_presets, load_policy


def _gate_one_action(db: str, policy=None):
    H.configure(log_path=db)

    @H.gate(tool_name="Read", policy=policy)
    def read_file(path: str):
        return "ok"

    read_file(path="/tmp/example.txt")
    return DecisionLog(db).query_recent(limit=5)


def test_config_hash_is_written_by_a_production_path_not_only_by_tests():
    with tempfile.TemporaryDirectory() as tmp:
        rows = _gate_one_action(str(Path(tmp) / "a.db"))
    assert rows, "gating an action must write a decision row"
    assert rows[0].get("config_hash"), (
        "config_hash is NULL on a row written through the gate: the record cannot say "
        "which policy content decided"
    )


def test_a_preset_loaded_by_name_reaches_the_decision_record():
    """The whole point of a named posture: the NAME has to survive to the record."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = load_policy("read_only")
        assert policy.preset_name == "read_only"
        rows = _gate_one_action(str(Path(tmp) / "b.db"), policy=policy)
    assert rows, "gating an action must write a decision row"
    assert rows[0].get("policy_preset") == "read_only", (
        "a policy loaded as a named preset must record that name; otherwise the posture "
        "is lost at adoption and cannot be cited at a change board"
    )


def test_a_policy_that_is_not_a_preset_records_no_preset_name():
    """NULL must mean 'no preset was named', not 'we forgot to write it'."""
    with tempfile.TemporaryDirectory() as tmp:
        rows = _gate_one_action(str(Path(tmp) / "c.db"))
    assert rows[0].get("policy_preset") in (None, ""), (
        "the default policy is not a preset and must not claim to be one"
    )


@pytest.mark.parametrize("name", list_presets())
def test_every_packaged_preset_loads_by_name_and_carries_it(name):
    """A preset that cannot be loaded by name is a file, not a posture."""
    assert load_policy(name).preset_name == name


def test_an_unknown_preset_name_lists_the_real_ones():
    """The error has to be actionable, or the feature is undiscoverable."""
    with pytest.raises(FileNotFoundError) as e:
        load_policy("stricct")
    assert "read_only" in str(e.value), "the error must enumerate the loadable presets"
