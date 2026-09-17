"""The audit-record column shape: identity, policy content, outcome history, chain seam.

WHY COLUMNS AND NOT A LATER FEATURE. Column shape cannot be retrofitted. Every record written
without a column is a record that can never answer the question that column exists to answer —
there is nothing to back-fill from, because the fact was never captured. An audit log is the one
artifact whose value is entirely in what it recorded at the time.

WHAT WAS MISSING, and the first one was a documented capability that did not exist:

  * **`acting_principal_id` / `acting_principal_type`.** `ActingIdentity`'s own docstring said its
    fields "flow through to the audit log and NDJSON events unchanged." The NDJSON half was true.
    The audit-log half was not: `acting_identity` appeared **zero times** in `logger.py`, and a
    decision logged with an identity persisted nothing about it. A user reading that sentence
    believed their log recorded who authorised each action, and it did not.
  * **`config_hash`.** `policy_version` is a string the author types. Two deployments can both say
    `0.2.0` with different thresholds and floor rules, and a policy can change while its version
    does not — the case that matters when someone asks why an action scored differently last month.
  * **`outcome_history`.** `update_outcome` overwrote `outcome`. A decision that went
    pending -> approved -> executed left no trace of having been anything but its last state, so
    "what happened, in what order" was unanswerable from the row that recorded it.
  * **`prev_hash` / `record_hash`.** No tamper-evidence at all.

WHAT THE CHAIN DELIBERATELY DOES NOT COVER, tested here so the limit is a property and not a
footnote: `outcome` and `outcome_history` are mutable by design, so they sit outside the chain.
Including them would make verification fail on ordinary authorised use, and an integrity alarm
that fires on correct work is one people learn to click past.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from fivedrisk import classify_tool_call, load_policy, score
from fivedrisk.logger import DecisionLog
from fivedrisk.schema import ActingIdentity, PrincipalType

NEW_COLUMNS = ("acting_principal_id", "acting_principal_type", "config_hash",
               "outcome_history", "prev_hash", "record_hash")


@pytest.fixture()
def log(tmp_path):
    return DecisionLog(str(tmp_path / "decisions.sqlite"))


@pytest.fixture()
def policy():
    return load_policy()


def _cols(log) -> list[str]:
    con = sqlite3.connect(log.path)
    return [r[1] for r in con.execute("PRAGMA table_info(decisions)")]


def _row(log, rid: int) -> dict:
    con = sqlite3.connect(log.path)
    con.row_factory = sqlite3.Row
    return dict(con.execute("SELECT * FROM decisions WHERE id = ?", (rid,)).fetchone())


def _act(policy, cmd="rm -rf /tmp/x", identity=None):
    a = classify_tool_call("Bash", {"command": cmd}, policy)
    if identity is not None:
        a.acting_identity = identity
    return score(a, policy)


# ── the shape exists ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("col", NEW_COLUMNS)
def test_the_column_exists(log, col):
    assert col in _cols(log)


def test_a_pre_existing_log_is_migrated_additively(tmp_path):
    """An older log must keep working, and its rows must read back NULL rather than break."""
    p = tmp_path / "old.sqlite"
    con = sqlite3.connect(p)
    con.execute("""CREATE TABLE decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, tool_name TEXT NOT NULL,
        tool_input_hash TEXT NOT NULL, data_sensitivity INTEGER NOT NULL,
        tool_privilege INTEGER NOT NULL, reversibility INTEGER NOT NULL,
        external_impact INTEGER NOT NULL, autonomy_context INTEGER NOT NULL,
        composite_score REAL NOT NULL, max_dimension INTEGER NOT NULL, band TEXT NOT NULL,
        rationale TEXT, source TEXT, outcome TEXT, policy_version TEXT NOT NULL,
        session_id TEXT, routing_model TEXT, routing_floor TEXT, metadata TEXT)""")
    con.execute("""INSERT INTO decisions (timestamp, tool_name, tool_input_hash, data_sensitivity,
        tool_privilege, reversibility, external_impact, autonomy_context, composite_score,
        max_dimension, band, policy_version) VALUES
        ('2026-01-01T00:00:00', 'Bash', 'h', 1,1,1,1,1, 1.0, 1, 'GREEN', '0.1.0')""")
    con.commit(); con.close()

    lg = DecisionLog(str(p))                       # migrates on open
    assert set(NEW_COLUMNS) <= set(_cols(lg))
    old = _row(lg, 1)
    for col in NEW_COLUMNS:
        assert old[col] is None, f"{col} back-filled a guess onto a pre-existing row"
    # ...and the log still WORKS after migration
    assert lg.log(_act(load_policy())) == 2


def test_the_migration_note_says_what_old_rows_cannot_answer(log):
    """🔴 The gate line. A NULL here has a specific meaning and it is not the obvious one."""
    note = DecisionLog.MIGRATION_NOTE
    for col in NEW_COLUMNS:
        assert col in note, f"{col} is not named in the migration note"
    assert "THE COLUMN DID NOT EXIST" in note
    assert "cannot be back-filled" in note


# ── identity: the documented claim that was not true ────────────────────────────────────────────

def test_acting_identity_now_reaches_the_audit_log(log, policy):
    """The docstring said these flow through to the audit log. Until 0.7.0 they did not."""
    rid = log.log(_act(policy, identity=ActingIdentity(
        principal_id="alice@example.com", principal_type=PrincipalType.USER)))
    r = _row(log, rid)
    assert r["acting_principal_id"] == "alice@example.com"
    assert "USER" in r["acting_principal_type"]


def test_no_identity_stores_NULL_rather_than_a_placeholder(log, policy):
    r = _row(log, log.log(_act(policy)))
    assert r["acting_principal_id"] is None, (
        "an absent identity must read as absent; a placeholder would be indistinguishable from a "
        "real anonymous principal")


# ── config_hash ─────────────────────────────────────────────────────────────────────────────────

def test_config_hash_records_which_policy_content_decided(log, policy):
    r = _row(log, log.log(_act(policy), config_hash=policy.content_hash()))
    assert r["config_hash"] == policy.content_hash()


def test_config_hash_separates_two_policies_that_share_a_version(policy):
    """The case `policy_version` cannot express, which is the reason the column exists."""
    import dataclasses
    other = dataclasses.replace(policy, red_score=9.9)
    assert other.version == policy.version
    assert other.content_hash() != policy.content_hash()


def test_config_hash_is_optional_and_absent_reads_as_not_recorded(log, policy):
    assert _row(log, log.log(_act(policy)))["config_hash"] is None


# ── outcome history ─────────────────────────────────────────────────────────────────────────────

def test_outcome_history_keeps_the_whole_sequence(log, policy):
    rid = log.log(_act(policy), outcome="pending")
    log.update_outcome(rid, "approved")
    log.update_outcome(rid, "executed")
    r = _row(log, rid)
    assert r["outcome"] == "executed", "the latest value still lives in `outcome`"
    assert json.loads(r["outcome_history"]) == ["pending", "approved", "executed"]


def test_outcome_history_survives_an_update_on_a_row_logged_without_one(log, policy):
    rid = log.log(_act(policy))
    log.update_outcome(rid, "approved")
    assert json.loads(_row(log, rid)["outcome_history"]) == ["approved"]


def test_unreadable_history_is_replaced_rather_than_silently_extended(log, policy):
    rid = log.log(_act(policy), outcome="pending")
    con = sqlite3.connect(log.path)
    con.execute("UPDATE decisions SET outcome_history='not json' WHERE id=?", (rid,)); con.commit()
    log.update_outcome(rid, "approved")
    assert json.loads(_row(log, rid)["outcome_history"]) == ["approved"]


# ── the chain seam ──────────────────────────────────────────────────────────────────────────────

def test_a_clean_log_verifies(log, policy):
    for i in range(4):
        log.log(_act(policy, cmd=f"echo {i}"), config_hash=policy.content_hash())
    v = log.verify_chain()
    assert v["ok"] is True and v["checked"] == 4 and v["first_bad_id"] is None


def test_each_row_links_to_the_one_before_it(log, policy):
    ids = [log.log(_act(policy, cmd=f"echo {i}")) for i in range(3)]
    rows = [_row(log, i) for i in ids]
    assert rows[0]["prev_hash"] is None
    for earlier, later in zip(rows, rows[1:]):
        assert later["prev_hash"] == earlier["record_hash"]


def test_editing_a_decision_field_BREAKS_the_chain(log, policy):
    ids = [log.log(_act(policy, cmd=f"echo {i}")) for i in range(4)]
    target = ids[1]
    was = _row(log, target)["band"]
    con = sqlite3.connect(log.path)
    con.execute("UPDATE decisions SET band=? WHERE id=?",
                ("RED" if was != "RED" else "GREEN", target))
    con.commit()
    v = log.verify_chain()
    assert v["ok"] is False
    assert v["first_bad_id"] == target


def test_DELETING_a_row_breaks_the_chain_at_the_next_one(log, policy):
    """A per-row checksum cannot catch this. Linking to the previous hash is what does."""
    ids = [log.log(_act(policy, cmd=f"echo {i}")) for i in range(4)]
    con = sqlite3.connect(log.path)
    con.execute("DELETE FROM decisions WHERE id=?", (ids[1],)); con.commit()
    v = log.verify_chain()
    assert v["ok"] is False
    assert v["first_bad_id"] == ids[2]


def test_an_outcome_update_does_NOT_break_the_chain(log, policy):
    """🔴 The deliberate limit. Outcome is mutable by design; an alarm that fires on authorised
    use is one people learn to ignore, so the chain excludes it and says so."""
    rid = log.log(_act(policy), outcome="pending")
    log.log(_act(policy, cmd="echo second"))
    log.update_outcome(rid, "approved")
    log.update_outcome(rid, "executed")
    assert log.verify_chain()["ok"] is True


def test_the_chain_does_not_claim_to_cover_the_outcome_fields():
    assert "outcome" not in DecisionLog._CHAINED_FIELDS
    assert "outcome_history" not in DecisionLog._CHAINED_FIELDS
    doc = DecisionLog.verify_chain.__doc__ or ""
    assert "outcome" in doc and "evidence, not proof" in doc.lower().replace("**", "")


def test_pre_chain_rows_are_SKIPPED_and_counted_never_treated_as_passing(tmp_path, policy):
    p = tmp_path / "mixed.sqlite"
    lg = DecisionLog(str(p))
    lg.log(_act(policy, cmd="echo old"))
    con = sqlite3.connect(p)                       # simulate a row written before the chain
    con.execute("UPDATE decisions SET record_hash=NULL, prev_hash=NULL WHERE id=1"); con.commit()
    lg.log(_act(policy, cmd="echo new"))
    v = lg.verify_chain()
    assert v["skipped_pre_chain"] == 1
    assert v["checked"] == 1
    assert v["ok"] is True, "a mixed log verifies over its chained rows only"
