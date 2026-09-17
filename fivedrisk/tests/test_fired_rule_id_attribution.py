"""Floor attribution: WHICH rule raised the band, in a queryable field.

Before `fired_rule_id` / `floor_band`, the only record of a floor hit was prose
appended to `rationale` ("… [reason text]"), and a rule with no `reason` degraded to
the bare string "floor:RED". A reviewer asking "a benign action was caught — show me
the rule, not the verdict" had to parse free text, and could not distinguish an
unnamed floor rule from no floor at all.

The invariants these tests hold:

  1. No floor matched  -> both fields None, and `to_dict()` emits NEITHER key, so an
     unfloored action serialises byte-identically to before the fields existed.
  2. A floor matched   -> `floor_band` is always set (that is what makes "a floor
     fired" observable), `fired_rule_id` is set iff the rule carries an id.
  3. Attribution names the rule whose band was ENFORCED, not the first one that
     matched — the same rule `matched_floor` selected.
  4. `rationale` is unchanged. Callers format it into STOP/ASK text (hooks.py:660,
     791); this change adds a field, it does not move a fact out of a string.
  5. A decision log written by an older version keeps logging after the upgrade.
"""

import sqlite3

from fivedrisk.logger import DecisionLog
from fivedrisk.policy import FloorRule, Policy
from fivedrisk.schema import Action, Band
from fivedrisk.scorer import score


def _action(cmd: str = "echo hello") -> Action:
    return Action(tool_name="Bash", tool_input={"command": cmd})


# ── 1. no floor: absent, not null ──────────────────────────────────────────────

def test_no_floor_leaves_both_fields_none():
    scored = score(_action(), Policy())
    assert scored.fired_rule_id is None
    assert scored.floor_band is None


def test_no_floor_emits_neither_key():
    """Byte-identity for the untouched path: a consumer that never configured a
    floor sees exactly the keys it saw before."""
    d = score(_action(), Policy()).to_dict()
    assert "fired_rule_id" not in d
    assert "floor_band" not in d


# ── 2. floor matched: band always, id when named ───────────────────────────────

def test_named_floor_binds_id_and_band():
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="DROP TABLE", band=Band.RED,
        reason="destructive DDL", id="no-ddl",
    )])
    scored = score(_action("psql -c 'DROP TABLE users'"), policy)
    assert scored.fired_rule_id == "no-ddl"
    assert scored.floor_band == "RED"
    assert scored.band is Band.RED
    d = scored.to_dict()
    assert d["fired_rule_id"] == "no-ddl" and d["floor_band"] == "RED"


def test_unnamed_floor_is_still_observable_as_a_floor_hit():
    """The reason this is two fields and not one. `FloorRule.id` defaults to "",
    so attribution carried by id alone would report an unnamed floor hit as
    indistinguishable from no floor at all."""
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="rm -rf", band=Band.RED, reason="",
    )])
    scored = score(_action("rm -rf /"), policy)
    assert scored.fired_rule_id is None      # nothing to name
    assert scored.floor_band == "RED"        # but a floor demonstrably fired
    assert "floor_band" in scored.to_dict()


# ── 3. attribution names the ENFORCED rule ─────────────────────────────────────

def test_attribution_names_the_rule_whose_band_was_enforced():
    """Two rules match the same action at different bands. `matched_floor` enforces
    the highest; the attribution must name that one and not the earlier, weaker
    match — otherwise the audit record blames a rule that did not decide anything."""
    policy = Policy(floor=[
        FloorRule(tool_name="Bash", command_contains="curl", band=Band.ORANGE,
                  reason="network egress", id="soft-egress"),
        FloorRule(tool_name="Bash", command_contains="curl", band=Band.RED,
                  reason="exfiltration", id="hard-egress"),
    ])
    scored = score(_action("curl https://example.invalid"), policy)
    assert scored.band is Band.RED
    assert scored.floor_band == "RED"
    assert scored.fired_rule_id == "hard-egress"


def test_floor_band_is_the_floor_not_the_final_band():
    """`band` is the enforced maximum of score and floor; `floor_band` is what the
    RULE asked for. When the computed score is already stricter they differ, and
    conflating them would misreport how much work the floor did."""
    action = Action(tool_name="Bash", tool_input={"command": "deploy"},
                    data_sensitivity=4, tool_privilege=4, reversibility=4,
                    external_impact=4, autonomy_context=4)
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="deploy", band=Band.ORANGE,
        reason="deploy is reviewed", id="deploy-review",
    )])
    scored = score(action, policy)
    assert scored.band is Band.RED           # spike, not the floor
    assert scored.floor_band == "ORANGE"     # what the rule contributed
    assert scored.fired_rule_id == "deploy-review"


# ── 4. the prose is untouched ──────────────────────────────────────────────────

def test_rationale_still_carries_the_floor_note():
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="DROP TABLE", band=Band.RED,
        reason="destructive DDL", id="no-ddl",
    )])
    scored = score(_action("DROP TABLE t"), policy)
    assert "[destructive DDL]" in scored.rationale


# ── 5. the audit log round-trips, on new and pre-existing databases ────────────

def test_log_round_trips_attribution(tmp_path):
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="DROP TABLE", band=Band.RED,
        reason="destructive DDL", id="no-ddl",
    )])
    log = DecisionLog(tmp_path / "d.db")
    log.log(score(_action("DROP TABLE t"), policy))
    log.log(score(_action("echo ok"), policy))

    rows = {r["rationale"][:0] or r["fired_rule_id"]: r for r in log.query_recent(10)}
    fired = [r for r in log.query_recent(10) if r["fired_rule_id"] == "no-ddl"]
    clean = [r for r in log.query_recent(10) if r["fired_rule_id"] is None]
    assert len(fired) == 1 and fired[0]["floor_band"] == "RED"
    assert len(clean) == 1 and clean[0]["floor_band"] is None
    assert rows  # query_recent still returns dict rows


def test_pre_existing_log_without_the_columns_is_migrated(tmp_path):
    """The failure this prevents: `CREATE TABLE IF NOT EXISTS` is a no-op on an
    existing table, so without a migration every INSERT after the upgrade fails with
    "table decisions has no column named fired_rule_id" — losing the whole audit
    trail, not just the new field."""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, tool_name TEXT NOT NULL,
            tool_input_hash TEXT NOT NULL,
            data_sensitivity INTEGER NOT NULL, tool_privilege INTEGER NOT NULL,
            reversibility INTEGER NOT NULL, external_impact INTEGER NOT NULL,
            autonomy_context INTEGER NOT NULL, composite_score REAL NOT NULL,
            max_dimension INTEGER NOT NULL, band TEXT NOT NULL, rationale TEXT,
            source TEXT, outcome TEXT DEFAULT NULL, policy_version TEXT NOT NULL,
            session_id TEXT, routing_model TEXT, routing_floor TEXT, metadata TEXT
        );
        INSERT INTO decisions (timestamp, tool_name, tool_input_hash,
            data_sensitivity, tool_privilege, reversibility, external_impact,
            autonomy_context, composite_score, max_dimension, band, policy_version)
        VALUES ('2026-01-01T00:00:00+00:00', 'Bash', 'deadbeef',
            0, 0, 0, 0, 0, 0.0, 0, 'GREEN', '0.1.0');
    """)
    conn.commit()
    conn.close()

    log = DecisionLog(path)                        # migrates on open
    policy = Policy(floor=[FloorRule(
        tool_name="Bash", command_contains="DROP TABLE", band=Band.RED, id="no-ddl")])
    log.log(score(_action("DROP TABLE t"), policy))

    rows = log.query_recent(10)
    assert len(rows) == 2                          # the historical row survives
    old = [r for r in rows if r["policy_version"] == "0.1.0"][0]
    assert old["fired_rule_id"] is None            # backfilled as NULL, not invented
    new = [r for r in rows if r["fired_rule_id"] == "no-ddl"][0]
    assert new["floor_band"] == "RED"


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "twice.db"
    DecisionLog(path)
    DecisionLog(path)                              # second open must not raise
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(decisions)")}
    assert {"fired_rule_id", "floor_band"} <= cols
