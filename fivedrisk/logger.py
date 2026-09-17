"""5D Risk Governance Engine — Append-only decision log + decision memory.

Two tables:
  1. decisions — append-only audit log of every scored action
  2. remembered_decisions — user preferences ("remember for project/global")
     that let 5D recall opt-in remembered human decisions on a later matching
     action. An opt-in decision-memory primitive; no bundled learning consumer.

Design principles:
  - Append-only decisions: never update or delete rows (except outcome).
  - Decision memory: user-controlled, scoped, with optional TTL.
  - Zero external deps: stdlib sqlite3 only.
  - Thread-safe: one connection per call.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Optional

from .schema import ScoredAction

DEFAULT_LOG_PATH = Path("fivedrisk_decisions.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_input_hash TEXT NOT NULL,
    data_sensitivity INTEGER NOT NULL,
    tool_privilege INTEGER NOT NULL,
    reversibility INTEGER NOT NULL,
    external_impact INTEGER NOT NULL,
    autonomy_context INTEGER NOT NULL,
    composite_score REAL NOT NULL,
    max_dimension INTEGER NOT NULL,
    band TEXT NOT NULL,
    rationale TEXT,
    source TEXT,
    outcome TEXT DEFAULT NULL,
    policy_version TEXT NOT NULL,
    session_id TEXT,
    routing_model TEXT,
    routing_floor TEXT,
    metadata TEXT,
    -- Floor attribution: WHICH policy floor raised this band, and to what.
    -- NULL on every action that matched no floor. Before these columns the only
    -- record was prose inside `rationale`, so "show me the rule that caught this,
    -- not the verdict" was a text-search question rather than a query.
    fired_rule_id TEXT,
    floor_band TEXT,
    -- WHO the action was taken on behalf of. `ActingIdentity` has always been
    -- captured on the Action and emitted to NDJSON events; it never reached this
    -- table, so an audit log could not answer "who authorised this" at all.
    acting_principal_id TEXT,
    acting_principal_type TEXT,
    -- WHICH policy content decided. `policy_version` is a string the author types;
    -- two deployments can both say "0.2.0" with different thresholds and floors, and
    -- a policy can change under a version that stays the same.
    config_hash TEXT,
    -- WHICH declared posture decided, when one was named. `policy_preset` holds the
    -- packaged preset name ("read_only"), which is the thing a control owner can
    -- defend in one sentence where a bag of thresholds cannot. NULL means no preset
    -- was named -- including a preset copied to a local path, which is no longer the
    -- preset whatever it started as.
    policy_preset TEXT,
    -- The FULL outcome sequence, append-only JSON. `outcome` holds the latest value
    -- and is overwritten by design; without this column a decision that went
    -- pending -> approved -> executed left no trace of having been anything else.
    outcome_history TEXT,
    -- Tamper-EVIDENCE seam. `record_hash` covers this row's decision fields plus the
    -- previous row's hash, so removing or editing a row breaks the chain from that
    -- point on. Evidence, not proof: the file is local and writable, so a writer who
    -- rewrites the whole tail can produce a consistent chain.
    prev_hash TEXT,
    record_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_decisions_band ON decisions(band);
CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_tool_hash ON decisions(tool_name, tool_input_hash);

-- Decision memory: user "remember" preferences
CREATE TABLE IF NOT EXISTS remembered_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    input_pattern TEXT NOT NULL,       -- normalized pattern (e.g. "docker compose *")
    decision TEXT NOT NULL,            -- approved | denied
    scope TEXT NOT NULL,               -- "global" | "project:<name>"
    band_override TEXT,                -- band to downgrade to (e.g. "GREEN")
    remembered_at TEXT NOT NULL,
    expires_at TEXT,                   -- NULL = permanent
    source_decision_id INTEGER,        -- FK to decisions.id that triggered this
    UNIQUE(tool_name, input_pattern, scope)
);

CREATE INDEX IF NOT EXISTS idx_remembered_scope ON remembered_decisions(scope);
CREATE INDEX IF NOT EXISTS idx_remembered_tool ON remembered_decisions(tool_name, input_pattern);
"""


class DecisionLog:
    """Append-only SQLite decision log with an opt-in remembered-decision store."""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else DEFAULT_LOG_PATH
        self.fallback_active = False
        try:
            self._ensure_schema()
        except sqlite3.DatabaseError as primary_err:
            # Primary path unwritable (read-only FS, sandbox restriction, missing
            # parent dir) OR the file exists but is corrupted / not a valid SQLite
            # database ("file is not a database", raised as a bare DatabaseError).
            # Fall back to the system temp dir so the agent is not taken down by a
            # logging-side I/O error. Logs persist for the session but not across
            # reboots when the fallback is active. (OperationalError is a subclass
            # of DatabaseError, so the prior unwritable-path behavior is unchanged.)
            import os
            import tempfile
            import warnings

            # M18: a fixed name in the world-writable temp dir is squattable /
            # readable by other local users. Isolate under a per-uid subdirectory
            # created with 0700 so another user cannot pre-create or read it.
            uid = getattr(os, "getuid", os.getpid)()
            tmp_dir = Path(tempfile.gettempdir()) / f"fivedrisk-{uid}"
            tmp_dir.mkdir(mode=0o700, exist_ok=True)
            try:
                os.chmod(tmp_dir, 0o700)  # tighten perms if the dir pre-existed
            except OSError:
                pass
            tmp_path = tmp_dir / "decisions.db"
            warnings.warn(
                f"DecisionLog could not write to {self.path}: {primary_err}. "
                f"Falling back to {tmp_path}; entries persist for this session "
                "only. Set an explicit writable path to silence this warning.",
                RuntimeWarning,
                stacklevel=2,
            )
            self.path = tmp_path
            self.fallback_active = True
            # If the fallback also fails, propagate. Something is genuinely wrong.
            self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with a busy_timeout (Low-13) so concurrent writers
        wait briefly instead of immediately raising 'database is locked'. The
        `with self._connect() as conn:` form still commits/rolls back on exit;
        the connection is released to GC (fine under CPython).

        WAL + synchronous=FULL (2026-08-12). The audit write measured 11x the
        cost of the decision it records -- the governance layer spending an
        order of magnitude more time proving what it did than deciding it.

        Connection reuse, the intuitive fix, buys 1.2x and is not the fix.
        WAL is. Measured here through THIS function's actual call pattern (a
        fresh connection per operation, n=400), which is what the logger really
        does:

          DELETE + FULL (before)   p50 314us   p99 506us   p99.9 550us
          WAL    + FULL (now)      p50 140us   p99 348us   p99.9 445us
                                   -> 2.2x p50, 1.5x p99

        An earlier measurement of this change recorded 5.1x p50 / 3.3x p99. It
        is not reproduced under per-call connect, and 2.2x is the number that
        describes the shipped path -- the connect and the two pragmas are paid
        on every write, so an amortised figure overstates what a caller sees.
        The gain is real either way; only its size was overstated.

        The faster variants were measured and REJECTED --

          synchronous=NORMAL  loses committed rows on power loss. (An earlier
                              note also claimed a worse p99.9 at 2182us; that
                              does NOT reproduce -- measured 285us here, i.e.
                              better than FULL. The timing argument was wrong
                              and is withdrawn. The DURABILITY argument stands
                              on its own and is the only one needed: an audit
                              log that can lose an acknowledged write is not an
                              audit log.)
          batched commits     lose up to 50 decisions on a crash. Same reason.

        synchronous=FULL keeps the pre-WAL durability guarantee exactly: every
        commit is fsynced. The speedup comes from WAL's append-only write path,
        not from weakening the fsync contract -- which is the only reason this
        is an acceptable change to an AUDIT trail at all.

        journal_mode persists in the database file; synchronous is per
        connection, so both are set on every connect rather than at schema
        creation. Set defensively: a database on a filesystem that cannot
        support WAL (some network mounts) refuses the pragma, and an audit
        logger must not fail to open because it could not go faster.
        """
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA busy_timeout = 5000")
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
        except sqlite3.DatabaseError:
            pass  # keep the rollback journal; slower, equally durable
        return conn

    # Columns added after v0.6.0. `CREATE TABLE IF NOT EXISTS` is a no-op on a
    # database that already has a `decisions` table, so a log written by an older
    # version keeps the old shape and every INSERT naming a new column fails with
    # "table decisions has no column named …" — the whole audit trail, not just the
    # new field. Each entry is additive and nullable; existing rows read back NULL.
    _ADDED_COLUMNS = (
        ("fired_rule_id", "TEXT"), ("floor_band", "TEXT"),
        # OSS-13, 0.7.0. Every one is additive and nullable, so an existing log keeps
        # working and its old rows read back NULL. 🔴 THAT NULL IS NOT "no identity",
        # "no policy" or "unbroken chain" — it is "this column did not exist when the
        # row was written", and the two are not the same answer. See `MIGRATION_NOTE`.
        ("acting_principal_id", "TEXT"), ("acting_principal_type", "TEXT"),
        ("config_hash", "TEXT"), ("outcome_history", "TEXT"),
        ("policy_preset", "TEXT"),
        ("prev_hash", "TEXT"), ("record_hash", "TEXT"),
    )

    #: What a pre-0.7.0 row cannot answer, in the words a reader needs. Exposed as an
    #: attribute rather than left in a changelog because the person querying an old log
    #: is not the person who upgraded it.
    MIGRATION_NOTE = (
        "Rows written before 0.7.0 have NULL in acting_principal_id, acting_principal_type, "
        "config_hash, outcome_history, prev_hash and record_hash. NULL here means THE COLUMN "
        "DID NOT EXIST, never 'there was no identity', 'no policy applied' or 'the chain is "
        "intact'. These cannot be back-filled: the identity and the policy content are not "
        "recoverable from the stored row, and a hash chain computed now over rows written "
        "earlier would attest to nothing. Treat the first row carrying a record_hash as the "
        "start of the verifiable chain."
    )

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Add post-v0.6.0 columns to a pre-existing `decisions` table.

        Idempotent and append-only: no row is rewritten, no column is dropped or
        retyped. A failure to add one column must not take the logger down — the
        caller is an agent whose action is already in flight — so a lost race with
        a concurrent writer (the column now exists) is swallowed.
        """
        existing = {row[1] for row in conn.execute("PRAGMA table_info(decisions)")}
        for name, decl in self._ADDED_COLUMNS:
            if name in existing:
                continue
            try:
                conn.execute(f"ALTER TABLE decisions ADD COLUMN {name} {decl}")
            except sqlite3.OperationalError:
                pass  # concurrent writer won the race; the column is there either way

    # ─── Core decision logging ──────────────────────────────────

    #: Fields covered by `record_hash`, in this order. Adding a column to the table does NOT
    #: extend the chain: an existing log's hashes must stay verifiable, so this tuple is a
    #: compatibility surface and changing it starts a new chain rather than fixing an old one.
    #:
    #: 🔴 DECISION-TIME FACTS ONLY, and the omissions are deliberate rather than accidental.
    #: `outcome` and `outcome_history` are legitimately mutated after the row is written, by
    #: `update_outcome`. Including them would make the chain fail on ordinary, authorised use —
    #: an integrity alarm that fires on correct work is one people learn to ignore, and a
    #: verifier nobody trusts protects nothing. The trade is stated plainly here and in
    #: `verify_chain`: **the chain does not attest to the outcome fields.** What it attests to is
    #: that the decision as recorded — who, what, which policy, what band, which rule — has not
    #: been altered or removed since it was written.
    _CHAINED_FIELDS = (
        "timestamp", "tool_name", "tool_input_hash", "band", "composite_score",
        "rationale", "source", "policy_version", "session_id",
        "fired_rule_id", "floor_band", "acting_principal_id", "config_hash",
        "policy_preset",
    )

    @staticmethod
    def _chain_hash(prev_hash: Optional[str], values: dict) -> str:
        """`record_hash` for one row: the previous hash folded into this row's fields.

        Deterministic and dependency-free (sha256 over a canonical JSON encoding). The previous
        hash is included so an edit or deletion anywhere invalidates every later row rather than
        only its own — that is the whole difference between a chain and a per-row checksum.
        """
        payload = {"prev": prev_hash or "", "row": {k: values.get(k) for k in DecisionLog._CHAINED_FIELDS}}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def log(
        self,
        scored: ScoredAction,
        outcome: Optional[str] = None,
        config_hash: Optional[str] = None,
        policy_preset: Optional[str] = None,
    ) -> int:
        """Append a scored action to the log.

        `config_hash` records WHICH policy content produced this decision. Supply
        ``policy.content_hash()``; it is optional so existing callers keep working, and a row
        written without one stores NULL, which reads as "not recorded" rather than "no policy".
        """
        action = scored.action
        routing_model = None
        routing_floor = None
        if scored.routing:
            routing_model = str(scored.routing.selected_model)
            routing_floor = str(scored.routing.model_floor)

        # Identity: captured on the Action all along, emitted to NDJSON events all along, and
        # never persisted here. `ActingIdentity`'s own docstring said these fields "flow through
        # to the audit log"; until 0.7.0 that half of the sentence was not true.
        identity = getattr(action, "acting_identity", None)
        principal_id = getattr(identity, "principal_id", None) if identity else None
        principal_type = str(getattr(identity, "principal_type", "")) or None if identity else None

        with self._connect() as conn:
            row = {
                "timestamp": action.timestamp.isoformat(),
                "tool_name": action.tool_name,
                "tool_input_hash": action.tool_input_hash,
                "data_sensitivity": action.data_sensitivity,
                "tool_privilege": action.tool_privilege,
                "reversibility": action.reversibility,
                "external_impact": action.external_impact,
                "autonomy_context": action.autonomy_context,
                "composite_score": scored.composite_score,
                "max_dimension": scored.max_dimension,
                "band": str(scored.band),
                "rationale": scored.rationale,
                "source": action.source,
                "outcome": outcome,
                "policy_version": scored.policy_version,
                "session_id": scored.session_id,
                "routing_model": routing_model,
                "routing_floor": routing_floor,
                "metadata": json.dumps(action.metadata) if action.metadata else None,
                "fired_rule_id": scored.fired_rule_id,
                "floor_band": scored.floor_band,
                "acting_principal_id": principal_id,
                "acting_principal_type": principal_type,
                "config_hash": config_hash,
                "policy_preset": policy_preset,
                "outcome_history": json.dumps([outcome]) if outcome is not None else None,
            }
            prev = conn.execute(
                "SELECT record_hash FROM decisions WHERE record_hash IS NOT NULL "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            row["prev_hash"] = prev[0] if prev else None
            row["record_hash"] = self._chain_hash(row["prev_hash"], row)

            cols = list(row)
            cursor = conn.execute(
                f"INSERT INTO decisions ({', '.join(cols)}) "
                f"VALUES ({', '.join('?' for _ in cols)})",
                tuple(row[c] for c in cols),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def verify_chain(self) -> dict:
        """Re-compute the hash chain and report the FIRST row that does not verify.

        Returns ``{"ok", "checked", "skipped_pre_chain", "first_bad_id", "reason"}``.

        WHAT A PASS DOES AND DOES NOT MEAN, because an integrity check that is over-read is worse
        than none:

        * it means the **decision-time** fields of every chained row recompute, so no such row was
          altered or removed after it was written;
        * it says nothing about ``outcome`` / ``outcome_history``, which are mutable by design and
          therefore outside the chain (see ``_CHAINED_FIELDS``);
        * it is **evidence, not proof**. The database is a local file; anything that can write it
          can rewrite the whole tail and produce a consistent chain. This detects edits, not an
          adversary with write access and patience.

        Rows predating the chain (``record_hash IS NULL``) are skipped and counted separately,
        never treated as passing — an unverifiable row must not read as a verified one.
        """
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM decisions ORDER BY id ASC").fetchall()

        checked = skipped = 0
        prev_hash: Optional[str] = None
        for r in rows:
            d = dict(r)
            if d.get("record_hash") is None:
                skipped += 1
                continue
            expected = self._chain_hash(prev_hash, d)
            if expected != d["record_hash"]:
                return {"ok": False, "checked": checked, "skipped_pre_chain": skipped,
                        "first_bad_id": d["id"],
                        "reason": "record_hash does not recompute — this row or an earlier one "
                                  "was changed after it was written"}
            prev_hash = d["record_hash"]
            checked += 1
        return {"ok": True, "checked": checked, "skipped_pre_chain": skipped,
                "first_bad_id": None, "reason": None}

    def log_egress_block(
        self,
        tool_name: str,
        reason: str,
        session_id: Optional[str] = None,
        source: str = "post-tool-egress",
    ) -> int:
        """M7: record a PostToolUse egress block in the audit trail.

        Egress blocks scan tool OUTPUT (there is no scored Action), so the
        dimension scores are stored as 0 with band=RED and the block reason in
        `rationale` — enough for an operator to reconstruct why an output was
        blocked. Previously these blocks were returned to the caller but never
        logged, so "audits every decision" did not hold for egress decisions.
        """
        from datetime import datetime, timezone

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO decisions (
                    timestamp, tool_name, tool_input_hash,
                    data_sensitivity, tool_privilege, reversibility,
                    external_impact, autonomy_context,
                    composite_score, max_dimension, band,
                    rationale, source, outcome, policy_version,
                    session_id, routing_model, routing_floor, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    tool_name,
                    "",
                    0, 0, 0, 0, 0,
                    0.0, 0, "RED",
                    reason, source, "blocked", "egress",
                    session_id, None, None, None,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def update_outcome(self, row_id: int, outcome: str) -> None:
        """Record a human's approve/deny response.

        `outcome` still holds the LATEST value and is still overwritten — callers and queries
        that read it are unaffected. `outcome_history` additionally accumulates the full ordered
        sequence, because a decision that went pending -> approved -> executed previously left no
        trace of having been anything but its last state, and "what happened, in what order" is
        the question an audit log exists to answer.

        🔴 The row's `record_hash` is deliberately NOT recomputed. The chain attests to what was
        written at decision time; silently re-hashing on every outcome update would let any later
        edit repair its own evidence, which is the opposite of tamper-evidence. An outcome
        recorded after the fact is a new fact about an old row, not a correction to it.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT outcome_history FROM decisions WHERE id = ?", (row_id,)
            ).fetchone()
            history = []
            if cur and cur[0]:
                try:
                    history = json.loads(cur[0]) or []
                except (ValueError, TypeError):
                    history = []          # unreadable history is replaced, never silently extended
            history.append(outcome)
            conn.execute(
                "UPDATE decisions SET outcome = ?, outcome_history = ? WHERE id = ?",
                (outcome, json.dumps(history), row_id),
            )

    def query_recent(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM decisions ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_by_band(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT band, COUNT(*) as cnt FROM decisions GROUP BY band"
            ).fetchall()
            return {row[0]: row[1] for row in rows}

    # ─── Decision memory (opt-in remembered decisions) ──────────

    def remember(
        self,
        tool_name: str,
        input_pattern: str,
        decision: str,
        scope: str,
        band_override: Optional[str] = None,
        source_decision_id: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> int:
        """Store a user's "remember this" preference.

        Args:
            tool_name: Tool name pattern (e.g. "Bash").
            input_pattern: Normalized input pattern (e.g. "docker compose restart").
            decision: "approved" or "denied".
            scope: "global" or "project:<name>".
            band_override: Band to downgrade to if approved (e.g. "GREEN").
            source_decision_id: The decision log row that triggered this.
            expires_at: ISO timestamp for TTL, or None for permanent.

        Returns:
            Row ID of the memory entry.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO remembered_decisions (
                    tool_name, input_pattern, decision, scope,
                    band_override, remembered_at, expires_at, source_decision_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tool_name, input_pattern, decision, scope,
                    band_override, now, expires_at, source_decision_id,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def check_memory(
        self,
        tool_name: str,
        input_pattern: str,
        scope: str = "global",
        project_scope: Optional[str] = None,
    ) -> Optional[dict]:
        """Check if there's a remembered decision for this action.

        Checks project-specific scope first, then global.
        Respects TTL (expired entries are ignored).

        Returns:
            Memory entry dict if found, None otherwise.
        """
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            scopes = []
            if project_scope:
                scopes.append(project_scope)
            scopes.append("global")

            for s in scopes:
                row = conn.execute(
                    """
                    SELECT * FROM remembered_decisions
                    WHERE tool_name = ? AND input_pattern = ? AND scope = ?
                      AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
                    ORDER BY remembered_at DESC LIMIT 1
                    """,
                    (tool_name, input_pattern, s),
                ).fetchone()
                if row:
                    return dict(row)

            return None

    def list_memories(self, scope: Optional[str] = None) -> list[dict]:
        """List all active remembered decisions."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if scope:
                rows = conn.execute(
                    """SELECT * FROM remembered_decisions
                       WHERE scope = ? AND (expires_at IS NULL OR julianday(expires_at) > julianday('now'))
                       ORDER BY remembered_at DESC""",
                    (scope,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM remembered_decisions
                       WHERE expires_at IS NULL OR julianday(expires_at) > julianday('now')
                       ORDER BY remembered_at DESC""",
                ).fetchall()
            return [dict(row) for row in rows]

    def find_similar_decisions(
        self, tool_name: str, limit: int = 5
    ) -> list[dict]:
        """Find prior decisions for the same tool (for HITL card context)."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT band, outcome, composite_score, rationale, timestamp
                   FROM decisions
                   WHERE tool_name = ? AND outcome IS NOT NULL
                   ORDER BY id DESC LIMIT ?""",
                (tool_name, limit),
            ).fetchall()
            return [dict(row) for row in rows]
