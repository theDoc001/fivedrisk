"""5D Risk Governance Engine — Append-only decision log + decision memory.

Two tables:
  1. decisions — append-only audit log of every scored action
  2. remembered_decisions — user preferences ("remember for project/global")
     that allow 5D to learn from prior human decisions and expand Dot's
     autonomous boundary over time.

Design principles:
  - Append-only decisions: never update or delete rows (except outcome).
  - Decision memory: user-controlled, scoped, with optional TTL.
  - Zero external deps: stdlib sqlite3 only.
  - Thread-safe: one connection per call.
"""

from __future__ import annotations

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
    metadata TEXT
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
    """Append-only SQLite decision log with adaptive memory."""

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else DEFAULT_LOG_PATH
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.executescript(_SCHEMA)

    # ─── Core decision logging ──────────────────────────────────

    def log(self, scored: ScoredAction, outcome: Optional[str] = None) -> int:
        """Append a scored action to the log."""
        action = scored.action
        routing_model = None
        routing_floor = None
        if scored.routing:
            routing_model = str(scored.routing.selected_model)
            routing_floor = str(scored.routing.model_floor)

        with sqlite3.connect(self.path) as conn:
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
                    action.timestamp.isoformat(),
                    action.tool_name,
                    action.tool_input_hash,
                    action.data_sensitivity,
                    action.tool_privilege,
                    action.reversibility,
                    action.external_impact,
                    action.autonomy_context,
                    scored.composite_score,
                    scored.max_dimension,
                    str(scored.band),
                    scored.rationale,
                    action.source,
                    outcome,
                    scored.policy_version,
                    scored.session_id,
                    routing_model,
                    routing_floor,
                    json.dumps(action.metadata) if action.metadata else None,
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def update_outcome(self, row_id: int, outcome: str) -> None:
        """Record a human's approve/deny response."""
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "UPDATE decisions SET outcome = ? WHERE id = ?",
                (outcome, row_id),
            )

    def query_recent(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM decisions ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_by_band(self) -> dict[str, int]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT band, COUNT(*) as cnt FROM decisions GROUP BY band"
            ).fetchall()
            return {row[0]: row[1] for row in rows}

    # ─── Decision memory (adaptive learning) ────────────────────

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

        with sqlite3.connect(self.path) as conn:
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
        with sqlite3.connect(self.path) as conn:
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
                      AND (expires_at IS NULL OR expires_at > datetime('now'))
                    ORDER BY remembered_at DESC LIMIT 1
                    """,
                    (tool_name, input_pattern, s),
                ).fetchone()
                if row:
                    return dict(row)

            return None

    def list_memories(self, scope: Optional[str] = None) -> list[dict]:
        """List all active remembered decisions."""
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            if scope:
                rows = conn.execute(
                    """SELECT * FROM remembered_decisions
                       WHERE scope = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
                       ORDER BY remembered_at DESC""",
                    (scope,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM remembered_decisions
                       WHERE expires_at IS NULL OR expires_at > datetime('now')
                       ORDER BY remembered_at DESC""",
                ).fetchall()
            return [dict(row) for row in rows]

    def find_similar_decisions(
        self, tool_name: str, limit: int = 5
    ) -> list[dict]:
        """Find prior decisions for the same tool (for HITL card context)."""
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT band, outcome, composite_score, rationale, timestamp
                   FROM decisions
                   WHERE tool_name = ? AND outcome IS NOT NULL
                   ORDER BY id DESC LIMIT ?""",
                (tool_name, limit),
            ).fetchall()
            return [dict(row) for row in rows]
