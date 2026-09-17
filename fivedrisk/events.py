"""NDJSON event emission layer.

Sibling to the SQLite DecisionLog. Emits one JSON object per line to a
configurable path, intended for streaming to log aggregators (ELK,
Datadog, Splunk) without requiring SQL queries.

Three event types ship in OSS:

  - `risk_decision`: emitted by @gate on every scored action; carries
    band, dimension scores, rationale, model routing, acting_identity if
    present.
  - `budget_intervention`: emitted by @gate when a tool call would
    exceed max_session_budget_tokens. Direct-DENY signal at the budget
    admission gate (see budget_accumulator.py).
  - `identity_required_denial`: emitted by @gate when policy declares
    identity_required and the caller supplied ANONYMOUS.

Every event carries `trace_id` and `session_id` for cross-event
correlation. `trace_id` is a fresh UUID per event; `session_id` is
caller-supplied and stable across events in a session.

Emission is best-effort. Failures to write the NDJSON event are logged
as warnings but do not interrupt the action pipeline. Disable by passing
`path=None` or leaving the default unset.
"""

from __future__ import annotations

import json
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# ─── Event reason codes ─────────────────────────────────────────

REASON_BUDGET_CAP_EXCEEDED = "BUDGET_CAP_EXCEEDED"
REASON_BUDGET_RESERVATION_BLOCKED = "BUDGET_RESERVATION_BLOCKED"
REASON_IDENTITY_REQUIRED_NOT_SUPPLIED = "IDENTITY_REQUIRED_NOT_SUPPLIED"


# ─── Event channel ──────────────────────────────────────────────


@dataclass
class NDJSONEventChannel:
    """Append-only NDJSON event emitter.

    Usage:
        channel = NDJSONEventChannel(path="audit-events.ndjson")
        channel.emit_risk_decision(
            session_id="s1", scored_action=scored, acting_identity=ai
        )
        channel.emit_budget_intervention(
            session_id="s1",
            reason_code=REASON_BUDGET_CAP_EXCEEDED,
            cumulative_token_spend=85_000,
            max_session_budget_tokens=100_000,
            pressure_ratio=0.85,
            tool_id="call-123",
        )

    Events are JSON objects with at minimum:
      {
        "event_type": "risk_decision" | "budget_intervention" | "identity_required_denial",
        "timestamp": "2026-05-10T...Z",
        "trace_id": "uuid-...",
        "session_id": "...",
        ...event-specific fields...
      }
    """

    path: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, event: Dict[str, Any]) -> None:
        """Best-effort write. Warns on I/O failure but does not raise."""
        if self.path is None:
            return
        event.setdefault("trace_id", str(uuid.uuid4()))
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except OSError as exc:
            warnings.warn(
                f"NDJSONEventChannel could not write to {self.path}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    def emit_risk_decision(
        self,
        session_id: Optional[str],
        scored_action: Any,                        # ScoredAction; typed loosely to avoid import cycle
        acting_identity: Optional[Any] = None,     # ActingIdentity
    ) -> None:
        event: Dict[str, Any] = {
            "event_type": "risk_decision",
            "session_id": session_id,
            "tool_name": scored_action.action.tool_name,
            "band": str(scored_action.band),
            "composite_score": scored_action.composite_score,
            "max_dimension": scored_action.max_dimension,
            "rationale": scored_action.rationale,
            "policy_version": scored_action.policy_version,
            "data_sensitivity": scored_action.action.data_sensitivity,
            "tool_privilege": scored_action.action.tool_privilege,
            "reversibility": scored_action.action.reversibility,
            "external_impact": scored_action.action.external_impact,
            "autonomy_context": scored_action.action.autonomy_context,
        }
        if scored_action.routing is not None:
            event["routing_model"] = str(scored_action.routing.selected_model)
            event["routing_floor"] = str(scored_action.routing.model_floor)
        if acting_identity is not None:
            event["acting_identity"] = acting_identity.to_dict()
        elif scored_action.action.acting_identity is not None:
            event["acting_identity"] = scored_action.action.acting_identity.to_dict()
        self._emit(event)

    def emit_budget_intervention(
        self,
        session_id: Optional[str],
        reason_code: str,
        cumulative_token_spend: int,
        max_session_budget_tokens: Optional[int],
        pressure_ratio: float,
        tool_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        reserved_tokens: int = 0,
        acting_identity: Optional[Any] = None,
    ) -> None:
        """Emit a budget intervention event.

        This is the channel through which budget breaches surface in
        the NDJSON event stream.
        """
        event: Dict[str, Any] = {
            "event_type": "budget_intervention",
            "session_id": session_id,
            "reason_code": reason_code,
            "cumulative_token_spend": cumulative_token_spend,
            "max_session_budget_tokens": max_session_budget_tokens,
            "pressure_ratio": pressure_ratio,
            "reserved_tokens": reserved_tokens,
        }
        if tool_id is not None:
            event["tool_id"] = tool_id
        if tool_name is not None:
            event["tool_name"] = tool_name
        if acting_identity is not None:
            event["acting_identity"] = acting_identity.to_dict()
        self._emit(event)

    def emit_identity_required_denial(
        self,
        session_id: Optional[str],
        tool_name: str,
        attempted_identity: Optional[Any] = None,
    ) -> None:
        event: Dict[str, Any] = {
            "event_type": "identity_required_denial",
            "session_id": session_id,
            "reason_code": REASON_IDENTITY_REQUIRED_NOT_SUPPLIED,
            "tool_name": tool_name,
        }
        if attempted_identity is not None:
            event["attempted_identity"] = attempted_identity.to_dict()
        self._emit(event)
