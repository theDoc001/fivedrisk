"""5D Risk Governance Engine — Core schema definitions.

Action, Band, ScoredAction, HITLCard, ModelClass dataclasses that
form the backbone of every scoring, routing, and intervention operation.

Aligned with DotOS Governance Spec v0.3 (§12-19).
4-band system: Green / Yellow / Orange / Red.
Model classes: M0-M4 per §19.2.

Provenance: 5D Risk Governance Model is DotOS-native.
Authored by Loren, March 2026. Apache-2.0 license.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional


# ─── Risk Bands (§12.4) ────────────────────────────────────────

class Band(Enum):
    """Risk band — 4-tier gate decision per governance spec v0.3 §12.4."""
    GREEN = "GREEN"    # Low-risk: execute, normal logging
    YELLOW = "YELLOW"  # Moderate: execute with enhanced logging + conditional approval
    ORANGE = "ORANGE"  # High: mandatory approval, stronger model, narrower tools
    RED = "RED"        # Critical: hard gate, dual control or deny

    def __str__(self) -> str:
        return self.value

    @property
    def requires_approval(self) -> bool:
        return self in (Band.ORANGE, Band.RED)

    @property
    def requires_enhanced_logging(self) -> bool:
        return self in (Band.YELLOW, Band.ORANGE, Band.RED)

    @property
    def is_denied(self) -> bool:
        return self == Band.RED


# Backward-compatible aliases for 3-band consumers (5D Light)
Band.GO = Band.GREEN
Band.ASK = Band.ORANGE
Band.STOP = Band.RED


# ─── Model Classes (§19.2) ─────────────────────────────────────

class ModelClass(Enum):
    """Abstract model quality classes — not vendor-specific."""
    M0 = "M0"  # Local utility: classification, parsing, routing (phi-4-mini)
    M1 = "M1"  # Cost-efficient general: simple summarization, drafts (Qwen3:8b)
    M2 = "M2"  # Balanced reasoning: planning, synthesis (Qwen3:8b /think)
    M3 = "M3"  # Premium reasoning: complex planning, high-stakes (Sonnet+Advisor)
    M4 = "M4"  # Trusted review path: Red/Orange control workflows (Opus direct)

    def __str__(self) -> str:
        return self.value


# ─── Model Routing Decision (§19.6) ────────────────────────────

@dataclass
class RoutingDecision:
    """Per-action model routing decision per governance spec v0.3 §19.6."""
    data_class: str                    # D0-D3
    risk_band: Band
    task_class: str                    # research, planning, drafting, execution, review
    model_floor: ModelClass            # minimum model quality allowed
    selected_model: ModelClass         # actual model selected
    downgrade_allowed: bool = True
    approval_required: bool = False
    verification_level: str = "standard"  # standard | enhanced | full_provenance
    reason: str = ""                   # why this routing was chosen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_class": self.data_class,
            "risk_band": str(self.risk_band),
            "task_class": self.task_class,
            "model_floor": str(self.model_floor),
            "selected_model": str(self.selected_model),
            "downgrade_allowed": self.downgrade_allowed,
            "approval_required": self.approval_required,
            "verification_level": self.verification_level,
            "reason": self.reason,
        }


# ─── Dimensions ────────────────────────────────────────────────

DIMENSION_NAMES = (
    "data_sensitivity",
    "tool_privilege",
    "reversibility",
    "external_impact",
    "autonomy_context",
)

DIM_MIN = 0
DIM_MAX = 4


# ─── Action ────────────────────────────────────────────────────

@dataclass
class Action:
    """An action about to be executed by an agent.

    Each of the five dimensions is scored 0-4 per §12.2:
        0 = no risk (e.g. read-only local file, public data)
        4 = maximum risk (e.g. irreversible, PII, unattended, admin)
    """
    tool_name: str
    tool_input: Dict[str, Any] = field(default_factory=dict)

    # --- 5 Dimensions (0-4 each) ---
    data_sensitivity: int = 0
    tool_privilege: int = 0
    reversibility: int = 0
    external_impact: int = 0
    autonomy_context: int = 0

    # --- Metadata ---
    source: str = "unknown"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for dim_name in DIMENSION_NAMES:
            val = getattr(self, dim_name)
            if not isinstance(val, int) or not (DIM_MIN <= val <= DIM_MAX):
                raise ValueError(
                    f"{dim_name} must be int in [{DIM_MIN}, {DIM_MAX}], got {val!r}"
                )

    @property
    def dimensions(self) -> tuple[int, ...]:
        return tuple(getattr(self, name) for name in DIMENSION_NAMES)

    @property
    def max_dimension(self) -> int:
        return max(self.dimensions)

    @property
    def tool_input_hash(self) -> str:
        raw = json.dumps(self.tool_input, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def data_class(self) -> str:
        """Map data_sensitivity to governance spec data classes D0-D3."""
        return f"D{min(self.data_sensitivity, 3)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_input_hash": self.tool_input_hash,
            **{name: getattr(self, name) for name in DIMENSION_NAMES},
            "data_class": self.data_class,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


# ─── Scored Action ─────────────────────────────────────────────

@dataclass
class ScoredAction:
    """Result of scoring an Action through a Policy."""
    action: Action
    band: Band
    composite_score: float
    max_dimension: int
    rationale: str
    policy_version: str
    routing: Optional[RoutingDecision] = None
    session_id: Optional[str] = None
    retry_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = {
            **self.action.to_dict(),
            "band": str(self.band),
            "composite_score": round(self.composite_score, 3),
            "max_dimension": self.max_dimension,
            "rationale": self.rationale,
            "policy_version": self.policy_version,
            "session_id": self.session_id,
            "retry_count": self.retry_count,
        }
        if self.routing:
            d["routing"] = self.routing.to_dict()
        return d


# ─── HITL Card (§15.4) ─────────────────────────────────────────

@dataclass
class HITLCard:
    """Human-in-the-loop intervention card per governance spec v0.3 §15.4.

    Rendered as a Discord embed. Progressive disclosure:
    - Default: summary + recommendation + actions
    - Expanded: full 5D score, chain-of-thought, prior decisions
    - Memory: "Remember for this project" / "Remember for all projects"
    """
    card_type: str                     # planner-clarification | 5d-risk-gate |
                                       # builder-error | retry-exhausted | model-escalation
    summary: str                       # one sentence: what happened
    why_it_matters: str                # one sentence: why this needs attention
    band: Band
    cost_impact: Optional[str] = None  # estimated cost of proceeding
    recommendation: str = ""           # default action suggestion
    actions: List[str] = field(default_factory=lambda: ["approve", "deny"])
    scored_action: Optional[ScoredAction] = None
    retry_history: List[Dict[str, Any]] = field(default_factory=list)
    prior_decisions: List[Dict[str, Any]] = field(default_factory=list)

    # Memory fields — set when user responds
    remember_scope: Optional[str] = None  # None | "project:<name>" | "global"
    remember_pattern: Optional[str] = None  # normalized tool+input pattern for matching

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "card_type": self.card_type,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "band": str(self.band),
            "recommendation": self.recommendation,
            "actions": self.actions,
        }
        if self.cost_impact:
            d["cost_impact"] = self.cost_impact
        if self.scored_action:
            d["scored_action"] = self.scored_action.to_dict()
        if self.retry_history:
            d["retry_history"] = self.retry_history
        if self.prior_decisions:
            d["prior_decisions"] = self.prior_decisions
        if self.remember_scope:
            d["remember_scope"] = self.remember_scope
            d["remember_pattern"] = self.remember_pattern
        return d
