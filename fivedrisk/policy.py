"""5D Risk Governance Engine — Policy definition and YAML loader.

Aligned with governance spec v0.3 §12.3-12.5, §16, §19.
4-band thresholds, dimension weights, tool defaults, bash overrides,
Cost×Risk coupling rules, and model routing floors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .schema import DIMENSION_NAMES


# ─── Default weights (§12.3) ───────────────────────────────────
# Spec recommends: DS=0.30, TP=0.20, R=0.20, EI=0.15, AC=0.15
# We use absolute weights that produce a 0-3 normalized score range
DEFAULT_WEIGHTS = {
    "data_sensitivity": 1.2,     # DS: highest weight (0.30 relative)
    "tool_privilege": 1.0,       # TP: privilege escalation
    "reversibility": 1.5,        # R: irreversible is always worse
    "external_impact": 0.8,      # EI: external blast radius
    "autonomy_context": 0.8,     # AC: oversight modifies, doesn't dominate
}

# ─── Default tool classification baselines ──────────────────────
DEFAULT_TOOL_DEFAULTS: Dict[str, Dict[str, int]] = {
    "Read":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Glob":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Grep":      {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
    "Edit":      {"tool_privilege": 1, "reversibility": 1, "external_impact": 0},
    "Write":     {"tool_privilege": 1, "reversibility": 1, "external_impact": 0},
    "Bash":      {"tool_privilege": 2, "reversibility": 2, "external_impact": 1},
    "WebFetch":  {"tool_privilege": 1, "reversibility": 0, "external_impact": 1},
    "WebSearch": {"tool_privilege": 0, "reversibility": 0, "external_impact": 0},
}

# ─── Bash command overrides ─────────────────────────────────────
DEFAULT_BASH_OVERRIDES: Dict[str, Dict[str, int]] = {
    "rm -rf":           {"tool_privilege": 4, "reversibility": 4},
    "docker":           {"tool_privilege": 3, "reversibility": 2},
    "git push --force": {"tool_privilege": 3, "reversibility": 4},
    r"curl.*POST":      {"tool_privilege": 2, "external_impact": 3},
    "pip install":      {"tool_privilege": 2, "reversibility": 1},
}


@dataclass
class Policy:
    """Scoring policy for the 5D Risk Governance Engine.

    4-band system per governance spec v0.3 §12.4:
      GREEN  (normalized 0.0-0.9)  → Low risk
      YELLOW (normalized 1.0-1.7)  → Moderate risk
      ORANGE (normalized 1.8-2.4)  → High risk
      RED    (normalized 2.5+)     → Critical
    """

    version: str = "0.2.0"

    # ── 4-Band normalized score thresholds (§12.4) ──
    green_score: float = 0.0       # everything below yellow
    yellow_score: float = 1.0      # moderate risk
    orange_score: float = 1.8      # high risk
    red_score: float = 2.5         # critical

    # ── Single-axis spike thresholds ──
    red_threshold: int = 4         # any dim >= this → RED
    orange_threshold: int = 3      # any dim >= this → ORANGE (minimum)

    # ── Dimension weights ──
    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    # ── Tool baselines ──
    tool_defaults: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_TOOL_DEFAULTS.items()}
    )

    # ── Bash overrides ──
    bash_overrides: Dict[str, Dict[str, int]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_BASH_OVERRIDES.items()}
    )

    # ── Retry budget (per task) ──
    retry_budget: int = 5

    # ── Cost-management attributes ──
    # Architectural contract: budget breach triggers a direct DENY at the
    # @gate reservation gate. The 5D Score function does not consume
    # budget state; admission and scoring are separate paths.
    max_session_budget_tokens: Optional[int] = None    # session-level token cap
    max_tool_call_budget_tokens: Optional[int] = None  # per-call output cap

    # ── Identity admission ──
    identity_required: bool = False                    # deny ANONYMOUS at admission

    # ── YELLOW band behavior ──
    # Default: 3-band experience (GREEN / ORANGE / RED). Scores that
    # would land in the YELLOW range are returned as GREEN. Simpler
    # mental model for OSS users who do not need a moderate tier.
    # Set enable_yellow_band=True for the 4-band compliance model:
    # adds a stable moderate-risk label for audit queries and dashboards
    # that need to track moderate-risk actions over time.
    enable_yellow_band: bool = False
    # When YELLOW is enabled, opt in to model-class promotion for D2/D3
    # data via yellow_model_escalation=True. The caller's stack still
    # decides whether to honour the routing recommendation.
    yellow_model_escalation: bool = False

    @property
    def weight_vector(self) -> tuple[float, ...]:
        return tuple(self.weights.get(name, 1.0) for name in DIMENSION_NAMES)

    def get_tool_baseline(self, tool_name: str) -> Dict[str, int]:
        return dict(self.tool_defaults.get(tool_name, {}))

    def get_bash_overrides(self, command: str) -> Dict[str, int]:
        merged: Dict[str, int] = {}
        for pattern, overrides in self.bash_overrides.items():
            if re.search(pattern, command):
                merged.update(overrides)
        return merged

    def admit_session(self, workflow_type: str = "default") -> "AdmissionResult":
        """Admission check L1: validate policy is configured for the workflow.

        Returns an AdmissionResult with admit=True in either of these cases:
          - max_session_budget_tokens is configured (the workflow has an
            explicit budget cap)
          - max_session_budget_tokens is None (the workflow opts out of
            budget enforcement; admission succeeds with a warning)

        Additional Operational FinOps admission layers (Tool Manifest
        validation, historical P95 baselines, post-step reconciliation)
        are on the project roadmap.
        """
        if self.max_session_budget_tokens is None:
            return AdmissionResult(
                admit=True,
                workflow_type=workflow_type,
                warning="max_session_budget_tokens not configured; admitting without budget enforcement",
            )
        return AdmissionResult(
            admit=True,
            workflow_type=workflow_type,
            max_session_budget_tokens=self.max_session_budget_tokens,
        )


@dataclass
class AdmissionResult:
    """Outcome of policy.admit_session()."""

    admit: bool
    workflow_type: str
    max_session_budget_tokens: Optional[int] = None
    warning: Optional[str] = None
    deny_reason: Optional[str] = None


def load_policy(path: Optional[str | Path] = None) -> Policy:
    """Load a Policy from a YAML file, or return defaults."""
    if path is None:
        return Policy()

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        raw: Dict[str, Any] = yaml.safe_load(f) or {}

    thresholds = raw.get("thresholds", {})
    bands = raw.get("bands", {})

    return Policy(
        version=raw.get("version", "0.2.0"),
        # 4-band score thresholds
        yellow_score=float(bands.get("yellow_score", 1.0)),
        orange_score=float(bands.get("orange_score", 1.8)),
        red_score=float(bands.get("red_score", 2.5)),
        # Spike thresholds
        red_threshold=thresholds.get("red_threshold", 4),
        orange_threshold=thresholds.get("orange_threshold", 3),
        # Weights
        weights={**DEFAULT_WEIGHTS, **raw.get("weights", {})},
        # Tools
        tool_defaults={
            **{k: dict(v) for k, v in DEFAULT_TOOL_DEFAULTS.items()},
            **{k: dict(v) for k, v in raw.get("tool_defaults", {}).items()},
        },
        bash_overrides={
            **{k: dict(v) for k, v in DEFAULT_BASH_OVERRIDES.items()},
            **{k: dict(v) for k, v in raw.get("bash_overrides", {}).items()},
        },
        retry_budget=raw.get("retry_budget", 5),
        # Cost-management attributes (OSS-COST-MVP-001)
        max_session_budget_tokens=raw.get("max_session_budget_tokens"),
        max_tool_call_budget_tokens=raw.get("max_tool_call_budget_tokens"),
        # Identity admission
        identity_required=bool(raw.get("identity_required", False)),
        # YELLOW band behavior
        enable_yellow_band=bool(raw.get("enable_yellow_band", False)),
        yellow_model_escalation=bool(raw.get("yellow_model_escalation", False)),
    )
