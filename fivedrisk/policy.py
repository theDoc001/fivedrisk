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
    tier: str = "standard"  # light | standard | enterprise

    # ── 4-Band normalized score thresholds (§12.4) ──
    green_score: float = 0.0       # everything below yellow
    yellow_score: float = 1.0      # moderate risk
    orange_score: float = 1.8      # high risk
    red_score: float = 2.5         # critical

    # ── Single-axis spike thresholds ──
    red_threshold: int = 4         # any dim >= this → RED
    orange_threshold: int = 3      # any dim >= this → ORANGE (minimum)

    # ── Legacy 3-band thresholds (backward compat for 5D Light) ──
    stop_threshold: int = 4
    ask_threshold: int = 3
    composite_ask: float = 8.0

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
        tier=raw.get("tier", "standard"),
        # 4-band score thresholds
        yellow_score=float(bands.get("yellow_score", 1.0)),
        orange_score=float(bands.get("orange_score", 1.8)),
        red_score=float(bands.get("red_score", 2.5)),
        # Spike thresholds
        red_threshold=thresholds.get("red_threshold", thresholds.get("stop_threshold", 4)),
        orange_threshold=thresholds.get("orange_threshold", thresholds.get("ask_threshold", 3)),
        # Legacy
        stop_threshold=thresholds.get("stop_threshold", 4),
        ask_threshold=thresholds.get("ask_threshold", 3),
        composite_ask=float(thresholds.get("composite_ask", 8.0)),
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
    )
