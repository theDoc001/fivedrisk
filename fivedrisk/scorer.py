"""5D Risk Governance Engine — Scoring algorithm.

4-band scoring per governance spec v0.3 §12.3-12.4:
  1. Single-axis spike: any dimension at threshold → immediate band.
  2. Composite: weighted sum for band discrimination.
  3. Band mapping: score → Green/Yellow/Orange/Red.

Bands (§12.4):
  GREEN  (0.0-0.9)  Low-risk, allowed if policy permits
  YELLOW (1.0-1.7)  Moderate, enhanced logging + conditional approval
  ORANGE (1.8-2.4)  High, mandatory approval + stronger model
  RED    (2.5+)     Critical, hard gate / deny
"""

from __future__ import annotations

from .policy import Policy
from .schema import DIMENSION_NAMES, Action, Band, ModelClass, RoutingDecision, ScoredAction


# ─── Model routing table (§19.3) ───────────────────────────────

def _route_model(band: Band, data_class: str, task_class: str = "execution") -> RoutingDecision:
    """Determine model floor and routing based on risk band + data class.

    Per governance spec v0.3 §19.3:
      D0 + Green → M0/M1 (cheapest)
      D1 + Green/Yellow → M1/M2 (normal)
      D2 + Yellow/Orange → M2/M3 (stronger verification)
      D3 + Orange/Red → M3/M4 (no silent downgrade)
    """
    # Default: cost-efficient
    floor = ModelClass.M1
    selected = ModelClass.M1
    downgrade = True
    verification = "standard"

    if band == Band.RED:
        floor = ModelClass.M4
        selected = ModelClass.M4
        downgrade = False
        verification = "full_provenance"
    elif band == Band.ORANGE:
        floor = ModelClass.M3
        selected = ModelClass.M3
        downgrade = False
        verification = "enhanced"
    elif band == Band.YELLOW:
        if data_class in ("D2", "D3"):
            floor = ModelClass.M2
            selected = ModelClass.M2
            verification = "enhanced"
        else:
            floor = ModelClass.M1
            selected = ModelClass.M2
    else:  # GREEN
        if data_class in ("D2", "D3"):
            floor = ModelClass.M1
            selected = ModelClass.M2
        else:
            floor = ModelClass.M0
            selected = ModelClass.M1

    return RoutingDecision(
        data_class=data_class,
        risk_band=band,
        task_class=task_class,
        model_floor=floor,
        selected_model=selected,
        downgrade_allowed=downgrade,
        approval_required=band.requires_approval,
        verification_level=verification,
        reason=f"Band={band}, Data={data_class} → floor={floor}",
    )


# ─── Rationale builder ─────────────────────────────────────────

def _build_rationale(action: Action, band: Band, max_dim: int,
                     composite: float, normalized: float, policy: Policy) -> str:
    """Generate a human-readable rationale for the scoring decision."""
    parts: list[str] = []

    for name in DIMENSION_NAMES:
        val = getattr(action, name)
        if val >= policy.red_threshold:
            label = name.replace("_", " ").title()
            parts.append(f"{label}={val} (≥ RED threshold {policy.red_threshold})")
        elif val >= policy.orange_threshold:
            label = name.replace("_", " ").title()
            parts.append(f"{label}={val} (≥ ORANGE threshold {policy.orange_threshold})")

    band_name = str(band)
    if band == Band.RED:
        trigger = "; ".join(parts) if parts else f"max_dim={max_dim}"
        return f"RED — {action.tool_name}: {trigger}"
    elif band == Band.ORANGE:
        if parts:
            return f"ORANGE — {action.tool_name}: {'; '.join(parts)}"
        return f"ORANGE — {action.tool_name}: normalized score {normalized:.2f} ≥ {policy.orange_score}"
    elif band == Band.YELLOW:
        return f"YELLOW — {action.tool_name}: normalized score {normalized:.2f} ≥ {policy.yellow_score}"
    else:
        return f"GREEN — {action.tool_name}: normalized score {normalized:.2f}, max_dim={max_dim}"


# ─── Main scoring function ─────────────────────────────────────

def score(action: Action, policy: Policy | None = None) -> ScoredAction:
    """Score an Action against a Policy, returning a ScoredAction.

    Algorithm (4-band, aligned with governance spec v0.3 §12.3):

        1. Compute weighted composite:
           composite = sum(dim_i × weight_i)

        2. Normalize to 0-3 range:
           normalized = composite / max_possible_composite × 3.0

        3. Single-axis spike (overrides composite):
           - Any dimension ≥ red_threshold (default 4) → RED
           - Any dimension ≥ orange_threshold (default 3) → ORANGE (minimum)

        4. Band from normalized score (§12.4):
           RED    ≥ 2.5
           ORANGE ≥ 1.8
           YELLOW ≥ 1.0
           GREEN  < 1.0

        5. Take the highest band from steps 3-4.

        6. Route model based on band + data class (§19.3).

    Args:
        action: The Action to score.
        policy: Scoring policy. Defaults to built-in Policy().

    Returns:
        ScoredAction with band, composite_score, routing, rationale.
    """
    if policy is None:
        policy = Policy()

    dims = action.dimensions
    weights = policy.weight_vector
    max_dim = max(dims)

    # Step 1: Weighted composite
    composite = sum(d * w for d, w in zip(dims, weights))

    # Step 2: Normalize to 0-3 scale
    max_possible = sum(DIM_MAX * w for w in weights)  # theoretical max
    normalized = (composite / max_possible * 3.0) if max_possible > 0 else 0.0

    # Step 3: Single-axis spike
    spike_band = Band.GREEN
    if max_dim >= policy.red_threshold:
        spike_band = Band.RED
    elif max_dim >= policy.orange_threshold:
        spike_band = Band.ORANGE

    # Step 4: Band from normalized score
    if normalized >= policy.red_score:
        score_band = Band.RED
    elif normalized >= policy.orange_score:
        score_band = Band.ORANGE
    elif normalized >= policy.yellow_score:
        score_band = Band.YELLOW
    else:
        score_band = Band.GREEN

    # Step 5: Highest band wins
    band_order = [Band.GREEN, Band.YELLOW, Band.ORANGE, Band.RED]
    band = max(spike_band, score_band, key=lambda b: band_order.index(b))

    # Step 6: Model routing
    routing = _route_model(band, action.data_class)

    rationale = _build_rationale(action, band, max_dim, composite, normalized, policy)

    return ScoredAction(
        action=action,
        band=band,
        composite_score=composite,
        max_dimension=max_dim,
        rationale=rationale,
        policy_version=policy.version,
        routing=routing,
    )


# ─── Convenience: 3-band mapping for 5D Light consumers ───────

DIM_MAX = 4  # re-export for max_possible calc

def score_light(action: Action, policy: Policy | None = None) -> ScoredAction:
    """Score using 3-band GO/ASK/STOP mapping (backward compat).

    Maps: GREEN→GO, YELLOW→GO, ORANGE→ASK, RED→STOP.
    """
    result = score(action, policy)
    # Band aliases are already set on the class
    # Consumers using Band.GO/ASK/STOP will match via the aliases
    return result
