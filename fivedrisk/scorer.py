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
from .schema import DIM_MAX, DIMENSION_NAMES, Action, Band, ModelClass, RoutingDecision, ScoredAction


# ─── Model routing table (§19.3) ───────────────────────────────

def _route_model(
    band: Band,
    data_class: str,
    task_class: str = "execution",
    policy: Policy | None = None,
) -> RoutingDecision:
    """Determine model floor and routing based on risk band + data class.

    fivedrisk stays deterministic. The 5D Score function and Band
    classification do not prescribe a model. RoutingDecision is a
    recommendation the caller's stack can honour or ignore.

    Defaults are conservative: the routing recommendation is based on
    data class for GREEN and RED bands. ORANGE signals that human
    approval is required; it does not auto-promote the model class.
    YELLOW only promotes the model class when the caller has opted in
    via `policy.yellow_model_escalation = True`.

    Band-by-band:
      GREEN: cost-efficient (M0/M1 floor by data class).
      YELLOW: neutral by default; opt-in to M2-class suggestion via policy.
      ORANGE: same routing recommendation as the data class would suggest
              outside HITL; the load-bearing signal is approval_required=True.
              The caller's HITL stack decides what model the reviewer (or
              the AI-assisted HITL pipeline) uses.
      RED: hard gate; M4 suggested but the action is blocked regardless.
    """
    floor = ModelClass.M1
    selected = ModelClass.M1
    downgrade = True
    verification = "standard"

    yellow_escalate = policy is not None and policy.yellow_model_escalation

    if band == Band.RED:
        floor = ModelClass.M4
        selected = ModelClass.M4
        downgrade = False
        verification = "full_provenance"
    elif band == Band.ORANGE:
        # No auto model promotion: caller's HITL stack decides.
        # Routing falls back to the data-class-appropriate default so the
        # recommendation field is still informative for downstream
        # consumers that want to know what fivedrisk would have suggested
        # absent HITL.
        if data_class in ("D2", "D3"):
            floor = ModelClass.M1
            selected = ModelClass.M2
        else:
            floor = ModelClass.M0
            selected = ModelClass.M1
        downgrade = True
        verification = "enhanced"
    elif band == Band.YELLOW:
        if yellow_escalate:
            if data_class in ("D2", "D3"):
                floor = ModelClass.M2
                selected = ModelClass.M2
                verification = "enhanced"
            else:
                floor = ModelClass.M1
                selected = ModelClass.M2
        else:
            # Default: no model promotion. Same as GREEN routing.
            if data_class in ("D2", "D3"):
                floor = ModelClass.M1
                selected = ModelClass.M2
            else:
                floor = ModelClass.M0
                selected = ModelClass.M1
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

    By default, YELLOW band collapses into GREEN (3-band experience). Enable
    the 4-band experience by setting ``enable_yellow_band: true`` in
    policy.yaml. The 4-band mode surfaces YELLOW as a stable audit-log label
    for moderate-risk decisions without requiring HITL approval.

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

        5. Take the highest band from steps 3-4. If the result is YELLOW
           and ``policy.enable_yellow_band`` is False (the default), fold
           YELLOW into GREEN so callers see a 3-band experience.

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

    # Step 5b: If YELLOW is not enabled, fold YELLOW into GREEN. Default
    # is a 3-band experience (GREEN / ORANGE / RED). Pro / compliance
    # deployments that need the moderate-risk tier opt in via
    # policy.enable_yellow_band = True.
    if band == Band.YELLOW and not policy.enable_yellow_band:
        band = Band.GREEN

    # Step 6: Model routing recommendation (caller is free to ignore)
    routing = _route_model(band, action.data_class, policy=policy)

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
