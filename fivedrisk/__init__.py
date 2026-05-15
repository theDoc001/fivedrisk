"""fivedrisk — 5D Risk Governance Engine.

Per-action risk scoring for AI agents. Scores every tool call on
5 dimensions (Data Sensitivity, Tool Privilege, Reversibility,
External Impact, Autonomy Context), assigns a GREEN/YELLOW/ORANGE/RED
band, routes to the appropriate model, and logs the decision.

4-band system aligned with DotOS Governance Spec v0.3 (§12-19).

Quick start:
    from fivedrisk import classify_tool_call, score, load_policy, Band

    policy = load_policy("policy.yaml")
    action = classify_tool_call("Bash", {"command": "rm -rf /"}, policy)
    result = score(action, policy)
    print(result.band)       # Band.RED
    print(result.routing)    # RoutingDecision(model_floor=M4, ...)

Provenance: 5D Risk Governance Model is DotOS-native.
Authored by Loren, March 2026. Apache-2.0 license.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("fivedrisk")
except PackageNotFoundError:  # editable / source checkout without metadata
    __version__ = "0.0.0+unknown"

from .budget_accumulator import BudgetAccumulator, ReservationResult
from .classifier import classify_tool_call
from .drift import DriftBump, SessionAccumulator
from .events import (
    NDJSONEventChannel,
    REASON_BUDGET_CAP_EXCEEDED,
    REASON_BUDGET_RESERVATION_BLOCKED,
    REASON_IDENTITY_REQUIRED_NOT_SUPPLIED,
)
from .hooks import (
    BudgetExceededError,
    IdentityRequiredError,
    check_destination_policy,
    configure,
    extract_external_destinations,
    fivedrisk_pre_tool,
    fivedrisk_post_tool,
    gate,
    hitl_queue_decrement,
    hitl_queue_increment,
    rate_limit_check,
    scan_input_for_injection,
    scan_output_for_leakage,
    scan_retrieved_content,
    session_id_conventions,
)
from .markov import (
    MarkovDriftTracker,
    build_transition_matrix,
    compute_absorption_probabilities,
    index_to_state,
    is_absorbing,
    make_default_transition_matrix,
    matmul,
    matrix_inverse,
    state_to_index,
)
from .logger import DecisionLog
from .policy import AdmissionResult, Policy, load_policy
from .router import ModelRouter, ModelConfig, EscalationSignal
from .schema import (
    Action,
    ActingIdentity,
    AttestationSource,
    AutonomySignals,
    Band,
    HITLCard,
    ModelClass,
    PrincipalType,
    RoutingDecision,
    ScoredAction,
)
from .scorer import score
from .token_costs import MODEL_COSTS, ModelCost, get_model_cost

__all__ = [
    "Action",
    "ActingIdentity",
    "AdmissionResult",
    "AttestationSource",
    "AutonomySignals",
    "Band",
    "BudgetAccumulator",
    "BudgetExceededError",
    "DecisionLog",
    "DriftBump",
    "EscalationSignal",
    "HITLCard",
    "IdentityRequiredError",
    "MarkovDriftTracker",
    "MODEL_COSTS",
    "ModelClass",
    "ModelConfig",
    "ModelCost",
    "ModelRouter",
    "NDJSONEventChannel",
    "Policy",
    "PrincipalType",
    "REASON_BUDGET_CAP_EXCEEDED",
    "REASON_BUDGET_RESERVATION_BLOCKED",
    "REASON_IDENTITY_REQUIRED_NOT_SUPPLIED",
    "ReservationResult",
    "RoutingDecision",
    "ScoredAction",
    "SessionAccumulator",
    "build_transition_matrix",
    "check_destination_policy",
    "classify_tool_call",
    "compute_absorption_probabilities",
    "configure",
    "extract_external_destinations",
    "fivedrisk_post_tool",
    "fivedrisk_pre_tool",
    "gate",
    "get_model_cost",
    "hitl_queue_decrement",
    "hitl_queue_increment",
    "index_to_state",
    "is_absorbing",
    "load_policy",
    "make_default_transition_matrix",
    "matmul",
    "matrix_inverse",
    "rate_limit_check",
    "scan_input_for_injection",
    "scan_output_for_leakage",
    "scan_retrieved_content",
    "score",
    "session_id_conventions",
    "state_to_index",
]
