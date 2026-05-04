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

__version__ = "0.3.0"

from .classifier import classify_tool_call
from .drift import DriftBump, SessionAccumulator
from .hooks import (
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
from .policy import Policy, load_policy
from .router import ModelRouter, ModelConfig, EscalationSignal
from .schema import (
    Action,
    Band,
    HITLCard,
    ModelClass,
    RoutingDecision,
    ScoredAction,
)
from .scorer import score, score_light

__all__ = [
    "Action",
    "Band",
    "DecisionLog",
    "EscalationSignal",
    "HITLCard",
    "ModelClass",
    "ModelConfig",
    "ModelRouter",
    "Policy",
    "RoutingDecision",
    "ScoredAction",
    "classify_tool_call",
    "check_destination_policy",
    "configure",
    "DriftBump",
    "extract_external_destinations",
    "fivedrisk_post_tool",
    "fivedrisk_pre_tool",
    "gate",
    "hitl_queue_decrement",
    "hitl_queue_increment",
    "load_policy",
    "MarkovDriftTracker",
    "build_transition_matrix",
    "compute_absorption_probabilities",
    "index_to_state",
    "is_absorbing",
    "make_default_transition_matrix",
    "matmul",
    "matrix_inverse",
    "rate_limit_check",
    "scan_input_for_injection",
    "scan_output_for_leakage",
    "scan_retrieved_content",
    "score",
    "score_light",
    "session_id_conventions",
    "state_to_index",
    "SessionAccumulator",
]
