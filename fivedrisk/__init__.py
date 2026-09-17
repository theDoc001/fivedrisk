"""fivedrisk — 5D Risk Governance Engine.

Per-action risk scoring for AI agents. Scores every tool call on
5 dimensions (Data Sensitivity, Tool Privilege, Reversibility,
External Impact, Autonomy Context), assigns a GREEN/YELLOW/ORANGE/RED
band, routes to the appropriate model, and logs the decision.

4-band system per the 5D governance model.

Quick start:
    from fivedrisk import classify_tool_call, score, load_policy, Band

    policy = load_policy("policy.yaml")
    action = classify_tool_call("Bash", {"command": "rm -rf /"}, policy)
    result = score(action, policy)
    print(result.band)       # Band.RED
    print(result.routing)    # RoutingDecision(model_floor=M4, ...)

Authored by Loren, March 2026. Apache-2.0 license.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("fivedrisk")
except PackageNotFoundError:  # editable / source checkout without metadata
    __version__ = "0.0.0+unknown"

from .adapters import (
    APPROVE,
    BLOCK,
    EXECUTE,
    Verdict,
    band_to_sentinel,
    sentinel_blocks,
    to_verdict,
)
from .budget_accumulator import BudgetAccumulator, ReservationResult
from .classifier import classify_tool_call
from .claude_code import posttooluse_hook, pretooluse_hook
from .framework_adapters import (
    make_adk_before_tool_callback,
    make_crewai_pre_tool_hook,
    make_ms_agent_framework_middleware,
    make_openai_tool_input_guardrail,
    make_pydantic_process_tool_call,
)
from .drift import DriftBump, SessionAccumulator
from .events import (
    NDJSONEventChannel,
    REASON_BUDGET_CAP_EXCEEDED,
    REASON_BUDGET_RESERVATION_BLOCKED,
    REASON_IDENTITY_REQUIRED_NOT_SUPPLIED,
)
from .hooks import (
    BandBlockError,
    BudgetExceededError,
    DestinationBlockError,
    FivedriskDenial,
    IdentityRequiredError,
    SessionRequiredError,
    check_destination_policy,
    configure,
    extract_external_destinations,
    fivedrisk_pre_tool,
    fivedrisk_post_tool,
    gate,
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
from .policy import (
    AdmissionResult,
    AxisPredicate,
    FieldValuePredicate,
    FloorRule,
    Policy,
    first_red_line_hit,
    load_policy,
    match_red_line,
    parse_axis_predicate,
    parse_value_match,
)
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
    "APPROVE",
    "BLOCK",
    "EXECUTE",
    "Verdict",
    "band_to_sentinel",
    "sentinel_blocks",
    "to_verdict",
    "make_adk_before_tool_callback",
    "make_crewai_pre_tool_hook",
    "make_openai_tool_input_guardrail",
    "make_pydantic_process_tool_call",
    "make_ms_agent_framework_middleware",
    "pretooluse_hook",
    "posttooluse_hook",
    "Action",
    "ActingIdentity",
    "AdmissionResult",
    "AttestationSource",
    "AxisPredicate",
    "AutonomySignals",
    "Band",
    "BandBlockError",
    "BudgetAccumulator",
    "BudgetExceededError",
    "DestinationBlockError",
    "FivedriskDenial",
    "DecisionLog",
    "DriftBump",
    "EscalationSignal",
    "FieldValuePredicate",
    "FloorRule",
    "HITLCard",
    "IdentityRequiredError",
    "SessionRequiredError",
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
    "first_red_line_hit",
    "fivedrisk_post_tool",
    "fivedrisk_pre_tool",
    "gate",
    "get_model_cost",
    "index_to_state",
    "is_absorbing",
    "load_policy",
    "make_default_transition_matrix",
    "match_red_line",
    "matmul",
    "matrix_inverse",
    "parse_axis_predicate",
    "parse_value_match",
    "scan_input_for_injection",
    "scan_output_for_leakage",
    "scan_retrieved_content",
    "score",
    "session_id_conventions",
    "state_to_index",
]
