"""5D Risk Governance Engine — LangGraph decision-gate node.

Drops into DotOS's LangGraph state machine as a gate between
the Builder's tool-call decision and actual execution.

Usage in graph.py:
    from fivedrisk.langgraph_node import fivedrisk_gate_node

    # Add as a node in the graph
    graph.add_node("fivedrisk_gate", fivedrisk_gate_node)

    # Wire: builder → fivedrisk_gate → tool_executor
    graph.add_edge("builder", "fivedrisk_gate")
    graph.add_conditional_edges(
        "fivedrisk_gate",
        route_by_band,
        {"go": "tool_executor", "ask": "hitl_review", "stop": "deny_response"}
    )
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .classifier import classify_tool_call
from . import hooks as runtime_hooks
from .logger import DecisionLog
from .policy import Policy, load_policy
from .schema import Band
from .scorer import score


def fivedrisk_gate_node(
    state: Dict[str, Any],
    policy: Optional[Policy] = None,
    log: Optional[DecisionLog] = None,
) -> Dict[str, Any]:
    """LangGraph node that scores the pending tool call and gates execution.

    Expects state to contain:
        - tool_name: str
        - tool_input: dict
        - autonomy_context: int (optional, default 0)
        - source: str (optional, default "langgraph")

    Returns updated state with:
        - fivedrisk_band: "GO" | "ASK" | "STOP"
        - fivedrisk_score: dict (full scored action)
        - fivedrisk_rationale: str
        - fivedrisk_log_id: int
    """
    if policy is None:
        policy = load_policy()
    if log is None:
        log = DecisionLog()

    tool_name = state.get("tool_name", "Unknown")
    tool_input = state.get("tool_input", {})
    autonomy_context = state.get("autonomy_context", 0)
    source = state.get("source", "langgraph")
    session_id = None
    for key in runtime_hooks.SESSION_ID_KEYS:
        value = state.get(key)
        if isinstance(value, str) and value:
            session_id = value
            break

    if runtime_hooks.session_id_conventions()["require_session_id"] and session_id is None:
        return {
            **state,
            "fivedrisk_band": str(Band.RED),
            "fivedrisk_rationale": "5D session id required for runtime integration",
            "fivedrisk_score": None,
            "fivedrisk_log_id": None,
            "fivedrisk_composite": None,
        }

    destination_check = runtime_hooks.check_destination_policy(tool_name, tool_input)
    if destination_check and destination_check.decision == "block":
        return {
            **state,
            "fivedrisk_band": str(Band.RED),
            "fivedrisk_rationale": destination_check.reason,
            "fivedrisk_score": None,
            "fivedrisk_log_id": None,
            "fivedrisk_composite": None,
        }

    action = classify_tool_call(
        tool_name=tool_name,
        tool_input=tool_input,
        policy=policy,
        autonomy_context=autonomy_context,
        source=source,
    )

    result = score(action, policy)
    if session_id:
        runtime_hooks._apply_drift(result, session_id)
    if destination_check and destination_check.decision == "warn":
        result.rationale = (
            f"{result.rationale} [DestinationPolicy: {destination_check.reason}]"
        )
    row_id = log.log(result)

    return {
        **state,
        "fivedrisk_band": str(result.band),
        "fivedrisk_score": result.to_dict(),
        "fivedrisk_rationale": result.rationale,
        "fivedrisk_log_id": row_id,
        "fivedrisk_composite": result.composite_score,
    }


def route_by_band(state: Dict[str, Any]) -> str:
    """Conditional edge router: returns 'go', 'ask', or 'stop'."""
    band = state.get("fivedrisk_band", "ASK")
    return band.lower()
