"""5D Risk Governance Engine — LangGraph decision-gate node.

Drops into a LangGraph state machine as a gate between the planner /
builder's tool-call decision and actual execution.

Usage in graph.py:
    from fivedrisk.langgraph_node import fivedrisk_gate_node, route_by_band

    # Add as a node in the graph
    graph.add_node("fivedrisk_gate", fivedrisk_gate_node)

    # Wire: builder → fivedrisk_gate → tool_executor
    graph.add_edge("builder", "fivedrisk_gate")
    graph.add_conditional_edges(
        "fivedrisk_gate",
        route_by_band,
        {"green": "tool_executor",
         "yellow": "tool_executor",   # YELLOW often log-elevates and continues
         "orange": "hitl_review",
         "red": "deny_response"},
    )

See `dev/examples/langgraph_multi_step.py` for a runnable walkthrough.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .adapters import to_verdict
from . import hooks as runtime_hooks
from .logger import DecisionLog
from .policy import Policy, load_policy
from .schema import Band


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
        - fivedrisk_band: "GREEN" | "YELLOW" | "ORANGE" | "RED" (str(Band))
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
        reason = "5D session id required for runtime integration"
        row_id = log.log_egress_block(
            tool_name,
            reason,
            None,
            source="langgraph-session-block",
            config_hash=policy.content_hash(),
            policy_preset=policy.preset_name,
        )
        return {
            **state,
            "fivedrisk_band": str(Band.RED),
            "fivedrisk_rationale": reason,
            "fivedrisk_score": None,
            "fivedrisk_log_id": row_id,
            "fivedrisk_composite": None,
        }

    destination_check = (
        runtime_hooks.check_destination_policy(tool_name, tool_input)
        if isinstance(tool_input, dict)
        else None
    )
    if destination_check and destination_check.decision == "block":
        row_id = log.log_egress_block(
            tool_name,
            destination_check.reason,
            session_id,
            source="langgraph-input-block",
            config_hash=policy.content_hash(),
            policy_preset=policy.preset_name,
        )
        return {
            **state,
            "fivedrisk_band": str(Band.RED),
            "fivedrisk_rationale": destination_check.reason,
            "fivedrisk_score": None,
            "fivedrisk_log_id": row_id,
            "fivedrisk_composite": None,
        }

    verdict = to_verdict(
        tool_name,
        tool_input,
        policy,
        session_id=session_id,
        log=log,
        autonomy=autonomy_context,
        source=source,
    )
    rationale = verdict.reason
    if destination_check and destination_check.decision == "warn":
        rationale = (
            f"{rationale} [DestinationPolicy: {destination_check.reason}]"
        )

    return {
        **state,
        "fivedrisk_band": verdict.band,
        "fivedrisk_score": (
            verdict.scored_action.to_dict() if verdict.scored_action is not None else None
        ),
        "fivedrisk_rationale": rationale,
        "fivedrisk_log_id": verdict.audit_log_id,
        "fivedrisk_composite": verdict.composite_score,
    }


def route_by_band(state: Dict[str, Any]) -> str:
    """Conditional edge router: returns the lowercased band name.

    One of 'green' | 'yellow' | 'orange' | 'red' — the exact edge keys shown in
    the module usage example. M14: previously the docstring promised 'go'/'ask'/
    'stop' and the missing-band default was "ASK", whose lowercase 'ask' is not an
    edge key and raised at runtime. The default is now fail-closed to RED.
    """
    band = state.get("fivedrisk_band", str(Band.RED))
    return band.lower()
