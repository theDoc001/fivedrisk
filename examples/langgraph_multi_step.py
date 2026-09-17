"""langgraph_multi_step.py — fivedrisk_gate_node inside a LangGraph state machine.

Demonstrates the integration shape: fivedrisk's `fivedrisk_gate_node` sits
between your builder/planner node and your tool-execution node. Conditional
edges route GREEN executions straight through, ORANGE to a HITL queue, and
RED to a deny path.

This example walks three pending tool calls (benign read, destructive bash,
external write) past the gate node and shows the resulting band and route.
It does NOT require LangGraph itself to be installed — the node is called
directly, which is what LangGraph would do under the hood.

Run:
    pip install fivedrisk
    python examples/langgraph_multi_step.py

What you see:
    - Three tool calls, each scored by fivedrisk's gate node.
    - The 5D band per call (GREEN/YELLOW/ORANGE/RED).
    - The conditional-edge route fivedrisk would push the state to.

A separate compositional-attack example using Markov SafetyDrift will ship
in a later release once we have a reproducible deterministic sequence.
"""

from typing import Any, Dict

from fivedrisk import load_policy
from fivedrisk.langgraph_node import fivedrisk_gate_node
from fivedrisk.logger import DecisionLog


SESSION_ID = "demo-langgraph-001"


def route_for_band(band: str) -> str:
    """Map fivedrisk band to LangGraph conditional-edge target.

    fivedrisk's own `route_by_band` returns the band name lowercased
    ('green', 'yellow', 'orange', 'red'); your graph can either match
    those directly in `add_conditional_edges` or wrap them like this.
    """
    return {
        "GREEN": "tool_executor",
        "YELLOW": "tool_executor",   # YELLOW often log-elevates and continues
        "ORANGE": "hitl_review",
        "RED": "deny_response",
    }.get(band, "deny_response")


def main() -> None:
    policy = load_policy()
    log = DecisionLog()

    pending = [
        ("Read", {"file_path": "/app/config.yaml"}),
        ("Bash", {"command": "rm -rf /var/log/app"}),
        ("WebFetch", {"url": "https://example.com/api", "method": "POST"}),
    ]

    print(f"{'step':4}  {'tool':10}  {'band':6}  next_node")
    for idx, (tool_name, tool_input) in enumerate(pending, start=1):
        state: Dict[str, Any] = {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "autonomy_context": 2,
            "source": "langgraph-demo",
            "session_id": SESSION_ID,
        }
        result_state = fivedrisk_gate_node(state, policy=policy, log=log)
        band = result_state["fivedrisk_band"]
        next_node = route_for_band(band)
        print(f"{idx:4}  {tool_name:10}  {band:6}  → {next_node}")


if __name__ == "__main__":
    main()


# ─── How to wire into a real LangGraph state machine ──────────────────────
#
# from langgraph.graph import StateGraph
# from fivedrisk.langgraph_node import fivedrisk_gate_node
#
# graph = StateGraph(YourState)
# graph.add_node("builder", builder_node)
# graph.add_node("fivedrisk_gate", fivedrisk_gate_node)
# graph.add_node("tool_executor", tool_node)
# graph.add_node("hitl_review", hitl_node)
# graph.add_node("deny_response", deny_node)
#
# graph.add_edge("builder", "fivedrisk_gate")
# graph.add_conditional_edges(
#     "fivedrisk_gate",
#     lambda s: route_for_band(s["fivedrisk_band"]),
#     {"tool_executor": "tool_executor",
#      "hitl_review":   "hitl_review",
#      "deny_response": "deny_response"},
# )
