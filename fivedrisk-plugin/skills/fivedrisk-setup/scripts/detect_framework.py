#!/usr/bin/env python3
"""detect_framework.py — tell the operator which 5D adapter to wire.

Probes which agent frameworks are importable in the current environment and, for
each, prints the matching fivedrisk adapter import + a one-line wiring snippet. No
network, no writes, no side effects — pure detection. Frameworks that live in
Node (Vercel AI SDK, Genkit) or are CLI-wired (Claude Code) are always listed with
their non-Python wiring, since this Python probe can't see them.

Run:
    python3 scripts/detect_framework.py

Exit code is always 0 (detection, not gating).
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Adapter:
    module: str            # import name to probe (None → non-Python, always shown)
    framework: str         # human name
    wiring_import: str     # the fivedrisk import
    wiring: str            # one-line wiring snippet
    node: bool = False     # lives in Node, not probeable from Python


# The 5D "works with" surface — each entry maps a framework to the adapter built
# for it (M1/M2/M4/M5) or the already-shipped LangGraph node.
ADAPTERS: List[Adapter] = [
    Adapter("crewai", "CrewAI",
            "from fivedrisk.framework_adapters import make_crewai_pre_tool_hook",
            "on(InterceptionPoint.PRE_TOOL_CALL)(make_crewai_pre_tool_hook())"),
    Adapter("agents", "OpenAI Agents SDK",
            "from fivedrisk.framework_adapters import make_openai_tool_input_guardrail",
            "@function_tool(tool_input_guardrails=[make_openai_tool_input_guardrail()])"),
    Adapter("google.adk", "Google ADK",
            "from fivedrisk.framework_adapters import make_adk_before_tool_callback",
            "LlmAgent(..., before_tool_callback=make_adk_before_tool_callback())"),
    Adapter("pydantic_ai", "Pydantic AI",
            "from fivedrisk.framework_adapters import make_pydantic_process_tool_call",
            "MCPToolset(..., process_tool_call=make_pydantic_process_tool_call())"),
    Adapter("agent_framework", "Microsoft Agent Framework",
            "from fivedrisk.framework_adapters import make_ms_agent_framework_middleware",
            "ChatAgent(..., middleware=make_ms_agent_framework_middleware())"),
    Adapter("langgraph", "LangGraph",
            "from fivedrisk.langgraph_node import fivedrisk_gate_node",
            "graph.add_node('fivedrisk_gate', fivedrisk_gate_node)"),
    Adapter("__claude_code__", "Claude Code (CLI hook)",
            "# no import — wire the CLI in .claude/settings.json",
            "PreToolUse/PostToolUse hook -> `python -m fivedrisk claude-hook`", node=True),
    Adapter("__vercel__", "Vercel AI SDK (Node)",
            "// npm install fivedrisk-gateway",
            "guardVercelTool(new FivedriskGateway(), 'my_tool', tool)", node=True),
    Adapter("__genkit__", "Genkit (Node)",
            "// npm install fivedrisk-gateway",
            "ai.defineTool({name}, guardGenkitTool(gw, 'my_tool', handler))", node=True),
]


def _importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False  # a broken/partial install is "not usable"


def detect(adapters: Optional[List[Adapter]] = None) -> List[dict]:
    """Return a report row per adapter: framework, installed, wiring_import, wiring."""
    rows = []
    for a in adapters if adapters is not None else ADAPTERS:
        installed = None if a.node else _importable(a.module)
        rows.append({
            "framework": a.framework,
            "installed": installed,   # True/False for Python, None for Node/CLI
            "node": a.node,
            "wiring_import": a.wiring_import,
            "wiring": a.wiring,
        })
    return rows


def _fmt(row: dict) -> str:
    if row["node"]:
        mark = "•"  # can't probe from Python
    else:
        mark = "✓ installed" if row["installed"] else "· not installed"
    return (f"[{mark}] {row['framework']}\n"
            f"      {row['wiring_import']}\n"
            f"      {row['wiring']}")


def main() -> int:
    rows = detect()
    any_py = any(r["installed"] for r in rows if not r["node"])
    print("5D adapter coverage — wire the one that matches your stack:\n")
    for row in rows:
        print(_fmt(row))
        print()
    if not any_py:
        print("No Python agent framework detected. That's fine — you can still use the")
        print("`@gate` decorator, the CLI (`fivedrisk score` / `claude-hook`), or the")
        print("Node client (`npm install fivedrisk-gateway`) for Vercel/Genkit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
