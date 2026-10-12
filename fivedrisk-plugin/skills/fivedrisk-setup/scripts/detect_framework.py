"""detect_framework.py — tell the operator which 5D adapter to wire.

Probes which agent frameworks are importable in the current environment and, for
each, prints the matching fivedrisk adapter import + a one-line wiring snippet. The
script itself performs no intentional network access or writes. Python module
discovery may import parent packages or invoke registered finder hooks. Frameworks that live in
Node (Vercel AI SDK, Genkit) or are CLI-wired (Claude Code) are always listed with
their non-Python wiring, since this Python probe can't see them.

Run:
    <SELECTED_PYTHON> <SKILL_ROOT>/scripts/detect_framework.py

Exit code is always 0 (detection, not gating).
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Adapter:
    module: str            # import name to probe (None → non-Python, always shown)
    framework: str         # human name
    wiring_import: str     # the fivedrisk import
    wiring: str            # one-line wiring snippet
    node: bool = False     # lives in Node, not probeable from Python


ADAPTERS: List[Adapter] = [
    Adapter("crewai", "CrewAI",
            "from fivedrisk.framework_adapters import make_crewai_pre_tool_hook",
            "on(InterceptionPoint.PRE_TOOL_CALL)(make_crewai_pre_tool_hook(policy=policy, log=audit_log))"),
    Adapter("agents", "OpenAI Agents SDK",
            "from fivedrisk.framework_adapters import make_openai_tool_input_guardrail",
            "@function_tool(tool_input_guardrails=[make_openai_tool_input_guardrail(policy=policy, log=audit_log)])"),
    Adapter("google.adk", "Google ADK",
            "from fivedrisk.framework_adapters import make_adk_before_tool_callback",
            "LlmAgent(..., before_tool_callback=make_adk_before_tool_callback(policy=policy, log=audit_log))"),
    Adapter("pydantic_ai", "Pydantic AI",
            "from fivedrisk.framework_adapters import make_pydantic_process_tool_call",
            "MCPToolset(..., process_tool_call=make_pydantic_process_tool_call(policy=policy, log=audit_log))"),
    Adapter("agent_framework", "Microsoft Agent Framework",
            "from fivedrisk.framework_adapters import make_ms_agent_framework_middleware",
            "ChatAgent(..., middleware=make_ms_agent_framework_middleware(policy=policy, log=audit_log))"),
    Adapter("langgraph", "LangGraph",
            "from fivedrisk.langgraph_node import fivedrisk_gate_node",
            "graph.add_node('fivedrisk_gate', lambda state: fivedrisk_gate_node(state, policy=policy, log=audit_log))"),
    Adapter("__claude_code__", "Claude Code (CLI hook)",
            "# no import — separate manual host integration; public skill is advisory",
            "Review https://github.com/theDoc001/fivedrisk/tree/main/fivedrisk-plugin/manual", node=True),
    Adapter("__vercel__", "Vercel AI SDK (Node)",
            'import { FivedriskGateway, guardVercelTool } from "fivedrisk-gateway";',
            f"const gw = new FivedriskGateway({{ command: {json.dumps(sys.executable)}, "
            'policyPath: "/absolute/path/policy.yaml", '
            'logPath: "/absolute/path/fivedrisk-decisions.db" }); '
            'const gatedTool = guardVercelTool(gw, "my_tool", tool);', node=True),
    Adapter("__genkit__", "Genkit (Node)",
            'import { FivedriskGateway, guardGenkitTool } from "fivedrisk-gateway";',
            f"const gw = new FivedriskGateway({{ command: {json.dumps(sys.executable)}, "
            'policyPath: "/absolute/path/policy.yaml", '
            'logPath: "/absolute/path/fivedrisk-decisions.db" }); '
            'ai.defineTool({ name: "my_tool" }, '
            'guardGenkitTool(gw, "my_tool", handler));', node=True),
]


def _importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except Exception:
        return False  # a broken/partial install is "not usable"


def detect(adapters: Optional[List[Adapter]] = None) -> List[dict]:
    """Return a report row per adapter: framework, installed, wiring_import, wiring."""
    rows = []
    for a in adapters if adapters is not None else ADAPTERS:
        installed = None if a.node else _importable(a.module)
        wiring = a.wiring.replace("<SELECTED_PYTHON>", shlex.quote(sys.executable))
        rows.append({
            "framework": a.framework,
            "installed": installed,   # True/False for Python, None for Node/CLI
            "node": a.node,
            "wiring_import": a.wiring_import,
            "wiring": wiring,
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
    print("First load an explicit policy and audit log as `policy` and `audit_log`;")
    print("see references/adapters.md. Factory defaults are not deployment configuration.\n")
    for row in rows:
        print(_fmt(row))
        print()
    shell_python = shlex.quote(sys.executable)
    print("[•] Other languages / custom hosts")
    print("      Generic long-lived JSON-lines gateway")
    print(
        f"      {shell_python} -I -m fivedrisk._bootstrap --policy policy.yaml "
        "--log-path /absolute/path/fivedrisk-decisions.db gateway stdio"
    )
    print()
    if not any_py:
        print("No Python agent framework detected. That's fine — you can still use the")
        print(f"`@gate` decorator, the CLI (`{shell_python} -I -m fivedrisk._bootstrap score`), or the")
        print("Node client for Vercel/Genkit or the generic gateway above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
