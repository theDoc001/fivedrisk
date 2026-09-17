# fivedrisk adapter wiring reference

Copy-paste wiring for each supported framework. Every adapter routes through the same
5D verdict socket and is **fail-closed**: RED blocks, ORANGE needs an approval channel
(else blocks), invalid input / engine error blocks. Pass a `policy=` and, optionally,
`session_id=` (for Markov drift) and `has_approval_channel=True` (only if you actually
route approvals) to any `make_*` factory.

## CrewAI

```python
from crewai.hooks import on, InterceptionPoint
from fivedrisk.framework_adapters import make_crewai_pre_tool_hook

on(InterceptionPoint.PRE_TOOL_CALL)(make_crewai_pre_tool_hook())
# blocks by raising HookAborted; GREEN/YELLOW proceed
```

## OpenAI Agents SDK

```python
from agents import function_tool
from fivedrisk.framework_adapters import make_openai_tool_input_guardrail

@function_tool(tool_input_guardrails=[make_openai_tool_input_guardrail()])
def my_tool(...): ...
# blocks via ToolGuardrailFunctionOutput.reject_content
```

## Google ADK

```python
from google.adk.agents import LlmAgent
from fivedrisk.framework_adapters import make_adk_before_tool_callback

agent = LlmAgent(..., before_tool_callback=make_adk_before_tool_callback())
# blocks by returning a dict tool-result; None → proceed
```

## Pydantic AI (MCP tools)

```python
from pydantic_ai.mcp import MCPToolset
from fivedrisk.framework_adapters import make_pydantic_process_tool_call

toolset = MCPToolset(<transport>, process_tool_call=make_pydantic_process_tool_call())
# MCP tools only; native @agent.tool functions bypass this hook
```

## Microsoft Agent Framework

```python
from agent_framework import ChatAgent
from fivedrisk.framework_adapters import make_ms_agent_framework_middleware

agent = ChatAgent(chat_client=client, name="assistant",
                  middleware=make_ms_agent_framework_middleware())
# blocks by short-circuiting (sets context.result, does not run the tool)
```

## LangGraph

```python
from fivedrisk.langgraph_node import fivedrisk_gate_node, route_by_band

graph.add_node("fivedrisk_gate", fivedrisk_gate_node)
graph.add_conditional_edges("fivedrisk_gate", route_by_band,
    {"green": "tool_executor", "yellow": "tool_executor",
     "orange": "hitl_review", "red": "deny_response"})
```

## Claude Code (CLI hooks)

Wire in `.claude/settings.json` — PreToolUse gates, PostToolUse verifies output:

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python -m fivedrisk claude-hook" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python -m fivedrisk claude-hook" }] }]
  }
}
```

ORANGE maps to Claude Code's native `ask` (human approval); RED → `deny`.

## Vercel AI SDK / Genkit (Node)

```bash
npm install fivedrisk-gateway   # Python side: pip install fivedrisk
```

```ts
import { FivedriskGateway, guardVercelTool, guardGenkitTool } from "fivedrisk-gateway";
const gw = new FivedriskGateway();                       // spawns `python -m fivedrisk gateway stdio`
const gatedTool = guardVercelTool(gw, "write_to_database", tool);           // Vercel AI SDK
// Genkit:  ai.defineTool({name}, guardGenkitTool(gw, "write_to_database", handler));
```

## Anything else — the `@gate` decorator

```python
from fivedrisk.hooks import gate

@gate(tool_name="write_to_database", autonomy_context=2)
async def write_record(table: str, data: dict) -> None:
    ...   # runs only on GREEN/YELLOW; ORANGE → approval; RED → blocked
```

## §policy

Point any adapter at a policy (`make_*(policy=...)`, `@gate` reads `configure(policy_path=...)`,
or set `FIVEDRISK_POLICY_PATH`). Start from a shipped preset, validate, then hand-tune:

```bash
python3 -m fivedrisk validate your-policy.yaml
```

Key knobs: `tool_defaults` (per-tool dimension scores), `bash_overrides` (regex floors for
`rm -rf`, `curl|sh`), `enable_yellow_band` (opt-in 4-band mode), and floor rules (hard
blocks that cannot be overridden at runtime). Tune from what your audit log shows, not by
guessing.
