# fivedrisk adapter wiring reference

Copy-paste wiring for each supported framework. Every adapter routes through the same
5D verdict socket and is **fail-closed**: RED blocks, ORANGE holds, invalid input /
engine error blocks. Pass a `policy=` and, optionally, `session_id=` (for Markov
drift) to any `make_*` factory. The deprecated `has_approval_channel` keyword is
accepted but ignored: these adapters do not consume approval for individual calls.
The host must own human review and authorized continuation. Claude's native hook
separately returns `ask`; a static flag never authorizes a framework tool call.

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

## Manual host integrations

The public ChatGPT/Codex artifact is advisory and contains no lifecycle configuration.
Manual Codex desktop and Claude Code installations can use host-specific hooks when
available, but those protocols differ. This release's reviewed hooks are Claude-specific;
they are not a Codex adapter. Claude setup and explicit settings belong in the separate
manual ZIP's `manual/README.md` or the
[manual integration guide](https://github.com/theDoc001/fivedrisk/tree/main/fivedrisk-plugin/manual).
Do not claim the public skill gates host tools or submit a hook-containing ZIP to the
public plugin directory.

## Vercel AI SDK / Genkit (Node)

```bash
npm install fivedrisk-gateway
"$PYTHON_BIN" -m pip install "fivedrisk>=0.7.1,<0.8.0"
PYTHON_BIN="$PYTHON_BIN" bash "$SKILL_ROOT/scripts/verify-install.sh"
```

```ts
import { FivedriskGateway, guardVercelTool, guardGenkitTool } from "fivedrisk-gateway";
const gw = new FivedriskGateway({ command: "<SELECTED_PYTHON>" });
const gatedTool = guardVercelTool(gw, "write_to_database", tool);           // Vercel AI SDK
// Genkit:  ai.defineTool({name}, guardGenkitTool(gw, "write_to_database", handler));
```

## Custom Python: the `@gate` decorator

`@gate` accepts detached exact built-in action data only: `None`, booleans,
integers, finite floats, strings, lists, tuples, and string-keyed dictionaries.
Convert paths, dataclasses, framework objects, and other custom values before the
call; unsupported values block before the wrapped function runs. Instance and
class methods are not supported because their receiver is a custom object; gate a
static or free data-only boundary function instead. A Bash gate accepts only one
exact built-in string in its `command` parameter, never an argv list or tuple.

```python
from fivedrisk.hooks import gate

@gate(tool_name="write_to_database", autonomy_context=2)
async def write_record(table: str, data: dict) -> None:
    ...   # runs only on GREEN/YELLOW; ORANGE → held for human review; RED → blocked
```

## Generic non-Python gateway

For Go, Rust, custom JavaScript, and other hosts, start one long-lived subprocess and
exchange one JSON request and one JSON decision per line over standard input/output:

```bash
"$PYTHON_BIN" -I -m fivedrisk._bootstrap gateway stdio --policy policy.yaml
```

Use the public JSON-lines protocol documented in the repository README. Keep the process
alive rather than starting Python for every action. The caller must place the request at
the actual pre-execution boundary and must treat startup failure, timeout, malformed
output, an unknown decision, or a closed pipe as blocked. A transport connection alone
does not prove that every tool path is gated; verify allowed and denied actions end to
end in the host application.

## §policy

Point any adapter at a policy (`make_*(policy=...)`, `@gate` reads `configure(policy_path=...)`,
or set `FIVEDRISK_POLICY_PATH`). Start from a shipped preset, validate, then hand-tune:

```bash
"$PYTHON_BIN" -I -m fivedrisk._bootstrap validate your-policy.yaml
```

Key knobs: `tool_defaults` (per-tool dimension scores), `bash_overrides` (regex floors for
`rm -rf`, `curl|sh`), `enable_yellow_band` (opt-in 4-band mode), and floor rules (hard
blocks that cannot be overridden at runtime). Tune from what your audit log shows, not by
guessing.
