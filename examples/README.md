# Examples

Worked examples showing how to integrate fivedrisk with common agentic
stacks. Each example is self-contained: it runs as-is, has no external
dependencies beyond the `fivedrisk[langgraph,dev]` extra, and can be
adapted to a real deployment by swapping the mocks for real services.

## Available examples

- **`minimal_gate.py`** — The smallest possible fivedrisk integration. One
  decorated function, one GREEN execution, one RED block, and the resulting
  audit-log rows. No LLM, no API key, no network.
- **`langgraph_multi_step.py`** — Per-call LangGraph gate-node and conditional
  routing shape. It scores a benign read, destructive Bash call, and external
  write, then shows the route each band would take. It is not a Markov sequence demo.
- **`spiffe_mcp_passthrough.py`** — End-to-end pattern for SPIFFE workload
  identity flowing through an MCP-shaped agent into fivedrisk policy
  evaluation. Uses mocks for the SPIRE workload API and the MCP server;
  the fivedrisk integration is real. Demonstrates how an identity claim
  attaches to `Action.metadata` and flows through to the audit log.

## Planned

- **Real SPIRE + MCP stack** — Same pattern as `spiffe_mcp_passthrough.py`
  but with a real SPIRE deployment (Docker compose) and a real MCP server.
  Backlog item `OSS-MCP-SPIFFE-REFERENCE-001`. Requires Docker on the host.
- **Claude Agent SDK hook integration** — Drop-in `fivedrisk_pre_tool` and
  `fivedrisk_post_tool` hooks wired into a working Agent SDK call.
- **OpenAI Agents SDK worked example** — The supported adapter wiring is in the
  [`fivedrisk-setup` adapter reference](../fivedrisk-plugin/skills/fivedrisk-setup/references/adapters.md#openai-agents-sdk);
  a validated runnable example is not yet shipped here.

## How to run

From the root of a public source checkout, select one Python interpreter. If
you use a virtual environment, create it outside the checkout and set
`PYTHON_BIN` to that environment's Python executable.

```bash
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -m pip install ".[langgraph,dev]"
"$PYTHON_BIN" examples/spiffe_mcp_passthrough.py
```

Each example prints what it does, what fivedrisk decided, and what the
audit log captured. Comment lines walk through the pattern so the example
is also documentation.
