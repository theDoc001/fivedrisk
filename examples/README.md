# Examples

Worked examples showing how to integrate fivedrisk with common agentic
stacks. Each example is self-contained: it runs as-is, has no external
dependencies beyond `pip install fivedrisk[langgraph,dev]`, and can be
adapted to a real deployment by swapping the mocks for real services.

## Available examples

- **`minimal_gate.py`** — The smallest possible fivedrisk integration. One
  decorated function, one GREEN execution, one RED block, and the resulting
  audit-log rows. No LLM, no API key, no network.
- **`langgraph_multi_step.py`** — Markov SafetyDrift catches a compositional
  exfiltration plan (read config, read secrets, summarize logs, call external
  API). Each step is GREEN in isolation; the sequence escalates.
- **`spiffe_mcp_passthrough.py`** — End-to-end pattern for SPIFFE workload
  identity flowing through an MCP-shaped agent into fivedrisk policy
  evaluation. Uses mocks for the SPIRE workload API and the MCP server;
  the fivedrisk integration is real. Demonstrates how an identity claim
  attaches to `Action.metadata` and flows through to the audit log.
- **`openai_agents_sdk_hook.py`** — fivedrisk wired as a tool guardrail
  inside an OpenAI Agents SDK-shaped runner. The runner is mocked; the
  fivedrisk gating is real.

## Planned

- **Real SPIRE + MCP stack** — Same pattern as `spiffe_mcp_passthrough.py`
  but with a real SPIRE deployment (Docker compose) and a real MCP server.
  Backlog item `OSS-MCP-SPIFFE-REFERENCE-001`. Requires Docker on the host.
- **Claude Agent SDK hook integration** — Drop-in `fivedrisk_pre_tool` and
  `fivedrisk_post_tool` hooks wired into a working Agent SDK call.

## How to run

```bash
cd "/path/to/fivedrisk-oss/dev"
source .venv/bin/activate
python examples/spiffe_mcp_passthrough.py
```

Each example prints what it does, what fivedrisk decided, and what the
audit log captured. Comment lines walk through the pattern so the example
is also documentation.
