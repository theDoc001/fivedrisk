# fivedrisk-gateway (TypeScript)

Gate any JavaScript/TypeScript agent through the deterministic **5D** risk engine —
without running Python in your Node process. This client spawns the shipped
`fivedrisk gateway stdio` process and talks to it over its JSON-lines protocol,
then maps the returned band to a canonical sentinel (`execute` / `approve` / `block`)
with the same never-demote invariant as the Python library: **RED → block, ORANGE →
approve (never execute), unknown / error / timeout → block (fail closed).**

## Install

```bash
# Python side (the engine):
pip install fivedrisk

# Node side (this client):
npm install fivedrisk-gateway
```

## Core client

```ts
import { FivedriskGateway } from "fivedrisk-gateway";

const gw = new FivedriskGateway({ command: "python" }); // spawns `python -m fivedrisk gateway stdio`

const verdict = await gw.score({ toolName: "Bash", toolInput: { command: "rm -rf /data" } });
// verdict.band === "RED", verdict.sentinel === "block", verdict.blocked === true

if (verdict.blocked) throw new Error(verdict.reason);
// ... otherwise run the tool

gw.close();
```

`score()` never rejects — a startup failure, gateway crash, or timeout resolves to a
fail-closed BLOCK verdict, so a caller that forgets `try/catch` still stops the tool.

## Vercel AI SDK

```ts
import { FivedriskGateway, guardVercelTool } from "fivedrisk-gateway";
import { tool } from "ai";

const gw = new FivedriskGateway();
const writeDb = tool({ /* ...parameters, execute... */ });

// Every invocation is scored by 5D before execute() runs; a block throws
// FivedriskBlockedError so the tool visibly does not run.
const gated = guardVercelTool(gw, "write_to_database", writeDb);
```

## Genkit

```ts
import { FivedriskGateway, guardGenkitTool } from "fivedrisk-gateway";
import { genkit } from "genkit";

const gw = new FivedriskGateway();
const ai = genkit({ /* ... */ });

ai.defineTool(
  { name: "write_to_database", /* ...schema... */ },
  guardGenkitTool(gw, "write_to_database", async (input) => { /* real handler */ }),
);
```

## Validation status

The wire protocol is verified end-to-end against the shipped gateway (handshake
`protocol_version: 1`, `id`-correlated responses, fail-closed on error) — see the
Python contract test `fivedrisk/tests/test_gateway_ts_contract.py` and the Node
integration test `src/integration.test.ts`. The Vercel / Genkit wrappers are built to
those SDKs' documented tool shapes; pin your SDK version and run a one-call smoke test
(a known RED tool call must not execute) before production.

Apache-2.0.
