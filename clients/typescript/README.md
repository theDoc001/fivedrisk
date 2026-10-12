# fivedrisk-gateway (TypeScript)

Gate any JavaScript/TypeScript agent through the deterministic **5D** risk engine —
without running Python in your Node process. This client starts the installed
gateway through Python isolated mode and its provenance-checking bootstrap, then talks
to it over its JSON-lines protocol,
then maps the returned band to a canonical sentinel (`execute` / `approve` / `block`)
with the same never-demote invariant as the Python library: **RED → block, ORANGE →
approve (never execute), unknown / error / timeout → block (fail closed).**

This client has no per-call approval exchange, so ORANGE always remains blocked.
The deprecated `hasApprovalChannel` option is ignored; capability metadata alone
is not proof that a particular invocation was approved.

## Install

```bash
# Python side (the engine):
PYTHON_BIN="${PYTHON_BIN:-python3}"
PYTHON_BIN="$("$PYTHON_BIN" -I -c 'import sys; print(sys.executable)')"
"$PYTHON_BIN" -I -m pip install "fivedrisk>=0.7.1,<0.8.0"
"$PYTHON_BIN" -I -c 'import importlib.machinery as m, importlib.metadata as d, pathlib, sys; x=d.distribution("fivedrisk"); r=next((p for p in x.files or () if str(p).replace("\\","/")=="fivedrisk/__init__.py"), None); r is not None or sys.exit("fivedrisk distribution has no recorded package"); e=pathlib.Path(x.locate_file(r)).resolve(strict=True); s=m.PathFinder.find_spec("fivedrisk",[str(e.parent.parent)]); a=pathlib.Path(s.origin).resolve(strict=True) if s and s.origin else None; a==e or sys.exit("fivedrisk provenance mismatch"); print(f"verified fivedrisk {x.version}: {e}")'
export FIVEDRISK_PYTHON="$PYTHON_BIN"

# Node side (this client):
npm install fivedrisk-gateway@0.7.1
```

The client has no PATH-based Python fallback. `command` is required, and startup
fails closed unless the command is an absolute interpreter path and the gateway
identifies itself as `fivedrisk`, speaks protocol 1, and reports a stable supported
version `>=0.7.1,<0.8.0`. Custom argv is rejected; the exact legacy argv is accepted
only as an input compatibility form and normalized to the isolated bootstrap.
The wire contract, including handshake, correlation, and fail-closed dispositions, is
[`docs/gateway-protocol.md`](../../docs/gateway-protocol.md).

## Core client

```ts
import { FivedriskGateway } from "fivedrisk-gateway";

const python = process.env.FIVEDRISK_PYTHON;
if (!python) throw new Error("Set FIVEDRISK_PYTHON to the verified absolute interpreter path");
const gw = new FivedriskGateway({
  command: python,
  policyPath: "/absolute/path/policy.yaml",
  logPath: "/absolute/path/fivedrisk-decisions.db",
});

const verdict = await gw.score({ toolName: "Bash", toolInput: { command: "rm -rf /data" } });
// verdict.band === "RED", verdict.sentinel === "block", verdict.blocked === true

if (verdict.blocked) throw new Error(verdict.reason);
// ... otherwise run the tool

gw.close();
```

`score()` never rejects — a startup failure, gateway crash, timeout, invalid request,
or write failure resolves to a
fail-closed BLOCK verdict, so a caller that forgets `try/catch` still stops the tool.
`prepareScore()` first converts tool input to a detached data-only JSON snapshot without
invoking accessors or `toJSON`; the Vercel and Genkit guards execute only that exact
snapshot after it is scored.

## Vercel AI SDK

```ts
import { FivedriskGateway, guardVercelTool } from "fivedrisk-gateway";
import { tool } from "ai";

const python = process.env.FIVEDRISK_PYTHON;
if (!python) throw new Error("Set FIVEDRISK_PYTHON to the verified absolute interpreter path");
const gw = new FivedriskGateway({ command: python });
const writeDb = tool({ /* ...parameters, execute... */ });

// Every invocation is scored by 5D before execute() runs; a block throws
// FivedriskBlockedError so the tool visibly does not run.
const gated = guardVercelTool(gw, "write_to_database", writeDb);
```

## Genkit

```ts
import { FivedriskGateway, guardGenkitTool } from "fivedrisk-gateway";
import { genkit } from "genkit";

const python = process.env.FIVEDRISK_PYTHON;
if (!python) throw new Error("Set FIVEDRISK_PYTHON to the verified absolute interpreter path");
const gw = new FivedriskGateway({ command: python });
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
