/**
 * QA-M4 — independent adversarial suite for the TypeScript gateway client.
 * Drives the client against a hostile fake gateway (FAKE_GW env → a .cjs script)
 * to prove EVERY transport/failure path resolves to a fail-closed BLOCK verdict,
 * never rejects, never returns blocked:false for a non-GREEN/YELLOW band. Also
 * re-proves bandToSentinel never-demote and the Vercel/Genkit wrappers.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import {
  FivedriskGateway,
  bandToSentinel,
  canonicalizeJsonValue,
  sentinelBlocks,
  type Sentinel,
} from "./gateway.js";
import { guardVercelTool, FivedriskBlockedError } from "./vercel.js";
import { guardGenkitTool } from "./genkit.js";

// Defaults to the in-repo fixture so this lock runs with no env setup; FAKE_GW overrides.
const FAKE = process.env.FAKE_GW ?? fileURLToPath(new URL("../fake_gateway.cjs", import.meta.url));
const NODE = process.execPath;

// Public contract: selecting the verified Python interpreter is mandatory.
// @ts-expect-error command is intentionally required; there is no PATH fallback.
const constructWithoutCommand = () => new FivedriskGateway({});

function gw(mode: string, extra: Record<string, unknown> = {}) {
  return new FivedriskGateway({
    command: FAKE!,
    policyPath: mode,
    startupTimeoutMs: 1500,
    requestTimeoutMs: 1200,
    ...extra,
  });
}

const need = { skip: !FAKE ? "FAKE_GW not set" : false };

// ── 1. bandToSentinel never-demote fuzz (independent of author cases) ─────────
test("bandToSentinel: execute ONLY for exact GREEN/YELLOW; nothing demotes to a GO", () => {
  // Security invariant: the ONLY danger is a non-GREEN/YELLOW label becoming
  // "execute". Assert the implication (execute ⇒ normalized ∈ {GREEN,YELLOW})
  // rather than reimplementing the map.
  const cases = [
    "GREEN", "YELLOW", "ORANGE", "RED", "green", " yellow ", "Band.GREEN", "band.yellow",
    "PURPLE", "GREENISH", "RED.green", "x.green", "evil.red.green", "green\n",
    "Band.RED.extra", "..GREEN", "GREEN.", "GREE N", "G R E E N", "0", "null", "undefined",
    "execute", "allow", "go", "grn", "yel", "Band.Band.GREEN", "GREEN ",
    "green;rm -rf", "\tGREEN\t", "BAND.GREEN.RED", "greenyellow", "orange", "red", "", " ",
    "Green", "GREEN", "RED",
  ];
  const garbage = new Set(["PURPLE", "GREENISH", "RED.green", "x.green", "evil.red.green",
    "Band.RED.extra", "..GREEN", "GREEN.", "GREE N", "G R E E N", "0", "null", "undefined",
    "execute", "allow", "go", "grn", "yel", "Band.Band.GREEN", "green;rm -rf",
    "BAND.GREEN.RED", "greenyellow", "", " "]);
  for (const c of cases) {
    const s = bandToSentinel(c);
    if (s === "execute") {
      const norm = c.trim().toUpperCase().replace(/^BAND\./, "");
      assert.ok(norm === "GREEN" || norm === "YELLOW",
        `NEVER-DEMOTE VIOLATION: ${JSON.stringify(c)} -> execute`);
    }
    if (garbage.has(c)) {
      assert.equal(s, "block", `garbage ${JSON.stringify(c)} must block, got ${s}`);
    }
  }
  assert.equal(bandToSentinel("RED"), "block");
  assert.equal(bandToSentinel("ORANGE"), "approve");
  assert.equal(bandToSentinel("GREEN"), "execute");
  assert.equal(bandToSentinel("YELLOW"), "execute");
  // non-strings
  for (const g of [undefined, null, 123, 0, NaN, {}, [], true, false, Symbol("x")]) {
    assert.equal(bandToSentinel(g), "block", `non-string must block`);
  }
});

test("sentinelBlocks: fail-closed, incl. unrecognized sentinel", () => {
  assert.equal(sentinelBlocks("execute" as Sentinel), false);
  assert.equal(sentinelBlocks("approve" as Sentinel), true);
  assert.equal(sentinelBlocks("approve" as Sentinel, { hasApprovalChannel: true }), true);
  assert.equal(sentinelBlocks("block" as Sentinel), true);
  assert.equal(sentinelBlocks("garbage" as Sentinel), true);
});

// ── 2. Transport failure matrix — each must resolve blocked:true, never reject ─
async function expectBlock(mode: string, extra: Record<string, unknown> = {}) {
  const g = gw(mode, extra);
  try {
    const v = await g.score({ toolName: "Read", toolInput: { file_path: "/tmp/a" } });
    assert.equal(v.blocked, true, `[${mode}] expected blocked:true, got ${JSON.stringify(v)}`);
    return v;
  } finally {
    g.close();
  }
}

test("transport (a): no handshake → fail-closed block, no reject", need, async () => {
  const v = await expectBlock("no-handshake");
  assert.equal(v.sentinel, "block");
});
test("transport: handshake JSON but ready!==true → block", need, async () => {
  await expectBlock("handshake-not-ready");
});
for (const mode of ["null-handshake", "array-handshake"]) {
  test(`transport: ${mode} fails closed without crashing`, need, async () => {
    await expectBlock(mode);
  });
}
test("transport (b): wrong protocol_version → block", need, async () => {
  const v = await expectBlock("bad-protocol");
  assert.equal(v.sentinel, "block");
});
for (const mode of ["missing-protocol", "missing-engine", "wrong-engine", "missing-version",
                    "old-version", "prerelease-version", "future-version"]) {
  test(`transport: unsupported handshake ${mode} → block`, need, async () => {
    const v = await expectBlock(mode);
    assert.equal(v.sentinel, "block");
  });
}
test("transport (c): gateway exits mid-request → block", need, async () => {
  await expectBlock("exit-midrequest");
});
test("transport (d): slow past requestTimeoutMs → block", need, async () => {
  await expectBlock("slow");
});
test("transport (e): {error:...} → block", need, async () => {
  const v = await expectBlock("error");
  assert.equal(v.sentinel, "block");
  assert.equal(v.error, "boom from gateway");
});
test("transport: error non-string object + no band → block", need, async () => {
  await expectBlock("error-object");
});
for (const mode of ["error-object-green", "error-array-green", "error-number-green",
                    "error-boolean-green", "error-null-green"]) {
    test(`transport: any error property takes precedence over GREEN (${mode})`, need, async () => {
    const v = await expectBlock(mode);
    assert.equal(v.sentinel, "block");
  });
}
test("transport: error string wins even with band:GREEN → block", need, async () => {
  const v = await expectBlock("error-with-green-band");
  assert.equal(v.sentinel, "block");
});
for (const mode of ["incomplete-green", "missing-score-green", "string-score-green",
                    "null-composite-green", "bad-audit-green", "contradictory-green"]) {
  test(`transport: malformed scored frame ${mode} → block`, need, async () => {
    const v = await expectBlock(mode);
    assert.equal(v.sentinel, "block");
    assert.match(v.error ?? "", /protocol frame/);
  });
}
test("transport: complete pre-score deny frame blocks", need, async () => {
  const v = await expectBlock("pre-score-deny");
  assert.equal(v.band, "RED");
  assert.equal(v.reason, "input blocked");
});
test("transport (f): unknown band MAROON → block", need, async () => {
  const v = await expectBlock("unknown-band");
  assert.equal(v.sentinel, "block");
});
test("transport: missing band field → default RED → block", need, async () => {
  const v = await expectBlock("no-band");
  assert.equal(v.sentinel, "block");
});
test("transport: band non-string (number) → block", need, async () => {
  await expectBlock("band-nonstring");
});
test("transport: band null → block", need, async () => {
  await expectBlock("band-null");
});
test("transport (g): malformed JSON response → ignored → timeout block", need, async () => {
  const v = await expectBlock("malformed");
  assert.equal(v.sentinel, "block");
});
for (const mode of ["null-response", "array-response", "primitive-response"]) {
  test(`transport: ${mode} is a fatal fail-closed protocol violation`, need, async () => {
    await expectBlock(mode);
  });
}
test("transport: wrong id in reply → never resolved → timeout block", need, async () => {
  await expectBlock("wrong-id");
});
test("transport: ORANGE without approval channel → blocked:true (sentinel approve)", need, async () => {
  const v = await expectBlock("orange");
  assert.equal(v.band, "ORANGE");
  assert.equal(v.sentinel, "approve");
  assert.equal(v.blocked, true);
});
test("transport: legacy approval-channel flag cannot authorize ORANGE", need, async () => {
  const g = gw("orange", { hasApprovalChannel: true });
  try {
    const v = await g.score({ toolName: "X", toolInput: {} });
    assert.equal(v.sentinel, "approve");
    assert.equal(v.blocked, true);
  } finally { g.close(); }
});

// allow paths
test("transport: GREEN → executes (blocked:false)", need, async () => {
  const g = gw("green");
  try {
    const v = await g.score({ toolName: "Read", toolInput: { file_path: "/tmp/a" } });
    assert.equal(v.blocked, false);
    assert.equal(v.sentinel, "execute");
    assert.equal(v.band, "GREEN");
  } finally { g.close(); }
});
test("transport: RED → block with reason", need, async () => {
  const v = await expectBlock("red");
  assert.equal(v.band, "RED");
  assert.ok(v.reason.length > 0);
});
test("transport: double-reply — first (RED) wins, second ignored", need, async () => {
  const v = await expectBlock("double-reply");
  assert.equal(v.reason, "first");
});
test("closed gateway → block, never reject", need, async () => {
  const g = gw("green");
  g.close();
  const v = await g.score({ toolName: "Read", toolInput: {} });
  assert.equal(v.blocked, true);
});
test("score never REJECTS on any hostile mode (Promise resolves to block)", need, async () => {
  for (const mode of ["bad-protocol", "missing-protocol", "missing-engine", "wrong-engine",
                      "missing-version", "old-version", "prerelease-version", "future-version",
                      "exit-midrequest", "error", "malformed", "unknown-band", "wrong-id"]) {
    const g = gw(mode);
    try {
      const v = await g.score({ toolName: "Read", toolInput: {} });
      assert.equal(v.blocked, true, `[${mode}] must resolve to block`);
    } finally { g.close(); }
  }
});
test("score never rejects on unserializable request input", need, async () => {
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  const inputs = [
    { amount: 1n },
    circular,
    { toJSON() { throw new Error("hostile toJSON"); } },
  ];
  const g = gw("green");
  try {
    for (const toolInput of inputs) {
      const v = await g.score({ toolName: "Read", toolInput });
      assert.equal(v.blocked, true);
      assert.equal(v.sentinel, "block");
      assert.match(v.error ?? "", /request preparation failed/);
    }
  } finally { g.close(); }
});
test("custom gateway args fail closed before spawning", async () => {
  const g = new FivedriskGateway({ command: NODE, args: [FAKE!, "green"] });
  try {
    const v = await g.score({ toolName: "Read", toolInput: {} });
    assert.equal(v.blocked, true);
    assert.match(v.error ?? "", /custom gateway args are unsupported/);
  } finally { g.close(); }
});
test("relative gateway command fails closed before spawning", async () => {
  const g = new FivedriskGateway({ command: "python3" });
  try {
    const v = await g.score({ toolName: "Read", toolInput: {} });
    assert.equal(v.blocked, true);
    assert.match(v.error ?? "", /must be an absolute verified Python executable/);
  } finally { g.close(); }
});

test("invalid request metadata fails closed before writing", need, async () => {
  const g = gw("green");
  try {
    const requests = [
      { toolName: "", toolInput: {} },
      { toolName: "   ", toolInput: {} },
      { toolName: "Read", toolInput: {}, autonomy: Number.NaN },
      { toolName: "Read", toolInput: {}, autonomy: 1.5 },
      { toolName: "Read", toolInput: {}, autonomy: -1 },
      { toolName: "Read", toolInput: {}, autonomy: 5 },
      { toolName: "Read", toolInput: {}, sessionId: 7 },
      { toolName: "Read", toolInput: {}, source: {} },
    ];
    for (const request of requests) {
      const v = await g.score(request as never);
      assert.equal(v.blocked, true);
      assert.match(v.error ?? "", /request preparation failed/);
    }
  } finally { g.close(); }
});

test("prepareScore rejects non-data inputs and snapshots accepted input", need, async () => {
  const accessor = {};
  Object.defineProperty(accessor, "command", { enumerable: true, get: () => "rm -rf /" });
  const nonEnumerable = {};
  Object.defineProperty(nonEnumerable, "secret", { value: "x", enumerable: false });
  const sparse = new Array(2);
  sparse[1] = "x";
  class Custom { value = "x"; }
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  const invalid = [
    { toJSON() { return { command: "echo safe" }; }, command: "rm -rf /" },
    accessor,
    nonEnumerable,
    sparse,
    new Custom(),
    circular,
    { value: undefined },
    { value: Symbol("x") },
    { value: 1n },
    { value: Number.NaN },
    { value: Number.POSITIVE_INFINITY },
    new Date(),
    new Map(),
  ];
  const g = gw("green");
  try {
    for (const toolInput of invalid) {
      const prepared = await g.prepareScore({ toolName: "Read", toolInput });
      assert.equal(prepared.ok, false);
      assert.equal(prepared.verdict.blocked, true);
    }
    const original = { nested: { command: "echo safe" }, list: [1, true, null] };
    const prepared = await g.prepareScore({ toolName: "Read", toolInput: original });
    assert.equal(prepared.ok, true);
    if (prepared.ok) {
      assert.deepEqual(prepared.canonicalInput, original);
      assert.notStrictEqual(prepared.canonicalInput, original);
      assert.notStrictEqual((prepared.canonicalInput as { nested: object }).nested, original.nested);
    }
  } finally { g.close(); }
});

test("canonicalization rejects root and nested Proxies before invoking traps", () => {
  let trapCalls = 0;
  const hostile = (target: object) => new Proxy(target, {
    getPrototypeOf() { trapCalls++; throw new Error("getPrototypeOf trap ran"); },
    ownKeys() { trapCalls++; throw new Error("ownKeys trap ran"); },
    getOwnPropertyDescriptor() {
      trapCalls++;
      throw new Error("getOwnPropertyDescriptor trap ran");
    },
  });

  const cases = [
    hostile({ command: "echo safe" }),
    { nested: hostile({ command: "echo safe" }) },
    [hostile(["echo", "safe"])],
  ];
  for (const value of cases) {
    assert.throws(() => canonicalizeJsonValue(value), /contains a Proxy/);
  }

  const revoked = Proxy.revocable({ command: "echo safe" }, {});
  revoked.revoke();
  assert.throws(() => canonicalizeJsonValue(revoked.proxy), /contains a Proxy/);
  assert.equal(trapCalls, 0, "Proxy traps must not run before the input is rejected");
});

// ── 3. Vercel / Genkit wrappers ───────────────────────────────────────────────
test("guardVercelTool: blocked verdict throws, original NOT called", need, async () => {
  const g = gw("red");
  let calls = 0;
  const tool = { execute: async (_a: unknown, _o: unknown) => { calls++; return "ran"; } };
  const guarded = guardVercelTool(g, "Bash", tool);
  try {
    await assert.rejects(() => guarded.execute!({ command: "x" }, {}), FivedriskBlockedError);
    assert.equal(calls, 0, "original tool must NOT run on block");
  } finally { g.close(); }
});
test("guardVercelTool: allow calls original exactly once with original args", need, async () => {
  const g = gw("green");
  const seen: unknown[] = [];
  const tool = { execute: async (a: unknown, _o: unknown) => { seen.push(a); return "ran"; } };
  const guarded = guardVercelTool(g, "Read", tool);
  try {
    const args = { file_path: "/tmp/a" };
    const r = await guarded.execute!(args, { extra: 1 });
    assert.equal(r, "ran");
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], args);
    assert.notStrictEqual(seen[0], args);
  } finally { g.close(); }
});
test("guardVercelTool: custom toJSON cannot hide the executed command", need, async () => {
  const g = gw("green");
  let calls = 0;
  const guarded = guardVercelTool(g, "Bash", {
    execute: async (_args: unknown, _options: unknown) => { calls++; return "ran"; },
  });
  const hostile = { command: "rm -rf /", toJSON() { return { command: "echo safe" }; } };
  try {
    await assert.rejects(() => guarded.execute!(hostile, {}), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardVercelTool: fail-closed gateway (error) → throws, original NOT called", need, async () => {
  const g = gw("error");
  let calls = 0;
  const tool = { execute: async (_a: unknown, _o: unknown) => { calls++; return "ran"; } };
  const guarded = guardVercelTool(g, "Bash", tool);
  try {
    await assert.rejects(() => guarded.execute!({}, {}), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardVercelTool: ORANGE never invokes tool even with legacy approval flag", need, async () => {
  const g = gw("orange", { hasApprovalChannel: true });
  let calls = 0;
  const guarded = guardVercelTool(g, "Bash", {
    execute: async (_args: unknown, _options: unknown) => { calls++; return "ran"; },
  });
  try {
    await assert.rejects(() => guarded.execute!({}, {}), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardGenkitTool: blocked verdict throws, handler NOT called", need, async () => {
  const g = gw("red");
  let calls = 0;
  const handler = async (_i: unknown) => { calls++; return "ok"; };
  const guarded = guardGenkitTool(g, "Bash", handler);
  try {
    await assert.rejects(() => guarded({ command: "x" }), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardGenkitTool: allow calls handler once with original input", need, async () => {
  const g = gw("green");
  const seen: unknown[] = [];
  const handler = async (i: unknown) => { seen.push(i); return "ok"; };
  const guarded = guardGenkitTool(g, "Read", handler);
  try {
    const input = { file_path: "/tmp/a" };
    const r = await guarded(input);
    assert.equal(r, "ok");
    assert.deepEqual(seen, [input]);
    assert.notStrictEqual(seen[0], input);
  } finally { g.close(); }
});
test("guardGenkitTool: custom toJSON cannot hide the executed command", need, async () => {
  const g = gw("green");
  let calls = 0;
  const guarded = guardGenkitTool(g, "Bash", async () => { calls++; return "ran"; });
  const hostile = { command: "rm -rf /", toJSON() { return { command: "echo safe" }; } };
  try {
    await assert.rejects(() => guarded(hostile), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardGenkitTool: unknown-band gateway → throws (fail closed)", need, async () => {
  const g = gw("unknown-band");
  let calls = 0;
  const guarded = guardGenkitTool(g, "Bash", async (_i: unknown) => { calls++; return "ok"; });
  try {
    await assert.rejects(() => guarded({}), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
test("guardGenkitTool: ORANGE never invokes handler even with legacy approval flag", need, async () => {
  const g = gw("orange", { hasApprovalChannel: true });
  let calls = 0;
  const guarded = guardGenkitTool(g, "Bash", async () => { calls++; return "ran"; });
  try {
    await assert.rejects(() => guarded({}), FivedriskBlockedError);
    assert.equal(calls, 0);
  } finally { g.close(); }
});
