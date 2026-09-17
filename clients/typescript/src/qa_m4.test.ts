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
import { FivedriskGateway, bandToSentinel, sentinelBlocks, type Sentinel } from "./gateway.js";
import { guardVercelTool, FivedriskBlockedError } from "./vercel.js";
import { guardGenkitTool } from "./genkit.js";

// Defaults to the in-repo fixture so this lock runs with no env setup; FAKE_GW overrides.
const FAKE = process.env.FAKE_GW ?? fileURLToPath(new URL("../fake_gateway.cjs", import.meta.url));
const NODE = process.execPath;

function gw(mode: string, extra: Record<string, unknown> = {}) {
  return new FivedriskGateway({
    command: NODE,
    args: [FAKE!, mode],
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
  assert.equal(sentinelBlocks("approve" as Sentinel, { hasApprovalChannel: true }), false);
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
test("transport (b): wrong protocol_version → block", need, async () => {
  const v = await expectBlock("bad-protocol");
  assert.equal(v.sentinel, "block");
});
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
test("transport: error string wins even with band:GREEN → block", need, async () => {
  const v = await expectBlock("error-with-green-band");
  assert.equal(v.sentinel, "block");
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
test("transport: wrong id in reply → never resolved → timeout block", need, async () => {
  await expectBlock("wrong-id");
});
test("transport: ORANGE without approval channel → blocked:true (sentinel approve)", need, async () => {
  const v = await expectBlock("orange");
  assert.equal(v.band, "ORANGE");
  assert.equal(v.sentinel, "approve");
  assert.equal(v.blocked, true);
});
test("transport: ORANGE WITH approval channel → blocked:false (by design)", need, async () => {
  const g = gw("orange", { hasApprovalChannel: true });
  try {
    const v = await g.score({ toolName: "X", toolInput: {} });
    assert.equal(v.sentinel, "approve");
    assert.equal(v.blocked, false);
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
  for (const mode of ["bad-protocol", "exit-midrequest", "error", "malformed",
                      "unknown-band", "wrong-id"]) {
    const g = gw(mode);
    try {
      const v = await g.score({ toolName: "Read", toolInput: {} });
      assert.equal(v.blocked, true, `[${mode}] must resolve to block`);
    } finally { g.close(); }
  }
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
