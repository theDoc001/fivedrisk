import { test } from "node:test";
import assert from "node:assert/strict";
import { bandToSentinel, sentinelBlocks, type Sentinel } from "./gateway.js";

// The never-demote spine, re-proved in TypeScript (mirrors the Python QA-1 invariant).
test("bandToSentinel: canonical bands", () => {
  assert.equal(bandToSentinel("GREEN"), "execute");
  assert.equal(bandToSentinel("YELLOW"), "execute");
  assert.equal(bandToSentinel("ORANGE"), "approve");
  assert.equal(bandToSentinel("RED"), "block");
});

test("bandToSentinel: case + enum-repr tolerant, still exact", () => {
  assert.equal(bandToSentinel("red"), "block");
  assert.equal(bandToSentinel("  RED  "), "block");
  assert.equal(bandToSentinel("Band.RED"), "block");
  assert.equal(bandToSentinel("Band.GREEN"), "execute");
});

test("bandToSentinel: never demotes — garbage/unknown → block", () => {
  for (const g of ["", "PURPLE", "GREENISH", "RED.green", "x.green", "evil.red.green",
                   "block", "allow", "..GREEN", "green\n", "Band.RED.extra"]) {
    const s = bandToSentinel(g);
    // may only be non-block for an EXACT known name (none of these are)
    if (s !== "block") {
      const name = g.trim().toUpperCase().replace(/^BAND\./, "");
      assert.ok(["GREEN", "YELLOW", "ORANGE", "RED"].includes(name), `${g} demoted to ${s}`);
    }
  }
});

test("bandToSentinel: non-string → block", () => {
  for (const g of [undefined, null, 123, {}, [], true]) {
    assert.equal(bandToSentinel(g), "block");
  }
});

test("sentinelBlocks: fail-closed semantics", () => {
  assert.equal(sentinelBlocks("execute" as Sentinel), false);
  assert.equal(sentinelBlocks("block" as Sentinel), true);
  assert.equal(sentinelBlocks("approve" as Sentinel), true);
  assert.equal(sentinelBlocks("approve" as Sentinel, { hasApprovalChannel: true }), false);
});
