import { test } from "node:test";
import assert from "node:assert/strict";
import { FivedriskGateway } from "./gateway.js";

// Live end-to-end: the real TS client spawns the real Python gateway and scores.
// Release-required: FIVEDRISK_PY must point at an absolute verified interpreter
// with fivedrisk installed. Missing configuration is a failure, never a skip.
const PY = process.env.FIVEDRISK_PY;
if (!PY) throw new Error("FIVEDRISK_PY is required for the live release test");

test("live gateway: RED blocks, GREEN executes, correlation holds", async () => {
  const gw = new FivedriskGateway({ command: PY, args: ["-m", "fivedrisk", "gateway", "stdio"] });
  try {
    const green = await gw.score({ toolName: "Read", toolInput: { file_path: "/tmp/a" } });
    assert.equal(green.band, "GREEN");
    assert.equal(green.sentinel, "execute");
    assert.equal(green.blocked, false);

    const red = await gw.score({ toolName: "Bash", toolInput: { command: "rm -rf /data" } });
    assert.equal(red.band, "RED");
    assert.equal(red.sentinel, "block");
    assert.equal(red.blocked, true);
    assert.ok(red.reason.length > 0);

    // concurrent calls correlate by id
    const [a, b] = await Promise.all([
      gw.score({ toolName: "Read", toolInput: { file_path: "/x" } }),
      gw.score({ toolName: "Bash", toolInput: { command: "rm -rf /y" } }),
    ]);
    assert.equal(a.band, "GREEN");
    assert.equal(b.band, "RED");
  } finally {
    gw.close();
  }
});

test("live gateway: bad tool_input fails closed to block", async () => {
  const gw = new FivedriskGateway({ command: PY, args: ["-m", "fivedrisk", "gateway", "stdio"] });
  try {
    // a non-object params → gateway error → TS maps to fail-closed BLOCK
    const v = await gw.score({ toolName: "Bash", toolInput: "rm -rf /data" });
    assert.equal(v.blocked, true);
    assert.equal(v.sentinel, "block");
  } finally {
    gw.close();
  }
});
