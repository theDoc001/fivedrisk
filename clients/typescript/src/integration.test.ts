import { test } from "node:test";
import assert from "node:assert/strict";
import { FivedriskGateway } from "./gateway.js";

// Live end-to-end: the real TS client spawns the real Python gateway and scores.
// Skips unless FIVEDRISK_PY points at a python with fivedrisk installed, so this
// stays green in environments without the engine. Run locally with:
//   FIVEDRISK_PY=~/.venvs/fivedrisk-dev/bin/python node --test dist/integration.test.js
const PY = process.env.FIVEDRISK_PY;

test("live gateway: RED blocks, GREEN executes, correlation holds", { skip: !PY }, async () => {
  const gw = new FivedriskGateway({ command: PY!, args: ["-m", "fivedrisk", "gateway", "stdio"] });
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

test("live gateway: bad tool_input fails closed to block", { skip: !PY }, async () => {
  const gw = new FivedriskGateway({ command: PY!, args: ["-m", "fivedrisk", "gateway", "stdio"] });
  try {
    // a non-object params → gateway error → TS maps to fail-closed BLOCK
    const v = await gw.score({ toolName: "Bash", toolInput: "rm -rf /data" });
    assert.equal(v.blocked, true);
    assert.equal(v.sentinel, "block");
  } finally {
    gw.close();
  }
});
