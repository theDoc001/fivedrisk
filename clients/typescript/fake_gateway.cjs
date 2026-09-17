#!/usr/bin/env node
// Adversarial fake 5D gateway. Mode selected by argv[2]. Speaks the JSON-lines
// protocol the TS client expects, but is deliberately hostile in each mode so we
// can prove the client fails CLOSED (block) on every failure path.
const readline = require("node:readline");
const mode = process.argv[2] || "green";

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}
function emitRaw(s) {
  process.stdout.write(s + "\n");
}

const handshake = { ready: true, protocol_version: 1, engine: "fivedrisk" };

// Handshake behaviour
if (mode === "no-handshake") {
  // never emit anything; just hang so stdin stays open
} else if (mode === "bad-protocol") {
  emit({ ready: true, protocol_version: 2, engine: "fivedrisk" });
} else if (mode === "bad-protocol-string") {
  emit({ ready: true, protocol_version: "999", engine: "fivedrisk" });
} else if (mode === "handshake-not-ready") {
  // emit a first line that is JSON but ready!==true, then never a real handshake
  emit({ hello: "world" });
} else {
  emit(handshake);
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const t = line.trim();
  if (!t) return;
  let msg;
  try { msg = JSON.parse(t); } catch { return; }
  const id = msg.id;
  switch (mode) {
    case "exit-midrequest":
      process.exit(0);
      break;
    case "slow":
    case "no-handshake":
    case "handshake-not-ready":
      // never respond
      break;
    case "error":
      emit({ id, error: "boom from gateway" });
      break;
    case "error-object":
      // error present but NOT a string; also no band field
      emit({ id, error: { msg: "structured" } });
      break;
    case "error-with-green-band":
      // error string AND a benign-looking band — error must win → block
      emit({ id, band: "GREEN", error: "boom", rationale: "should be ignored" });
      break;
    case "unknown-band":
      emit({ id, band: "MAROON", rationale: "unknown band" });
      break;
    case "no-band":
      emit({ id, rationale: "no band field at all" });
      break;
    case "band-nonstring":
      emit({ id, band: 123, rationale: "band is a number" });
      break;
    case "band-null":
      emit({ id, band: null, rationale: "band null" });
      break;
    case "malformed":
      emitRaw("this is definitely not json {");
      break;
    case "lowercase-red":
      emit({ id, band: "red", rationale: "lowercase red" });
      break;
    case "orange":
      emit({ id, band: "ORANGE", rationale: "needs approval" });
      break;
    case "green":
      emit({ id, band: "GREEN", rationale: "" });
      break;
    case "red":
      emit({ id, band: "RED", rationale: "hard no" });
      break;
    case "wrong-id":
      // respond with a different id than requested → client must not resolve it
      emit({ id: "not-" + String(id), band: "GREEN", rationale: "wrong id" });
      break;
    case "double-reply":
      // reply twice; second reply must be ignored, first (RED) wins
      emit({ id, band: "RED", rationale: "first" });
      emit({ id, band: "GREEN", rationale: "second" });
      break;
    default:
      emit({ id, band: "RED", rationale: "default deny" });
  }
});
rl.on("close", () => process.exit(0));
