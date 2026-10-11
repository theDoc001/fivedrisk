#!/usr/bin/env node
// Adversarial fake 5D gateway. Mode selected by argv[2]. Speaks the JSON-lines
// protocol the TS client expects, but is deliberately hostile in each mode so we
// can prove the client fails CLOSED (block) on every failure path.
const readline = require("node:readline");
const policyIndex = process.argv.lastIndexOf("--policy");
const mode = policyIndex >= 0 ? process.argv[policyIndex + 1] : "green";

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}
function emitRaw(s) {
  process.stdout.write(s + "\n");
}

const handshake = { ready: true, protocol_version: 1, engine: "fivedrisk", engine_version: "0.7.1" };
function scored(id, band, rationale, overrides = {}) {
  return {
    id,
    decision_id: "dec-" + String(id),
    band,
    scores: {
      data_sensitivity: 0,
      tool_privilege: band === "RED" ? 4 : 0,
      reversibility: band === "RED" ? 4 : 0,
      external_impact: 0,
      autonomy_context: 0,
    },
    composite_score: band === "RED" ? 8 : 0,
    rationale,
    audit_log_id: 1,
    ...overrides,
  };
}

// Handshake behaviour
if (mode === "no-handshake") {
  // never emit anything; just hang so stdin stays open
} else if (mode === "bad-protocol") {
  emit({ ...handshake, protocol_version: 2 });
} else if (mode === "bad-protocol-string") {
  emit({ ...handshake, protocol_version: "999" });
} else if (mode === "missing-protocol") {
  const { protocol_version, ...rest } = handshake;
  emit(rest);
} else if (mode === "missing-engine") {
  const { engine, ...rest } = handshake;
  emit(rest);
} else if (mode === "wrong-engine") {
  emit({ ...handshake, engine: "lookalike" });
} else if (mode === "missing-version") {
  const { engine_version, ...rest } = handshake;
  emit(rest);
} else if (mode === "old-version") {
  emit({ ...handshake, engine_version: "0.6.0" });
} else if (mode === "prerelease-version") {
  emit({ ...handshake, engine_version: "0.7.0rc1" });
} else if (mode === "future-version") {
  emit({ ...handshake, engine_version: "0.8.0" });
} else if (mode === "handshake-not-ready") {
  // emit a first line that is JSON but ready!==true, then never a real handshake
  emit({ hello: "world" });
} else if (mode === "null-handshake") {
  emitRaw("null");
} else if (mode === "array-handshake") {
  emit([]);
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
    case "error-object-green":
      emit({ id, band: "GREEN", error: { msg: "structured" } });
      break;
    case "error-array-green":
      emit({ id, band: "GREEN", error: ["boom"] });
      break;
    case "error-number-green":
      emit({ id, band: "GREEN", error: 500 });
      break;
    case "error-boolean-green":
      emit({ id, band: "GREEN", error: false });
      break;
    case "error-null-green":
      emit({ id, band: "GREEN", error: null });
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
    case "null-response":
      emitRaw("null");
      break;
    case "array-response":
      emit([]);
      break;
    case "primitive-response":
      emitRaw("42");
      break;
    case "lowercase-red":
      emit(scored(id, "red", "lowercase red"));
      break;
    case "orange":
      emit(scored(id, "ORANGE", "needs approval"));
      break;
    case "green":
      emit(scored(id, "GREEN", "allowed"));
      break;
    case "red":
      emit(scored(id, "RED", "hard no"));
      break;
    case "incomplete-green":
      emit({ id, band: "GREEN", rationale: "incomplete" });
      break;
    case "missing-score-green": {
      const frame = scored(id, "GREEN", "missing score");
      delete frame.scores.reversibility;
      emit(frame);
      break;
    }
    case "string-score-green":
      emit(scored(id, "GREEN", "bad score", {
        scores: {
          data_sensitivity: 0, tool_privilege: 0, reversibility: "0",
          external_impact: 0, autonomy_context: 0,
        },
      }));
      break;
    case "null-composite-green":
      emit(scored(id, "GREEN", "bad composite", { composite_score: null }));
      break;
    case "bad-audit-green":
      emit(scored(id, "GREEN", "bad audit", { audit_log_id: 0 }));
      break;
    case "contradictory-green":
      emit(scored(id, "GREEN", "contradiction", { blocked: true }));
      break;
    case "pre-score-deny":
      emit({
        id, decision_id: "dec-" + String(id), band: "RED", blocked: true,
        block_reason: "input blocked", rationale: "input blocked", audit_log_id: 1,
      });
      break;
    case "wrong-id":
      // respond with a different id than requested → client must not resolve it
      emit(scored("not-" + String(id), "GREEN", "wrong id"));
      break;
    case "double-reply":
      // reply twice; second reply must be ignored, first (RED) wins
      emit(scored(id, "RED", "first"));
      emit(scored(id, "GREEN", "second"));
      break;
    default:
      emit(scored(id, "RED", "default deny"));
  }
});
rl.on("close", () => process.exit(0));
