/**
 * fivedrisk gateway client (TypeScript) — gate any JS/TS agent through the 5D
 * engine over its JSON-lines stdio protocol. No Python-in-JS: this spawns the
 * shipped `fivedrisk gateway stdio` process and talks to it line by line.
 *
 * The 5D engine stays the single source of truth; this client only transports a
 * tool call to it and maps the returned band to a canonical sentinel. It mirrors
 * the Python `band_to_sentinel` never-demote invariant: RED → block, ORANGE →
 * approve (never execute), unknown/garbage/error/timeout → block (fail closed).
 *
 * Validation status: the wire protocol is verified against the shipped gateway
 * (handshake `protocol_version: 1`, `id`-correlated responses). The Vercel /
 * Genkit wrappers are built to those SDKs' documented tool shapes — smoke-test
 * against your pinned SDK version before production.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { isAbsolute } from "node:path";
import { createInterface, type Interface } from "node:readline";
import { types as utilTypes } from "node:util";

export type Sentinel = "execute" | "approve" | "block";
export type JsonPrimitive = null | boolean | string | number;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type PreparedScore =
  | { ok: true; canonicalInput: JsonValue; verdict: FivedriskVerdict }
  | { ok: false; verdict: FivedriskVerdict };

const BAND_SENTINEL: Record<string, Sentinel> = {
  GREEN: "execute",
  YELLOW: "execute",
  ORANGE: "approve",
  RED: "block",
};

/**
 * Map a 5D band to the canonical sentinel. Whole-token match only: a garbage or
 * attacker-influenced label can never normalize into a GO. Unknown → block.
 */
export function bandToSentinel(band: unknown): Sentinel {
  if (typeof band !== "string") return "block";
  const name = band.trim().toUpperCase().replace(/^BAND\./, "");
  return BAND_SENTINEL[name] ?? "block";
}

/** Whether an adapter should STOP the tool call for this sentinel. */
export function sentinelBlocks(
  sentinel: Sentinel,
  _opts: { hasApprovalChannel?: boolean } = {},
): boolean {
  if (sentinel === "execute") return false;
  if (sentinel === "approve") return true;
  return true; // block, or anything unrecognized → stop
}

export interface FivedriskVerdict {
  band: string;
  sentinel: Sentinel;
  blocked: boolean;
  reason: string;
  decisionId?: string;
  scores?: Record<string, number>;
  compositeScore?: number;
  auditLogId?: number;
  /** Set when the gateway returned an error or the call failed closed. */
  error?: string;
}

export interface ScoreRequest {
  toolName: string;
  toolInput?: unknown;
  autonomy?: number;
  sessionId?: string;
  source?: string;
}

export interface GatewayOptions {
  /** Absolute verified Python executable that launches a supported stable >=0.7.1,<0.8 gateway. */
  command: string;
  /** @deprecated Only the exact legacy canonical argv is accepted and normalized. */
  args?: string[];
  /** Path to a policy.yaml (adds "--policy <path>"). */
  policyPath?: string;
  /** Explicit SQLite audit path (adds "--log-path <path>"). */
  logPath?: string;
  /** Max ms to wait for the startup handshake. Default 10000. */
  startupTimeoutMs?: number;
  /** Max ms to wait for a single score response. Default 5000. */
  requestTimeoutMs?: number;
  /** @deprecated Ignored. ORANGE remains blocked until a per-call approval API exists. */
  hasApprovalChannel?: boolean;
}

interface Pending {
  resolve: (v: FivedriskVerdict) => void;
  timer: ReturnType<typeof setTimeout>;
  req: ScoreRequest;
}

const EXPECTED_PROTOCOL_VERSION = 1;
const SCORE_KEYS = [
  "data_sensitivity",
  "tool_privilege",
  "reversibility",
  "external_impact",
  "autonomy_context",
] as const;
const ISOLATED_GATEWAY_ARGS = ["-B", "-I", "-m", "fivedrisk._bootstrap", "gateway", "stdio"];
const LEGACY_GATEWAY_ARGS = ["-m", "fivedrisk", "gateway", "stdio"];

function sameArgs(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function encodeJsonData(value: unknown, seen: Set<object>, depth = 0): string {
  if (depth > 100) throw new TypeError("tool input exceeds the maximum JSON depth");
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("tool input contains a non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new TypeError(`tool input contains unsupported ${typeof value}`);
  }
  if (utilTypes.isProxy(value)) {
    throw new TypeError("tool input contains a Proxy");
  }
  if (seen.has(value)) throw new TypeError("tool input contains a cycle");
  seen.add(value);
  try {
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const symbols = Object.getOwnPropertySymbols(value);
    if (symbols.length > 0) throw new TypeError("tool input contains symbol properties");

    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) throw new TypeError("tool input array has a custom prototype");
      const keys = Object.keys(descriptors).filter((key) => key !== "length");
      if (keys.length !== value.length) throw new TypeError("tool input array is sparse or has extra properties");
      const parts: string[] = [];
      for (let index = 0; index < value.length; index++) {
        const key = String(index);
        const descriptor = descriptors[key];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
          throw new TypeError("tool input array contains an accessor or non-enumerable element");
        }
        parts.push(encodeJsonData(descriptor.value, seen, depth + 1));
      }
      if (keys.some((key) => !/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)) {
        throw new TypeError("tool input array has extra properties");
      }
      return `[${parts.join(",")}]`;
    }

    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("tool input object has a custom prototype");
    }
    const parts: string[] = [];
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("tool input object contains an accessor or non-enumerable property");
      }
      parts.push(`${JSON.stringify(key)}:${encodeJsonData(descriptor.value, seen, depth + 1)}`);
    }
    return `{${parts.join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

/** Snapshot an untrusted value into detached, data-only JSON without invoking toJSON. */
export function canonicalizeJsonValue(value: unknown): { value: JsonValue; encoded: string } {
  let encoded: string;
  try {
    encoded = encodeJsonData(value, new Set<object>());
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new TypeError("cannot canonicalize tool input: " + message);
  }
  return { value: JSON.parse(encoded) as JsonValue, encoded };
}

/**
 * A long-lived connection to the 5D gateway. Spawn once, `score()` many times,
 * `close()` when done. Every failure path resolves to a fail-closed BLOCK
 * verdict rather than rejecting, so a caller that forgets try/catch still stops
 * the tool instead of running it.
 */
export class FivedriskGateway {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private rl: Interface | null = null;
  private ready: Promise<void>;
  private pending = new Map<string, Pending>();
  private seq = 0;
  private closed = false;
  private readonly configurationError?: string;
  private readonly opts: Required<Omit<GatewayOptions, "policyPath" | "logPath">> & {
    policyPath?: string;
    logPath?: string;
  };

  constructor(options: GatewayOptions) {
    const suppliedArgs = options.args;
    let configurationError: string | undefined;
    const args = suppliedArgs === undefined || sameArgs(suppliedArgs, LEGACY_GATEWAY_ARGS)
      ? [...ISOLATED_GATEWAY_ARGS]
      : [];
    if (suppliedArgs !== undefined && !sameArgs(suppliedArgs, LEGACY_GATEWAY_ARGS)) {
      configurationError = "custom gateway args are unsupported; use the isolated installed bootstrap";
    } else if (!isAbsolute(options.command)) {
      configurationError = "gateway command must be an absolute verified Python executable path";
    }
    this.configurationError = configurationError;
    const fullArgs = [...args];
    if (options.policyPath) fullArgs.push("--policy", options.policyPath);
    if (options.logPath) fullArgs.push("--log-path", options.logPath);
    this.opts = {
      command: options.command,
      args: fullArgs,
      startupTimeoutMs: options.startupTimeoutMs ?? 10_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 5_000,
      hasApprovalChannel: options.hasApprovalChannel ?? false,
      policyPath: options.policyPath,
      logPath: options.logPath,
    };
    this.ready = this.configurationError ? Promise.resolve() : this.start();
  }

  private start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const proc = spawn(this.opts.command, this.opts.args, { stdio: "pipe" });
      this.proc = proc;
      const startupTimer = setTimeout(() => {
        reject(new Error(`5D gateway did not emit a handshake within ${this.opts.startupTimeoutMs}ms`));
        this.destroy();
      }, this.opts.startupTimeoutMs);

      const rl = createInterface({ input: proc.stdout });
      this.rl = rl;
      let handshakeSeen = false;

      rl.on("line", (line: string) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(trimmed) as unknown;
        } catch {
          return; // ignore non-JSON noise on stdout
        }
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          const reason = "5D gateway emitted a non-object protocol frame";
          clearTimeout(startupTimer);
          if (!handshakeSeen) reject(new Error(reason));
          this.failAllPending(reason);
          this.destroy();
          return;
        }
        const msg = parsed as Record<string, unknown>;
        if (!handshakeSeen && msg.ready === true) {
          handshakeSeen = true;
          clearTimeout(startupTimer);
          const engineVersion = msg.engine_version;
          const stableSupportedVersion = (
            typeof engineVersion === "string"
            && /^0\.7\.\d+$/.test(engineVersion)
            && Number(engineVersion.split(".")[2]) >= 1
          );
          if (
            msg.engine !== "fivedrisk"
            || msg.protocol_version !== EXPECTED_PROTOCOL_VERSION
            || !stableSupportedVersion
          ) {
            reject(new Error(
              "unsupported 5D gateway handshake: "
              + `engine=${String(msg.engine)}, `
              + `protocol=${String(msg.protocol_version)}, `
              + `version=${String(engineVersion)}`,
            ));
            this.destroy();
            return;
          }
          resolve();
          return;
        }
        this.dispatch(msg);
      });

      proc.on("error", (err: Error) => {
        clearTimeout(startupTimer);
        reject(err);
        this.failAllPending("5D gateway process error: " + err.message);
      });
      proc.on("exit", () => {
        clearTimeout(startupTimer);
        this.failAllPending("5D gateway process exited");
      });
    });
  }

  private dispatch(msg: Record<string, unknown>): void {
    const id = typeof msg.id === "string" ? msg.id : undefined;
    if (id === undefined) return; // unsolicited / handshake echo
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    clearTimeout(p.timer);
    p.resolve(this.toVerdict(msg));
  }

  private toVerdict(msg: Record<string, unknown>): FivedriskVerdict {
    if (Object.prototype.hasOwnProperty.call(msg, "error")) {
      const reason = typeof msg.error === "string" && msg.error.length > 0
        ? msg.error
        : "5D gateway returned an error";
      return { band: "RED", sentinel: "block", blocked: true, reason, error: reason };
    }

    const decisionId = msg.decision_id;
    const auditLogId = msg.audit_log_id;
    const rationale = msg.rationale;
    const validIdentity = (
      typeof decisionId === "string"
      && decisionId.length > 0
      && typeof auditLogId === "number"
      && Number.isSafeInteger(auditLogId)
      && auditLogId > 0
      && typeof rationale === "string"
    );

    if (
      msg.band === "RED"
      && msg.blocked === true
      && validIdentity
      && typeof msg.block_reason === "string"
      && msg.block_reason.length > 0
    ) {
      return {
        band: "RED",
        sentinel: "block",
        blocked: true,
        reason: rationale as string,
        decisionId: decisionId as string,
        auditLogId: auditLogId as number,
      };
    }

    const band = msg.band;
    const scores = msg.scores;
    const compositeScore = msg.composite_score;
    if (
      !validIdentity
      || typeof band !== "string"
      || !["GREEN", "YELLOW", "ORANGE", "RED"].includes(band)
      || scores === null
      || typeof scores !== "object"
      || Array.isArray(scores)
      || typeof compositeScore !== "number"
      || !Number.isFinite(compositeScore)
    ) {
      return this.failClosed("5D gateway returned an invalid scored protocol frame");
    }
    const scoreRecord = scores as Record<string, unknown>;
    const canonicalScores: Record<string, number> = {};
    for (const key of SCORE_KEYS) {
      const value = scoreRecord[key];
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 4) {
        return this.failClosed("5D gateway returned an invalid scored protocol frame");
      }
      canonicalScores[key] = value;
    }
    const sentinel = bandToSentinel(band);
    const blocked = sentinelBlocks(sentinel);
    if (Object.prototype.hasOwnProperty.call(msg, "blocked")) {
      if (typeof msg.blocked !== "boolean" || msg.blocked !== blocked) {
        return this.failClosed("5D gateway returned a contradictory scored protocol frame");
      }
    }
    return {
      band,
      sentinel,
      blocked,
      reason: rationale as string,
      decisionId: decisionId as string,
      scores: canonicalScores,
      compositeScore,
      auditLogId: auditLogId as number,
    };
  }

  private failClosed(reason: string): FivedriskVerdict {
    return { band: "RED", sentinel: "block", blocked: true, reason, error: reason };
  }

  private failAllPending(reason: string): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.resolve(this.failClosed(reason));
    }
    this.pending.clear();
  }

  /** Snapshot one call before awaiting, then score exactly that detached snapshot. */
  async prepareScore(req: ScoreRequest): Promise<PreparedScore> {
    let canonicalInput: JsonValue;
    let encodedInput: string;
    let snapshot: Omit<ScoreRequest, "toolInput">;
    try {
      const canonical = canonicalizeJsonValue(req.toolInput ?? {});
      canonicalInput = canonical.value;
      encodedInput = canonical.encoded;
      snapshot = {
        toolName: req.toolName,
        autonomy: req.autonomy,
        sessionId: req.sessionId,
        source: req.source,
      };
      if (typeof snapshot.toolName !== "string" || snapshot.toolName.trim().length === 0) {
        throw new TypeError("toolName must be a non-empty string");
      }
      if (snapshot.autonomy !== undefined && (
        typeof snapshot.autonomy !== "number"
        || !Number.isInteger(snapshot.autonomy)
        || snapshot.autonomy < 0
        || snapshot.autonomy > 4
      )) {
        throw new TypeError("autonomy must be an integer in [0, 4]");
      }
      if (snapshot.sessionId !== undefined && typeof snapshot.sessionId !== "string") {
        throw new TypeError("sessionId must be a string");
      }
      if (snapshot.source !== undefined && typeof snapshot.source !== "string") {
        throw new TypeError("source must be a string");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, verdict: this.failClosed("5D gateway request preparation failed: " + message) };
    }
    const verdict = await this.scorePrepared(snapshot, canonicalInput, encodedInput);
    return { ok: true, canonicalInput, verdict };
  }

  /** Score one tool call. Resolves to a verdict; never rejects (fails closed). */
  async score(req: ScoreRequest): Promise<FivedriskVerdict> {
    const prepared = await this.prepareScore(req);
    return prepared.verdict;
  }

  private async scorePrepared(
    req: Omit<ScoreRequest, "toolInput">,
    canonicalInput: JsonValue,
    _encodedInput: string,
  ): Promise<FivedriskVerdict> {
    if (this.configurationError) return this.failClosed(this.configurationError);
    if (this.closed) return this.failClosed("5D gateway is closed");
    try {
      await this.ready;
    } catch (err) {
      return this.failClosed("5D gateway failed to start: " + (err as Error).message);
    }
    const proc = this.proc;
    if (!proc || !proc.stdin.writable) return this.failClosed("5D gateway stdin not writable");

    const id = String(++this.seq);
    const payload: Record<string, unknown> = { id, tool_name: req.toolName, params: canonicalInput };
    if (req.autonomy !== undefined) payload.autonomy = req.autonomy;
    if (req.sessionId !== undefined) payload.session_id = req.sessionId;
    if (req.source !== undefined) payload.source = req.source;

    let encoded: string;
    try {
      encoded = JSON.stringify(payload);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.failClosed("5D gateway request serialization failed: " + message);
    }

    return new Promise<FivedriskVerdict>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(this.failClosed(`5D gateway timed out after ${this.opts.requestTimeoutMs}ms`));
      }, this.opts.requestTimeoutMs);
      this.pending.set(id, { resolve, timer, req });
      try {
        proc.stdin.write(encoded + "\n", (err) => {
          if (!err) return;
          this.pending.delete(id);
          clearTimeout(timer);
          resolve(this.failClosed("5D gateway write failed: " + err.message));
        });
      } catch (err) {
        this.pending.delete(id);
        clearTimeout(timer);
        const message = err instanceof Error ? err.message : String(err);
        resolve(this.failClosed("5D gateway write failed: " + message));
      }
    });
  }

  private destroy(): void {
    this.rl?.close();
    this.proc?.kill();
    this.rl = null;
    this.proc = null;
  }

  /** Shut down the gateway process. */
  close(): void {
    this.closed = true;
    this.failAllPending("5D gateway is closing");
    this.destroy();
  }
}
