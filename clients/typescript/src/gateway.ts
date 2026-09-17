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
import { createInterface, type Interface } from "node:readline";

export type Sentinel = "execute" | "approve" | "block";

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
  opts: { hasApprovalChannel?: boolean } = {},
): boolean {
  if (sentinel === "execute") return false;
  if (sentinel === "approve") return !opts.hasApprovalChannel;
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
  /** Executable that launches the gateway. Default: "python". */
  command?: string;
  /** Args. Default: ["-m", "fivedrisk", "gateway", "stdio"]. */
  args?: string[];
  /** Path to a policy.yaml (adds "--policy <path>"). */
  policyPath?: string;
  /** Max ms to wait for the startup handshake. Default 10000. */
  startupTimeoutMs?: number;
  /** Max ms to wait for a single score response. Default 5000. */
  requestTimeoutMs?: number;
  /** Whether the host has a synchronous human-approval channel (ORANGE). */
  hasApprovalChannel?: boolean;
}

interface Pending {
  resolve: (v: FivedriskVerdict) => void;
  timer: ReturnType<typeof setTimeout>;
  req: ScoreRequest;
}

const EXPECTED_PROTOCOL_VERSION = 1;

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
  private readonly opts: Required<Omit<GatewayOptions, "policyPath">> & { policyPath?: string };

  constructor(options: GatewayOptions = {}) {
    const args = options.args ?? ["-m", "fivedrisk", "gateway", "stdio"];
    const fullArgs = options.policyPath ? [...args, "--policy", options.policyPath] : args;
    this.opts = {
      command: options.command ?? "python",
      args: fullArgs,
      startupTimeoutMs: options.startupTimeoutMs ?? 10_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 5_000,
      hasApprovalChannel: options.hasApprovalChannel ?? false,
      policyPath: options.policyPath,
    };
    this.ready = this.start();
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
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(trimmed) as Record<string, unknown>;
        } catch {
          return; // ignore non-JSON noise on stdout
        }
        if (!handshakeSeen && msg.ready === true) {
          handshakeSeen = true;
          clearTimeout(startupTimer);
          // Reject a present-but-wrong protocol version of ANY type (a non-numeric
          // "999" must not slip past the guard — QA-M4 F1).
          if (msg.protocol_version !== undefined && msg.protocol_version !== EXPECTED_PROTOCOL_VERSION) {
            reject(new Error(
              `5D gateway protocol ${String(msg.protocol_version)} != expected ${EXPECTED_PROTOCOL_VERSION}`,
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
    if (typeof msg.error === "string") {
      return { band: "RED", sentinel: "block", blocked: true, reason: msg.error, error: msg.error };
    }
    const band = typeof msg.band === "string" ? msg.band : "RED";
    const sentinel = bandToSentinel(band);
    return {
      band,
      sentinel,
      blocked: sentinelBlocks(sentinel, { hasApprovalChannel: this.opts.hasApprovalChannel }),
      reason: typeof msg.rationale === "string" ? msg.rationale : "",
      decisionId: typeof msg.decision_id === "string" ? msg.decision_id : undefined,
      scores: (msg.scores as Record<string, number> | undefined) ?? undefined,
      compositeScore: typeof msg.composite_score === "number" ? msg.composite_score : undefined,
      auditLogId: typeof msg.audit_log_id === "number" ? msg.audit_log_id : undefined,
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

  /** Score one tool call. Resolves to a verdict; never rejects (fails closed). */
  async score(req: ScoreRequest): Promise<FivedriskVerdict> {
    if (this.closed) return this.failClosed("5D gateway is closed");
    try {
      await this.ready;
    } catch (err) {
      return this.failClosed("5D gateway failed to start: " + (err as Error).message);
    }
    const proc = this.proc;
    if (!proc || !proc.stdin.writable) return this.failClosed("5D gateway stdin not writable");

    const id = String(++this.seq);
    const payload: Record<string, unknown> = { id, tool_name: req.toolName, params: req.toolInput ?? {} };
    if (req.autonomy !== undefined) payload.autonomy = req.autonomy;
    if (req.sessionId !== undefined) payload.session_id = req.sessionId;
    if (req.source !== undefined) payload.source = req.source;

    return new Promise<FivedriskVerdict>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(this.failClosed(`5D gateway timed out after ${this.opts.requestTimeoutMs}ms`));
      }, this.opts.requestTimeoutMs);
      this.pending.set(id, { resolve, timer, req });
      proc.stdin.write(JSON.stringify(payload) + "\n", (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          resolve(this.failClosed("5D gateway write failed: " + err.message));
        }
      });
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
