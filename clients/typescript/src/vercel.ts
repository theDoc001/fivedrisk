/**
 * Vercel AI SDK integration — gate a tool's execution through 5D.
 *
 * The AI SDK runs a tool via its `execute(args, options)` method. `guardVercelTool`
 * wraps that method: it scores the pending call through the gateway first and, on a
 * block (RED, or ORANGE without an approval channel), throws `FivedriskBlockedError`
 * so the tool visibly does NOT run — never a fake success. GREEN/YELLOW pass through
 * to the real `execute`. Structural typing (no `import from "ai"`) keeps this
 * typecheckable without the SDK installed; it matches the AI SDK tool shape.
 */

import type { FivedriskGateway } from "./gateway.js";

export class FivedriskBlockedError extends Error {
  readonly band: string;
  readonly toolName: string;
  constructor(toolName: string, band: string, reason: string) {
    super(`blocked by 5D (${band}): ${reason}`);
    this.name = "FivedriskBlockedError";
    this.toolName = toolName;
    this.band = band;
  }
}

/** Minimal structural view of a Vercel AI SDK tool (only what we wrap). */
export interface VercelToolLike {
  execute?: (args: unknown, options: unknown) => Promise<unknown>;
  [key: string]: unknown;
}

export interface GuardOptions {
  autonomy?: number;
  sessionId?: string;
}

/**
 * Wrap a Vercel AI SDK tool so every invocation is scored by 5D before it runs.
 * Returns a new tool object; the original is not mutated.
 */
export function guardVercelTool<T extends VercelToolLike>(
  gateway: FivedriskGateway,
  toolName: string,
  tool: T,
  opts: GuardOptions = {},
): T {
  const original = tool.execute;
  if (typeof original !== "function") return tool; // nothing to gate
  const guarded: VercelToolLike = {
    ...tool,
    execute: async (args: unknown, options: unknown): Promise<unknown> => {
      const verdict = await gateway.score({
        toolName,
        toolInput: args,
        autonomy: opts.autonomy,
        sessionId: opts.sessionId,
        source: "vercel-ai-sdk",
      });
      if (verdict.blocked) {
        throw new FivedriskBlockedError(toolName, verdict.band, verdict.reason);
      }
      return original(args, options);
    },
  };
  return guarded as T;
}
