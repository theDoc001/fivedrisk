/**
 * Firebase Genkit integration — gate a tool's handler through 5D.
 *
 * A Genkit tool is `ai.defineTool({ name, ... }, async (input) => result)`.
 * `guardGenkitTool` wraps that async handler: it scores the input through the
 * gateway first and, on a block, throws `FivedriskBlockedError` so the tool does
 * not run. GREEN/YELLOW call the real handler. Structural typing keeps this
 * typecheckable without Genkit installed.
 */

import type { FivedriskGateway } from "./gateway.js";
import { FivedriskBlockedError, type GuardOptions } from "./vercel.js";

export type GenkitToolHandler<I = unknown, O = unknown> = (input: I) => Promise<O>;

/**
 * Wrap a Genkit tool handler so every invocation is scored by 5D before it runs.
 * Pass the wrapped handler as the second argument to `ai.defineTool`.
 */
export function guardGenkitTool<I, O>(
  gateway: FivedriskGateway,
  toolName: string,
  handler: GenkitToolHandler<I, O>,
  opts: GuardOptions = {},
): GenkitToolHandler<I, O> {
  return async (input: I): Promise<O> => {
    const verdict = await gateway.score({
      toolName,
      toolInput: input,
      autonomy: opts.autonomy,
      sessionId: opts.sessionId,
      source: "genkit",
    });
    if (verdict.blocked) {
      throw new FivedriskBlockedError(toolName, verdict.band, verdict.reason);
    }
    return handler(input);
  };
}
