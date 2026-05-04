# fivedrisk — 5D Risk Governance Plugin for Claude Code

Per-action risk governance for AI agents. Scores every tool call on 5 dimensions,
assigns a GO/ASK/STOP band, and gates execution.

## Install

```
/plugin install fivedrisk
```

## How it works

The plugin hooks into `PreToolUse` for Bash, Edit, Write, and WebFetch tool calls.
Each action is scored across 5 risk dimensions:

1. **Data Sensitivity** (0-4)
2. **Tool Privilege** (0-4)
3. **Reversibility** (0-4)
4. **External Impact** (0-4)
5. **Autonomy Context** (0-4)

Bands:
- **GO** — execute silently, log the score
- **ASK** — surface to human for approval
- **STOP** — refuse and explain

## Configuration

Override `policy.yaml` in the plugin root to customize thresholds and weights.

## License

Apache-2.0 — Authored by Loren, March 2026.
