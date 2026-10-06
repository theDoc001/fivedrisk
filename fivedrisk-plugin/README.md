# fivedrisk - 5D Risk Governance Plugin

Per-action risk governance for AI agents. Scores every tool call on 5 dimensions
(Data, Tool, Reversibility, External, Autonomy), assigns a **GREEN / YELLOW /
ORANGE / RED** band, and gates execution: GREEN/YELLOW execute, ORANGE routes to
Claude's native approval prompt, RED is denied. A PostToolUse hook also scans tool output for
leakage. Every decision is logged to a local SQLite audit trail.

The plugin manifest version follows the bundled package/repository release. The
setup skill has its own independently managed artifact version.

The setup skill starts as a 5D deployment consultant. It can derive a reviewable
deployment profile from either a redacted agent system prompt or a description of the
agent's goals and likely actions, then compare deterministic-only governance with general
observer-LLM and TypeSafe Jev designs. The profile is not runtime configuration, and no
observer runtime is bundled.

This directory is a portable Agent Plugin with one auto-discovered setup skill. Codex and
other compatible hosts can use the skill for deployment consultation, configuration,
verification, and recovery. Skill execution is advisory and does not intercept tool calls.

The same directory is also a Claude Code plugin. Only Claude Code loads the bundled
`PreToolUse` and `PostToolUse` hooks, so only that host integration can gate tool calls
directly. Other agents must wire one of the supported runtime adapters before claiming
enforcement.

The root `plugin.json` is the portable manifest. `.codex-plugin/plugin.json` is its
schema-specific Codex compatibility projection with presentation metadata, and
`.claude-plugin/plugin.json` owns Claude-specific hook metadata. The plugin intentionally
ships one skill: `fivedrisk-setup`.

## Load this local plugin

This repository does not yet publish a Claude marketplace entry. Clone or unpack
the repository, review the plugin, then start Claude Code with the official local
development form:

```bash
PLUGIN_ROOT=/absolute/path/to/fivedrisk-plugin
export FIVEDRISK_PYTHON=/absolute/path/to/.venv/bin/python
PYTHON_BIN="$FIVEDRISK_PYTHON" bash "$PLUGIN_ROOT/skills/fivedrisk-setup/scripts/verify-install.sh"
claude --plugin-dir "$PLUGIN_ROOT"
```

Claude supplies `$CLAUDE_PLUGIN_ROOT` while an installed or locally loaded plugin
hook is running; users do not export it. Use the explicit `PLUGIN_ROOT` variable
for manual verification before startup.

The launcher rejects a missing, relative, mismatched, or unsupported interpreter
with blocking exit code 2. It never falls back to `python`, `python3`, or PATH.
The outer hook command itself uses Python isolated mode before the launcher imports
standard-library modules. The launcher then starts the installed package in isolated mode through a bootstrap that
verifies the distribution location and stable version `>=0.7.1,<0.8.0`, preventing a
working-directory or `PYTHONPATH` package from shadowing the verified installation.
It also validates and canonicalizes the child command's structured hook result;
empty, malformed, wrong-event, incomplete, or ambiguous output blocks with exit 2.

## How it works

The plugin uses the all-tool matcher for both PreToolUse and PostToolUse, including
built-in, task, notebook, and MCP tools. PreToolUse gates before execution;
PostToolUse can stop further processing after a result but cannot undo a completed tool.
Each action is scored across 5 risk dimensions:

1. **Data Sensitivity** (0-4)
2. **Tool Privilege** (0-4)
3. **Reversibility** (0-4)
4. **External Impact** (0-4)
5. **Autonomy Context** (0-4)

Default dispositions:
- **GREEN / YELLOW** — execute and log (YELLOW is opt-in and logs more detail)
- **ORANGE** — emit Claude's structured `ask` decision for human approval
- **RED** — deny

These are the plugin's shipped mappings. The band itself is the audit-stable
severity label; other integrations may map a band to a different disposition.

## Configuration

The bundled `policy.yaml` is a starter template; the hook does not load it
automatically. Copy it to an operator-owned path, validate that copy, and add
its absolute path as `FIVEDRISK_POLICY_PATH`. The fail-closed launcher passes it
to the PreToolUse score command. Do not edit the bundled template in place.

## License

Apache-2.0 — Authored by Loren, March 2026.
