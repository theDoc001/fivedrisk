# Manual host integration — not a public-directory artifact

This guide, the Claude manifest, hook configuration, launcher, and starter policy are
included only in `fivedrisk-plugin-manual-0.7.1.zip` (and the source checkout). Any ZIP
containing lifecycle hooks is not eligible for the public plugin directory. The
`fivedrisk-plugin-public-0.7.1.zip` skill is advisory and contains none of those files.

Manually installed Codex desktop plugins support their own lifecycle hooks when
available, but this release's reviewed launcher and payload protocol are Claude-specific.
They are not a Codex hook implementation. Do not copy the Claude hook configuration into
Codex; a separately implemented and verified Codex adapter would be required.

## Load this local Claude Code plugin

Review the manual ZIP or source directory, then select the project's verified
interpreter. This repository does not claim a published Claude marketplace entry.

```bash
PLUGIN_ROOT=/absolute/path/to/fivedrisk-plugin
export FIVEDRISK_PYTHON=/absolute/path/to/.venv/bin/python
export FIVEDRISK_SURFACE=sdk-hook
export FIVEDRISK_AUDIT_PATH=/absolute/path/to/fivedrisk-decisions.db
PYTHON_BIN="$FIVEDRISK_PYTHON" FIVEDRISK_SURFACE="$FIVEDRISK_SURFACE" \
  bash "$PLUGIN_ROOT/skills/fivedrisk-setup/scripts/verify-install.sh"
claude --plugin-dir "$PLUGIN_ROOT"
```

Claude supplies `$CLAUDE_PLUGIN_ROOT` while the plugin hook runs; users do not export it.
Use `PLUGIN_ROOT` for manual verification before startup. Export the same verified
absolute interpreter as `FIVEDRISK_PYTHON` before activation. The launcher blocks with
exit 2 when it is missing, relative, mismatched, or outside stable `>=0.7.1,<0.8.0`.
It never falls back to `python`, `python3`, or PATH.
`FIVEDRISK_AUDIT_PATH` must be an absolute path with a writable parent directory;
the launcher blocks when it is absent or invalid. This reviewed hook command requires
a POSIX shell. Native Windows without WSL is not supported in 0.7.1.

The outer hook uses isolated Python before importing standard-library modules. The
launcher then runs the installed package through an isolated bootstrap that checks
distribution provenance and the supported version. A cwd or `PYTHONPATH` shadow cannot
substitute for the verified installation. Empty, malformed, wrong-event, incomplete,
or ambiguous child output blocks with exit 2.

## How the Claude integration works

The all-tool matcher covers PreToolUse and PostToolUse, including built-in, task,
notebook, and MCP tools. PreToolUse scores before execution: GREEN/YELLOW proceed,
ORANGE emits Claude's structured `ask` for human approval, and RED denies.
PostToolUse scans output for leakage; it can stop further processing but cannot undo
an action already completed. Decisions are logged to a local SQLite audit trail.

The five scored dimensions are data sensitivity, tool privilege, reversibility,
external impact, and autonomy context (each 0–4). The band is an audit-stable severity
label; other runtime adapters may map dispositions differently.

## Policy ownership

The bundled `policy.yaml` is a starter template; the hook does not load it
automatically. Copy it to an operator-owned path, validate the copy, and set the absolute
path as `FIVEDRISK_POLICY_PATH`. A missing or unreadable configured path blocks
PreToolUse. Do not edit the bundled template in place or lower a threshold to pass a test.

Follow the packaged setup skill for installation, provenance verification, policy
validation, and simulated/real adapter acceptance probes before activating a live agent.

## Claude Code (CLI hooks)

For an operator who chooses explicit settings instead of plugin loading, replace
`<SELECTED_PYTHON>` below with the verified absolute interpreter. Wire the two phases in
the operator-owned `.claude/settings.json`; do not enable duplicate integrations.

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "\"<SELECTED_PYTHON>\" -I -m fivedrisk._bootstrap --policy \"<POLICY_PATH>\" --log-path \"<AUDIT_PATH>\" claude-hook" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "\"<SELECTED_PYTHON>\" -I -m fivedrisk._bootstrap --policy \"<POLICY_PATH>\" --log-path \"<AUDIT_PATH>\" claude-hook" }] }]
  }
}
```

ORANGE maps to Claude Code's native `ask`; RED maps to `deny`. Configuration is not proof
of enforcement: verify the actual host blocks a simulated denied call before execution
and records the decision, using the same interpreter, policy, and entrypoint.

Official host references:

- [OpenAI manual lifecycle hook boundary](https://developers.openai.com/plugins/build/plugins)
- [Claude Code plugin documentation](https://code.claude.com/docs/en/plugins)
