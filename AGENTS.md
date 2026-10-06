---
tags: [status/active, type/instructions, scope/repository]
---
# Agent instructions

These instructions apply to the entire repository.

Local editing, commits, builds, and tests may run at any time.

Before a publication task, verify `git config --get core.hooksPath` prints exactly
`.githooks`. On a fresh clone, run
`python3 -I tools/install_release_controls.py`, then
`python3 -I tools/install_release_controls.py --check`. The tracked hook is a required
local control, not an optional convenience.

Before every external mutation, run `python3 -I tools/release_window.py --action <action>`
from the repository root and proceed only when it exits 0. Use one of the action names
accepted by the command. External mutations include:

- pushing any branch or tag;
- creating, editing, or publishing a GitHub release;
- uploading a package to any registry;
- submitting or updating a plugin, skill, or marketplace listing;
- changing remote repository rules or release settings; and
- dispatching a workflow that can perform any of those actions.

The permitted window is 19:00 inclusive through 07:00 exclusive in
`Europe/Tirane`. Do not calculate the window independently, override the timezone,
bypass Git hooks, use `--no-verify`, substitute another publication path, or continue
when the gate, clock, or timezone data is unavailable. Re-run the gate immediately
before each external mutation.

An open window permits timing only. It does not replace release approval, required
tests, repository protections, or other release checks. Fail closed when any required
check is missing or disagrees. The repository rulesets described in
`docs/release-controls.md` are mandatory for the protected branch and release tags.
