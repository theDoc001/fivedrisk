# Release controls

External mutations are permitted only from 19:00 inclusive through 07:00 exclusive
in `Europe/Tirane`. Local edits, tests, builds, and commits can happen at any time.

On every fresh clone, activate and verify the tracked pre-push hook:

```bash
python3 -I tools/install_release_controls.py
python3 -I tools/install_release_controls.py --check
```

The hook and every release workflow call the same fail-closed timezone gate with
isolated Python. A missing clock, timezone database, hook, or gate is a denial. Agents
must follow the repository-root `AGENTS.md`; they may not use `--no-verify`, calculate
the window independently, or substitute another publication route.

The repository owner must also apply the managed server rulesets during an open window:

```bash
python3 -I tools/release_window.py --action ruleset-update
python3 -I tools/repository_rulesets.py --apply --repository theDoc001/fivedrisk
python3 -I tools/repository_rulesets.py --check --repository theDoc001/fivedrisk
```

These rules require pull requests and the release-window, Python, and TypeScript checks
on the default branch, and make `v*` tags immutable after creation. The scheduled
publisher binds the merged default-branch commit to the independently cleared
candidate tree, builds one reproducible artifact set, includes a versioned portable
plugin ZIP, emits a
root-relative `SHA256SUMS`, creates GitHub build provenance attestations, and reconciles
PyPI, an annotated tag, and the GitHub release in order. A matching partial release
resumes; any wrong digest, SHA, tag form, asset, ordering, or unverifiable remote
response stops without overwriting or deleting data. OpenAI directory review and
publication remain a separate human portal step; the workflow does not impersonate it.

Publication has no manual workflow trigger. Two UTC schedules cover the Europe/Tirane
DST variants; one becomes the active 19:05 local slot and the other exits without
building or mutating. After a release converges, retire its schedules in a separate
gated cleanup pull request before any later change reaches the default branch.

GitHub rulesets cannot prevent an already-authorized credential from pushing an
ordinary non-protected branch. The pre-push hook prevents that for conforming agents.
For a cryptographically non-bypassable all-branch time boundary, do not issue raw push
or publication credentials to agents; place those credentials behind a server-side
publisher that runs this gate. Do not claim stronger enforcement while agents retain
raw credentials.
