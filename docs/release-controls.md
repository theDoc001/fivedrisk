# Release controls

External mutations are permitted all day on Saturday and Sunday in `Europe/Tirane`.
Monday through Friday they are permitted only from 19:00 inclusive through 07:00
exclusive. Local edits, tests, builds, and commits can happen at any time.

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
on the default branch, and make `v*` tags immutable after creation. The on-demand
publisher binds the merged default-branch commit to the independently cleared
candidate commit and tree, builds one source-bound, normalized artifact set, includes both
`fivedrisk-plugin-public-0.7.1.zip` (hooks-free advisory directory candidate) and
`fivedrisk-plugin-manual-0.7.1.zip` (reviewed Claude-specific local integration), emits a
root-relative `SHA256SUMS`, creates GitHub build provenance attestations, and reconciles
PyPI, an annotated tag, and the GitHub release in order. A matching partial release
resumes; any wrong digest, SHA, tag form, asset, ordering, or unverifiable remote
response stops without overwriting or deleting data. OpenAI directory review and
publication remain a separate human portal step; the workflow does not impersonate it.
The checksum and remote-state checks require both exact versioned ZIP names, the wheel,
and the source distribution. Hook-containing ZIPs are not directory eligible. The
public ZIP must be built with `--variant public --git-ref <cleared-commit>`; do not upload
the manual ZIP or the complete source directory to a public plugin portal.

The workflow records checksums and provenance for that exact build. It does not claim
bit-for-bit environment reproducibility: Python dependency ranges are resolved when the
job runs, while external GitHub Actions are pinned to reviewed full commit SHAs.

Publication is on demand only. The workflow has no schedule or cron trigger and must
remain disabled unless an approved release is ready. During an open publication
window, the repository owner may enable it and explicitly dispatch it from `main`
with the full approved candidate commit SHA. The workflow accepts only the repository
owner as both actor and triggering actor, requires the supplied SHA to match the
release and QA bindings, and rechecks the release window before work begins and before
each external mutation. Enabling the manual-only workflow schedules nothing. After a
release converges, disable the workflow again. A dispatch does not replace fresh QA,
explicit human approval, or the exact candidate SHA and tree bindings.

GitHub rulesets cannot prevent an already-authorized credential from pushing an
ordinary non-protected branch. The pre-push hook prevents that for conforming agents.
For a cryptographically non-bypassable all-branch time boundary, do not issue raw push
or publication credentials to agents; place those credentials behind a server-side
publisher that runs this gate. Do not claim stronger enforcement while agents retain
raw credentials.
