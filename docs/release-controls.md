# Release controls

This file is the single source for how fivedrisk is published. It applies to the
entire repository, to people and to agents.

## Rules

1. Local editing, commits, builds, and tests may run at any time.
2. External mutations need explicit written approval from the repository owner for
   that specific action. External mutations are: pushing any branch or tag; creating,
   editing, or publishing a GitHub release; uploading a package to any registry;
   submitting or updating a plugin, skill, or marketplace listing; changing remote
   repository rules or release settings; and dispatching a workflow that can do any
   of these.
3. External mutations are blocked Monday through Friday from 07:00 inclusive to 19:00
   exclusive in `Europe/Tirane`. Saturday and Sunday are open all day. Monday through
   Friday the window is open from 19:00 inclusive through 07:00 exclusive.
4. Check the window with `python3 -I tools/release_window.py --action <action>` and
   proceed only on exit 0. Do not calculate the window yourself, override the
   timezone, use `--no-verify`, or bypass Git hooks. A missing clock, timezone
   database, hook, or gate is a denial.
5. Publication is on demand only. Never add a scheduled publisher, cron trigger, or
   recurring automation capable of publishing.

An open window permits timing only. It does not replace approval, tests, or
repository protections.

## Setup on a fresh clone

```bash
python3 -I tools/install_release_controls.py
python3 -I tools/install_release_controls.py --check
```

Before a publication task, `git config --get core.hooksPath` must print `.githooks`.

## Repository settings (owner, once)

- PyPI trusted publisher: owner `theDoc001`, repository `fivedrisk`, workflow
  `publish.yml`, environment `release`.
- GitHub environment `release` with the owner as required reviewer, so every publish
  run waits for an explicit approval click.
- Managed rulesets, applied during an open window:

```bash
python3 -I tools/release_window.py --action ruleset-update
python3 -I tools/repository_rulesets.py --apply --repository theDoc001/fivedrisk
python3 -I tools/repository_rulesets.py --check --repository theDoc001/fivedrisk
```

These require pull requests and the release-window, Python, and TypeScript checks on
the default branch, and make `v*` tags immutable after creation.

## Releasing

1. Bump `version` in `pyproject.toml` and both plugin manifests, merge to `main`
   through a pull request with green checks.
2. The owner approves the release in writing.
3. During an open window, the owner runs **Publish release** from `main` with the
   full `main` commit SHA as `candidate_sha`, then approves the `release` environment.
4. The workflow checks the window once, binds the run to that exact commit, runs the
   Python and TypeScript release suites, builds the wheel, the sdist,
   `fivedrisk-plugin-public-<version>.zip` (hooks-free, directory candidate) and
   `fivedrisk-plugin-manual-<version>.zip` (local hook integration), writes
   `SHA256SUMS`, attests provenance, then publishes PyPI, the annotated tag, and the
   GitHub release in that order. A matching partial release resumes; any wrong
   digest, SHA, tag, or asset stops without overwriting or deleting anything.
5. Read back PyPI, the tag, and the release assets.

Plugin portal submissions (OpenAI directory, skills.sh, Tessl) stay manual. Never
upload the manual ZIP or the source directory to a public plugin portal.

The workflow records checksums and provenance for that exact build. It does not claim
bit-for-bit environment reproducibility: Python dependency ranges resolve when the job
runs, while external GitHub Actions are pinned to reviewed full commit SHAs.

GitHub rulesets cannot stop an already-authorized credential from pushing an ordinary
branch. The pre-push hook stops that for conforming agents. For a hard boundary, do not
give agents raw push or publication credentials.
