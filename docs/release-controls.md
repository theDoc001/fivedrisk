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
3. External mutations run only inside the configured publication window.
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
- Managed rulesets: `main` cannot be deleted or force-pushed, and `v*` tags cannot be
  moved or deleted once created. Apply them during an open window:

```bash
python3 -I tools/release_window.py --action ruleset-update
python3 -I tools/repository_rulesets.py --apply --repository theDoc001/fivedrisk
python3 -I tools/repository_rulesets.py --check --repository theDoc001/fivedrisk
```

## Continuous integration

`tests.yml` runs the Python suite (3.10 and 3.12) and the TypeScript release suite on
every push to `main` and every pull request. `bench.yml` runs the paired benchmark only
when scored code, benchmarks, or `pyproject.toml` change.

## Releasing

1. Bump `version` in `pyproject.toml`, the three plugin manifests, the skill's
   `metadata.version`, and the TypeScript client, add a CHANGELOG entry, and push to
   `main`. Wait for green CI.
2. The owner approves the release in writing.
3. Create and push an annotated tag on that commit during an open window:

```bash
git tag -a v0.7.2 -m "fivedrisk 0.7.2"
git push origin v0.7.2
```

4. **Publish release** starts from the tag. The owner approves the `release`
   environment. The workflow checks the window, confirms the tag matches
   `pyproject.toml` and sits on `main`, runs both release suites, builds the wheel, the
   sdist, `fivedrisk-plugin-public-<version>.zip` (hooks-free) and
   `fivedrisk-plugin-manual-<version>.zip` (local hook integration), writes
   `SHA256SUMS`, attests provenance, then publishes PyPI and the GitHub release. A
   matching partial release resumes; any wrong digest, tag, or asset stops without
   overwriting or deleting anything.
5. Read back PyPI, the tag, and the release assets.

Plugin portal submissions (OpenAI directory, skills.sh, Tessl) stay manual. Never
upload the manual ZIP or the source directory to a public plugin portal.

The workflow records checksums and provenance for that exact build. It does not claim
bit-for-bit environment reproducibility: Python dependency ranges resolve when the job
runs, while external GitHub Actions are pinned to reviewed full commit SHAs.
