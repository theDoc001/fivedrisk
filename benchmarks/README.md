# Benchmarks

Reproducible performance measurement for fivedrisk.

## Scripts

**`bench_minimal.py`** — short, human-readable. Run anywhere with `python benchmarks/bench_minimal.py`. Reports p50 / p95 / p99 across the core scenarios. Used to publish the numbers in the README.

**`bench_ci.py`** — full scenario set including async paths, cold-start, deeper sample counts. Outputs JSON for CI artifact capture (`--json`) or human-readable to stdout (no flag). Used by GitHub Actions to detect regressions on every PR.

**`bench_aiid_patterns.py`** — local AIID-style incident-pattern smoke. Compares default 5D, a targeted deployment profile, and optionally a local Ollama observer (`--observer ollama:gemma3:1b`). This is for calibration and Workbench evidence, not a replacement for the deterministic CI benchmark.

The attack-class benchmark is an expectation-match harness. A passing run means the configured scenarios observed their expected outcomes. It is useful for regression control and audit evidence, but it is not statistical proof of real-world attack coverage. Use targeted profiles, unseen scenarios, and observer/HITL comparison runs before making deployment claims.

## Regression detection

CI runs `bench_ci.py --json > bench_current.json` on every PR and compares against `benchmarks/baselines/main.json`. Any scenario where p99 increased by more than **30%** relative to a comparable baseline fails the workflow (30%, not 20%, because single-run p99 on shared CI runners is heavy-tailed — see the rationale in `check_regression.py`). The CI job runs on `macos-latest` (arm64/Darwin) to match the committed baseline. If CPU or platform still differs from the baseline, the checker now **fails** (it no longer silently skips) and prints both environments so the baseline gets regenerated on the right platform.

To establish or refresh the baseline:

1. Push to main and wait for the bench workflow to complete.
2. Download the `bench-results-<run_id>` artifact.
3. Copy the JSON to `benchmarks/baselines/main.json` and commit.

For strongest CI enforcement, refresh the baseline from the same runner class used by the benchmark workflow.

The threshold is tunable via `python benchmarks/check_regression.py current.json baseline.json --threshold 0.15` (for stricter 15% rule, etc).

## What is measured

- 5D core (classify + score)
- 5D core without a per-scenario warmup loop (not a process cold-start)
- Injection scanner at short, medium, and long input
- Leakage scanner at short and long output
- Full per-action path (scan + classify + score + scan)
- 5D + Markov drift update
- 5D + SQLite audit-log write
- `@gate` decorator overhead (sync)
- `@gate` decorator overhead (async)

All scenarios run in-process, single-thread, no external API calls. Deterministic.

`bench_aiid_patterns.py` can call a local observer when `--observer` is set. Without that flag it stays offline and deterministic.
