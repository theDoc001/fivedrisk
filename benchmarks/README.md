# Benchmarks

Reproducible performance measurement for fivedrisk.

## Two scripts

**`bench_minimal.py`** — short, human-readable. Run anywhere with `python benchmarks/bench_minimal.py`. Reports p50 / p95 / p99 across the core scenarios. Used to publish the numbers in the README.

**`bench_ci.py`** — full scenario set including async paths, cold-start, deeper sample counts. Outputs JSON for CI artifact capture (`--json`) or human-readable to stdout (no flag). Used by GitHub Actions to detect regressions on every PR.

## Regression detection

CI runs `bench_ci.py --json > bench_current.json` on every PR and compares against `benchmarks/baselines/main.json`. Any scenario where p99 increased by more than 20% relative to the baseline fails the workflow.

To establish or refresh the baseline:

1. Push to main and wait for the bench workflow to complete.
2. Download the `bench-results-<run_id>` artifact.
3. Copy the JSON to `benchmarks/baselines/main.json` and commit.

The threshold is tunable via `python benchmarks/check_regression.py current.json baseline.json --threshold 0.15` (for stricter 15% rule, etc).

## What is measured

- 5D core (classify + score)
- 5D core cold start (no warmup)
- Injection scanner at short, medium, and long input
- Leakage scanner at short and long output
- Full per-action path (scan + classify + score + scan)
- 5D + Markov drift update
- 5D + SQLite audit-log write
- `@gate` decorator overhead (sync)
- `@gate` decorator overhead (async)

All scenarios run in-process, single-thread, no external API calls. Deterministic.
