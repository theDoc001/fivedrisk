# Benchmarks

Reproducible performance measurement for fivedrisk.

## Scripts

**`bench_minimal.py`** — short, human-readable. Run anywhere with `python benchmarks/bench_minimal.py`. Reports p50 / p95 / p99 across the core scenarios. Used to publish the numbers in the README.

**`bench_ci.py`** — full scenario set including async paths, cold-start, deeper sample counts. Outputs JSON for CI artifact capture (`--json`) or human-readable to stdout (no flag). Used by GitHub Actions to detect regressions on every PR.

**`bench_aiid_patterns.py`** — local AIID-style incident-pattern smoke. Compares default 5D, a targeted deployment profile, and optionally a local Ollama observer (`--observer ollama:gemma3:1b`). This is for calibration and Workbench evidence, not a replacement for the deterministic CI benchmark.

The attack-class benchmark is an expectation-match harness. A passing run means the configured scenarios observed their expected outcomes. It is useful for regression control and audit evidence, but it is not statistical proof of real-world attack coverage. Use targeted profiles, unseen scenarios, and observer/HITL comparison runs before making deployment claims.

## Regression detection

On every PR, CI measures the frozen base and candidate commits on the same `macos-latest` runner with Python 3.14.6. Each commit is built as a wheel, installed non-editably into a separate environment, and run in balanced base/candidate/candidate/base order. The two three-run summaries per commit are aggregated into an effective six-run comparison. Any scenario where candidate p99 crosses both the **30%** relative and **25µs** absolute limits fails the workflow. Environment, dependency, workload, or scenario mismatches fail closed, and the workflow uploads the raw and aggregated evidence.

`benchmarks/baselines/main.json` is retained as a historical reference; it is not the PR merge gate. Replace it only from a separately approved, provenance-recorded run of the exact protected-main commit on the declared runner. Never derive it from candidate measurements or use a baseline refresh to waive a failing paired comparison.

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
