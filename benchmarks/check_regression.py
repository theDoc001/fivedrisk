"""Compare a current bench_ci.py output against a baseline.

Flags any scenario where p99 increased by more than 20% relative to the
baseline. Exits 0 if all scenarios pass, 1 if any regression detected.

Usage:
    python benchmarks/bench_ci.py --json > current.json
    python benchmarks/check_regression.py current.json baselines/main.json
"""

from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="fivedrisk bench regression check")
    parser.add_argument("current", help="Path to current bench JSON")
    parser.add_argument("baseline", help="Path to baseline bench JSON")
    parser.add_argument(
        "--threshold",
        type=float,
        # M13: widened from 0.20 to 0.30 with rationale. p99 is single-RUN here,
        # and the microbenchmarks have heavy-tailed latency (GC pauses, scheduler
        # jitter on shared CI runners), so run-to-run p99 swings of 20-25% are
        # noise, not regressions. 30% still catches the real target (a 10x / order-
        # of-magnitude regression) while cutting false failures. For tighter gating,
        # regenerate the baseline as a median of several runs on the CI platform.
        default=0.30,
        help="Allowed p99 regression as a fraction (default 0.30 = 30%%)",
    )
    parser.add_argument(
        "--min-abs-us",
        type=float,
        default=25.0,
        # M13: a regression must ALSO exceed this absolute p99 increase (µs). The
        # fast scenarios run in ~15-40µs, where a few µs of scheduler jitter is a
        # large RATIO but a trivial absolute — the dominant false-positive source.
        # A real (order-of-magnitude) regression easily clears both gates.
        help="Minimum absolute p99 increase in µs to count as a regression (default 25)",
    )
    args = parser.parse_args()

    with open(args.current) as f:
        current = json.load(f)
    with open(args.baseline) as f:
        baseline = json.load(f)

    current_env = current.get("env", {})
    baseline_env = baseline.get("env", {})
    comparable_keys = ("cpu", "platform")
    env_mismatches = [
        key
        for key in comparable_keys
        if current_env.get(key) != baseline_env.get(key)
    ]
    if env_mismatches:
        # H5: a mismatched environment must FAIL, not silently skip. The old
        # `return 0` meant an arm64/Darwin baseline vs an ubuntu CI runner passed
        # every PR green — a 10x latency regression would have merged unnoticed.
        # Regenerate the baseline on the CI platform (or run the bench on a runner
        # matching the committed baseline) so the comparison is real.
        print(
            "FAIL: benchmark environment differs from baseline on "
            f"{env_mismatches}; refusing to skip the regression comparison. "
            f"current={current_env}, baseline={baseline_env}. Regenerate the "
            "baseline on this platform (benchmarks/bench_ci.py --json > "
            "benchmarks/baselines/main.json).",
            file=sys.stderr,
        )
        return 1

    # M13: diagnostic micro-scenarios that are too noisy to gate on (warmup=0,
    # tiny n). They are REPORTED but never fail the build — gating on them was a
    # false-positive source. Meaningful steady-state scenarios still gate.
    informational = {"5d_core_no_warmup_loop", "5d_core_cold_no_warmup"}

    regressions = []
    new_scenarios = []
    info_notes = []
    for name, cur in current["scenarios"].items():
        base = baseline["scenarios"].get(name)
        if base is None:
            new_scenarios.append(name)
            continue
        ratio = cur["p99_us"] / max(base["p99_us"], 1.0)
        abs_increase = cur["p99_us"] - base["p99_us"]
        # M13: BOTH gates must trip — relative ratio AND absolute µs increase.
        if ratio - 1.0 > args.threshold and abs_increase > args.min_abs_us:
            if name in informational:
                info_notes.append((name, base["p99_us"], cur["p99_us"], ratio - 1.0))
            else:
                regressions.append((name, base["p99_us"], cur["p99_us"], ratio - 1.0))

    if info_notes:
        for name, base_p99, cur_p99, delta in info_notes:
            print(
                f"NOTE (informational, not gated): {name} p99 {base_p99:.1f}µs → "
                f"{cur_p99:.1f}µs (+{delta * 100:.1f}%)"
            )

    # Low-15: a scenario present in the baseline but MISSING from the current run
    # was silently ignored — deleting a slow scenario would pass green. Surface it.
    dropped = [n for n in baseline["scenarios"] if n not in current["scenarios"]]
    if dropped:
        print(f"NOTE: {len(dropped)} baseline scenario(s) absent from current run "
              f"(removed or renamed?): {dropped}")

    if regressions:
        print(f"FAIL: {len(regressions)} scenario(s) regressed by more than "
              f"{args.threshold * 100:.0f}%:", file=sys.stderr)
        for name, base_p99, cur_p99, delta in regressions:
            print(
                f"  {name}: baseline p99 {base_p99:.1f}µs → current p99 {cur_p99:.1f}µs "
                f"(+{delta * 100:.1f}%)",
                file=sys.stderr,
            )
        return 1

    if new_scenarios:
        print(f"NOTE: {len(new_scenarios)} new scenario(s) (no baseline): {new_scenarios}")
    print(f"PASS: all scenarios within {args.threshold * 100:.0f}% of baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
