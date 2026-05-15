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
        default=0.20,
        help="Allowed p99 regression as a fraction (default 0.20 = 20%%)",
    )
    args = parser.parse_args()

    with open(args.current) as f:
        current = json.load(f)
    with open(args.baseline) as f:
        baseline = json.load(f)

    regressions = []
    new_scenarios = []
    for name, cur in current["scenarios"].items():
        base = baseline["scenarios"].get(name)
        if base is None:
            new_scenarios.append(name)
            continue
        ratio = cur["p99_us"] / max(base["p99_us"], 1.0)
        if ratio - 1.0 > args.threshold:
            regressions.append((name, base["p99_us"], cur["p99_us"], ratio - 1.0))

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
