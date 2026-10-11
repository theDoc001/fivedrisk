"""Aggregate isolated benchmark summaries for a paired CI comparison."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def aggregate(paths: list[Path], *, subject: str) -> dict:
    if len(paths) < 2:
        raise ValueError("at least two benchmark results are required")
    if any(not path.name.startswith(f"{subject}-") for path in paths):
        raise ValueError(f"input subject mismatch: expected only {subject!r} results")
    results = [_load(path) for path in paths]
    run_counts = [result.get("runs", 1) for result in results]
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count <= 0
        for count in run_counts
    ):
        raise ValueError("benchmark run counts must be positive integers")
    first = results[0]
    environment = first.get("env")
    if not isinstance(environment, dict):
        raise ValueError(f"{paths[0]}: missing benchmark environment")
    if any(result.get("env") != environment for result in results[1:]):
        raise ValueError("benchmark environment mismatch between inputs")

    scenarios = first.get("scenarios")
    if not isinstance(scenarios, dict) or not scenarios:
        raise ValueError(f"{paths[0]}: missing benchmark scenarios")
    scenario_names = set(scenarios)
    if any(set(result.get("scenarios", {})) != scenario_names for result in results[1:]):
        raise ValueError("benchmark scenario mismatch between inputs")

    merged: dict[str, dict] = {}
    for name in sorted(scenario_names):
        measurements = [result["scenarios"][name] for result in results]
        keys = set(measurements[0])
        if any(set(measurement) != keys for measurement in measurements[1:]):
            raise ValueError(f"benchmark metric mismatch for scenario {name!r}")
        merged[name] = {}
        for key in sorted(keys):
            values = [measurement[key] for measurement in measurements]
            numeric = all(
                isinstance(value, (int, float)) and not isinstance(value, bool)
                for value in values
            )
            if numeric:
                if not all(math.isfinite(value) for value in values):
                    raise ValueError(
                        f"benchmark metric must be finite for {name!r}.{key}"
                    )
                merged[name][key] = round(statistics.median(values), 3)
            elif len(set(values)) == 1:
                merged[name][key] = values[0]
            else:
                raise ValueError(
                    f"non-numeric benchmark metric mismatch for {name!r}.{key}"
                )

    return {
        "env": environment,
        "runs": sum(run_counts),
        "sources": sorted(path.name for path in paths),
        "subject": subject,
        "scenarios": merged,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate benchmark JSON summaries with strict compatibility checks"
    )
    parser.add_argument("--subject", required=True, choices=("base", "candidate"))
    parser.add_argument("results", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        result = aggregate(args.results, subject=args.subject)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
