"""Aggregate a fixed balanced 12-pair benchmark experiment."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path


PAIR_RE = re.compile(
    r"^pair-(?P<pair>\d{2})-(?P<order>base-first|candidate-first)-"
    r"(?P<subject>base|candidate)\.json$"
)
ORDERS = ("base-first", "candidate-first")
SUBJECTS = ("base", "candidate")
THRESHOLD = 0.30
MIN_ABS_US = 25.0


@dataclass(frozen=True)
class Record:
    pair: int
    order: str
    subject: str
    path: Path
    value: dict


def _load_records(input_dir: Path) -> list[Record]:
    records: list[Record] = []
    for path in sorted(input_dir.glob("*.json")):
        match = PAIR_RE.fullmatch(path.name)
        if match is None:
            raise ValueError(f"unexpected benchmark result name: {path.name}")
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError(f"{path.name}: expected a JSON object")
        records.append(
            Record(
                pair=int(match.group("pair")),
                order=match.group("order"),
                subject=match.group("subject"),
                path=path,
                value=value,
            )
        )

    expected = {
        (pair, "base-first" if pair % 2 else "candidate-first", subject)
        for pair in range(1, 13)
        for subject in SUBJECTS
    }
    observed = {(record.pair, record.order, record.subject) for record in records}
    if observed != expected or len(records) != len(expected):
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ValueError(
            f"expected exactly 12 balanced adjacent pairs; missing={missing}, extra={extra}"
        )
    return records


def _validate(records: list[Record]) -> tuple[dict, tuple[str, ...], dict[str, tuple[str, ...]]]:
    first = records[0].value
    environment = first.get("env")
    scenarios = first.get("scenarios")
    if not isinstance(environment, dict) or not isinstance(scenarios, dict) or not scenarios:
        raise ValueError("benchmark results require non-empty env and scenarios objects")
    scenario_names = tuple(sorted(scenarios))
    metric_names = {
        scenario: tuple(sorted(scenarios[scenario])) for scenario in scenario_names
    }

    for record in records:
        value = record.value
        # bench_ci.py preserves its historical single-run schema and only adds
        # ``runs`` when more than one repetition is requested.  The workflow
        # invokes ``--runs 1``, so an omitted field is the canonical value 1.
        if value.get("runs", 1) != 1:
            raise ValueError(f"{record.path.name}: runs must be absent or the positive integer 1")
        if value.get("env") != environment:
            raise ValueError(f"{record.path.name}: benchmark environment mismatch")
        current_scenarios = value.get("scenarios")
        if not isinstance(current_scenarios, dict) or tuple(sorted(current_scenarios)) != scenario_names:
            raise ValueError(f"{record.path.name}: benchmark scenario mismatch")
        for scenario in scenario_names:
            metrics = current_scenarios[scenario]
            if not isinstance(metrics, dict) or tuple(sorted(metrics)) != metric_names[scenario]:
                raise ValueError(f"{record.path.name}: benchmark metric mismatch for {scenario}")
            for metric, measurement in metrics.items():
                if (
                    not isinstance(measurement, (int, float))
                    or isinstance(measurement, bool)
                    or not math.isfinite(measurement)
                ):
                    raise ValueError(
                        f"{record.path.name}: {scenario}.{metric} must be finite numeric data"
                    )
    return environment, scenario_names, metric_names


def _median(values: list[float]) -> float:
    return round(float(statistics.median(values)), 3)


def _mad(values: list[float]) -> float:
    center = statistics.median(values)
    return round(float(statistics.median(abs(value - center) for value in values)), 3)


def _summary(
    records: list[Record],
    environment: dict,
    scenario_names: tuple[str, ...],
    metric_names: dict[str, tuple[str, ...]],
    *,
    subject: str,
    order: str | None,
) -> dict:
    selected = [
        record for record in records
        if record.subject == subject and (order is None or record.order == order)
    ]
    return {
        "env": environment,
        "runs": len(selected),
        "subject": subject,
        "order": order or "overall",
        "scenarios": {
            scenario: {
                metric: _median(
                    [record.value["scenarios"][scenario][metric] for record in selected]
                )
                for metric in metric_names[scenario]
            }
            for scenario in scenario_names
        },
    }


def _breaches(base: float, candidate: float) -> bool:
    return candidate / max(base, 1.0) - 1.0 > THRESHOLD and candidate - base > MIN_ABS_US


def aggregate(input_dir: Path) -> tuple[dict[str, dict], dict]:
    records = _load_records(input_dir)
    environment, scenario_names, metric_names = _validate(records)
    summaries: dict[str, dict] = {}
    for label, order in (("overall", None), ("base-first", "base-first"), ("candidate-first", "candidate-first")):
        for subject in SUBJECTS:
            summaries[f"{label}-{subject}"] = _summary(
                records, environment, scenario_names, metric_names,
                subject=subject, order=order,
            )

    diagnostic_scenarios: dict[str, dict] = {}
    for scenario in scenario_names:
        strata: dict[str, dict] = {}
        for label in ("overall", *ORDERS):
            base = summaries[f"{label}-base"]["scenarios"][scenario]["p99_us"]
            candidate = summaries[f"{label}-candidate"]["scenarios"][scenario]["p99_us"]
            strata[label] = {
                "base_median_p99_us": base,
                "candidate_median_p99_us": candidate,
                "delta_fraction": round(candidate / max(base, 1.0) - 1.0, 6),
                "delta_us": round(candidate - base, 3),
                "breaches": _breaches(base, candidate),
            }
        decisions = [strata[label]["breaches"] for label in ("overall", *ORDERS)]
        classification = (
            "stable-regression" if all(decisions)
            else "pass" if not any(decisions)
            else "inconclusive"
        )
        raw = []
        for pair in range(1, 13):
            order = "base-first" if pair % 2 else "candidate-first"
            pair_records = {
                record.subject: record for record in records if record.pair == pair
            }
            base_value = pair_records["base"].value["scenarios"][scenario]["p99_us"]
            candidate_value = pair_records["candidate"].value["scenarios"][scenario]["p99_us"]
            raw.append(
                {
                    "pair": pair,
                    "order": order,
                    "base_p99_us": base_value,
                    "candidate_p99_us": candidate_value,
                    "delta_us": round(candidate_value - base_value, 3),
                }
            )
        dispersion = {}
        for label, order in (("overall", None), ("base-first", "base-first"), ("candidate-first", "candidate-first")):
            dispersion[label] = {
                subject: _mad(
                    [
                        record.value["scenarios"][scenario]["p99_us"]
                        for record in records
                        if record.subject == subject and (order is None or record.order == order)
                    ]
                )
                for subject in SUBJECTS
            }
        diagnostic_scenarios[scenario] = {
            "classification": classification,
            "strata": strata,
            "mad_p99_us": dispersion,
            "pairs": raw,
        }

    diagnostics = {
        "policy": {"threshold": THRESHOLD, "min_abs_us": MIN_ABS_US},
        "pair_count": 12,
        "order_counts": {"base-first": 6, "candidate-first": 6},
        "environment": environment,
        "scenarios": diagnostic_scenarios,
    }
    return summaries, diagnostics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        summaries, diagnostics = aggregate(args.input_dir)
        args.output_dir.mkdir(parents=True, exist_ok=False)
        for name, value in summaries.items():
            args.output_dir.joinpath(f"{name}.json").write_text(
                json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
                encoding="utf-8",
            )
        args.output_dir.joinpath("diagnostics.json").write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
