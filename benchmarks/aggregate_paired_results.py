"""Aggregate a fixed balanced 12-block crossover benchmark experiment."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path


BLOCK_RE = re.compile(
    r"^block-(?P<block>\d{2})-(?P<design>abba|baab)-pos-"
    r"(?P<position>[1-4])-(?P<subject>base|candidate)\.json$"
)
DESIGNS = ("abba", "baab")
SUBJECTS_BY_DESIGN = {
    "abba": ("base", "candidate", "candidate", "base"),
    "baab": ("candidate", "base", "base", "candidate"),
}
THRESHOLD = 0.30
MIN_ABS_US = 25.0


@dataclass(frozen=True)
class Record:
    block: int
    design: str
    position: int
    subject: str
    path: Path
    value: dict


def _load_records(input_dir: Path) -> list[Record]:
    records: list[Record] = []
    for path in sorted(input_dir.glob("*.json")):
        match = BLOCK_RE.fullmatch(path.name)
        if match is None:
            raise ValueError(f"unexpected benchmark result name: {path.name}")
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError(f"{path.name}: expected a JSON object")
        records.append(
            Record(
                block=int(match.group("block")),
                design=match.group("design"),
                position=int(match.group("position")),
                subject=match.group("subject"),
                path=path,
                value=value,
            )
        )

    expected = set()
    for block in range(1, 13):
        design = "abba" if block % 2 else "baab"
        for position, subject in enumerate(SUBJECTS_BY_DESIGN[design], start=1):
            expected.add((block, design, position, subject))
    observed = {
        (record.block, record.design, record.position, record.subject)
        for record in records
    }
    if observed != expected or len(records) != len(expected):
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ValueError(
            "expected exactly 12 balanced crossover blocks; "
            f"missing={missing}, extra={extra}"
        )
    return records


def _validate(records: list[Record]) -> tuple[dict, tuple[str, ...]]:
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
        if "runs" in value and (
            type(value["runs"]) is not int or value["runs"] != 1
        ):
            raise ValueError(
                f"{record.path.name}: runs must be absent or the positive integer 1"
            )
        if value.get("env") != environment:
            raise ValueError(f"{record.path.name}: benchmark environment mismatch")
        current_scenarios = value.get("scenarios")
        if (
            not isinstance(current_scenarios, dict)
            or tuple(sorted(current_scenarios)) != scenario_names
        ):
            raise ValueError(f"{record.path.name}: benchmark scenario mismatch")
        for scenario in scenario_names:
            metrics = current_scenarios[scenario]
            if (
                not isinstance(metrics, dict)
                or tuple(sorted(metrics)) != metric_names[scenario]
            ):
                raise ValueError(
                    f"{record.path.name}: benchmark metric mismatch for {scenario}"
                )
            for metric, measurement in metrics.items():
                if (
                    not isinstance(measurement, (int, float))
                    or isinstance(measurement, bool)
                    or not math.isfinite(measurement)
                ):
                    raise ValueError(
                        f"{record.path.name}: {scenario}.{metric} must be finite numeric data"
                    )
            if metrics.get("p99_us", 0) <= 0:
                raise ValueError(
                    f"{record.path.name}: {scenario}.p99_us must be positive"
                )
    return environment, scenario_names


def _median(values: list[float]) -> float:
    return float(statistics.median(values))


def _mad(values: list[float]) -> float:
    center = statistics.median(values)
    return float(statistics.median(abs(value - center) for value in values))


def _strictly_exceeds(value: float, limit: float) -> bool:
    """Return true only above, not numerically equal to, a policy limit."""
    return value > limit and not math.isclose(
        value, limit, rel_tol=1e-12, abs_tol=1e-12
    )


def _block_effect(records: list[Record], scenario: str) -> dict:
    values = {
        subject: [
            float(record.value["scenarios"][scenario]["p99_us"])
            for record in records
            if record.subject == subject
        ]
        for subject in ("base", "candidate")
    }
    relative = math.exp(
        (
            sum(math.log(value) for value in values["candidate"])
            - sum(math.log(value) for value in values["base"])
        )
        / 2.0
    ) - 1.0
    absolute = (sum(values["candidate"]) - sum(values["base"])) / 2.0
    return {
        "base_p99_us": values["base"],
        "candidate_p99_us": values["candidate"],
        "relative_effect": relative,
        "absolute_effect_us": absolute,
    }


def _population(effects: list[dict], design: str | None) -> dict:
    selected = [
        effect for effect in effects
        if design is None or effect["design"] == design
    ]
    relative_values = [effect["relative_effect"] for effect in selected]
    absolute_values = [effect["absolute_effect_us"] for effect in selected]
    relative = _median(relative_values)
    absolute = _median(absolute_values)
    return {
        "block_count": len(selected),
        "median_relative_effect": round(relative, 6),
        "median_absolute_effect_us": round(absolute, 3),
        "mad_relative_effect": round(_mad(relative_values), 6),
        "mad_absolute_effect_us": round(_mad(absolute_values), 3),
        "breaches": (
            _strictly_exceeds(relative, THRESHOLD)
            and _strictly_exceeds(absolute, MIN_ABS_US)
        ),
    }


def aggregate(input_dir: Path) -> dict:
    records = _load_records(input_dir)
    environment, scenario_names = _validate(records)
    diagnostic_scenarios: dict[str, dict] = {}
    for scenario in scenario_names:
        effects = []
        for block in range(1, 13):
            block_records = [record for record in records if record.block == block]
            effect = _block_effect(block_records, scenario)
            effect.update({"block": block, "design": block_records[0].design})
            effects.append(effect)
        populations = {
            label: _population(effects, design)
            for label, design in (("overall", None), ("abba", "abba"), ("baab", "baab"))
        }
        decisions = [populations[label]["breaches"] for label in ("overall", *DESIGNS)]
        classification = (
            "stable-regression" if all(decisions)
            else "pass" if not any(decisions)
            else "inconclusive"
        )
        for effect in effects:
            effect["relative_effect"] = round(effect["relative_effect"], 6)
            effect["absolute_effect_us"] = round(effect["absolute_effect_us"], 3)
        diagnostic_scenarios[scenario] = {
            "classification": classification,
            "populations": populations,
            "blocks": effects,
        }

    return {
        "policy": {"threshold": THRESHOLD, "min_abs_us": MIN_ABS_US},
        "block_count": 12,
        "design_counts": {"abba": 6, "baab": 6},
        "environment": environment,
        "scenarios": diagnostic_scenarios,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        diagnostics = aggregate(args.input_dir)
        args.output_dir.mkdir(parents=True, exist_ok=False)
        args.output_dir.joinpath("diagnostics.json").write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    blocked = {
        name: value["classification"]
        for name, value in diagnostics["scenarios"].items()
        if value["classification"] != "pass"
    }
    if blocked:
        print(f"FAIL: non-passing crossover verdicts: {blocked}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
