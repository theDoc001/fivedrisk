"""5D Risk Governance Engine — CLI entry point.

Usage:
    python -m fivedrisk score '{"tool_name": "Bash", "command": "rm -rf /"}'
    python -m fivedrisk score action.json --policy policy.yaml --format json
    python -m fivedrisk log --recent 10
    python -m fivedrisk stats

Also usable as a pipe (for Claude Code plugin hooks):
    echo '$TOOL_INPUT' | python -m fivedrisk score --policy policy.yaml --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .benchmarks import run_runtime_benchmarks
from .classifier import classify_tool_call
from .logger import DecisionLog
from .policy import load_policy
from .scorer import score


def _read_input(input_arg: str | None) -> dict:
    """Read tool input from argument, file, or stdin."""
    if input_arg is None or input_arg == "-":
        raw = sys.stdin.read().strip()
    elif Path(input_arg).exists():
        raw = Path(input_arg).read_text().strip()
    else:
        raw = input_arg

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_score(args: argparse.Namespace) -> None:
    """Score a tool call and output the result."""
    policy = load_policy(args.policy)
    data = _read_input(args.input)

    tool_name = data.pop("tool_name", data.pop("name", "Unknown"))
    tool_input = data.pop("tool_input", data)

    action = classify_tool_call(
        tool_name=tool_name,
        tool_input=tool_input,
        policy=policy,
        autonomy_context=args.autonomy or 0,
        source=args.source or "cli",
    )

    result = score(action, policy)

    # Log if not --dry-run
    if not args.dry_run:
        log = DecisionLog(args.log_path)
        row_id = log.log(result)
        result_dict = result.to_dict()
        result_dict["log_id"] = row_id
    else:
        result_dict = result.to_dict()

    if args.format == "json":
        print(json.dumps(result_dict, indent=2))
    else:
        band = result.band
        print(f"[5D {band}] {result.rationale}")
        print(f"  Composite: {result.composite_score:.1f} | Max dim: {result.max_dimension}")
        dims = ", ".join(
            f"{n}={getattr(action, n)}" for n in
            ("data_sensitivity", "tool_privilege", "reversibility",
             "external_impact", "autonomy_context")
        )
        print(f"  Dims: {dims}")

    # Exit code: 0=GO, 1=ASK, 2=STOP
    from .schema import Band
    if result.band == Band.STOP:
        sys.exit(2)
    elif result.band == Band.ASK:
        sys.exit(1)
    else:
        sys.exit(0)


def cmd_log(args: argparse.Namespace) -> None:
    """Show recent decision log entries."""
    log = DecisionLog(args.log_path)
    entries = log.query_recent(limit=args.recent)

    if args.format == "json":
        print(json.dumps(entries, indent=2, default=str))
    else:
        for entry in entries:
            print(
                f"[{entry['band']}] {entry['tool_name']} | "
                f"composite={entry['composite_score']:.1f} | "
                f"{entry['timestamp']}"
            )


def cmd_stats(args: argparse.Namespace) -> None:
    """Show decision log statistics."""
    log = DecisionLog(args.log_path)
    counts = log.count_by_band()
    total = sum(counts.values())

    if args.format == "json":
        print(json.dumps({"total": total, "by_band": counts}, indent=2))
    else:
        print(f"Total decisions: {total}")
        for band in ("GREEN", "YELLOW", "ORANGE", "RED"):
            count = counts.get(band, 0)
            pct = (count / total * 100) if total > 0 else 0
            print(f"  {band}: {count} ({pct:.1f}%)")


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Run the offline runtime validation benchmark pack."""
    summary = run_runtime_benchmarks(args.log_path)

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("5D runtime benchmark")
        print(f"  Total: {summary['total']}")
        print(f"  Passed: {summary['passed']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Pass rate: {summary['pass_rate'] * 100:.1f}%")
        if summary["failures"]:
            print("  Failures:")
            for failure in summary["failures"]:
                print(f"    - {failure['suite']}::{failure['case']}")

    sys.exit(1 if summary["failed"] else 0)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="fivedrisk",
        description="5D Risk Governance Engine — per-action risk scoring for AI agents",
    )
    parser.add_argument(
        "--policy", type=str, default=None,
        help="Path to policy.yaml (default: built-in)",
    )
    parser.add_argument(
        "--log-path", type=str, default=None,
        help="Path to SQLite decision log (default: fivedrisk_decisions.db)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # score
    p_score = subparsers.add_parser("score", help="Score a tool call")
    p_score.add_argument("input", nargs="?", default=None, help="JSON string, file, or - for stdin")
    p_score.add_argument("--autonomy", type=int, default=0, help="Autonomy context (0-4)")
    p_score.add_argument("--source", type=str, default="cli", help="Action source")
    p_score.add_argument("--dry-run", action="store_true", help="Score without logging")
    p_score.set_defaults(func=cmd_score)

    # log
    p_log = subparsers.add_parser("log", help="Show recent decisions")
    p_log.add_argument("--recent", type=int, default=20, help="Number of entries")
    p_log.set_defaults(func=cmd_log)

    # stats
    p_stats = subparsers.add_parser("stats", help="Decision log statistics")
    p_stats.set_defaults(func=cmd_stats)

    # benchmark
    p_benchmark = subparsers.add_parser(
        "benchmark",
        help="Run the offline runtime benchmark suite",
    )
    p_benchmark.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
