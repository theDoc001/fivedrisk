"""Offline runtime benchmark runner for 5D.

Compatibility wrapper around `fivedrisk.harness`. New calibration tooling
should import from `fivedrisk.harness` directly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .harness import run_harness


def run_runtime_benchmarks(log_path: str | Path | None = None) -> dict[str, Any]:
    """Run the offline runtime benchmark pack and return a structured summary."""
    return run_harness(log_path).to_dict(include_results=False)
