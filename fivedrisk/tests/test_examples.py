"""Run the shipped examples end-to-end so a flagship demo can't silently break.

`examples/minimal_gate.py` shipped catching ValueError while `@gate` raises
BandBlockError (a FivedriskDenial) — so the RED demo crashed instead of printing
'blocked:'. Nothing ran it in CI. This test does.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DEV = Path(__file__).resolve().parents[2]


def test_minimal_gate_example_runs_and_blocks_red():
    out = subprocess.run(
        [sys.executable, str(DEV / "examples" / "minimal_gate.py")],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, f"minimal_gate.py crashed:\n{out.stderr}"
    assert "blocked:" in out.stdout   # the RED action is caught, not uncaught
    assert "would execute: echo" in out.stdout  # the GREEN action ran
