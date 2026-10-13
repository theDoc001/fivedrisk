"""Run the shipped examples end-to-end so a flagship demo can't silently break.

`examples/minimal_gate.py` shipped catching ValueError while `@gate` raises
BandBlockError (a FivedriskDenial) — so the RED demo crashed instead of printing
'blocked:'. Nothing ran it in CI. This test does.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

DEV = Path(__file__).resolve().parents[2]


def test_minimal_gate_example_runs_and_blocks_red(tmp_path):
    catalog = (DEV / "examples" / "README.md").read_text()
    available = catalog.split("## Available examples", 1)[1].split("## Planned", 1)[0]
    assert "openai_agents_sdk_hook.py" not in available
    assert "Per-call LangGraph gate-node" in available
    assert "It is not a Markov sequence demo" in available

    out = subprocess.run(
        [sys.executable, str(DEV / "examples" / "minimal_gate.py")],
        cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, f"minimal_gate.py crashed:\n{out.stderr}"
    assert "blocked:" in out.stdout   # the RED action is caught, not uncaught
    assert "would execute: echo" in out.stdout  # the GREEN action ran


def test_quickstart_exact_first_example_runs_and_blocks_red(tmp_path):
    quickstart = (DEV / "docs" / "quickstart.md").read_text()
    match = re.search(
        r"Save as `try_fivedrisk\.py`:\s*```python\n(?P<code>.*?)\n```",
        quickstart,
        re.DOTALL,
    )
    assert match, "quickstart must contain the runnable try_fivedrisk.py block"

    script = tmp_path / "try_fivedrisk.py"
    script.write_text(match.group("code"))
    out = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert out.returncode == 0, f"quickstart example crashed:\n{out.stderr}"
    assert "would execute: echo hello-from-fivedrisk" in out.stdout
    assert "blocked:" in out.stdout
    assert "would execute: rm -rf" not in out.stdout
