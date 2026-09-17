"""M6 — fivedrisk-setup skill: lock the detect helper + its adapter references.

The skill tells operators which adapter to wire. These tests prove the detection
runs and that every adapter name it advertises is a REAL fivedrisk symbol — so the
skill can't drift from the shipped API (same spirit as the docs-currency guards).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

DEV = Path(__file__).resolve().parents[2]
SKILL = DEV / "fivedrisk-plugin" / "skills" / "fivedrisk-setup"
DETECT = SKILL / "scripts" / "detect_framework.py"


def _load_detect():
    spec = importlib.util.spec_from_file_location("detect_framework", DETECT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["detect_framework"] = mod  # dataclass type resolution needs this
    spec.loader.exec_module(mod)
    return mod


def test_detect_reports_a_row_per_adapter():
    mod = _load_detect()
    rows = mod.detect()
    assert len(rows) == len(mod.ADAPTERS)
    names = {r["framework"] for r in rows}
    for expected in ("CrewAI", "OpenAI Agents SDK", "Google ADK", "Pydantic AI",
                     "Microsoft Agent Framework", "LangGraph"):
        assert expected in names


def test_python_rows_report_bool_node_rows_report_none():
    mod = _load_detect()
    for r in mod.detect():
        if r["node"]:
            assert r["installed"] is None
        else:
            assert isinstance(r["installed"], bool)


def test_advertised_adapters_are_real_symbols():
    """Every Python adapter the skill names must exist in the shipped package —
    guards against the skill drifting from the real API."""
    import fivedrisk.framework_adapters as fa
    import fivedrisk.langgraph_node as lg

    mod = _load_detect()
    for a in mod.ADAPTERS:
        if a.node:
            continue
        # pull the symbol name out of the "from ... import NAME" wiring line
        assert "import " in a.wiring_import
        symbol = a.wiring_import.split("import", 1)[1].strip()
        source = lg if "langgraph_node" in a.wiring_import else fa
        assert hasattr(source, symbol), f"skill names {symbol!r}, missing from {source.__name__}"


def test_detect_script_runs_clean():
    out = subprocess.run([sys.executable, str(DETECT)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0
    assert "5D adapter coverage" in out.stdout


def test_example_gate_runs_and_shows_both_bands():
    out = subprocess.run(
        [sys.executable, str(SKILL / "scripts" / "example_gate.py")],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "GREEN" in out.stdout and "blocked:" in out.stdout


def test_skill_md_and_references_present():
    assert (SKILL / "SKILL.md").is_file()
    assert (SKILL / "references" / "adapters.md").is_file()
    assert (SKILL / "scripts" / "verify-install.sh").is_file()
