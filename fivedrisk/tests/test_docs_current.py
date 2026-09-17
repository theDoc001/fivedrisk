"""Docs-currency guard (OSS-DOC-GUARD-001).

Machine-checkable documentation claims are asserted against the code, so
drift shows up as a red test instead of a stale doc.

The capability-map checks skip on checkouts that don't have the map
(CAPABILITY_MAP.md is a local planning file above the repo root, not part
of the package).
"""
import re
from pathlib import Path

import pytest

PKG_DIR = Path(__file__).resolve().parents[1]        # fivedrisk/
DEV_DIR = PKG_DIR.parent                             # repo root
MAP_PATH = DEV_DIR.parent / "CAPABILITY_MAP.md"      # absent on public clones

PRIVATE = {"__init__", "__main__"}


def _map_text():
    if not MAP_PATH.exists():
        pytest.skip("CAPABILITY_MAP.md not present (public clone) — local-only check")
    return MAP_PATH.read_text(encoding="utf-8")


def test_capability_map_names_every_module():
    """Every shipped module must appear in the capability map — the
    anti-duplication core: fails when a module ships undocumented or the
    map names a module that no longer exists."""
    text = _map_text()
    modules = {p.stem for p in PKG_DIR.glob("*.py")} - PRIVATE
    missing = sorted(m for m in modules if f"{m}.py" not in text)
    assert not missing, f"modules shipped but absent from CAPABILITY_MAP.md: {missing}"
    named = set(re.findall(r"`(\w+)\.py`", text))
    ghosts = sorted(
        n for n in named
        if n not in modules and next(DEV_DIR.rglob(f"{n}.py"), None) is None
    )
    assert not ghosts, f"CAPABILITY_MAP.md names modules that do not exist: {ghosts}"


def test_capability_map_version_matches_pyproject():
    text = _map_text()
    pyproject = (DEV_DIR / "pyproject.toml").read_text(encoding="utf-8")
    real = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
    claimed = re.search(r"package v(\d+\.\d+\.\d+)", text)
    assert claimed is not None, "CAPABILITY_MAP.md header must state 'package vX.Y.Z'"
    assert claimed.group(1) == real, (
        f"CAPABILITY_MAP.md claims v{claimed.group(1)}, pyproject.toml says v{real}"
    )


def _live_test_count():
    return sum(
        len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
        for p in (PKG_DIR / "tests").glob("test_*.py")
    )


def test_public_docs_test_count_claims():
    """Any 'N tests' claim in the public README must match the live def-test count.

    M19: xfail removed 2026-07-11 after reconciliation — count drift is now a hard
    failure (the standing docs-currency gate, OSS-DOC-GUARD-001). Scoped to
    README.md, the current-state doc. CHANGELOG.md is an append-only historical
    ledger whose per-release 'Test count: N' entries are correct for their version
    and must NOT be rewritten to the current number.
    """
    live = _live_test_count()
    doc = DEV_DIR / "README.md"
    text = doc.read_text(encoding="utf-8")
    for m in re.finditer(r"(\d{3,})(?:\+)?\s+(?:passing\s+)?tests|[Tt]est count:\s*(\d+)", text):
        n = int(m.group(1) or m.group(2))
        assert n == live, f"{doc.name} claims {n} tests; live def-test count is {live}"
