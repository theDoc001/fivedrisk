"""Docs-currency guard (OSS-DOC-GUARD-001).

Machine-checkable documentation claims are asserted against the code, so
drift shows up as a red test instead of a stale doc.

The capability-map checks skip on checkouts that don't have the map
(CAPABILITY_MAP.md is a local planning file above the repo root, not part
of the package).
"""
import json
import re
import subprocess
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


def test_public_package_versions_match_pyproject():
    pyproject = (DEV_DIR / "pyproject.toml").read_text(encoding="utf-8")
    real = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
    assert not (PKG_DIR / "ARCHITECTURE.md").exists()

    plugin_manifest = json.loads(
        (DEV_DIR / "fivedrisk-plugin" / ".claude-plugin" / "plugin.json").read_text()
    )
    assert plugin_manifest["version"] == real

    ts_package = json.loads(
        (DEV_DIR / "clients" / "typescript" / "package.json").read_text()
    )
    ts_lock = json.loads(
        (DEV_DIR / "clients" / "typescript" / "package-lock.json").read_text()
    )
    assert ts_package["version"] == real
    assert ts_lock["version"] == real
    assert ts_lock["packages"][""]["version"] == real

    text = _map_text()
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
    assert "latest main" not in text
    assert "git+https://github.com/theDoc001/fivedrisk.git\n" not in text
    assert "@<FULL_COMMIT>" in text
    assert "only after the user approves both the repository URL" in text
    assert "The arrows show the shipped default dispositions" in text
    assert "A band is severity; a deployment may remap its disposition" in text
    assert "fivedrisk._bootstrap.gateway" not in text
    assert "fivedrisk._bootstrap.gateway" not in (
        DEV_DIR / "fivedrisk" / "README.md"
    ).read_text(encoding="utf-8")
    for m in re.finditer(r"(\d{3,})(?:\+)?\s+(?:passing\s+)?tests|[Tt]est count:\s*(\d+)", text):
        n = int(m.group(1) or m.group(2))
        assert n == live, f"{doc.name} claims {n} tests; live def-test count is {live}"
    assert not re.search(r"\b\d{3,}\s+tests\b", text)

    instruction_files = [DEV_DIR / "README.md"]
    instruction_files.append(DEV_DIR / "fivedrisk" / "README.md")
    instruction_files.append(DEV_DIR / "clients" / "typescript" / "README.md")
    instruction_files.extend((DEV_DIR / "docs").rglob("*.md"))
    instruction_files.extend((DEV_DIR / "examples").glob("*.md"))
    instruction_files.extend((DEV_DIR / "examples").glob("*.py"))
    instruction_files.extend((DEV_DIR / "fivedrisk-plugin").rglob("*.md"))
    bare_command = re.compile(
        r"(?m)^\s*(?:pip\s+install\b|python(?:3)?\s+(?:-m\s+|examples/|benchmarks/|-c\s+))"
    )
    unbounded_install = re.compile(
        r"-m\s+pip\s+install\s+[\"']?fivedrisk(?:\[[^\]]+\])?[\"']?(?=\s|$)"
    )
    offenders = {
        path.relative_to(DEV_DIR).as_posix(): "unsafe Python/package command"
        for path in instruction_files
        if (
            bare_command.search(path.read_text())
            or unbounded_install.search(path.read_text())
        )
    }
    assert not offenders, f"public run instructions bypass interpreter/version bounds: {offenders}"


def test_python_wheel_contract_is_runtime_only():
    text = (DEV_DIR / "pyproject.toml").read_text(encoding="utf-8")
    finder = text.split("[tool.setuptools.packages.find]", 1)[1].split(
        "[tool.setuptools.package-data]", 1
    )[0]
    assert 'include = ["fivedrisk", "fivedrisk.*"]' in finder
    assert 'exclude = ["fivedrisk.tests", "fivedrisk.tests.*"]' in finder
    assert "namespaces = false" in finder
    package_data = text.split("[tool.setuptools.package-data]", 1)[1]
    assert "tests/" not in package_data


def test_repository_plugin_bundle_is_complete():
    plugin = DEV_DIR / "fivedrisk-plugin"
    required = [
        plugin / ".claude-plugin" / "plugin.json",
        plugin / "hooks" / "hooks.json",
        plugin / "scripts" / "run_hook.py",
        plugin / "skills" / "fivedrisk-setup" / "SKILL.md",
        plugin / "skills" / "fivedrisk-setup" / "references" / "adapters.md",
        plugin / "skills" / "fivedrisk-setup" / "references" / "configuration-and-recovery.md",
        plugin / "skills" / "fivedrisk-setup" / "references" / "deployment-intake.md",
        plugin / "skills" / "fivedrisk-setup" / "references" / "deployment-profile-template.yaml",
        plugin / "skills" / "fivedrisk-setup" / "references" / "observer-options.md",
        plugin / "skills" / "fivedrisk-setup" / "references" / "examples" / "goals-description-profile.yaml",
        plugin / "skills" / "fivedrisk-setup" / "references" / "examples" / "redacted-prompt-profile.yaml",
        plugin / "skills" / "fivedrisk-setup" / "scripts" / "verify-install.sh",
    ]
    assert all(path.is_file() for path in required)

def test_readme_rm_rf_example_matches_runtime_red_result():
    from fivedrisk import Band, classify_tool_call, load_policy, score

    policy = load_policy(str(DEV_DIR / "policy.yaml"))
    result = score(
        classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"}, policy),
        policy,
    )
    readme = (DEV_DIR / "README.md").read_text(encoding="utf-8")
    assert result.band is Band.RED
    assert result.rationale.startswith("RED — Bash:")
    assert "print(result.band)                      # Band.RED" in readme
    assert "RED is still denied by the gate" in readme


def test_plugin_policy_ownership_and_hook_files_are_truthful():
    plugin = DEV_DIR / "fivedrisk-plugin"
    hooks = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (plugin / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    readme = (plugin / "README.md").read_text(encoding="utf-8")
    template = (plugin / "policy.yaml").read_text(encoding="utf-8")
    assert set(hooks["hooks"]) == {"PreToolUse", "PostToolUse"}
    assert all(hooks["hooks"][phase][0]["matcher"] == "*" for phase in hooks["hooks"])
    assert "FIVEDRISK_PYTHON" in manifest["description"]
    assert "FIVEDRISK_POLICY_PATH" in manifest["description"]
    assert "structured ask" in manifest["description"]
    assert "starter template" in readme
    assert "does not load it\nautomatically" in readme
    assert "FIVEDRISK_POLICY_PATH" in readme
    assert "never falls back to `python`, `python3`, or PATH" in readme
    assert 'claude --plugin-dir "$PLUGIN_ROOT"' in readme
    assert "all-tool matcher" in readme
    assert "structured `ask`" in readme
    assert "Starter template only" in template


def test_public_markdown_relative_links_resolve_and_new_reference_is_releasable():
    if (DEV_DIR / ".git").is_dir():
        listed = subprocess.run(
            ["git", "ls-files", "*.md"], cwd=DEV_DIR,
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        markdown = [DEV_DIR / relative for relative in listed if (DEV_DIR / relative).is_file()]
    else:
        markdown = [DEV_DIR / "README.md", DEV_DIR / "SECURITY.md"]
        markdown.extend((DEV_DIR / "docs").rglob("*.md"))
        markdown.extend((DEV_DIR / "examples").glob("*.md"))
        markdown.extend((DEV_DIR / "fivedrisk-plugin").rglob("*.md"))
    new_reference = (
        DEV_DIR / "fivedrisk-plugin" / "skills" / "fivedrisk-setup"
        / "references" / "configuration-and-recovery.md"
    )
    if new_reference not in markdown:
        markdown.append(new_reference)
    missing = []
    link_pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for document in markdown:
        for raw in link_pattern.findall(document.read_text(encoding="utf-8")):
            target = raw.strip().split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            if not (document.parent / target).resolve().exists():
                missing.append((document.relative_to(DEV_DIR).as_posix(), raw))
    assert not missing, f"unresolved public relative links: {missing}"

    reference = new_reference
    assert reference.is_file()
    if (DEV_DIR / ".git").is_dir():
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", reference.relative_to(DEV_DIR).as_posix()],
            cwd=DEV_DIR, capture_output=True, text=True,
        )
        assert ignored.returncode != 0, "configuration-and-recovery.md is ignored and cannot ship"
