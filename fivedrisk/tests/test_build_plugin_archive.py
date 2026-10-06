from __future__ import annotations

import importlib.util
import os
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_plugin_archive", ROOT / "tools" / "build_plugin_archive.py"
)
assert SPEC and SPEC.loader
build_plugin_archive = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_plugin_archive
SPEC.loader.exec_module(build_plugin_archive)


def test_plugin_zip_is_rooted_and_reproducible(tmp_path: Path):
    source = tmp_path / "fivedrisk-plugin"
    (source / "skills" / "setup").mkdir(parents=True)
    (source / "plugin.json").write_text("{}\n", encoding="utf-8")
    skill = source / "skills" / "setup" / "SKILL.md"
    skill.write_text("# setup\n", encoding="utf-8")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    build_plugin_archive.build(source, first, 1_800_000_000)
    os.utime(skill, (1, 1))
    build_plugin_archive.build(source, second, 1_800_000_000)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == [
            "fivedrisk-plugin/plugin.json",
            "fivedrisk-plugin/skills/setup/SKILL.md",
        ]


def test_plugin_zip_rejects_symlinks(tmp_path: Path):
    source = tmp_path / "fivedrisk-plugin"
    source.mkdir()
    target = source / "target"
    target.write_text("x", encoding="utf-8")
    (source / "link").symlink_to(target)
    try:
        build_plugin_archive.build(source, tmp_path / "plugin.zip", 1_800_000_000)
    except RuntimeError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlink was accepted")


def test_release_archive_contains_only_the_tracked_plugin_tree(tmp_path: Path):
    output = tmp_path / "plugin.zip"
    build_plugin_archive.build_from_git(ROOT / "fivedrisk-plugin", output, "HEAD")
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert "fivedrisk-plugin/plugin.json" in names
    assert "fivedrisk-plugin/.codex-plugin/plugin.json" in names
    assert "fivedrisk-plugin/.claude-plugin/plugin.json" in names
    assert "fivedrisk-plugin/skills/fivedrisk-setup/SKILL.md" in names
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)
