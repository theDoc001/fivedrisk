from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath

import pytest


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


def test_plugin_zip_rejects_backslash_paths(tmp_path: Path):
    source = tmp_path / "fivedrisk-plugin"
    source.mkdir()
    (source / "..\\escape.txt").write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unsafe plugin archive path"):
        build_plugin_archive.build(source, tmp_path / "plugin.zip", 1_800_000_000)


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


def _git(repo: Path, *args: str) -> None:
    subprocess.run(("git", "-C", str(repo), *args), check=True, capture_output=True)


def _minimal_plugin_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    source = repo / "fivedrisk-plugin"
    (source / ".codex-plugin").mkdir(parents=True)
    (source / ".claude-plugin").mkdir()
    (source / "skills" / "fivedrisk-setup").mkdir(parents=True)
    (source / "scripts").mkdir()
    for path in (
        source / "plugin.json",
        source / ".codex-plugin" / "plugin.json",
        source / ".claude-plugin" / "plugin.json",
    ):
        path.write_text("{}\n", encoding="utf-8")
    (source / "skills" / "fivedrisk-setup" / "SKILL.md").write_text(
        "# setup\n", encoding="utf-8"
    )
    executable = source / "scripts" / "run"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "archive test")
    _git(repo, "config", "user.email", "archive@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "candidate")
    return repo, source


def test_git_archive_is_reproducible_tracked_only_and_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _repo, source = _minimal_plugin_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    build_plugin_archive.build_from_git(source, first, "HEAD")
    (source / "plugin.json").write_text('{"uncommitted": true}\n', encoding="utf-8")
    (source / "untracked-secret.txt").write_text("not shipped\n", encoding="utf-8")
    time.sleep(2.1)
    build_plugin_archive.build_from_git(source, second, "HEAD")
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert "fivedrisk-plugin/untracked-secret.txt" not in archive.namelist()
        assert archive.read("fivedrisk-plugin/plugin.json") == b"{}\n"
        modes = {
            info.filename: (info.external_attr >> 16) & 0o777
            for info in archive.infolist()
        }
    assert modes["fivedrisk-plugin/plugin.json"] == 0o644
    assert modes["fivedrisk-plugin/scripts/run"] == 0o755


def test_git_archive_rejects_a_tracked_symlink(tmp_path: Path):
    repo, source = _minimal_plugin_repo(tmp_path)
    (source / "link").symlink_to("plugin.json")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add symlink")
    with pytest.raises(RuntimeError, match="unsupported Git entry"):
        build_plugin_archive.build_from_git(source, tmp_path / "plugin.zip", "HEAD")


def test_git_archive_rejects_a_tracked_backslash_path(tmp_path: Path):
    repo, source = _minimal_plugin_repo(tmp_path)
    (source / "..\\escape.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add backslash path")
    with pytest.raises(RuntimeError, match="unsafe plugin archive path"):
        build_plugin_archive.build_from_git(source, tmp_path / "plugin.zip", "HEAD")


def test_tar_reader_rejects_traversal_before_destination_replacement(tmp_path: Path):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    destination = tmp_path / "existing.zip"
    destination.write_bytes(b"keep")
    modes = {PurePosixPath("fivedrisk-plugin/plugin.json"): 0o644}
    with pytest.raises(RuntimeError, match="unsafe plugin archive path"):
        entries = build_plugin_archive._tar_entries(
            payload.getvalue(), PurePosixPath("fivedrisk-plugin"), modes
        )
        build_plugin_archive._write_zip(entries, destination, 1_800_000_000)
    assert destination.read_bytes() == b"keep"


@pytest.mark.parametrize(
    "member_name", ["fivedrisk-plugin/./plugin.json", "fivedrisk-plugin//plugin.json"]
)
def test_tar_reader_rejects_noncanonical_member_names(member_name: str):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        member = tarfile.TarInfo(member_name)
        member.size = 2
        archive.addfile(member, io.BytesIO(b"{}"))
    modes = {PurePosixPath("fivedrisk-plugin/plugin.json"): 0o644}
    with pytest.raises(RuntimeError, match="unsafe plugin archive path"):
        build_plugin_archive._tar_entries(
            payload.getvalue(), PurePosixPath("fivedrisk-plugin"), modes
        )


def test_tar_reader_rejects_trailing_garbage_and_truncation():
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        member = tarfile.TarInfo("fivedrisk-plugin/plugin.json")
        member.size = 2
        archive.addfile(member, io.BytesIO(b"{}"))
    valid = payload.getvalue()
    modes = {PurePosixPath("fivedrisk-plugin/plugin.json"): 0o644}
    assert build_plugin_archive._tar_entries(
        valid, PurePosixPath("fivedrisk-plugin"), modes
    )
    for malformed in (valid + b"JUNK", valid[:-1]):
        with pytest.raises(RuntimeError, match="Git TAR"):
            build_plugin_archive._tar_entries(
                malformed, PurePosixPath("fivedrisk-plugin"), modes
            )

    marker = next(
        offset
        for offset in range(0, len(valid), 512)
        if valid[offset : offset + 1024] == b"\0" * 1024
    )
    garbage_after_marker = (
        valid[: marker + 1024] + b"JUNK" + b"\0" * (len(valid) - marker - 1028)
    )
    with pytest.raises(RuntimeError, match="follows the Git TAR end marker"):
        build_plugin_archive._tar_entries(
            garbage_after_marker, PurePosixPath("fivedrisk-plugin"), modes
        )
