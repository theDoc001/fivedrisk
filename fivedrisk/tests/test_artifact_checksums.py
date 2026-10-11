from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "artifact_checksums", ROOT / "tools" / "artifact_checksums.py"
)
assert SPEC and SPEC.loader
artifact_checksums = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = artifact_checksums
SPEC.loader.exec_module(artifact_checksums)


def test_manifest_is_root_relative_excludes_itself_and_verifies(tmp_path: Path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "nested" / "b.txt").write_text("b", encoding="utf-8")
    manifest = artifact_checksums.write_manifest(tmp_path)
    text = manifest.read_text(encoding="utf-8")
    assert "  a.txt\n" in text
    assert "  nested/b.txt\n" in text
    assert "SHA256SUMS" not in text
    assert "../" not in text
    artifact_checksums.verify_manifest(tmp_path)


def test_manifest_rejects_changes_and_unsafe_paths(tmp_path: Path):
    file = tmp_path / "a.txt"
    file.write_text("a", encoding="utf-8")
    manifest = artifact_checksums.write_manifest(tmp_path)
    file.write_text("changed", encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed"):
        artifact_checksums.verify_manifest(tmp_path)
    manifest.write_text("0" * 64 + "  ../escape\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unsafe"):
        artifact_checksums.verify_manifest(tmp_path)


@pytest.mark.parametrize("relative", ["..\\escape", "nested//file", "nested/./file"])
def test_manifest_rejects_nonportable_path_spellings(tmp_path: Path, relative: str):
    (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / relative).write_text("x", encoding="utf-8")
    (tmp_path / "SHA256SUMS").write_text(
        artifact_checksums.digest(tmp_path / relative) + f"  {relative}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="unsafe"):
        artifact_checksums.verify_manifest(tmp_path)


@pytest.mark.parametrize("target", ["file", "directory", "manifest", "root"])
def test_checksum_operations_reject_symlinks_without_reading_targets(tmp_path: Path, target: str):
    root = tmp_path / "dist"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("outside", encoding="utf-8")
    (root / "file.txt").write_text("inside", encoding="utf-8")
    artifact_checksums.write_manifest(root)
    if target == "file":
        (root / "linked.txt").symlink_to(outside / "file.txt")
    elif target == "directory":
        (root / "linked").symlink_to(outside, target_is_directory=True)
    elif target == "manifest":
        (root / "SHA256SUMS").unlink()
        (root / "SHA256SUMS").symlink_to(outside / "file.txt")
    else:
        linked_root = tmp_path / "linked-dist"
        linked_root.symlink_to(root, target_is_directory=True)
        root = linked_root
    for operation in (artifact_checksums.write_manifest, artifact_checksums.verify_manifest):
        with pytest.raises(RuntimeError, match="symlink|regular|directory"):
            operation(root)
    assert (outside / "file.txt").read_text(encoding="utf-8") == "outside"


def test_digest_rejects_symlink_in_parent_directory(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a").write_text("a", encoding="utf-8")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symlink"):
        artifact_checksums.digest(tmp_path / "linked" / "a")


def test_manifest_accepts_current_directory_as_root(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("a").write_text("a", encoding="utf-8")
    artifact_checksums.write_manifest(Path("."))
    artifact_checksums.verify_manifest(Path("."))
