#!/usr/bin/env python3
"""Create or verify a root-relative SHA-256 manifest for a directory."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath


MANIFEST_NAME = "SHA256SUMS"


def _portable_path(relative: str) -> PurePosixPath:
    parts = relative.split("/")
    candidate = PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
        or candidate.as_posix() != relative
        or relative == MANIFEST_NAME
    ):
        raise RuntimeError(f"unsafe manifest path: {relative}")
    return candidate


def _open_path(path: Path, *, directory: bool = False, write: bool = False) -> int:
    """Open every component relative to a no-follow directory descriptor.

    Checking ``is_symlink`` before an ordinary open leaves a replacement race.
    Release files and their parent directories must instead remain real objects
    throughout the open, including roots supplied through aliases.
    """
    absolute = path.absolute()
    try:
        relative = absolute.relative_to(Path.cwd())
        anchor = "."  # the process already owns this physical directory
        parts = relative.parts
    except ValueError:
        anchor = absolute.anchor
        parts = absolute.parts[1:]
    if not parts and directory:
        return os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if not parts or any(part in {".", ".."} for part in parts):
        raise RuntimeError(f"artifact path is not canonical: {path}")
    descriptor = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        flags = os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= os.O_RDONLY | os.O_DIRECTORY if directory else (os.O_WRONLY | os.O_CREAT if write else os.O_RDONLY)
        opened = os.open(parts[-1], flags, 0o644, dir_fd=descriptor)
        mode = os.fstat(opened).st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            os.close(opened)
            raise RuntimeError(f"artifact is not a regular {'directory' if directory else 'file'}: {path}")
        return opened
    except OSError as exc:
        raise RuntimeError(f"artifact path contains a symlink or is unavailable: {path}") from exc
    finally:
        os.close(descriptor)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with os.fdopen(_open_path(path), "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def files(root: Path) -> list[Path]:
    paths: list[Path] = []
    def walk(descriptor: int, relative: Path) -> None:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                current = relative / entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        walk(child, current)
                    finally:
                        os.close(child)
                elif not stat.S_ISREG(mode):
                    raise RuntimeError(f"artifact is a symlink or non-regular file: {root / current}")
                elif current.as_posix() != MANIFEST_NAME:
                    paths.append(root / current)
    descriptor = _open_path(root, directory=True)
    try:
        walk(descriptor, Path())
    except OSError as exc:
        raise RuntimeError("artifact enumeration encountered an unsafe or changed directory") from exc
    finally:
        os.close(descriptor)
    return sorted(paths)


def write_manifest(root: Path) -> Path:
    root = root.absolute()
    manifest = root / MANIFEST_NAME
    lines = []
    for path in files(root):
        relative = path.relative_to(root).as_posix()
        _portable_path(relative)
        lines.append(f"{digest(path)}  {relative}")
    descriptor = _open_path(manifest, write=True)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.truncate(0)
        output.write("\n".join(lines) + ("\n" if lines else ""))
    return manifest


def verify_manifest(root: Path) -> None:
    root = root.absolute()
    manifest = root / MANIFEST_NAME
    with os.fdopen(_open_path(manifest), "r", encoding="utf-8") as source:
        manifest_lines = source.read().splitlines()
    declared: dict[str, str] = {}
    for number, line in enumerate(manifest_lines, 1):
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise RuntimeError(f"invalid manifest line {number}") from exc
        if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
            raise RuntimeError(f"invalid SHA-256 on manifest line {number}")
        try:
            normalized = _portable_path(relative).as_posix()
        except RuntimeError as exc:
            raise RuntimeError(f"unsafe manifest path on line {number}") from exc
        if normalized in declared:
            raise RuntimeError(f"duplicate manifest path: {normalized}")
        declared[normalized] = expected
    actual = {path.relative_to(root).as_posix(): digest(path) for path in files(root)}
    if declared != actual:
        missing = sorted(set(actual) - set(declared))
        extra = sorted(set(declared) - set(actual))
        changed = sorted(
            name for name in set(actual) & set(declared) if actual[name] != declared[name]
        )
        raise RuntimeError(
            f"checksum mismatch (missing={missing}, extra={extra}, changed={changed})"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.write:
            path = write_manifest(args.directory)
            print(path)
        else:
            verify_manifest(args.directory)
            print(f"OK: {args.directory / MANIFEST_NAME}")
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
