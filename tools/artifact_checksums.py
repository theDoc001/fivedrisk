#!/usr/bin/env python3
"""Create or verify a root-relative SHA-256 manifest for a directory."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


MANIFEST_NAME = "SHA256SUMS"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() != MANIFEST_NAME
    )


def write_manifest(root: Path) -> Path:
    root = root.resolve(strict=True)
    manifest = root / MANIFEST_NAME
    lines = [f"{digest(path)}  {path.relative_to(root).as_posix()}" for path in files(root)]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest


def verify_manifest(root: Path) -> None:
    root = root.resolve(strict=True)
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        raise RuntimeError(f"missing {MANIFEST_NAME}")
    declared: dict[str, str] = {}
    for number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        try:
            expected, relative = line.split("  ", 1)
        except ValueError as exc:
            raise RuntimeError(f"invalid manifest line {number}") from exc
        if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
            raise RuntimeError(f"invalid SHA-256 on manifest line {number}")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative == MANIFEST_NAME:
            raise RuntimeError(f"unsafe manifest path on line {number}")
        normalized = candidate.as_posix()
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
