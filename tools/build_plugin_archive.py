#!/usr/bin/env python3
"""Build a deterministic, portable ZIP of the public fivedrisk plugin."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def build(source: Path, destination: Path, epoch: int) -> None:
    source = source.resolve(strict=True)
    destination = destination.resolve()
    if not source.is_dir() or destination == source or source in destination.parents:
        raise RuntimeError("plugin archive destination must be outside the source directory")
    if epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be non-negative")
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if timestamp.year < 1980:
        timestamp = timestamp.replace(year=1980, month=1, day=1, hour=0, minute=0, second=0)
    zip_time = (timestamp.year, timestamp.month, timestamp.day, timestamp.hour, timestamp.minute, timestamp.second)
    paths = sorted(
        path
        for path in source.rglob("*")
        if (path.is_file() or path.is_symlink())
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path.name != ".DS_Store"
    )
    if not paths:
        raise RuntimeError("plugin source is empty")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in paths:
                if path.is_symlink():
                    raise RuntimeError(f"plugin archive refuses symlink: {path}")
                relative = Path(source.name) / path.relative_to(source)
                info = zipfile.ZipInfo(relative.as_posix(), zip_time)
                info.create_system = 3
                mode = stat.S_IMODE(path.stat().st_mode)
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, path.read_bytes())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build_from_git(source: Path, destination: Path, ref: str) -> None:
    """Archive only files tracked by one immutable Git tree."""

    repository = subprocess.run(
        ("git", "rev-parse", "--show-toplevel"),
        check=False,
        capture_output=True,
        text=True,
    )
    if repository.returncode:
        raise RuntimeError("cannot resolve Git repository for plugin archive")
    root = Path(repository.stdout.strip()).resolve()
    source = source.resolve(strict=True)
    try:
        relative = source.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("plugin source is outside the Git repository") from exc
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    try:
        result = subprocess.run(
            (
                "git",
                "archive",
                "--format=zip",
                f"--prefix={source.name}/",
                f"--output={temporary}",
                f"{ref}:{relative.as_posix()}",
            ),
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "git archive failed")
        with zipfile.ZipFile(temporary) as archive:
            names = set(archive.namelist())
            required = {
                f"{source.name}/plugin.json",
                f"{source.name}/.codex-plugin/plugin.json",
                f"{source.name}/.claude-plugin/plugin.json",
                f"{source.name}/skills/fivedrisk-setup/SKILL.md",
            }
            if not required <= names:
                raise RuntimeError("plugin archive is missing required public surfaces")
            for info in archive.infolist():
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"plugin archive refuses symlink: {info.filename}")
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("fivedrisk-plugin"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-ref", help="archive only the plugin tree at this Git ref")
    parser.add_argument(
        "--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "-1"))
    )
    args = parser.parse_args(argv)
    try:
        if args.git_ref:
            build_from_git(args.source, args.output, args.git_ref)
        else:
            build(args.source, args.output, args.epoch)
        print(args.output)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
