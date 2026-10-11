#!/usr/bin/env python3
"""Install or verify the repository-local fivedrisk publication hook."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


EXPECTED_HOOKS_PATH = ".githooks"


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *args),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def repository_root(cwd: Path) -> Path:
    result = _git("rev-parse", "--show-toplevel", cwd=cwd)
    if result.returncode:
        raise RuntimeError("not inside a Git repository")
    return Path(result.stdout.strip()).resolve()


def verify(root: Path) -> None:
    hook = root / EXPECTED_HOOKS_PATH / "pre-push"
    gate = root / "tools" / "release_window.py"
    if not hook.is_file() or not hook.stat().st_mode & 0o111:
        raise RuntimeError("tracked pre-push hook is missing or not executable")
    if not gate.is_file():
        raise RuntimeError("release-window gate is missing")
    configured = _git("config", "--local", "--get", "core.hooksPath", cwd=root)
    if configured.returncode or configured.stdout.strip() != EXPECTED_HOOKS_PATH:
        raise RuntimeError("core.hooksPath is not configured as .githooks")


def install(root: Path) -> None:
    result = _git(
        "config", "--local", "core.hooksPath", EXPECTED_HOOKS_PATH, cwd=root
    )
    if result.returncode:
        detail = result.stderr.strip() or "git config failed"
        raise RuntimeError(detail)
    verify(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="verify without changing Git configuration"
    )
    args = parser.parse_args(argv)
    try:
        root = repository_root(Path.cwd())
        if args.check:
            verify(root)
            print("OK: repository-local publication hook is active")
        else:
            install(root)
            print("INSTALLED: core.hooksPath=.githooks")
    except (OSError, RuntimeError) as exc:
        print(f"DENY: release controls are not active: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
