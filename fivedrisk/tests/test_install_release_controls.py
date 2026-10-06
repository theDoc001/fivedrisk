from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def test_fresh_clone_bootstrap_installs_and_verifies_hook(tmp_path: Path):
    repository = tmp_path / "candidate"
    (repository / ".githooks").mkdir(parents=True)
    (repository / "tools").mkdir()
    shutil.copy2(ROOT / ".githooks" / "pre-push", repository / ".githooks")
    shutil.copy2(ROOT / "tools" / "release_window.py", repository / "tools")
    shutil.copy2(
        ROOT / "tools" / "install_release_controls.py", repository / "tools"
    )
    hook = repository / ".githooks" / "pre-push"
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    assert _run("git", "init", "-q", cwd=repository).returncode == 0

    before = _run(
        sys.executable,
        "-I",
        "tools/install_release_controls.py",
        "--check",
        cwd=repository,
    )
    assert before.returncode == 2

    install = _run(
        sys.executable, "-I", "tools/install_release_controls.py", cwd=repository
    )
    assert install.returncode == 0, install.stderr
    assert "core.hooksPath=.githooks" in install.stdout

    after = _run(
        sys.executable,
        "-I",
        "tools/install_release_controls.py",
        "--check",
        cwd=repository,
    )
    assert after.returncode == 0, after.stderr
    configured = _run(
        "git", "config", "--local", "--get", "core.hooksPath", cwd=repository
    )
    assert configured.stdout.strip() == ".githooks"
