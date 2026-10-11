#!/usr/bin/env python3
"""Build deterministic public-advisory or manual-integration plugin ZIPs."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


Entry = tuple[PurePosixPath, bytes, int]
ONBOARDING_SKILL = "./skills/fivedrisk-setup/SKILL.md"
# Explicitly reviewed public surfaces. New helpers/references require deliberate
# inclusion; a future lifecycle file must not silently enter the directory ZIP.
PUBLIC_FILES = frozenset({
    "README.md", "plugin.json", ".codex-plugin/plugin.json",
    "skills/fivedrisk-setup/SKILL.md",
    "skills/fivedrisk-setup/scripts/detect_framework.py",
    "skills/fivedrisk-setup/scripts/example_gate.py",
    "skills/fivedrisk-setup/scripts/verify-install.sh",
    "skills/fivedrisk-setup/references/adapters.md",
    "skills/fivedrisk-setup/references/configuration-and-recovery.md",
    "skills/fivedrisk-setup/references/deployment-intake.md",
    "skills/fivedrisk-setup/references/deployment-profile-template.yaml",
    "skills/fivedrisk-setup/references/observer-options.md",
    "skills/fivedrisk-setup/references/examples/goals-description-profile.yaml",
    "skills/fivedrisk-setup/references/examples/redacted-prompt-profile.yaml",
})


def _variant_entries(entries: list[Entry], root_name: str, variant: str) -> list[Entry]:
    if variant == "manual":
        return entries
    if variant != "public":
        raise RuntimeError(f"unknown plugin archive variant: {variant}")
    root = PurePosixPath(root_name)
    selected = []
    for entry in entries:
        path = entry[0].relative_to(root)
        if path.as_posix() in PUBLIC_FILES or (
            path.parts[0] == "assets"
            and path.suffix.lower() in {".svg", ".png", ".jpg", ".jpeg", ".webp"}
        ):
            selected.append(entry)
    content = {entry[0].relative_to(root).as_posix(): entry[1] for entry in selected}
    if not PUBLIC_FILES <= content.keys():
        raise RuntimeError("public plugin archive is missing required advisory surfaces")

    def has_hooks(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                key.lower() in {"hooks", "pretooluse", "posttooluse"} or has_hooks(item)
                for key, item in value.items()
            )
        return isinstance(value, list) and any(has_hooks(item) for item in value)

    manifests = []
    for name in ("plugin.json", ".codex-plugin/plugin.json"):
        try:
            manifest = json.loads(content[name])
            if not isinstance(manifest, dict) or has_hooks(manifest):
                raise RuntimeError("public plugin manifest must not declare lifecycle hooks")
            extension = manifest["extensions"]["com.openai"]
            if extension["onboardingSkill"] != ONBOARDING_SKILL:
                raise RuntimeError("public onboarding skill must resolve to the packaged consultant")
            if ONBOARDING_SKILL.removeprefix("./") not in content:
                raise RuntimeError("public onboarding skill is missing")
            manifests.append(manifest)
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("invalid public plugin manifest or onboarding metadata") from exc
    try:
        interface = manifests[0]["extensions"]["com.openai"]["interface"]
        if not isinstance(interface, dict) or not interface or interface != manifests[1]["interface"]:
            raise RuntimeError("public manifest presentation metadata must agree")
        for key in ("logo", "composerIcon"):
            path = interface[key]
            if (
                not isinstance(path, str) or not path.startswith("./assets/")
                or path.removeprefix("./") not in content
            ):
                raise RuntimeError("public manifest asset is not packaged")
    except (KeyError, TypeError) as exc:
        raise RuntimeError("invalid public manifest presentation or asset metadata") from exc
    return selected


def _validate_archive_path(path: PurePosixPath) -> None:
    rendered = path.as_posix()
    if (
        not rendered
        or "\\" in rendered
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or PurePosixPath(rendered).as_posix() != rendered
    ):
        raise RuntimeError(f"unsafe plugin archive path: {rendered}")


def _validate_raw_tar_name(name: str, *, directory: bool) -> None:
    if "\\" in name or name.startswith("/"):
        raise RuntimeError(f"unsafe plugin archive path: {name}")
    parts = name.split("/")
    if directory and parts and parts[-1] == "":
        parts.pop()
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeError(f"unsafe plugin archive path: {name}")


def _validate_tar_envelope(payload: bytes) -> None:
    block_size = 512
    zero = b"\0" * block_size
    if len(payload) < block_size * 2 or len(payload) % block_size:
        raise RuntimeError("invalid Git TAR framing")
    offset = 0
    while offset + block_size * 2 <= len(payload):
        header = payload[offset : offset + block_size]
        if header == zero:
            if payload[offset + block_size : offset + block_size * 2] != zero:
                raise RuntimeError("invalid Git TAR end marker")
            if any(payload[offset + block_size * 2 :]):
                raise RuntimeError("nonzero data follows the Git TAR end marker")
            return
        raw_size = header[124:136].rstrip(b"\0 ").lstrip(b" ") or b"0"
        try:
            size = int(raw_size, 8)
        except ValueError as exc:
            raise RuntimeError("invalid Git TAR size field") from exc
        offset += block_size + ((size + block_size - 1) // block_size) * block_size
    raise RuntimeError("missing Git TAR end marker")


def _zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    if epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be non-negative")
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if timestamp.year < 1980:
        timestamp = timestamp.replace(
            year=1980, month=1, day=1, hour=0, minute=0, second=0
        )
    if timestamp.year > 2107:
        raise RuntimeError("SOURCE_DATE_EPOCH exceeds the ZIP timestamp range")
    second = timestamp.second - timestamp.second % 2
    return (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        second,
    )


def _write_zip(entries: list[Entry], destination: Path, epoch: int) -> None:
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for relative, content, mode in sorted(entries, key=lambda entry: entry[0].as_posix()):
                _validate_archive_path(relative)
                info = zipfile.ZipInfo(relative.as_posix(), _zip_time(epoch))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(info, content)
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build(source: Path, destination: Path, epoch: int, *, variant: str = "manual") -> None:
    source = source.resolve(strict=True)
    destination = destination.resolve()
    if not source.is_dir() or destination == source or source in destination.parents:
        raise RuntimeError("plugin archive destination must be outside the source directory")
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
    entries: list[Entry] = []
    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"plugin archive refuses symlink: {path}")
        relative = PurePosixPath(source.name) / PurePosixPath(
            path.relative_to(source).as_posix()
        )
        mode = 0o755 if stat.S_IMODE(path.stat().st_mode) & 0o111 else 0o644
        entries.append((relative, path.read_bytes(), mode))
    _write_zip(_variant_entries(entries, source.name, variant), destination, epoch)


def _git(root: Path, *args: str, binary: bool = False) -> str | bytes:
    result = subprocess.run(
        ("git", "-C", str(root), *args),
        check=False,
        capture_output=True,
        text=not binary,
    )
    if result.returncode:
        error = result.stderr
        if isinstance(error, bytes):
            error = error.decode("utf-8", errors="replace")
        raise RuntimeError(error.strip() or "Git command failed")
    return result.stdout


def _tracked_modes(root: Path, commit: str, relative: PurePosixPath) -> dict[PurePosixPath, int]:
    output = _git(
        root,
        "ls-tree",
        "-rz",
        "--full-tree",
        commit,
        "--",
        relative.as_posix(),
        binary=True,
    )
    assert isinstance(output, bytes)
    modes: dict[PurePosixPath, int] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise RuntimeError("malformed git tree record")
        fields = metadata.split()
        if len(fields) != 3:
            raise RuntimeError("malformed git tree metadata")
        mode, object_type, _object_id = fields
        if object_type != b"blob" or mode not in {b"100644", b"100755"}:
            path = raw_path.decode("utf-8", errors="replace")
            raise RuntimeError(f"plugin archive refuses unsupported Git entry: {path}")
        decoded_path = raw_path.decode("utf-8")
        if "\\" in decoded_path:
            raise RuntimeError(f"unsafe plugin archive path: {decoded_path}")
        path = PurePosixPath(decoded_path)
        try:
            within_source = path.relative_to(relative)
        except ValueError as exc:
            raise RuntimeError("Git tree entry escaped the plugin source") from exc
        archive_path = PurePosixPath(relative.name) / within_source
        if archive_path in modes:
            raise RuntimeError(f"duplicate Git tree entry: {archive_path}")
        modes[archive_path] = 0o755 if mode == b"100755" else 0o644
    if not modes:
        raise RuntimeError("plugin source is empty")
    return modes


def _tar_entries(
    payload: bytes,
    relative: PurePosixPath,
    modes: dict[PurePosixPath, int],
) -> list[Entry]:
    entries: dict[PurePosixPath, Entry] = {}
    _validate_tar_envelope(payload)
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive:
                _validate_raw_tar_name(member.name, directory=member.isdir())
                raw = PurePosixPath(member.name)
                if raw.is_absolute() or ".." in raw.parts:
                    raise RuntimeError(f"unsafe plugin archive path: {member.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise RuntimeError(
                        f"plugin archive refuses non-regular TAR entry: {member.name}"
                    )
                try:
                    within_source = raw.relative_to(relative)
                except ValueError as exc:
                    raise RuntimeError("TAR entry escaped the plugin source") from exc
                normalized = PurePosixPath(relative.name) / within_source
                if normalized in entries:
                    raise RuntimeError(f"duplicate TAR entry: {normalized}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"cannot read TAR entry: {member.name}")
                mode = modes.get(normalized)
                if mode is None:
                    raise RuntimeError(f"unvalidated TAR entry: {member.name}")
                entries[normalized] = (normalized, extracted.read(), mode)
    except tarfile.TarError as exc:
        raise RuntimeError("invalid Git TAR archive") from exc
    if set(entries) != set(modes):
        raise RuntimeError("Git TAR files do not match the validated tree")
    return list(entries.values())


def build_from_git(source: Path, destination: Path, ref: str, *, variant: str = "manual") -> None:
    """Archive only files tracked by one immutable Git tree."""

    source = source.resolve(strict=True)
    repository = subprocess.run(
        ("git", "-C", str(source), "rev-parse", "--show-toplevel"),
        check=False,
        capture_output=True,
        text=True,
    )
    if repository.returncode:
        raise RuntimeError("cannot resolve Git repository for plugin archive")
    root = Path(repository.stdout.strip()).resolve()
    try:
        relative = PurePosixPath(source.relative_to(root).as_posix())
    except ValueError as exc:
        raise RuntimeError("plugin source is outside the Git repository") from exc
    commit_output = _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    assert isinstance(commit_output, str)
    commit = commit_output.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
        raise RuntimeError("Git did not resolve an immutable commit")
    epoch_output = _git(root, "show", "-s", "--format=%ct", commit)
    assert isinstance(epoch_output, str)
    try:
        epoch = int(epoch_output.strip())
    except ValueError as exc:
        raise RuntimeError("invalid Git commit timestamp") from exc
    modes = _tracked_modes(root, commit, relative)
    payload = _git(
        root,
        "archive",
        "--format=tar",
        commit,
        "--",
        relative.as_posix(),
        binary=True,
    )
    assert isinstance(payload, bytes)
    entries = _tar_entries(payload, relative, modes)
    names = {entry[0].as_posix() for entry in entries}
    required = {
        f"{source.name}/plugin.json",
        f"{source.name}/.codex-plugin/plugin.json",
        f"{source.name}/.claude-plugin/plugin.json",
        f"{source.name}/skills/fivedrisk-setup/SKILL.md",
    }
    if not required <= names:
        raise RuntimeError("plugin archive is missing required source surfaces")
    _write_zip(_variant_entries(entries, source.name, variant), destination, epoch)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("fivedrisk-plugin"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-ref", help="archive only the plugin tree at this Git ref")
    parser.add_argument("--variant", choices=("public", "manual"), default="manual")
    parser.add_argument(
        "--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "-1"))
    )
    args = parser.parse_args(argv)
    try:
        if args.variant == "public" and not args.git_ref:
            raise RuntimeError("public plugin archives require --git-ref")
        if args.git_ref:
            build_from_git(args.source, args.output, args.git_ref, variant=args.variant)
        else:
            build(args.source, args.output, args.epoch, variant=args.variant)
        print(args.output)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
