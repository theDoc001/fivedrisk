#!/usr/bin/env python3
"""Normalize a built .tar.gz sdist to one deterministic SOURCE_DATE_EPOCH."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path


def _safe_name(name: str, *, directory: bool = False) -> str:
    normalized = name.removesuffix("/") if directory else name
    if (not normalized or "\\" in normalized or ":" in normalized
        or any(ord(char) < 32 or ord(char) == 127 for char in normalized)
        or any(part in {"", ".", ".."} for part in normalized.split("/"))):
        raise RuntimeError(f"unsafe sdist member: {name!r}")
    return normalized


def _tar_payload(path: Path) -> tuple[bytes, int]:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        payload = decoder.decompress(path.read_bytes())
    except zlib.error as exc:
        raise RuntimeError("invalid sdist gzip framing") from exc
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise RuntimeError("sdist must contain exactly one complete gzip stream")
    if len(payload) < 1024 or len(payload) % 512:
        raise RuntimeError("invalid sdist TAR framing")
    offset = 0
    while offset + 1024 <= len(payload):
        header = payload[offset:offset + 512]
        if header == b"\0" * 512:
            if any(payload[offset:]):
                raise RuntimeError("data follows the sdist TAR end marker")
            return payload, offset
        try:
            member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
        except tarfile.HeaderError as exc:
            raise RuntimeError("invalid sdist TAR header") from exc
        if member.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            _safe_name(member.name, directory=member.isdir())
            if member.isdir():
                _safe_name(tarfile.nts(header[:100], "utf-8", "surrogateescape"), directory=True)
        if member.size < 0:
            raise RuntimeError("negative sdist TAR member size")
        data_end = offset + 512 + member.size
        next_header = offset + 512 + ((member.size + 511) // 512) * 512
        if next_header > len(payload) or any(payload[data_end:next_header]):
            raise RuntimeError("invalid sdist TAR member padding")
        offset = next_header
    raise RuntimeError("missing sdist TAR end marker")


def normalize(path: Path, epoch: int) -> None:
    if path.is_symlink():
        raise RuntimeError("sdist path must not be a symlink")
    path = path.resolve(strict=True)
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise RuntimeError("SOURCE_DATE_EPOCH must fit a non-negative gzip timestamp")
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    names: dict[str, bool] = {}
    payload, end_offset = _tar_payload(path)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as source:
        for member in source.getmembers():
            name = _safe_name(member.name, directory=member.isdir())
            if "path" in member.pax_headers:
                _safe_name(member.pax_headers["path"], directory=member.isdir())
            if (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or member.sparse is not None or member.mode & 0o6000
                or any(key.startswith("GNU.sparse") for key in member.pax_headers)):
                raise RuntimeError(f"unsafe sdist member type or mode: {name}")
            parts = name.split("/")
            if (name in names
                or any(names.get("/".join(parts[:index])) is False for index in range(1, len(parts)))
                or (not member.isdir() and any(other.startswith(name + "/") for other in names))):
                raise RuntimeError(f"duplicate or conflicting sdist member: {name}")
            names[name] = member.isdir()
            if member.isfile():
                extracted = source.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"cannot read sdist member: {member.name}")
                data = extracted.read()
                if len(data) != member.size:
                    raise RuntimeError(f"incomplete sdist member: {member.name}")
            else:
                data = None
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            members.append((member, data))
        if source.offset != end_offset:
            raise RuntimeError("sdist TAR parser and physical framing disagree")

    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as target:
                    for member, data in sorted(members, key=lambda item: item[0].name):
                        target.addfile(member, io.BytesIO(data) if data is not None else None)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdist", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "-1")),
    )
    args = parser.parse_args(argv)
    try:
        normalize(args.sdist, args.epoch)
        print(f"normalized {args.sdist}")
    except (OSError, RuntimeError, tarfile.TarError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
