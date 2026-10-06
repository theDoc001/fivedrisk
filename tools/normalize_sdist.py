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
from pathlib import Path


def normalize(path: Path, epoch: int) -> None:
    path = path.resolve(strict=True)
    if epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be non-negative")
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise RuntimeError(f"unsafe sdist member: {member.name}")
            if member.islnk() or member.issym():
                data = None
            elif member.isfile():
                extracted = source.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"cannot read sdist member: {member.name}")
                data = extracted.read()
            else:
                data = None
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            members.append((member, data))

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
