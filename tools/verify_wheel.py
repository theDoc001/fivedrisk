"""Verify that a fivedrisk wheel contains only the supported runtime surface."""

from __future__ import annotations

import argparse
import io
from email import policy
from email.parser import BytesParser
from pathlib import Path
import stat
import struct
import zipfile
import zlib


REQUIRED = {
    "fivedrisk/__init__.py",
    "fivedrisk/_bootstrap.py",
    "fivedrisk/py.typed",
    "fivedrisk/cli.py",
    "fivedrisk/gateway.py",
    "fivedrisk/hooks.py",
    "fivedrisk/policies/presets/read_only.yaml",
    "fivedrisk/fixtures/attacker/safe_article.txt",
}


def _validate_extra(extra: bytes, member: zipfile.ZipInfo) -> None:
    """Alternate ZIP readers must see the same pathname and regular-file type."""
    offset = 0
    seen: set[int] = set()
    while offset < len(extra):
        if offset + 4 > len(extra):
            raise ValueError("truncated wheel extra-field header")
        kind, size = struct.unpack_from("<HH", extra, offset)
        end = offset + 4 + size
        if end > len(extra) or kind in seen:
            raise ValueError("truncated or duplicate wheel extra field")
        seen.add(kind)
        data = extra[offset + 4:end]
        if kind == 0x7075:  # Info-ZIP Unicode Path: version, original-name CRC, UTF-8 name
            encoded = member.filename.encode("utf-8" if member.flag_bits & 0x800 else "cp437")
            try:
                consistent = (len(data) >= 5 and data[0] == 1
                    and struct.unpack_from("<L", data, 1)[0] == zlib.crc32(encoded)
                    and data[5:].decode("utf-8") == member.filename)
            except UnicodeDecodeError as exc:
                raise ValueError("invalid wheel Unicode Path extra field") from exc
            if not consistent:
                raise ValueError("wheel extra field provides an alternate pathname")
        elif kind not in {0x5455, 0x5855, 0x7855, 0x7875, 0x6375}:
            # Only timestamp, UID/GID and comment metadata is otherwise supported.
            # Unix/ASi link fields, ZIP64 and unknown extraction semantics fail closed.
            raise ValueError(f"unsupported wheel extra field: {kind:#06x}")
        offset = end


def _validate_members(members: list[zipfile.ZipInfo]) -> None:
    paths: dict[str, bool] = {}
    for member in members:
        name = member.filename.removesuffix("/") if member.is_dir() else member.filename
        parts = name.split("/")
        if (
            member.orig_filename != member.filename
            or not name or "\\" in name or ":" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError(f"unsafe wheel member path: {member.orig_filename!r}")
        if name in paths:
            raise ValueError(f"duplicate wheel member: {name}")
        if any(paths.get("/".join(parts[:index])) is False for index in range(1, len(parts))):
            raise ValueError(f"wheel file/directory collision: {name}")
        if not member.is_dir() and any(path.startswith(name + "/") for path in paths):
            raise ValueError(f"wheel file/directory collision: {name}")
        mode = member.external_attr >> 16
        expected_type = stat.S_IFDIR if member.is_dir() else stat.S_IFREG
        if stat.S_IFMT(mode) not in (0, expected_type) or mode & 0o6000:
            raise ValueError(f"unsafe wheel member type or mode: {name}")
        if member.external_attr & 0x10 and not member.is_dir():
            raise ValueError(f"inconsistent wheel directory attributes: {name}")
        _validate_extra(member.extra, member)
        paths[name] = member.is_dir()


def _validate_envelope(raw: bytes, members: list[zipfile.ZipInfo], start_dir: int) -> None:
    """Require one ordinary ZIP with contiguous members and no hidden framing.

    Release wheels are small, seekable ZIP_STORED/DEFLATED archives; ZIP64,
    encryption and alternate compression formats are outside this build contract.
    """
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or end + 22 > len(raw):
        raise ValueError("wheel has no complete ZIP end record")
    _, disk, central_disk, count_disk, count, size, offset, comment = struct.unpack_from("<4s4H2LH", raw, end)
    if (disk or central_disk or count_disk != count or count != len(members)
        or count == 65535 or size == 0xFFFFFFFF or offset == 0xFFFFFFFF
        or end + 22 + comment != len(raw) or offset != start_dir or offset + size != end):
        raise ValueError("ambiguous wheel ZIP framing")
    cursor = 0
    for member in sorted(members, key=lambda item: item.header_offset):
        if member.header_offset != cursor or cursor + 30 > start_dir:
            raise ValueError("wheel has a prefix, overlap or unlisted member data")
        header = struct.unpack_from("<4s5H3L2H", raw, cursor)
        signature, _, flags, compression, _, _, crc, compressed, uncompressed, name_len, extra_len = header
        if (signature != b"PK\x03\x04" or flags != member.flag_bits or flags & ~0x80E
            or compression != member.compress_type or compression not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            or compressed == 0xFFFFFFFF or uncompressed == 0xFFFFFFFF):
            raise ValueError(f"unsupported wheel local header: {member.filename}")
        data_start = cursor + 30 + name_len + extra_len
        data_end = data_start + member.compress_size
        if data_end > start_dir:
            raise ValueError("truncated wheel member")
        encoding = "utf-8" if flags & 0x800 else "cp437"
        if raw[cursor + 30:cursor + 30 + name_len] != member.filename.encode(encoding):
            raise ValueError("wheel local and central names disagree")
        _validate_extra(raw[cursor + 30 + name_len:data_start], member)
        if not flags & 8 and (crc, compressed, uncompressed) != (member.CRC, member.compress_size, member.file_size):
            raise ValueError("wheel local and central sizes/CRC disagree")
        payload = raw[data_start:data_end]
        if compression == zipfile.ZIP_DEFLATED:
            decoder = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                decoder.decompress(payload)
            except zlib.error as exc:
                raise ValueError("invalid wheel compressed member") from exc
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("ambiguous wheel compressed member framing")
        elif member.compress_size != member.file_size:
            raise ValueError("stored wheel member sizes disagree")
        cursor = data_end
        if flags & 8:
            if raw[cursor:cursor + 4] == b"PK\x07\x08":
                cursor += 4
            if cursor + 12 > start_dir or struct.unpack_from("<3L", raw, cursor) != (member.CRC, member.compress_size, member.file_size):
                raise ValueError("invalid wheel data descriptor")
            cursor += 12
    if cursor != start_dir:
        raise ValueError("unlisted data before wheel central directory")
    for _ in members:
        if cursor + 46 > end or raw[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("invalid wheel central directory")
        name_len, extra_len, comment_len = struct.unpack_from("<3H", raw, cursor + 28)
        cursor += 46 + name_len + extra_len + comment_len
    if cursor != end:
        raise ValueError("unlisted wheel central-directory data")


def verify(path: Path) -> None:
    raw = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        members = wheel.infolist()
        _validate_members(members)
        _validate_envelope(raw, members, wheel.start_dir)
        bad_member = wheel.testzip()
        if bad_member is not None:
            raise ValueError(f"wheel member failed CRC verification: {bad_member}")
        names = set(wheel.namelist())
        metadata_names = sorted(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        if len(metadata_names) != 1:
            raise ValueError(f"wheel must contain one METADATA file: {metadata_names}")
        metadata_bytes = wheel.read(metadata_names[0])
        metadata = BytesParser(policy=policy.default).parsebytes(metadata_bytes)
        version = metadata.get("Version", "")
        expected_metadata = f"fivedrisk-{version.replace('-', '_')}.dist-info/METADATA"
        if metadata.get("Name", "").lower() != "fivedrisk" or metadata_names != [expected_metadata]:
            raise ValueError("wheel METADATA and permitted distribution root disagree")

    missing = sorted(REQUIRED - names)
    if missing:
        raise ValueError(f"wheel is missing runtime files: {missing}")
    forbidden = sorted(
        name
        for name in names
        if name.startswith("fivedrisk/tests/")
        or name.startswith("fivedrisk-plugin/")
    )
    if forbidden:
        raise ValueError(f"wheel contains repository-only files: {forbidden}")
    unexpected = sorted(
        name
        for name in names
        if name.split("/", 1)[0] not in {
            "fivedrisk", metadata_names[0].split("/", 1)[0]
        }
    )
    if unexpected:
        raise ValueError(f"wheel contains unexpected top-level files: {unexpected}")

    typed_classifier = "Typing :: Typed" in metadata.get_all("Classifier", [])
    if typed_classifier != ("fivedrisk/py.typed" in names):
        raise ValueError("Typing :: Typed classifier and fivedrisk/py.typed disagree")

    source_readme = Path(__file__).resolve().parents[1] / "fivedrisk" / "README.md"
    separator = b"\r\n\r\n" if b"\r\n\r\n" in metadata_bytes else b"\n\n"
    long_description = metadata_bytes.partition(separator)[2].decode("utf-8")
    if long_description.rstrip("\n") != source_readme.read_text(encoding="utf-8").rstrip("\n"):
        raise ValueError("wheel METADATA long description differs from fivedrisk/README.md")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    verify(args.wheel)
    print("wheel runtime allowlist verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
