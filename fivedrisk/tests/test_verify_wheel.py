from __future__ import annotations

import importlib.util
import io
import stat
import struct
import sys
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_wheel", ROOT / "tools/verify_wheel.py")
assert SPEC and SPEC.loader
verify_wheel = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_wheel
SPEC.loader.exec_module(verify_wheel)


def _wheel(path: Path, extra: zipfile.ZipInfo | str | None = None) -> None:
    readme = (ROOT / "fivedrisk/README.md").read_bytes()
    metadata = b"Metadata-Version: 2.4\nName: fivedrisk\nVersion: 0.7.1\nClassifier: Typing :: Typed\n\n" + readme
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(verify_wheel.REQUIRED):
                archive.writestr(name, b"runtime")
            archive.writestr("fivedrisk-0.7.1.dist-info/METADATA", metadata)
            if extra is not None:
                archive.writestr(extra, b"extra")


def test_wheel_verifier_accepts_normal_runtime_archive(tmp_path: Path):
    path = tmp_path / "normal.whl"
    _wheel(path)
    verify_wheel.verify(path)


def test_wheel_accepts_modeless_producers_and_normal_comments(tmp_path: Path):
    path = tmp_path / "normal.whl"
    member = zipfile.ZipInfo("fivedrisk/extra.py")
    member.create_system = 0
    member.external_attr = 0o600 << 16
    _wheel(path, member)
    with zipfile.ZipFile(path, "a") as archive:
        archive.comment = b"ordinary wheel comment"
    verify_wheel.verify(path)


def test_wheel_rejects_unrelated_distribution_metadata_root(tmp_path: Path):
    path = tmp_path / "bad.whl"
    _wheel(path)
    raw = path.read_bytes().replace(b"fivedrisk-0.7.1.dist-info", b"othername-0.7.1.dist-info")
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        verify_wheel.verify(path)


@pytest.mark.parametrize("scope", ["both", "local-only", "central-only"])
def test_wheel_rejects_alternate_unicode_path_extra_fields(tmp_path: Path, scope: str):
    path = tmp_path / "bad.whl"
    member = zipfile.ZipInfo("fivedrisk/extra.py")
    payload = b"\x01" + struct.pack("<I", zlib.crc32(member.filename.encode())) + b"../escape.py"
    member.extra = struct.pack("<HH", 0x7075, len(payload)) + payload
    _wheel(path, member)
    raw = bytearray(path.read_bytes())
    if scope != "both":
        with zipfile.ZipFile(path) as archive:
            if scope == "central-only":
                entry = next(info for info in archive.infolist() if info.extra == member.extra)
                offset = entry.header_offset + 30 + len(member.filename)
            else:
                offset = raw.index(member.extra, archive.start_dir)
        # The other header has a harmless timestamp extra of equal length.
        struct.pack_into("<H", raw, offset, 0x5455)
        path.write_bytes(raw)
    with pytest.raises(ValueError):
        verify_wheel.verify(path)


def test_wheel_accepts_consistent_unicode_path_metadata(tmp_path: Path):
    path = tmp_path / "normal.whl"
    member = zipfile.ZipInfo("fivedrisk/é.py")
    encoded = member.filename.encode("utf-8")
    payload = b"\x01" + struct.pack("<I", zlib.crc32(encoded)) + encoded
    member.extra = struct.pack("<HH", 0x7075, len(payload)) + payload
    _wheel(path, member)
    verify_wheel.verify(path)


@pytest.mark.parametrize("extra", [
    struct.pack("<HH", kind, 16) + b"x" * 16 for kind in (0x000D, 0x756E, 0x0001)
] + [b"\x75\x70\x10\x00short", b"\x75", struct.pack("<HH", 0x5455, 0) * 2])
def test_wheel_rejects_unsupported_or_malformed_extra_fields(tmp_path: Path, extra: bytes):
    path = tmp_path / "bad.whl"
    member = zipfile.ZipInfo("fivedrisk/extra.py")
    member.extra = extra
    _wheel(path, member)
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        verify_wheel.verify(path)


@pytest.mark.parametrize("name", [
    "fivedrisk/../escape.py", "fivedrisk//extra.py", "fivedrisk/./extra.py",
    "fivedrisk/extra\\escape.py", "fivedrisk/C:escape.py", "fivedrisk/extra\x01.py",
    "fivedrisk/__init__.py", "evil.dist-info/../../escape", "fivedrisk/nested/child.py",
])
def test_wheel_rejects_unsafe_duplicate_and_file_parent_paths(tmp_path: Path, name: str):
    path = tmp_path / "bad.whl"
    _wheel(path, name)
    if name == "fivedrisk/nested/child.py":
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("fivedrisk/nested", b"file blocks directory")
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        verify_wheel.verify(path)


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFCHR | 0o600,
    stat.S_IFBLK | 0o600, stat.S_IFIFO | 0o600, stat.S_IFREG | 0o4755,
    stat.S_IFREG | 0o2755])
def test_wheel_rejects_special_file_types_and_privileged_modes(tmp_path: Path, mode: int):
    path = tmp_path / "bad.whl"
    member = zipfile.ZipInfo("fivedrisk/extra.py")
    member.create_system = 3
    member.external_attr = mode << 16
    _wheel(path, member)
    with pytest.raises(ValueError):
        verify_wheel.verify(path)


@pytest.mark.parametrize("framing", ["prefix", "suffix", "second-zip", "central-gap"])
def test_wheel_rejects_ambiguous_archive_framing(tmp_path: Path, framing: str):
    path = tmp_path / "bad.whl"
    _wheel(path)
    raw = path.read_bytes()
    if framing == "prefix":
        raw = b"preamble" + raw
    elif framing == "suffix":
        raw += b"trailing bytes"
    elif framing == "second-zip":
        second = io.BytesIO()
        with zipfile.ZipFile(second, "w") as archive:
            archive.writestr("hidden", b"another archive")
        raw += second.getvalue()
    else:
        import struct
        end = raw.rfind(b"PK\x05\x06")
        offset = struct.unpack_from("<L", raw, end + 16)[0]
        raw = raw[:offset] + b"hidden gap" + raw[offset:]
        raw = bytearray(raw)
        struct.pack_into("<L", raw, end + len(b"hidden gap") + 16, offset + len(b"hidden gap"))
    path.write_bytes(raw)
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        verify_wheel.verify(path)
