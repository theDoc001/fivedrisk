from __future__ import annotations

import gzip
import importlib.util
import io
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "normalize_sdist", ROOT / "tools" / "normalize_sdist.py"
)
assert SPEC and SPEC.loader
normalize_sdist = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = normalize_sdist
SPEC.loader.exec_module(normalize_sdist)


def _sdist(path: Path, *, gzip_epoch: int, member_epoch: int) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="variable", mode="wb", fileobj=raw, mtime=gzip_epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                info = tarfile.TarInfo("package/file.txt")
                data = b"content"
                info.size = len(data)
                info.mtime = member_epoch
                info.uid = 501
                info.gid = 20
                info.uname = "builder"
                archive.addfile(info, io.BytesIO(data))


def test_normalization_is_reproducible_across_input_timestamps(tmp_path: Path):
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _sdist(first, gzip_epoch=10, member_epoch=20)
    _sdist(second, gzip_epoch=30, member_epoch=40)
    normalize_sdist.normalize(first, 100)
    normalize_sdist.normalize(second, 100)
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:gz") as archive:
        member = archive.getmember("package/file.txt")
        assert member.mtime == 100
        assert member.uid == member.gid == 0
        assert archive.extractfile(member).read() == b"content"


def _custom_sdist(path: Path, members: list[tarfile.TarInfo]) -> None:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(b"x" * member.size) if member.isfile() else None)
    path.write_bytes(gzip.compress(content.getvalue()))


@pytest.mark.parametrize("name", ["../escape", "/absolute", "package/../escape",
    "package//file", "package/./file", "package\\file", "C:escape", "package/file\x01"])
def test_sdist_rejects_noncanonical_member_paths_without_rewriting(tmp_path: Path, name: str):
    path = tmp_path / "bad.tar.gz"
    _custom_sdist(path, [tarfile.TarInfo(name)])
    before = path.read_bytes()
    with pytest.raises((RuntimeError, tarfile.TarError, ValueError)):
        normalize_sdist.normalize(path, 100)
    assert path.read_bytes() == before


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
    tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE])
def test_sdist_rejects_links_devices_and_sparse_members(tmp_path: Path, kind: bytes):
    path = tmp_path / "bad.tar.gz"
    member = tarfile.TarInfo("package/file")
    member.type = kind
    member.linkname = "../../outside"
    _custom_sdist(path, [member])
    with pytest.raises((RuntimeError, tarfile.TarError, ValueError)):
        normalize_sdist.normalize(path, 100)


@pytest.mark.parametrize("mode", [0o4755, 0o2755])
def test_sdist_rejects_privileged_modes(tmp_path: Path, mode: int):
    path = tmp_path / "bad.tar.gz"
    member = tarfile.TarInfo("package/file")
    member.mode = mode
    _custom_sdist(path, [member])
    with pytest.raises(RuntimeError):
        normalize_sdist.normalize(path, 100)


@pytest.mark.parametrize("names", [
    ["package/file", "package/file"],
    ["package/file", "package/file/child"],
    ["package/file/child", "package/file"],
])
def test_sdist_rejects_duplicates_and_file_directory_collisions(tmp_path: Path, names: list[str]):
    path = tmp_path / "bad.tar.gz"
    _custom_sdist(path, [tarfile.TarInfo(name) for name in names])
    with pytest.raises(RuntimeError):
        normalize_sdist.normalize(path, 100)


@pytest.mark.parametrize("framing", ["gzip-tail", "gzip-second", "gzip-truncated",
    "tar-tail", "tar-no-end", "tar-partial-block", "tar-bad-header", "tar-member-padding"])
def test_sdist_rejects_ambiguous_or_incomplete_framing(tmp_path: Path, framing: str):
    path = tmp_path / "bad.tar.gz"
    _sdist(path, gzip_epoch=10, member_epoch=20)
    raw = path.read_bytes()
    if framing == "gzip-tail":
        raw += b"junk"
    elif framing == "gzip-second":
        raw += gzip.compress(b"second member")
    elif framing == "gzip-truncated":
        raw = raw[:-4]
    else:
        tar = gzip.decompress(raw)
        if framing == "tar-tail":
            tar += b"hidden bytes"
        elif framing == "tar-no-end":
            tar = tar[:1024]
        elif framing == "tar-partial-block":
            tar = tar[:-1]
        elif framing == "tar-bad-header":
            tar = tar[:1024] + b"bad header".ljust(512, b"x") + tar[1536:]
        else:
            tar = tar[:519] + b"hidden padding" + tar[533:]
        raw = gzip.compress(tar)
    path.write_bytes(raw)
    before = path.read_bytes()
    with pytest.raises((RuntimeError, tarfile.TarError, ValueError, EOFError, OSError)):
        normalize_sdist.normalize(path, 100)
    assert path.read_bytes() == before


def test_sdist_preserves_directories_and_pax_long_unicode_names(tmp_path: Path):
    path = tmp_path / "normal.tar.gz"
    directory = tarfile.TarInfo("package/")
    directory.type = tarfile.DIRTYPE
    member = tarfile.TarInfo("package/" + "long-" * 25 + "é.txt")
    member.size = 1
    member.mtime = 12.5
    _custom_sdist(path, [directory, member])
    normalize_sdist.normalize(path, 100)
    with tarfile.open(path, "r:gz") as archive:
        assert archive.getmember("package").isdir()
        assert archive.extractfile(member.name).read() == b"x"


def test_current_built_sdist_remains_normalizable(tmp_path: Path):
    built = ROOT / "dist/fivedrisk-0.7.2.tar.gz"
    if not built.is_file():
        pytest.skip("no local release build")
    path = tmp_path / built.name
    path.write_bytes(built.read_bytes())
    normalize_sdist.normalize(path, 100)


def test_sdist_rejects_conflicting_pax_size_interpretation(tmp_path: Path):
    path = tmp_path / "bad.tar.gz"
    member = tarfile.TarInfo("package/file")
    member.size = 1
    member.pax_headers = {"size": "0"}
    _custom_sdist(path, [member])
    before = path.read_bytes()
    with pytest.raises(RuntimeError):
        normalize_sdist.normalize(path, 100)
    assert path.read_bytes() == before


def test_sdist_rejects_noncanonical_raw_directory_spelling(tmp_path: Path):
    path = tmp_path / "bad.tar.gz"
    directory = tarfile.TarInfo("package//")
    directory.type = tarfile.DIRTYPE
    _custom_sdist(path, [directory])
    with pytest.raises(RuntimeError):
        normalize_sdist.normalize(path, 100)
