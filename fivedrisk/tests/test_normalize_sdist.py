from __future__ import annotations

import gzip
import importlib.util
import io
import sys
import tarfile
from pathlib import Path


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
