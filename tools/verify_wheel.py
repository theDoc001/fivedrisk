"""Verify that a fivedrisk wheel contains only the supported runtime surface."""

from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
from pathlib import Path
import zipfile


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


def verify(path: Path) -> None:
    with zipfile.ZipFile(path) as wheel:
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
        if not name.startswith("fivedrisk/")
        and ".dist-info/" not in name
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
