"""Isolated installed-distribution bootstrap for security-sensitive child processes."""

from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path
import re
import sys

from . import __version__


def _verified_distribution() -> tuple[str, Path]:
    """Return the supported version and package root, or raise before dispatch."""
    distribution = metadata.distribution("fivedrisk")
    version = distribution.version
    match = re.fullmatch(r"0\.7\.(\d+)", version)
    if match is None or int(match.group(1)) < 1:
        raise RuntimeError(
            f"unsupported fivedrisk version {version!r}; require stable >=0.7.1,<0.8.0"
        )
    if __version__ != version:
        raise RuntimeError(
            f"fivedrisk version provenance mismatch: runtime {__version__!r}, "
            f"metadata {version!r}"
        )

    imported_root = Path(__file__).resolve().parent
    recorded_root = Path(distribution.locate_file("fivedrisk")).resolve()
    if imported_root != recorded_root:
        raise RuntimeError(
            "fivedrisk import provenance mismatch: "
            f"imported {imported_root}, distribution records {recorded_root}"
        )
    return version, imported_root


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        _verified_distribution()
    except (metadata.PackageNotFoundError, OSError, RuntimeError) as exc:
        print(f"fivedrisk bootstrap: {exc}; blocking", file=sys.stderr)
        return 2

    gateway_args: list[str] | None = None
    if args and args[0] == "gateway":
        gateway_args = args[1:]
    else:
        prefix: list[str] = []
        index = 0
        while index + 1 < len(args) and args[index] in {"--policy", "--log-path"}:
            prefix.extend(args[index:index + 2])
            index += 2
        if index < len(args) and args[index] == "gateway":
            gateway_args = [*args[index + 1:], *prefix]

    if gateway_args is not None:
        from .gateway import main as gateway_main

        return gateway_main(gateway_args)

    from .cli import main as cli_main

    sys.argv = ["fivedrisk", *args]
    cli_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
