#!/usr/bin/env python3
"""Classify remote release surfaces against local, checksum-verified artifacts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_CHECKSUMS_SPEC = importlib.util.spec_from_file_location(
    "_fivedrisk_artifact_checksums", Path(__file__).with_name("artifact_checksums.py")
)
if _CHECKSUMS_SPEC is None or _CHECKSUMS_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("cannot load artifact checksum verifier")
_CHECKSUMS = importlib.util.module_from_spec(_CHECKSUMS_SPEC)
_CHECKSUMS_SPEC.loader.exec_module(_CHECKSUMS)
MANIFEST_NAME = _CHECKSUMS.MANIFEST_NAME
digest = _CHECKSUMS.digest
verify_manifest = _CHECKSUMS.verify_manifest


class ReleaseStateError(RuntimeError):
    """The remote release state is conflicting, ambiguous, or unverifiable."""


@dataclass(frozen=True)
class ReleaseState:
    pypi: str
    tag: str
    release: str
    missing_pypi: tuple[str, ...]
    missing_release: tuple[str, ...]
    release_is_draft: bool


def expected_artifacts(dist: Path, *, version: str | None = None) -> tuple[dict[str, str], dict[str, str]]:
    verify_manifest(dist)
    artifact_paths = _CHECKSUMS.files(dist)
    package_paths = [path for path in artifact_paths if path.parent == dist and (path.name.endswith(".whl") or path.name.endswith(".tar.gz"))]
    if len(package_paths) != 2 or sum(path.name.endswith(".whl") for path in package_paths) != 1:
        raise ReleaseStateError("expected exactly one wheel and one source distribution")
    wheel = next(path for path in package_paths if path.name.endswith(".whl"))
    if version is None:
        parts = wheel.name.split("-")
        if len(parts) < 5 or parts[0] != "fivedrisk":
            raise ReleaseStateError("cannot infer release version from wheel name")
        version = parts[1]
    if not wheel.name.startswith(f"fivedrisk-{version}-") or not any(
        path.name == f"fivedrisk-{version}.tar.gz" for path in package_paths
    ):
        raise ReleaseStateError("package artifact set does not match the release version")
    package = {path.name: digest(path) for path in package_paths}
    release = {
        path.name: digest(path)
        for path in artifact_paths
        if path.parent == dist
    }
    plugins = {
        f"fivedrisk-plugin-public-{version}.zip",
        f"fivedrisk-plugin-manual-{version}.zip",
    }
    if set(release) != set(package) | plugins or len(release) != len(artifact_paths):
        raise ReleaseStateError("expected exact public and manual plugin artifact set")
    release[MANIFEST_NAME] = digest(dist / MANIFEST_NAME)
    return package, release


def _subset_state(
    present: Mapping[str, str], expected: Mapping[str, str], *, surface: str
) -> tuple[str, tuple[str, ...]]:
    unexpected = sorted(set(present) - set(expected))
    changed = sorted(
        name for name in set(present) & set(expected) if present[name] != expected[name]
    )
    if unexpected or changed:
        raise ReleaseStateError(
            f"{surface} conflict (unexpected={unexpected}, changed={changed})"
        )
    missing = tuple(sorted(set(expected) - set(present)))
    if not present:
        return "absent", missing
    return ("matching-partial" if missing else "matching-complete"), missing


def classify_pypi(payload: dict | None, expected: Mapping[str, str]) -> tuple[str, tuple[str, ...]]:
    if payload is None:
        return "absent", tuple(sorted(expected))
    urls = payload.get("urls")
    if not isinstance(urls, list):
        raise ReleaseStateError("PyPI response has no unambiguous files list")
    present: dict[str, str] = {}
    for item in urls:
        try:
            name = item["filename"]
            sha256 = item["digests"]["sha256"]
        except (KeyError, TypeError) as exc:
            raise ReleaseStateError("PyPI file metadata is incomplete") from exc
        if name in present:
            raise ReleaseStateError(f"duplicate PyPI filename: {name}")
        present[name] = sha256
    return _subset_state(present, expected, surface="PyPI")


def classify_tag(lines: str, *, version: str, candidate_sha: str) -> str:
    plain = f"refs/tags/v{version}"
    peeled = f"{plain}^{{}}"
    refs: dict[str, str] = {}
    for line in lines.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[1] in refs:
            raise ReleaseStateError("tag response is ambiguous")
        refs[fields[1]] = fields[0]
    if not refs:
        return "absent"
    if set(refs) != {plain, peeled}:
        raise ReleaseStateError("release tag is not one unambiguous annotated tag")
    if refs[peeled] != candidate_sha:
        raise ReleaseStateError("release tag does not resolve to the cleared commit")
    return "matching"


def classify_release(
    payload: dict | None,
    expected: Mapping[str, str],
    *,
    version: str,
) -> tuple[str, tuple[str, ...], bool]:
    if payload is None:
        return "absent", tuple(sorted(expected)), False
    if payload.get("tag_name") != f"v{version}":
        raise ReleaseStateError("GitHub release points to the wrong tag")
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ReleaseStateError("GitHub release assets are ambiguous")
    present: dict[str, str] = {}
    for asset in assets:
        try:
            name = asset["name"]
            asset_digest = asset["sha256"]
        except (KeyError, TypeError) as exc:
            raise ReleaseStateError("GitHub release asset digest is unavailable") from exc
        if name in present:
            raise ReleaseStateError(f"duplicate GitHub release asset: {name}")
        present[name] = asset_digest
    state, missing = _subset_state(present, expected, surface="GitHub release")
    draft = payload.get("draft") is True
    if state == "matching-complete" and not draft:
        return state, missing, False
    return "matching-partial", missing, draft


def validate_order(pypi: str, tag: str, release: str) -> None:
    if pypi != "matching-complete" and (tag != "absent" or release != "absent"):
        raise ReleaseStateError("out-of-order state: tag/release exists before PyPI is complete")
    if tag == "absent" and release != "absent":
        raise ReleaseStateError("out-of-order state: release exists before tag")


def _json_url(url: str, *, missing_is_none: bool = False) -> dict | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "fivedrisk-release-gate"}
    token = os.environ.get("GH_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if missing_is_none and exc.code == 404:
            return None
        raise ReleaseStateError(f"remote request failed with HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise ReleaseStateError("remote response is unavailable or invalid") from exc


def _release_payload(repository: str, version: str) -> dict | None:
    payload = _json_url(
        f"https://api.github.com/repos/{repository}/releases/tags/v{version}",
        missing_is_none=True,
    )
    if payload is None:
        return None
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ReleaseStateError("GitHub release assets are unavailable")
    normalized = dict(payload)
    normalized_assets = []
    for asset in assets:
        item = dict(asset)
        reported = item.get("digest")
        if isinstance(reported, str) and reported.startswith("sha256:"):
            item["sha256"] = reported.removeprefix("sha256:")
        else:
            url = item.get("browser_download_url")
            if not isinstance(url, str):
                raise ReleaseStateError("GitHub release asset cannot be verified")
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    hasher = hashlib.sha256()
                    for block in iter(lambda: response.read(1024 * 1024), b""):
                        hasher.update(block)
                item["sha256"] = hasher.hexdigest()
            except OSError as exc:
                raise ReleaseStateError("GitHub release asset cannot be downloaded") from exc
        normalized_assets.append(item)
    normalized["assets"] = normalized_assets
    return normalized


def inspect(version: str, candidate_sha: str, dist: Path, repository: str) -> ReleaseState:
    packages, release_artifacts = expected_artifacts(dist, version=version)
    pypi_payload = _json_url(
        f"https://pypi.org/pypi/fivedrisk/{version}/json", missing_is_none=True
    )
    pypi, missing_pypi = classify_pypi(pypi_payload, packages)
    tag_result = subprocess.run(
        (
            "git",
            "ls-remote",
            "--tags",
            "origin",
            f"refs/tags/v{version}",
            f"refs/tags/v{version}^{{}}",
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    if tag_result.returncode:
        raise ReleaseStateError("release tag state is unavailable")
    tag = classify_tag(tag_result.stdout, version=version, candidate_sha=candidate_sha)
    release, missing_release, draft = classify_release(
        _release_payload(repository, version), release_artifacts, version=version
    )
    validate_order(pypi, tag, release)
    return ReleaseState(pypi, tag, release, missing_pypi, missing_release, draft)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        state = inspect(args.version, args.candidate_sha, args.dist, args.repository)
        values = {
            "pypi": state.pypi,
            "tag": state.tag,
            "release": state.release,
            "missing_pypi": ",".join(state.missing_pypi),
            "missing_release": ",".join(state.missing_release),
            "release_is_draft": str(state.release_is_draft).lower(),
        }
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in values.items():
                    output.write(f"{key}={value}\n")
        print(json.dumps(values, sort_keys=True))
    except (OSError, ReleaseStateError, RuntimeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
