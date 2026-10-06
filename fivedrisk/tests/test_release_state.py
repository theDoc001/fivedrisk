from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("release_state", TOOLS / "release_state.py")
assert SPEC and SPEC.loader
release_state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_state
SPEC.loader.exec_module(release_state)


EXPECTED = {"fivedrisk.whl": "a" * 64, "fivedrisk.tar.gz": "b" * 64}


def _pypi(files: dict[str, str]) -> dict:
    return {
        "urls": [
            {"filename": name, "digests": {"sha256": digest}}
            for name, digest in files.items()
        ]
    }


def _release(files: dict[str, str], *, draft: bool = False) -> dict:
    return {
        "tag_name": "v0.7.1",
        "draft": draft,
        "assets": [{"name": name, "sha256": digest} for name, digest in files.items()],
    }


def test_pypi_absent_partial_complete_and_conflict():
    assert release_state.classify_pypi(None, EXPECTED)[0] == "absent"
    one = {"fivedrisk.whl": "a" * 64}
    assert release_state.classify_pypi(_pypi(one), EXPECTED) == (
        "matching-partial",
        ("fivedrisk.tar.gz",),
    )
    assert release_state.classify_pypi(_pypi(EXPECTED), EXPECTED)[0] == "matching-complete"
    with pytest.raises(release_state.ReleaseStateError, match="conflict"):
        release_state.classify_pypi(_pypi({"fivedrisk.whl": "f" * 64}), EXPECTED)


def test_tag_requires_annotated_exact_candidate():
    sha = "1" * 40
    lines = f"{'2' * 40}\trefs/tags/v0.7.1\n{sha}\trefs/tags/v0.7.1^{{}}\n"
    assert release_state.classify_tag(lines, version="0.7.1", candidate_sha=sha) == "matching"
    with pytest.raises(release_state.ReleaseStateError, match="annotated"):
        release_state.classify_tag(
            f"{sha}\trefs/tags/v0.7.1\n", version="0.7.1", candidate_sha=sha
        )


def test_release_allows_matching_partial_and_draft_but_rejects_conflicts():
    assets = {**EXPECTED, "SHA256SUMS": "c" * 64}
    state = release_state.classify_release(
        _release({"fivedrisk.whl": "a" * 64}), assets, version="0.7.1"
    )
    assert state == (
        "matching-partial",
        ("SHA256SUMS", "fivedrisk.tar.gz"),
        False,
    )
    assert release_state.classify_release(
        _release(assets, draft=True), assets, version="0.7.1"
    ) == ("matching-partial", (), True)
    assert release_state.classify_release(
        _release(assets), assets, version="0.7.1"
    ) == ("matching-complete", (), False)
    with pytest.raises(release_state.ReleaseStateError, match="conflict"):
        release_state.classify_release(
            _release({**assets, "unexpected": "d" * 64}), assets, version="0.7.1"
        )


@pytest.mark.parametrize(
    ("pypi", "tag", "release"),
    [
        ("absent", "matching", "absent"),
        ("matching-partial", "absent", "matching-partial"),
        ("matching-complete", "absent", "matching-partial"),
    ],
)
def test_out_of_order_state_fails_closed(pypi: str, tag: str, release: str):
    with pytest.raises(release_state.ReleaseStateError, match="out-of-order"):
        release_state.validate_order(pypi, tag, release)
