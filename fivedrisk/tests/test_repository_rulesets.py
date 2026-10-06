from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "repository_rulesets", ROOT / "tools" / "repository_rulesets.py"
)
assert SPEC and SPEC.loader
repository_rulesets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = repository_rulesets
SPEC.loader.exec_module(repository_rulesets)


def test_rulesets_protect_main_checks_and_release_tags():
    branch, tag = repository_rulesets.desired_rulesets()
    assert branch["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    types = {rule["type"] for rule in branch["rules"]}
    assert {"pull_request", "required_status_checks", "deletion", "non_fast_forward"} <= types
    checks = next(
        rule for rule in branch["rules"] if rule["type"] == "required_status_checks"
    )["parameters"]["required_status_checks"]
    assert {item["context"] for item in checks} == {
        "release-window",
        "pytest (3.10)",
        "pytest (3.12)",
        "typescript-release",
    }
    assert tag["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
    assert {rule["type"] for rule in tag["rules"]} == {
        "deletion",
        "non_fast_forward",
        "update",
    }


def test_ruleset_apply_uses_the_shared_isolated_gate():
    source = (ROOT / "tools" / "repository_rulesets.py").read_text(encoding="utf-8")
    assert '(sys.executable, "-I", str(gate), "--action", "ruleset-update")' in source
    assert "--force" not in source
