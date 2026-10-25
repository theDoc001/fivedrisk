from __future__ import annotations

import copy
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


def test_rulesets_protect_main_history_and_release_tags():
    branch, tag = repository_rulesets.desired_rulesets()
    assert branch["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert {rule["type"] for rule in branch["rules"]} == {"deletion", "non_fast_forward"}
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


def test_security_control_drift_fails_closed():
    desired = repository_rulesets.desired_rulesets()[0]
    assert repository_rulesets._matches_desired(copy.deepcopy(desired), desired)

    inactive = copy.deepcopy(desired)
    inactive["enforcement"] = "evaluate"
    bypassed = copy.deepcopy(desired)
    bypassed["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole"}]
    missing_rule = copy.deepcopy(desired)
    missing_rule["rules"] = [r for r in missing_rule["rules"] if r["type"] != "deletion"]
    extra_rule = copy.deepcopy(desired)
    extra_rule["rules"].append({"type": "required_linear_history"})

    for actual in (inactive, bypassed, missing_rule, extra_rule):
        assert not repository_rulesets._matches_desired(actual, desired)


def test_apply_does_not_update_an_equivalent_ruleset(monkeypatch):
    desired_branch, desired_tag = repository_rulesets.desired_rulesets()
    current = {
        desired_branch["name"]: copy.deepcopy(desired_branch),
        desired_tag["name"]: copy.deepcopy(desired_tag),
    }
    monkeypatch.setattr(repository_rulesets, "current_rulesets", lambda _repository: current)
    monkeypatch.setattr(
        repository_rulesets,
        "_gh",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected mutation")),
    )

    repository_rulesets.apply("theDoc001/fivedrisk")
