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


def _github_canonical_branch() -> dict:
    branch = copy.deepcopy(repository_rulesets.desired_rulesets()[0])
    parameters = next(
        rule for rule in branch["rules"] if rule["type"] == "pull_request"
    )["parameters"]
    parameters.pop("automatic_copilot_code_review_enabled")
    parameters["required_reviewers"] = []
    parameters["require_extra_approval_for_unattributed_changes"] = True
    return branch


def test_github_canonical_pull_request_defaults_match_desired():
    desired = repository_rulesets.desired_rulesets()[0]
    assert repository_rulesets._matches_desired(desired, desired)
    assert repository_rulesets._matches_desired(_github_canonical_branch(), desired)


def test_weaker_or_unknown_pull_request_drift_fails_closed():
    desired = repository_rulesets.desired_rulesets()[0]

    for field, value in (
        ("require_extra_approval_for_unattributed_changes", False),
        ("required_reviewers", ["octocat"]),
        ("required_reviewers", None),
        ("automatic_copilot_code_review_enabled", True),
        ("future_unknown_control", True),
    ):
        actual = _github_canonical_branch()
        parameters = next(
            rule for rule in actual["rules"] if rule["type"] == "pull_request"
        )["parameters"]
        parameters[field] = value
        assert not repository_rulesets._matches_desired(actual, desired)


def test_security_control_drift_fails_closed():
    desired = repository_rulesets.desired_rulesets()[0]

    cases = []
    inactive = _github_canonical_branch()
    inactive["enforcement"] = "evaluate"
    cases.append(inactive)

    bypassed = _github_canonical_branch()
    bypassed["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole"}]
    cases.append(bypassed)

    non_strict = _github_canonical_branch()
    status_parameters = next(
        rule for rule in non_strict["rules"] if rule["type"] == "required_status_checks"
    )["parameters"]
    status_parameters["strict_required_status_checks_policy"] = False
    cases.append(non_strict)

    missing_check = _github_canonical_branch()
    status_parameters = next(
        rule for rule in missing_check["rules"] if rule["type"] == "required_status_checks"
    )["parameters"]
    status_parameters["required_status_checks"].pop()
    cases.append(missing_check)

    missing_rule = _github_canonical_branch()
    missing_rule["rules"] = [
        rule for rule in missing_rule["rules"] if rule["type"] != "deletion"
    ]
    cases.append(missing_rule)

    for actual in cases:
        assert not repository_rulesets._matches_desired(actual, desired)


def test_duplicate_or_malformed_pull_request_rules_fail_closed():
    desired = repository_rulesets.desired_rulesets()[0]
    duplicate = _github_canonical_branch()
    duplicate["rules"].append(
        copy.deepcopy(next(rule for rule in duplicate["rules"] if rule["type"] == "pull_request"))
    )
    malformed = _github_canonical_branch()
    next(rule for rule in malformed["rules"] if rule["type"] == "pull_request")[
        "parameters"
    ] = []

    assert not repository_rulesets._matches_desired(duplicate, desired)
    assert not repository_rulesets._matches_desired(malformed, desired)


def test_apply_does_not_update_github_canonical_equivalent(monkeypatch):
    desired_branch, desired_tag = repository_rulesets.desired_rulesets()
    current = {
        desired_branch["name"]: _github_canonical_branch(),
        desired_tag["name"]: copy.deepcopy(desired_tag),
    }
    monkeypatch.setattr(repository_rulesets, "current_rulesets", lambda _repository: current)
    monkeypatch.setattr(
        repository_rulesets,
        "_gh",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected mutation")),
    )

    repository_rulesets.apply("theDoc001/fivedrisk")
