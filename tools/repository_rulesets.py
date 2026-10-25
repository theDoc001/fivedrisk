#!/usr/bin/env python3
"""Idempotently verify or apply fivedrisk GitHub repository rulesets."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path


RULESET_NAMES = {
    "branch": "fivedrisk protected publication path",
    "tag": "fivedrisk immutable release tags",
}


def desired_rulesets() -> list[dict]:
    return [
        {
            "name": RULESET_NAMES["branch"],
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
            ],
        },
        {
            "name": RULESET_NAMES["tag"],
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "update"},
            ],
        },
    ]


def _gh(repository: str, *args: str, stdin: str | None = None) -> str:
    result = subprocess.run(
        ("gh", "api", f"repos/{repository}/rulesets", *args),
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "GitHub ruleset API failed")
    return result.stdout


def _normalized(ruleset: dict) -> dict:
    return {
        key: ruleset[key]
        for key in ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
    }


def _matches_desired(existing: dict, desired: dict) -> bool:
    """Accept only explicitly classified GitHub response canonicalization."""

    try:
        actual = copy.deepcopy(_normalized(existing))
    except (KeyError, TypeError):
        return False
    rules = actual.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        return False
    pull_requests = [rule for rule in rules if rule.get("type") == "pull_request"]
    if len(pull_requests) > 1:
        return False
    if pull_requests:
        parameters = pull_requests[0].get("parameters")
        if not isinstance(parameters, dict):
            return False
        parameters.setdefault("automatic_copilot_code_review_enabled", False)
        if parameters.get("required_reviewers") == []:
            parameters.pop("required_reviewers")
        if parameters.get("require_extra_approval_for_unattributed_changes") is True:
            parameters.pop("require_extra_approval_for_unattributed_changes")
    try:
        return actual == _normalized(desired)
    except (KeyError, TypeError):
        return False


def current_rulesets(repository: str) -> dict[str, dict]:
    summary = json.loads(_gh(repository))
    if not isinstance(summary, list):
        raise RuntimeError("GitHub ruleset list is ambiguous")
    current: dict[str, dict] = {}
    for item in summary:
        name = item.get("name")
        if name not in RULESET_NAMES.values():
            continue
        if name in current or not isinstance(item.get("id"), int):
            raise RuntimeError(f"duplicate or invalid managed ruleset: {name}")
        detail = subprocess.run(
            ("gh", "api", f"repos/{repository}/rulesets/{item['id']}"),
            text=True,
            capture_output=True,
            check=False,
        )
        if detail.returncode:
            raise RuntimeError(detail.stderr.strip() or "GitHub ruleset read failed")
        current[name] = json.loads(detail.stdout)
    return current


def verify(repository: str) -> None:
    current = current_rulesets(repository)
    for desired in desired_rulesets():
        existing = current.get(desired["name"])
        if existing is None or not _matches_desired(existing, desired):
            raise RuntimeError(f"ruleset is missing or differs: {desired['name']}")


def _gate_mutation() -> None:
    gate = Path(__file__).with_name("release_window.py")
    decision = subprocess.run(
        (sys.executable, "-I", str(gate), "--action", "ruleset-update"), check=False
    )
    if decision.returncode:
        raise RuntimeError("release-window gate denied ruleset mutation")


def apply(repository: str) -> None:
    current = current_rulesets(repository)
    for desired in desired_rulesets():
        payload = json.dumps(desired, separators=(",", ":"))
        existing = current.get(desired["name"])
        if existing is None:
            _gate_mutation()
            _gh(repository, "--method", "POST", "--input", "-", stdin=payload)
        elif not _matches_desired(existing, desired):
            _gate_mutation()
            result = subprocess.run(
                (
                    "gh",
                    "api",
                    f"repos/{repository}/rulesets/{existing['id']}",
                    "--method",
                    "PUT",
                    "--input",
                    "-",
                ),
                input=payload,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "GitHub ruleset update failed")
    verify(repository)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    args = parser.parse_args(argv)
    if not args.repository or "/" not in args.repository:
        parser.error("--repository OWNER/REPOSITORY is required")
    try:
        if args.apply:
            apply(args.repository)
        else:
            verify(args.repository)
        print("OK: managed repository rulesets match the release contract")
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
