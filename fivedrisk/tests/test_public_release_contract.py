"""Population-level checks for public install, policy, and typing claims."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

from fivedrisk.cli import (
    _floor_control_warnings,
    _floor_unknown_key_warnings,
    _floor_unsupplyable_axis_warnings,
    _identity_admission_warnings,
    _policy_placement_warnings,
    _redos_lint_warnings,
    _spike_threshold_reachability_warnings,
    _unknown_key_warnings,
    _validate_policy_config,
)


ROOT = Path(__file__).resolve().parents[2]
PROVENANCE_MARKERS = (
    'd.distribution("fivedrisk")',
    'PathFinder.find_spec("fivedrisk"',
)


def _public_instruction_files() -> list[Path]:
    files = [ROOT / "README.md", ROOT / "fivedrisk" / "README.md"]
    files.extend((ROOT / "docs").rglob("*.md"))
    files.extend((ROOT / "clients").rglob("*.md"))
    files.extend((ROOT / "examples").glob("*.md"))
    files.extend((ROOT / "examples").glob("*.py"))
    files.extend((ROOT / "fivedrisk-plugin").rglob("*.md"))
    return sorted(set(files))


def _markdown_fences(text: str, language: str) -> list[str]:
    return re.findall(rf"```{language}\s*\n(.*?)```", text, re.DOTALL)


def _workflow_run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_index = next(
        index for index, line in enumerate(lines) if line.strip() == f"name: {step_name}"
    )
    run_index = next(
        index
        for index in range(name_index + 1, len(lines))
        if lines[index].strip() == "run: |"
    )
    indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    body: list[str] = []
    for line in lines[run_index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def test_every_public_install_workflow_verifies_provenance_first():
    offenders: list[str] = []
    for path in _public_instruction_files():
        text = path.read_text(encoding="utf-8")
        blocks = _markdown_fences(text, "bash") if path.suffix == ".md" else [text]
        for index, block in enumerate(blocks, start=1):
            if not re.search(r"-m\s+pip\s+install\s+[\"']?fivedrisk", block):
                continue
            has_inline_check = all(marker in block for marker in PROVENANCE_MARKERS)
            has_skill_check = "verify-install.sh" in block
            if not (has_inline_check or has_skill_check):
                offenders.append(f"{path.relative_to(ROOT)} block {index}")
                continue
            first_package_execution = re.search(
                r"(?:import\s+fivedrisk|(?:^|\s)-m\s+fivedrisk(?:\.|\s)|"
                r"examples/[A-Za-z0-9_.-]+\.py)",
                block,
                re.MULTILINE,
            )
            check_positions = [
                position
                for marker in (*PROVENANCE_MARKERS, "verify-install.sh")
                if (position := block.find(marker)) >= 0
            ]
            assert check_positions
            if first_package_execution and min(check_positions) > first_package_execution.start():
                offenders.append(f"{path.relative_to(ROOT)} block {index} executes first")
    assert not offenders, f"install workflows without provenance-first verification: {offenders}"


def test_every_published_policy_fence_validates_without_warnings(tmp_path):
    offenders: dict[str, list[str]] = {}
    fence_number = 0
    for path in _public_instruction_files():
        if path.suffix != ".md":
            continue
        for index, block in enumerate(_markdown_fences(path.read_text(encoding="utf-8"), "yaml"), start=1):
            if "# policy.yaml" not in block:
                continue
            fence_number += 1
            policy_path = tmp_path / f"policy-{fence_number}.yaml"
            policy_path.write_text(block, encoding="utf-8")
            problems = _validate_policy_config(str(policy_path))
            problems += _policy_placement_warnings(str(policy_path))
            problems += _unknown_key_warnings(str(policy_path))
            problems += _floor_control_warnings(str(policy_path))
            problems += _floor_unsupplyable_axis_warnings(str(policy_path))
            problems += _floor_unknown_key_warnings(str(policy_path))
            problems += _spike_threshold_reachability_warnings(str(policy_path))
            problems += _identity_admission_warnings(str(policy_path))
            problems += _redos_lint_warnings(str(policy_path))
            if problems:
                offenders[f"{path.relative_to(ROOT)} fence {index}"] = problems
    assert not offenders, f"published policy fences have errors or warnings: {offenders}"


def test_typed_classifier_has_packaged_marker():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    marker = ROOT / "fivedrisk" / "py.typed"
    assert ("Typing :: Typed" in pyproject) == marker.is_file()
    assert 'fivedrisk = ["py.typed",' in pyproject


def test_portable_and_codex_manifests_share_identity_and_are_host_honest():
    plugin_root = ROOT / "fivedrisk-plugin"
    portable_path = plugin_root / "plugin.json"
    fallback_path = plugin_root / ".codex-plugin" / "plugin.json"
    claude_path = plugin_root / ".claude-plugin" / "plugin.json"
    portable = json.loads(portable_path.read_text(encoding="utf-8"))
    fallback = json.loads(fallback_path.read_text(encoding="utf-8"))
    claude = json.loads(claude_path.read_text(encoding="utf-8"))

    assert portable["$schema"] == (
        "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
    )
    assert set(portable) <= {
        "$schema",
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "extensions",
    }
    assert "$schema" not in fallback
    for field in (
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
    ):
        assert portable[field] == fallback[field]
    assert portable["version"] == fallback["version"] == claude["version"] == "0.7.1"
    portable_prose = json.dumps(portable).lower()
    codex_prose = json.dumps(fallback).lower()
    assert "pretooluse" not in portable_prose
    assert "posttooluse" not in portable_prose
    assert "intercept" not in portable_prose
    assert "pretooluse" not in codex_prose
    assert "posttooluse" not in codex_prose
    assert "intercept" not in codex_prose
    assert fallback["interface"]["capabilities"] == [
        "Advisory",
        "Configuration",
        "Verification",
    ]
    assert "claude code" in claude["description"].lower()


def test_plugin_auto_discovers_only_the_consultant_skill():
    skills_root = ROOT / "fivedrisk-plugin" / "skills"
    skills = sorted(path.parent.name for path in skills_root.glob("*/SKILL.md"))
    assert skills == ["fivedrisk-setup"]
    shipped_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "fivedrisk-plugin").rglob("*.md")
    ).lower()
    assert "composite >= 8.0" not in shipped_text
    assert "data sensitivity: 1.0" not in shipped_text


def test_typescript_readme_exports_a_canonical_absolute_interpreter():
    readme = (ROOT / "clients" / "typescript" / "README.md").read_text(
        encoding="utf-8"
    )
    canonicalize = 'PYTHON_BIN="$("$PYTHON_BIN" -I -c \'import sys; print(sys.executable)\')"'
    assert readme.index(canonicalize) < readme.index(
        'export FIVEDRISK_PYTHON="$PYTHON_BIN"'
    )


def test_agent_instructions_route_every_publication_class_to_one_gate():
    instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    required = (
        "entire repository",
        "python3 -I tools/release_window.py",
        "Europe/Tirane",
        "19:00 inclusive through 07:00 exclusive",
        "pushing any branch or tag",
        "GitHub release",
        "package to any registry",
        "plugin, skill, or marketplace listing",
        "workflow",
        "--no-verify",
        "git config --get core.hooksPath",
        "tools/install_release_controls.py",
    )
    for phrase in required:
        assert phrase in instructions


def test_release_workflows_have_no_time_bypass_and_recheck_mutations():
    gate = (ROOT / ".github" / "workflows" / "release-gate.yml").read_text(
        encoding="utf-8"
    )
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    combined = (gate + publish).lower()
    assert "--force" not in combined
    assert 'cron: "5 17 * * *"' in publish
    assert 'cron: "5 18 * * *"' in publish
    assert "workflow_dispatch" not in publish
    assert "steps.slot.outputs.active == 'true'" in publish
    assert 'elif [ "$status" -eq 3 ]' in publish
    assert publish.count(
        "steps.metadata.outputs.version != '' && steps.state.outputs.pypi != 'matching-complete'"
    ) == 3
    assert "python -I tools/release_window.py" in gate
    assert "python3 -I tools/release_window.py" in publish
    assert "npm run test:release" in publish
    assert "build==1.5.0" in publish
    assert "setuptools==82.0.1" in publish
    assert "wheel==0.47.0" in publish
    assert "python -m build --no-isolation" in publish
    assert "tools/normalize_sdist.py" in publish
    assert "tools/build_plugin_archive.py" in publish
    assert '--git-ref "$GITHUB_SHA"' in publish
    assert "actions/attest-build-provenance@v2" in publish
    assert publish.index("--action package-publish") < publish.index(
        "pypa/gh-action-pypi-publish"
    )
    assert publish.index("--action attestation") < publish.index(
        "actions/attest-build-provenance@v2"
    )
    assert publish.index("--action tag") < publish.index('git push origin "v$VERSION"')
    assert publish.index("--action github-release") < publish.index("gh release create")
    assert publish.index("pypa/gh-action-pypi-publish") < publish.index(
        'git push origin "v$VERSION"'
    )
    assert publish.index('git push origin "v$VERSION"') < publish.index(
        "gh release create"
    )
    assert "FIVEDRISK_RELEASE_CANDIDATE_SHA" in publish
    assert "FIVEDRISK_QA_VERDICT_SHA" in publish
    assert "FIVEDRISK_RELEASE_CANDIDATE_TREE" in publish
    assert "FIVEDRISK_QA_VERDICT_TREE" in publish
    assert 'test "$GITHUB_EVENT_NAME" = \'schedule\'' in publish
    assert 'test "$GITHUB_REF" = \'refs/heads/main\'' in publish
    assert 'test "$RELEASE_CANDIDATE_SHA" = "$QA_VERDICT_SHA"' in publish
    assert 'test "$RELEASE_CANDIDATE_TREE" = "$QA_VERDICT_TREE"' in publish
    assert (
        'test "$RELEASE_CANDIDATE_TREE" = "$(git rev-parse '
        '\"$GITHUB_SHA^{tree}\")"'
    ) in publish


def test_publish_metadata_gate_accepts_only_the_cleared_main_tree(tmp_path):
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    script = _workflow_run_block(
        publish, "Bind merged main to the independently cleared tree"
    )
    tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    base = os.environ.copy()
    base.update(
        {
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "HEAD",
            "GITHUB_OUTPUT": str(tmp_path / "output"),
            "GITHUB_ENV": str(tmp_path / "environment"),
            "RELEASE_CANDIDATE_SHA": "qa-subject",
            "QA_VERDICT_SHA": "qa-subject",
            "RELEASE_CANDIDATE_TREE": tree,
            "QA_VERDICT_TREE": tree,
        }
    )

    accepted = subprocess.run(
        ("bash", "-eu", "-o", "pipefail", "-c", script),
        cwd=ROOT,
        env=base,
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stderr

    for key, value in (
        ("QA_VERDICT_TREE", ""),
        ("RELEASE_CANDIDATE_TREE", "0" * 40),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REF", "refs/heads/release/0.7.1"),
    ):
        denied_environment = base | {key: value}
        denied_environment["GITHUB_OUTPUT"] = str(tmp_path / f"denied-{key}")
        denied_environment["GITHUB_ENV"] = str(tmp_path / f"denied-env-{key}")
        denied = subprocess.run(
            ("bash", "-eu", "-o", "pipefail", "-c", script),
            cwd=ROOT,
            env=denied_environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert denied.returncode != 0, key
        assert not Path(denied_environment["GITHUB_OUTPUT"]).exists(), key
