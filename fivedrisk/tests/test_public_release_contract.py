"""Population-level checks for public install, policy, and typing claims."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

from fivedrisk.policy import load_policy
from fivedrisk.schema import Action, Band
from fivedrisk.scorer import score
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
        index for index, line in enumerate(lines)
        if line.strip().removeprefix("- ") == f"name: {step_name}"
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


def test_public_python_install_commands_use_isolated_mode():
    offenders = []
    for path in _public_instruction_files():
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if re.search(r"-m\s+pip\s+install\s+[\"']?fivedrisk", line):
                if " -I -m pip install " not in line:
                    offenders.append(f"{path.relative_to(ROOT)}: {line.strip()}")
    assert not offenders, f"non-isolated fivedrisk installs: {offenders}"


def test_gateway_claims_are_bounded_and_protocol_is_public():
    root = (ROOT / "README.md").read_text(encoding="utf-8")
    package = (ROOT / "fivedrisk" / "README.md").read_text(encoding="utf-8")
    protocol = (ROOT / "docs" / "gateway-protocol.md").read_text(encoding="utf-8")
    combined = root + package
    assert "governance parity" not in combined.lower()
    assert "| Surface | Input scans | Session drift |" in root
    for required in (
        "protocol_version", "engine_version", "unique `id`", "Exact `ORANGE`",
        "timeout", "EOF", "UnsupportedPolicyControls", "--log-path",
    ):
        assert required in protocol


def test_public_install_commands_pin_skill_cli_source_and_node_client():
    prose = "\n".join(
        path.read_text(encoding="utf-8") for path in _public_instruction_files()
    )
    assert "npx skills add" not in prose
    assert "npx --yes skills add" not in prose
    assert "skills@1.7.2" in prose
    assert "--branch v0.7.1" in prose
    assert "npm install fivedrisk-gateway\n" not in prose
    assert "fivedrisk-gateway@0.7.1" in prose


def test_framework_and_script_support_claims_are_bounded():
    root = (ROOT / "README.md").read_text(encoding="utf-8")
    plugin = (ROOT / "fivedrisk-plugin" / "README.md").read_text(encoding="utf-8")
    adapters = (
        ROOT / "fivedrisk-plugin" / "skills" / "fivedrisk-setup" /
        "references" / "adapters.md"
    ).read_text(encoding="utf-8")
    assert "provisional adapters" in root
    assert "tested with local fakes" in adapters
    assert "Native Windows without WSL is not supported" in plugin


def test_skill_shell_examples_do_not_use_angle_bracket_assignments():
    skill = (
        ROOT / "fivedrisk-plugin" / "skills" / "fivedrisk-setup" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert "FIVEDRISK_SURFACE=<" not in skill


def test_public_presets_do_not_document_removed_configure_arguments():
    preset = (
        ROOT / "fivedrisk" / "policies" / "presets" / "customer_data.yaml"
    ).read_text(encoding="utf-8")
    assert "enforce_destination_policy" not in preset


def test_python_ci_exercises_the_noneditable_installed_distribution():
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert 'pip install -e' not in workflow
    assert 'python -m pip install ".[langgraph,dev]"' in workflow
    assert workflow.count("working-directory: ${{ runner.temp }}") >= 2
    assert 'Path(fivedrisk.__file__).resolve().parent' in workflow
    assert 'metadata.distribution("fivedrisk").locate_file("fivedrisk")' in workflow
    assert 'python -I -m pytest "$GITHUB_WORKSPACE/fivedrisk/tests"' in workflow
    assert "--import-mode=importlib" in workflow


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
    skill_files = sorted(skills_root.glob("*/SKILL.md"))
    assert [path.parent.name for path in skill_files] == ["fivedrisk-setup"]
    frontmatter = skill_files[0].read_text(encoding="utf-8").split("---", 2)[1]
    assert "  version: 0.7.1" in frontmatter
    assert "internal:" not in frontmatter
    shipped_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "fivedrisk-plugin").rglob("*.md")
    ).lower()
    assert "composite >= 8.0" not in shipped_text
    assert "data sensitivity: 1.0" not in shipped_text


def test_plugin_starter_policy_explicitly_uses_default_folded_yellow_behavior():
    path = ROOT / "fivedrisk-plugin" / "policy.yaml"
    policy = load_policy(str(path))
    moderate = Action(
        tool_name="TestTool",
        data_sensitivity=0,
        tool_privilege=1,
        reversibility=2,
        external_impact=2,
        autonomy_context=2,
    )

    assert "enable_yellow_band: false" in path.read_text(encoding="utf-8")
    assert policy.enable_yellow_band is False
    assert score(moderate, policy).band is Band.GREEN
    policy.enable_yellow_band = True
    assert score(moderate, policy).band is Band.YELLOW


def test_readme_does_not_present_an_observer_as_a_shipped_default_route():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    opening = readme.split("## What it scores", 1)[0]

    assert "YELLOW ─► LLM scanner" not in opening
    assert "does not bundle or invoke a semantic scanner" in opening
    assert "YELLOW is opt-in" in opening


def test_openai_presentation_and_onboarding_are_complete_in_both_formats():
    root = ROOT / "fivedrisk-plugin"
    portable = json.loads((root / "plugin.json").read_text())
    compat = json.loads((root / ".codex-plugin" / "plugin.json").read_text())
    metadata = portable["extensions"]["com.openai"]
    assert metadata["interface"] == compat["interface"]
    for manifest in (portable, compat):
        extension = manifest["extensions"]["com.openai"]
        assert extension["onboardingSkill"] == "./skills/fivedrisk-setup/SKILL.md"
        assert (root / extension["onboardingSkill"]).is_file()
        assert "hooks" not in extension
    interface = metadata["interface"]
    assert 1 <= len(interface["displayName"]) <= 30
    assert 1 <= len(interface["shortDescription"]) <= 30
    assert 1 <= len(interface["longDescription"]) <= 4000
    assert interface["category"] == "Developer Tools"
    assert interface["defaultPrompt"]
    for key in ("logo", "composerIcon"):
        assert interface[key].startswith("./assets/")
        assert (root / interface[key]).is_file()
    import xml.etree.ElementTree as ET
    icon = ET.parse(root / interface["logo"]).getroot()
    assert icon.tag.endswith("svg")
    assert int(icon.attrib["width"]) == int(icon.attrib["height"]) >= 48


def test_publisher_builds_both_plugin_variants_before_checksums_and_attestation():
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text()
    build = _workflow_run_block(publish, "Build one source-bound, checksum-verified artifact set")
    assert build.count('--git-ref "$GITHUB_SHA"') == 2
    for variant in ("public", "manual"):
        assert f"--variant {variant}" in build
        assert f"dist/fivedrisk-plugin-{variant}-${{{{ steps.metadata.outputs.version }}}}.zip" in build
    assert build.index("--variant manual") < build.index("tools/artifact_checksums.py --write")
    assert 'subject-path: "dist/*"' in publish
    assert 'gh release create "v$VERSION" dist/*' in publish


def test_external_github_actions_are_pinned_to_full_commit_shas():
    offenders = []
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match or match.group(1).startswith("./"):
                continue
            reference = match.group(1).rsplit("@", 1)[-1]
            if not re.fullmatch(r"[0-9a-f]{40}", reference):
                offenders.append(f"{workflow.name}: {line.strip()}")
    assert not offenders, f"mutable external action refs: {offenders}"


def test_public_reproducibility_claims_are_bounded():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    controls = (ROOT / "docs" / "release-controls.md").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "two reproducible measurement surfaces" not in readme
    assert "one reproducible artifact set" not in controls
    assert "NOT A COMPLETE LOCK" in requirements


def test_typescript_readme_exports_a_canonical_absolute_interpreter():
    readme = (ROOT / "clients" / "typescript" / "README.md").read_text(
        encoding="utf-8"
    )
    canonicalize = 'PYTHON_BIN="$("$PYTHON_BIN" -I -c \'import sys; print(sys.executable)\')"'
    assert readme.index(canonicalize) < readme.index(
        'export FIVEDRISK_PYTHON="$PYTHON_BIN"'
    )


def test_agent_instructions_route_every_publication_class_to_one_gate():
    instructions = (ROOT / "docs" / "release-controls.md").read_text(encoding="utf-8")
    required = (
        "entire repository",
        "python3 -I tools/release_window.py",
        "configured publication window",
        "written approval",
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
    assert publish.count("workflow_dispatch:") == 1
    assert "schedule:" not in publish
    assert "cron:" not in publish
    dispatch = publish.split("workflow_dispatch:", 1)[1].split("permissions:", 1)[0]
    assert "candidate_sha:" in dispatch
    assert "required: true" in dispatch
    assert "default:" not in dispatch
    assert publish.count(
        "steps.metadata.outputs.version != '' && steps.state.outputs.pypi != 'matching-complete'"
    ) == 2
    assert publish.count("tools/release_window.py") == 1
    assert publish.index("tools/release_window.py") < publish.index("id: metadata")
    assert "environment: release" in publish
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
    assert "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be" in publish
    assert publish.index("pypa/gh-action-pypi-publish") < publish.index(
        'git push origin "v$VERSION"'
    )
    assert publish.index('git push origin "v$VERSION"') < publish.index(
        "gh release create"
    )
    assert "vars." not in publish
    assert 'test "$GITHUB_EVENT_NAME" = \'workflow_dispatch\'' in publish
    assert 'test "$GITHUB_REF" = \'refs/heads/main\'' in publish
    assert 'test "$GITHUB_ACTOR" = "$REPOSITORY_OWNER"' in publish
    assert 'test "$TRIGGERING_ACTOR" = "$REPOSITORY_OWNER"' in publish
    assert 'test "$DISPATCH_CANDIDATE_SHA" = "$GITHUB_SHA"' in publish


def test_publish_metadata_gate_accepts_only_the_cleared_main_tree(tmp_path):
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    script = _workflow_run_block(
        publish, "Bind the dispatch to the approved main commit"
    )
    sha, tree = subprocess.run(
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    base = os.environ.copy()
    base.update(
        {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": sha,
            "GITHUB_ACTOR": "theDoc001",
            "REPOSITORY_OWNER": "theDoc001",
            "TRIGGERING_ACTOR": "theDoc001",
            "DISPATCH_CANDIDATE_SHA": sha,
            "GITHUB_OUTPUT": str(tmp_path / "output"),
            "GITHUB_ENV": str(tmp_path / "environment"),
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
        ("GITHUB_EVENT_NAME", "schedule"),
        ("GITHUB_REF", "refs/heads/release/0.7.1"),
        ("DISPATCH_CANDIDATE_SHA", ""),
        ("DISPATCH_CANDIDATE_SHA", "0" * 40),
        ("GITHUB_ACTOR", "not-owner"),
        ("TRIGGERING_ACTOR", "not-owner"),
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

    for candidate in ("qa-subject", "HEAD", "0" * 40, tree):
        denied_environment = base | {
            "DISPATCH_CANDIDATE_SHA": candidate,
            "GITHUB_OUTPUT": str(tmp_path / f"denied-sha-{candidate}"),
        }
        denied = subprocess.run(
            ("bash", "-eu", "-o", "pipefail", "-c", script), cwd=ROOT,
            env=denied_environment, capture_output=True, text=True, check=False,
        )
        assert denied.returncode != 0, candidate
        assert not Path(denied_environment["GITHUB_OUTPUT"]).exists(), candidate


def test_release_workflows_pin_benchmark_runtime_to_baseline():
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    bench = (ROOT / ".github" / "workflows" / "bench.yml").read_text(
        encoding="utf-8"
    )
    baseline = json.loads(
        (ROOT / "benchmarks" / "baselines" / "main.json").read_text(
            encoding="utf-8"
        )
    )

    assert "tomllib" not in publish
    assert "sed -n '/^\\[project\\]$/,/^\\[/" in publish
    assert f'python-version: "{baseline["env"]["python"]}"' in bench


def test_benchmark_workflow_pairs_frozen_base_and_candidate():
    bench = (ROOT / ".github" / "workflows" / "bench.yml").read_text(
        encoding="utf-8"
    )

    assert "github.event.pull_request.base.sha" in bench
    assert "github.event.pull_request.head.sha" in bench
    assert "EVIDENCE: ${{ runner.temp }}" not in bench
    assert 'root="$RUNNER_TEMP/fivedrisk-paired-bench-$GITHUB_RUN_ID"' in bench
    assert bench.count("persist-credentials: false") >= 2
    assert 'git -C "$BASE_TREE" rev-parse HEAD' in bench
    assert 'git -C "$CANDIDATE_TREE" rev-parse HEAD' in bench
    assert "pip install -e" not in bench
    assert "pip freeze --all" in bench
    assert "grep -Eiv '^fivedrisk(==|[[:space:]]+@)'" in bench
    assert "diff -u" in bench
    assert "seq -w 1 12" in bench
    assert 'design="abba"' in bench
    assert 'subjects="base candidate candidate base"' in bench
    assert 'subjects="candidate base base candidate"' in bench
    assert "--runs 1 --json" in bench
    assert "aggregate_paired_results.py" in bench
    assert "check_regression.py" in bench
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in bench
    assert 'cp "$BASE_TREE/benchmarks/bench_ci.py"' in bench
    assert 'cp "$BASE_TREE/benchmarks/check_regression.py"' in bench
    assert 'cp "$BASE_TREE/benchmarks/aggregate_paired_results.py"' in bench
    assert 'cp "$CANDIDATE_TREE/benchmarks/check_regression.py"' not in bench
    assert 'cp "$CANDIDATE_TREE/benchmarks/aggregate_paired_results.py"' not in bench
    assert "ast.dump" in bench
    assert bench.count("--threshold 0.30 --min-abs-us 25") == 1
    assert "positive-control-current.json" in bench
    assert "unexpectedly accepted synthetic slowdown" in bench
    assert "AGGREGATE_STATUS" in bench
    assert 'test "$AGGREGATE_STATUS" -eq 0' in bench


def test_benchmark_driver_documents_the_enforced_dual_threshold():
    driver = (ROOT / "benchmarks" / "bench_ci.py").read_text(encoding="utf-8")
    assert "more than 20%" not in driver
    assert "greater than 30%" in driver
    assert "greater than 25" in driver
