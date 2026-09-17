"""5D Risk Governance Engine — CLI entry point.

Usage:
    python -m fivedrisk score '{"tool_name": "Bash", "command": "rm -rf /"}'
    python -m fivedrisk score action.json --policy policy.yaml --format json
    python -m fivedrisk log --recent 10
    python -m fivedrisk stats

Also usable as a pipe (for Claude Code plugin hooks):
    echo '$TOOL_INPUT' | python -m fivedrisk score --policy policy.yaml --format json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .classifier import classify_tool_call
from .harness import run_harness
from .logger import DecisionLog
from .policy import _RED_LINE_AXES, load_policy
from .schema import DIM_MAX, Band
from .scorer import score


def _read_input(input_arg: str | None) -> dict:
    """Read tool input from argument, file, or stdin."""
    if input_arg is None or input_arg == "-":
        raw = sys.stdin.read().strip()
    elif Path(input_arg).exists():
        raw = Path(input_arg).read_text().strip()
    else:
        raw = input_arg

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_score(args: argparse.Namespace) -> None:
    """Score a tool call and output the result."""
    policy = load_policy(args.policy)
    data = _read_input(args.input)

    # Low-1: resolve tool_name without the eager inner pop that used to strip a
    # legitimate "name" key from tool_input even when tool_name was present.
    tool_name = data.pop("tool_name", None)
    if tool_name is None:
        tool_name = data.pop("name", "Unknown")
    tool_input = data.pop("tool_input", data)

    action = classify_tool_call(
        tool_name=tool_name,
        tool_input=tool_input,
        policy=policy,
        autonomy_context=args.autonomy or 0,
        source=args.source or "cli",
    )

    result = score(action, policy)

    # Log if not --dry-run
    if not args.dry_run:
        log = DecisionLog(args.log_path)
        row_id = log.log(result)
        result_dict = result.to_dict()
        result_dict["log_id"] = row_id
    else:
        result_dict = result.to_dict()

    if args.format == "json":
        print(json.dumps(result_dict, indent=2))
    else:
        band = result.band
        print(f"[5D {band}] {result.rationale}")
        print(f"  Composite: {result.composite_score:.1f} | Max dim: {result.max_dimension}")
        dims = ", ".join(
            f"{n}={getattr(action, n)}" for n in
            ("data_sensitivity", "tool_privilege", "reversibility",
             "external_impact", "autonomy_context")
        )
        print(f"  Dims: {dims}")

    # Exit codes follow host hook semantics (Claude Code): only exit 2 BLOCKS the
    # tool call; exit 1 is a non-blocking error. RED (deny) and ORANGE (mandatory
    # approval) must therefore BOTH exit 2 — an ORANGE that exits 1 would let a
    # "requires human approval" action execute unreviewed (audit H6, decision Q7:
    # map ORANGE -> block). GREEN/YELLOW execute (0).
    from .schema import Band
    if result.band in (Band.RED, Band.ORANGE):
        if result.band == Band.ORANGE:
            print(
                "[5D ORANGE] Blocked pending human approval. This action needs "
                "explicit review before it runs; approve and re-issue if intended.",
                file=sys.stderr,
            )
        sys.exit(2)
    else:
        sys.exit(0)


def cmd_log(args: argparse.Namespace) -> None:
    """Show recent decision log entries."""
    log = DecisionLog(args.log_path)
    entries = log.query_recent(limit=args.recent)

    if args.format == "json":
        print(json.dumps(entries, indent=2, default=str))
    else:
        for entry in entries:
            print(
                f"[{entry['band']}] {entry['tool_name']} | "
                f"composite={entry['composite_score']:.1f} | "
                f"{entry['timestamp']}"
            )


def cmd_stats(args: argparse.Namespace) -> None:
    """Show decision log statistics."""
    log = DecisionLog(args.log_path)
    counts = log.count_by_band()
    total = sum(counts.values())

    if args.format == "json":
        print(json.dumps({"total": total, "by_band": counts}, indent=2))
    else:
        print(f"Total decisions: {total}")
        for band in ("GREEN", "YELLOW", "ORANGE", "RED"):
            count = counts.get(band, 0)
            pct = (count / total * 100) if total > 0 else 0
            print(f"  {band}: {count} ({pct:.1f}%)")


def _validate_policy_config(policy_path: str | None) -> list[str]:
    """Return validation errors for a policy file."""
    errors: list[str] = []
    try:
        policy = load_policy(policy_path)
    except Exception as exc:
        return [str(exc)]

    if not (policy.yellow_score <= policy.orange_score <= policy.red_score):
        errors.append("band thresholds must satisfy yellow_score <= orange_score <= red_score")
    if policy.orange_threshold > policy.red_threshold:
        errors.append("orange_threshold must be <= red_threshold")
    for name, weight in policy.weights.items():
        if weight < 0:
            errors.append(f"weight {name} must be non-negative")
    for tool_name, dims in policy.tool_defaults.items():
        for dim_name, value in dims.items():
            if value < 0 or value > 4:
                errors.append(f"tool_defaults.{tool_name}.{dim_name} must be between 0 and 4")
    for pattern, dims in policy.bash_overrides.items():
        # M5: compile the override regex key so a malformed pattern is caught at
        # `validate` time, not as a skipped override (or a crash) at runtime.
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"bash_overrides invalid regex {pattern!r}: {exc}")
        for dim_name, value in dims.items():
            if value < 0 or value > 4:
                errors.append(f"bash_overrides.{pattern}.{dim_name} must be between 0 and 4")
    for label, patterns in policy.semantic_review_patterns.items():
        if not isinstance(patterns, list):
            errors.append(f"semantic_review_patterns.{label} must be a list")
            continue
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"semantic_review_patterns.{label} invalid regex {pattern!r}: {exc}")
    # F1: an opt-in `command_regex` floor is a real regex — compile it at validate time so a
    # malformed pattern is REJECTED before deploy, never a runtime `re.error`. (`command_contains`
    # is a literal substring and needs no compile check.)
    for rule in policy.floor:
        if rule.command_regex:
            try:
                re.compile(rule.command_regex)
            except re.error as exc:
                errors.append(
                    f"floor rule for tool '{rule.tool_name}' has invalid command_regex "
                    f"{rule.command_regex!r}: {exc}"
                )
    return errors


# Band-score keys are read only from the `bands:` block; spike-threshold keys
# only from `thresholds:`. A key placed under the wrong block is silently
# ignored (the default is used), so `validate` surfaces it as a warning.
# `green_score` is intentionally NOT here: it is the "everything below yellow"
# floor (always 0.0) and load_policy never reads it from `bands:`, so warning to
# move it there would be misleading — it is inert wherever it is placed.
_BAND_SCORE_KEYS = frozenset({"yellow_score", "orange_score", "red_score"})
_THRESHOLD_KEYS = frozenset({"red_threshold", "orange_threshold"})


def _policy_placement_warnings(policy_path: str | None) -> list[str]:
    """Warn when band/threshold keys sit under the wrong YAML block.

    Catches the silent misconfiguration where an operator puts band scores
    under `thresholds:` (or spike thresholds under `bands:`): the loader
    ignores them and uses defaults, yet `validate` otherwise passes.
    """
    if policy_path is None:
        return []
    import yaml

    try:
        raw = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []  # load errors are reported by _validate_policy_config
    if not isinstance(raw, dict):
        return []

    warnings: list[str] = []
    thresholds = raw.get("thresholds") or {}
    bands = raw.get("bands") or {}
    if isinstance(thresholds, dict):
        for key in sorted(_BAND_SCORE_KEYS & set(thresholds)):
            warnings.append(
                f"'{key}' is under 'thresholds:' but band scores are read only from "
                f"'bands:' — it is being IGNORED and the default is used. "
                f"Move it under a 'bands:' block."
            )
    if isinstance(bands, dict):
        for key in sorted(_THRESHOLD_KEYS & set(bands)):
            warnings.append(
                f"'{key}' is under 'bands:' but spike thresholds are read only from "
                f"'thresholds:' — it is being IGNORED and the default is used. "
                f"Move it under a 'thresholds:' block."
            )
    return warnings


# Every top-level key `load_policy` reads. A key outside this set is accepted
# silently by the loader and has NO effect, which is how a one-letter typo of a
# real control (`max_sesion_budget_tokens`) passes `validate` while the control
# it was meant to set stays at its default. Keep in sync with `load_policy`.
_KNOWN_TOP_LEVEL_KEYS = frozenset({
    "version",
    "bands",
    "thresholds",
    "weights",
    "tool_defaults",
    "bash_overrides",
    "semantic_review_patterns",
    "floor",
    "identity_required",
    "enable_yellow_band",
    "yellow_model_escalation",
    "max_session_budget_tokens",
    "max_tool_call_budget_tokens",
    "retry_budget",
})

# Keys the loader still accepts but which no code path enforces. Declaring one
# looks like configuring a control and configures nothing, so `validate` says so
# rather than passing in silence.
# Emptied 2026-08-24: `retry_budget` is now ENFORCED (see `hooks.check_retry_budget`), so the
# one entry here was removed rather than reworded. This dict stays because the CLASS of defect
# recurs — a key the loader accepts and nothing enforces — and the next one should be declared
# here on the day it is found rather than after someone trips over it.
_ACCEPTED_BUT_UNENFORCED_KEYS: dict[str, str] = {}


def _unknown_key_warnings(policy_path: str | None) -> list[str]:
    """Warn on top-level keys the loader does not read, and on inert ones.

    A policy key that is silently ignored is worse than a rejected one: an
    operator sets it, a reviewer approves it, a change record captures it, and
    the control it names does not exist. Near-misses of real keys are called out
    by name because that is the case which costs the most to discover in
    production.
    """
    if policy_path is None:
        return []
    import difflib
    import yaml

    try:
        raw = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []  # load errors are reported by _validate_policy_config
    if not isinstance(raw, dict):
        return []

    warnings: list[str] = []
    for key in sorted(set(raw) - _KNOWN_TOP_LEVEL_KEYS):
        close = difflib.get_close_matches(key, sorted(_KNOWN_TOP_LEVEL_KEYS), n=1, cutoff=0.8)
        if close:
            warnings.append(
                f"'{key}' is not a policy key and is being IGNORED. "
                f"Did you mean '{close[0]}'?"
            )
        else:
            warnings.append(f"'{key}' is not a policy key and is being IGNORED.")
    for key, why in sorted(_ACCEPTED_BUT_UNENFORCED_KEYS.items()):
        if key in raw:
            warnings.append(f"'{key}' is accepted but NOT ENFORCED: {why}.")
    return warnings


def _floor_control_warnings(policy_path: str | None) -> list[str]:
    """Warn when a hard-control floor is gated on an evadable command_contains.

    ``command_contains`` is a best-effort, case-sensitive substring match (see
    FloorRule): an attacker can bypass it with casing, whitespace, comment
    splicing, or encoding. A floor that must ALWAYS fire — a RED/ORANGE hard or
    regulated control — should key on ``tool_name`` alone (unconditional). This
    surfaces the gap so an operator does not mistake an evadable substring floor
    for a hard control.
    """
    if policy_path is None:
        return []
    try:
        policy = load_policy(policy_path)
    except Exception:
        return []  # load errors are reported by _validate_policy_config
    warnings: list[str] = []
    for rule in policy.floor:
        if rule.command_contains and rule.band in (Band.RED, Band.ORANGE):
            warnings.append(
                f"floor rule for tool '{rule.tool_name}' enforces {rule.band.value} only "
                f"when command_contains {rule.command_contains!r} matches — that is a "
                f"best-effort, case-sensitive substring and is EVADABLE "
                f"(casing/whitespace/encoding). For an unconditional hard control, use a "
                f"tool_name-only floor (drop command_contains)."
            )
    return warnings


# Axes the raw OSS API (`Policy.matched_floor` / `score()`) cannot supply — asserted
# `data_classes` labels and `list_ref` lookups arrive only from a caller that supplies
# full context. A floor rule keyed ONLY on these no-ops silently GREEN on the raw API (F-D).
_SCORE_UNSUPPLYABLE_FLOOR_AXES = ("data_classes", "list_ref")
_FLOOR_AXIS_ATTRS = {
    "data_classes": "data_classes",
    "list_ref": "list_ref",
    "tools": "tools",
    "patterns": "patterns",
    "checksum": "checksum",
    "destinations": "destinations",
    "fields": "fields",
}


def _floor_unsupplyable_axis_warnings(policy_path: str | None) -> list[str]:
    """Warn when a floor rule is keyed ONLY on axes the raw `score()` path cannot supply.

    ``data_classes`` and ``list_ref`` need context (asserted labels, list lookups) that only a
    full-context caller supplies; on the raw OSS API they are absent, so a rule with NO other axis silently
    scores GREEN — an inert hard control the deployer believes is enforcing (F-D). Surfaced as a
    warning (not a hard error) because the identical rule DOES enforce on the full-context gate."""
    if policy_path is None:
        return []
    try:
        policy = load_policy(policy_path)
    except Exception:
        return []  # load errors are reported by _validate_policy_config
    warnings: list[str] = []
    for rule in policy.floor:
        specified = [a for a, attr in _FLOOR_AXIS_ATTRS.items() if getattr(rule, attr) is not None]
        if rule.tool_name or rule.command_contains or rule.command_regex:
            continue  # has a score()-supplyable legacy axis
        if specified and all(a in _SCORE_UNSUPPLYABLE_FLOOR_AXES for a in specified):
            rid = rule.id or rule.tool_name or "<floor>"
            warnings.append(
                f"floor rule '{rid}' is keyed only on {sorted(specified)} — the raw score()/API "
                f"cannot supply those axes, so this floor is INERT (silently GREEN) outside the "
                f"full-context gate. Add a score()-supplyable axis (tools/patterns/checksum/fields) "
                f"or enforce it on the gate path."
            )
    return warnings


# Keys `_parse_floor_rules` actually reads on a floor entry. Anything else in the mapping is
# dropped on the floor, which is the failure this list exists to make visible.
_FLOOR_ENTRY_KEYS = frozenset({
    "id", "tool_name", "band", "command_contains", "command_regex", "reason", "match",
    "value_match", *_RED_LINE_AXES,
})
#: Axis keys, plus `value_match`, are also legal nested under `match:`.
_FLOOR_MATCH_KEYS = frozenset({"value_match", *_RED_LINE_AXES})


def _floor_unknown_key_warnings(policy_path: str | None) -> list[str]:
    """Warn when a floor rule carries a key the parser does not read.

    A floor rule that also carries a recognised axis PARSES FINE with the unrecognised key simply
    dropped. Nothing raises, `validate` says valid, and the control that deploys is not the control
    the operator wrote. The commonest shape is a near-miss on an axis name — `tool_names` for
    `tools`, `pattern` for `patterns`, `data_class` for `data_classes` — and the result is a rule
    that is WIDER than intended, because the axis meant to narrow it was never compiled.

    The direction is fail-safe (a dropped axis can only widen a floor, never disable it) which is
    exactly why this is a warning and not an error, and also why it is worth surfacing: a
    fail-safe silent difference is the kind nobody discovers, because nothing ever breaks.

    Read from the RAW YAML, necessarily -- by the time the rule is a FloorRule the unknown key is
    already gone, so a check over the parsed object could never see it.
    """
    if policy_path is None:
        return []
    import yaml

    try:
        raw = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []  # load errors are reported by _validate_policy_config
    if not isinstance(raw, dict):
        return []
    entries = raw.get("floor")
    if not isinstance(entries, list):
        return []

    warnings: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("id") or entry.get("tool_name") or f"#{index}")
        for key in sorted(set(entry) - _FLOOR_ENTRY_KEYS):
            warnings.append(
                f"floor rule '{label}' has unrecognised key {key!r} — it is IGNORED, not applied. "
                f"The deployed rule is whatever remains, which is wider than what you wrote. "
                f"Recognised keys: {', '.join(sorted(_FLOOR_ENTRY_KEYS))}."
            )
        match = entry.get("match")
        if isinstance(match, dict):
            for key in sorted(set(match) - _FLOOR_MATCH_KEYS):
                warnings.append(
                    f"floor rule '{label}' has unrecognised key {key!r} under 'match:' — it is "
                    f"IGNORED, not applied. Recognised axes: "
                    f"{', '.join(sorted(_FLOOR_MATCH_KEYS))}."
                )
    return warnings


def _spike_threshold_reachability_warnings(policy_path: str | None) -> list[str]:
    """Warn when a spike threshold is set above the highest score a dimension can hold.

    Dimensions are integers clamped to [0, DIM_MAX], and the band spike rule is `any dim >=
    threshold`. So `red_threshold: 5` is not a strict policy — it is an UNREACHABLE one, and it
    silently removes the single-axis RED guarantee that a maximally dangerous dimension always
    floors the action at RED. The action then scores on the weighted total alone.

    `_validate_policy_config` already checks `orange_threshold <= red_threshold`, so the pair is
    checked for ORDER and neither is checked for REACH. An operator hardening a policy by raising a
    threshold gets the opposite of what they intended and no signal at all.

    A warning rather than an error: the config is coherent and loadable, and refusing to start on it
    would be a breaking change to any deployment already carrying one.
    """
    if policy_path is None:
        return []
    try:
        policy = load_policy(policy_path)
    except Exception:
        return []  # load errors are reported by _validate_policy_config
    warnings: list[str] = []
    for name, value, band in (("red_threshold", policy.red_threshold, "RED"),
                              ("orange_threshold", policy.orange_threshold, "ORANGE")):
        if value > DIM_MAX:
            warnings.append(
                f"{name}: {value} is above the maximum a dimension can score ({DIM_MAX}), so no "
                f"single dimension can EVER reach it. The single-axis {band} guarantee is removed "
                f"and these actions band on the weighted total alone. Use a value in "
                f"[0, {DIM_MAX}]."
            )
    return warnings


def _collect_floor_regex_patterns(policy) -> "list[tuple[str, str]]":
    """(source-label, pattern) for every regex a floor rule scans — the ReDoS-lint/audit corpus.

    Covers the ``patterns`` axis values, an opt-in ``command_regex``, and a ``value_match`` whose
    kind is ``regex``. Literal / checksum / membership axes are not regexes and are skipped."""
    corpus: list[tuple[str, str]] = []
    for rule in policy.floor:
        rid = rule.id or rule.tool_name or "<floor>"
        if rule.command_regex:
            corpus.append((f"{rid}.command_regex", rule.command_regex))
        if rule.patterns is not None:
            for p in rule.patterns.values:
                corpus.append((f"{rid}.patterns", p))
        vm = rule.value_match
        if vm is not None and vm.kind == "regex":
            for p in vm.values:
                corpus.append((f"{rid}.value_match[{vm.field}]", p))
    return corpus


def _redos_lint_warnings(policy_path: str | None) -> list[str]:
    """Warn (never reject) when a floor regex trips a classic catastrophic-backtracking shape."""
    if policy_path is None:
        return []
    try:
        policy = load_policy(policy_path)
    except Exception:
        return []  # load errors are reported by _validate_policy_config
    from .policy import lint_redos_pattern
    warnings: list[str] = []
    for label, pat in _collect_floor_regex_patterns(policy):
        for msg in lint_redos_pattern(pat):
            warnings.append(f"ReDoS lint — floor '{label}' pattern {pat!r}: {msg}")
    return warnings


def _pattern_construct_audit(policy_path: str | None) -> list[str]:
    """Inventory of non-linear constructs (backref/lookaround) in the floor regex corpus —
    the pre-work a deferred RE2 / Rust `regex` swap would have to rewrite. Reported by --audit."""
    if policy_path is None:
        return []
    try:
        policy = load_policy(policy_path)
    except Exception:
        return []
    from .policy import audit_pattern_construct
    findings: list[str] = []
    for label, pat in _collect_floor_regex_patterns(policy):
        constructs = audit_pattern_construct(pat)
        if constructs:
            findings.append(f"floor '{label}' pattern {pat!r} uses: {', '.join(constructs)}")
    return findings


def _identity_admission_warnings(policy_path: str | None) -> list[str]:
    """Warn that ``identity_required`` is unenforced on the hook/gateway/langgraph paths.

    O2: ``identity_required: true`` denies ANONYMOUS callers only on the ``@gate``
    admission path (``_perform_identity_admission``). The SDK PreToolUse hook
    (``fivedrisk_pre_tool``), the JSON-lines gateway, and the LangGraph node do NOT
    run identity admission — an operator who sets the flag expecting a hard control
    gets a silent fail-open on those surfaces. Warn only when the flag is true;
    silent when false or absent.
    """
    if policy_path is None:
        return []
    import yaml

    try:
        raw = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []  # load errors are reported by _validate_policy_config
    if not isinstance(raw, dict) or not bool(raw.get("identity_required", False)):
        return []
    return [
        "identity_required: true is enforced ONLY on the @gate admission path — the "
        "SDK-hook (fivedrisk_pre_tool), gateway, and langgraph paths do NOT run identity "
        "admission, so ANONYMOUS callers are admitted there (fail-open). Enforce identity "
        "upstream on those surfaces or route all tool calls through @gate."
    ]


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate a policy file can be loaded and has coherent basic ranges."""
    errors = _validate_policy_config(args.input)
    warnings = _policy_placement_warnings(args.input)
    warnings += _unknown_key_warnings(args.input)
    warnings += _floor_control_warnings(args.input)
    warnings += _floor_unsupplyable_axis_warnings(args.input)
    warnings += _floor_unknown_key_warnings(args.input)
    warnings += _spike_threshold_reachability_warnings(args.input)
    warnings += _identity_admission_warnings(args.input)
    warnings += _redos_lint_warnings(args.input)
    audit = _pattern_construct_audit(args.input) if getattr(args, "audit", False) else []
    payload = {
        "valid": not errors,
        "policy": args.input,
        "errors": errors,
        "warnings": warnings,
    }
    if getattr(args, "audit", False):
        payload["pattern_construct_audit"] = audit
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        if errors:
            print(f"Policy invalid: {args.input}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"Policy valid: {args.input}")
        for warning in warnings:
            print(f"  ! warning: {warning}")
        if getattr(args, "audit", False):
            if audit:
                print("  pattern-construct audit (non-linear constructs for a future RE2/rust swap):")
                for finding in audit:
                    print(f"    - {finding}")
            else:
                print("  pattern-construct audit: no backreferences or lookaround in the floor corpus")

    sys.exit(1 if errors else 0)


def cmd_scan_output(args: argparse.Namespace) -> None:
    """Scan a tool RESULT for egress leakage / injection-echo (PostToolUse).

    E1: thin wrapper over the already-shipped `fivedrisk_post_tool` egress scan.
    Reads the host hook payload JSON (carrying `tool_name` + `tool_result`) from
    stdin/arg, and BLOCKS (exit 2 — only exit 2 blocks under host hook semantics)
    when the output leaks or echoes an injection. Clean output → exit 0.
    """
    import asyncio

    from .hooks import fivedrisk_post_tool

    data = _read_input(args.input)
    tool_use_id = str(data.get("tool_use_id") or data.get("id") or "cli")
    result = asyncio.run(fivedrisk_post_tool(data, tool_use_id))

    blocked = result.get("decision") == "block"
    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif blocked:
        print(f"[5D egress block] {result.get('reason')}", file=sys.stderr)
    sys.exit(2 if blocked else 0)


def cmd_claude_hook(args: argparse.Namespace) -> None:
    """Claude Code structured hook (PreToolUse gate + PostToolUse verify-close).

    ONE command wired to both Claude Code hook events; it auto-detects the event
    from the payload's ``hook_event_name`` (defaults to PreToolUse). Unlike the
    exit-code `score`/`scan-output` commands, this emits Claude Code's structured
    output so an ORANGE routes to ``permissionDecision: "ask"`` (native human
    approval) instead of a hard deny. Emits JSON on stdout with exit 0 so Claude
    applies the decision.
    """
    from .claude_code import posttooluse_hook, pretooluse_hook

    data = _read_input(args.input)
    if not isinstance(data, dict):
        # a non-object payload is not a valid hook input → fail closed (deny)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "5D: malformed hook payload (not a JSON object)",
            }
        }, indent=2))
        sys.exit(0)
    event = data.get("hook_event_name", "PreToolUse")
    if event == "PostToolUse":
        hook_output, _ = posttooluse_hook(data)
    else:
        policy = load_policy(args.policy)
        log = None if args.dry_run else DecisionLog(args.log_path)
        hook_output, _ = pretooluse_hook(data, policy, log)

    print(json.dumps(hook_output, indent=2))
    sys.exit(0)


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Run the offline runtime validation benchmark pack."""
    summary = run_harness(args.log_path).to_dict(include_results=args.include_results)
    output_format = getattr(args, "benchmark_format", None) or args.format

    if output_format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("5D runtime benchmark")
        print(f"  Evaluation: {summary['evaluation_mode']}")
        print(f"  Mission verdict: {summary['mission_verdict']}")
        print(f"  Total: {summary['total']}")
        print(f"  Passed: {summary['passed']}")
        print(f"  Failed: {summary['failed']}")
        print(f"  Pass rate: {summary['pass_rate'] * 100:.1f}%")
        print(
            "  Controls: "
            f"{summary['control_counts'].get('positive', 0)} positive, "
            f"{summary['control_counts'].get('negative', 0)} negative"
        )
        print("  Observed outcomes:")
        for outcome, count in sorted(summary["observed_outcomes"].items()):
            print(f"    - {outcome}: {count}")
        if summary["failures"]:
            print("  Failures:")
            for failure in summary["failures"]:
                print(f"    - {failure['suite']}::{failure['case']}")
        print("  Claim limit: built-in deterministic scenarios are expectation checks, not open-ended proof.")

    sys.exit(1 if summary["failed"] else 0)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="fivedrisk",
        description="5D Risk Governance Engine — per-action risk scoring for AI agents",
    )
    parser.add_argument(
        "--policy", type=str, default=None,
        help="Path to policy.yaml (default: built-in)",
    )
    parser.add_argument(
        "--log-path", type=str, default=None,
        help="Path to SQLite decision log (default: fivedrisk_decisions.db)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # score
    p_score = subparsers.add_parser("score", help="Score a tool call")
    p_score.add_argument("input", nargs="?", default=None, help="JSON string, file, or - for stdin")
    p_score.add_argument("--autonomy", type=int, default=0, help="Autonomy context (0-4)")
    p_score.add_argument("--source", type=str, default="cli", help="Action source")
    p_score.add_argument("--dry-run", action="store_true", help="Score without logging")
    p_score.set_defaults(func=cmd_score)

    # log
    p_log = subparsers.add_parser("log", help="Show recent decisions")
    p_log.add_argument("--recent", type=int, default=20, help="Number of entries")
    p_log.set_defaults(func=cmd_log)

    # stats
    p_stats = subparsers.add_parser("stats", help="Decision log statistics")
    p_stats.set_defaults(func=cmd_stats)

    # validate
    # scan-output (PostToolUse egress scan)
    p_scan = subparsers.add_parser(
        "scan-output",
        help="Scan a tool result for egress leakage / injection-echo (blocks exit 2)",
    )
    p_scan.add_argument("input", nargs="?", default=None, help="Hook payload JSON (default: stdin)")
    p_scan.set_defaults(func=cmd_scan_output)

    # claude-hook (structured PreToolUse gate + PostToolUse verify-close)
    p_claude = subparsers.add_parser(
        "claude-hook",
        help="Claude Code structured hook: PreToolUse gate (ORANGE→ask) + PostToolUse verify",
    )
    p_claude.add_argument("input", nargs="?", default=None, help="Hook payload JSON (default: stdin)")
    p_claude.add_argument("--dry-run", action="store_true", help="Do not write the decision log")
    p_claude.set_defaults(func=cmd_claude_hook)

    p_validate = subparsers.add_parser("validate", help="Validate a policy file")
    p_validate.add_argument("input", nargs="?", default=None, help="Policy path (default: built-in)")
    p_validate.add_argument(
        "--audit", action="store_true",
        help="Inventory non-linear regex constructs (backref/lookaround) in the floor corpus",
    )
    p_validate.set_defaults(func=cmd_validate)

    # benchmark
    p_benchmark = subparsers.add_parser(
        "benchmark",
        help="Run the offline runtime benchmark suite",
    )
    p_benchmark.add_argument(
        "--format",
        dest="benchmark_format",
        choices=["text", "json"],
        default=None,
        help="Output format for benchmark results",
    )
    p_benchmark.add_argument(
        "--include-results",
        action="store_true",
        help="Include per-scenario harness results in JSON output",
    )
    p_benchmark.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
