"""5D Risk Governance Engine — Tool-call classifier.

Maps a raw tool call (tool name + input dict) into a fully-scored
Action by combining policy baselines, bash overrides, and content
heuristics.

The classifier is intentionally conservative: when in doubt, it
bumps dimensions UP (toward ASK), never down.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from .policy import Policy
from .schema import DIMENSION_NAMES, Action


# ─── Content heuristics ────────────────────────────────────────

# Patterns that suggest sensitive data in tool input
_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(password|secret|token|api[_-]?key|credential)", "data_sensitivity"),
    (r"(?i)(ssn|social.?security|passport|credit.?card)", "data_sensitivity"),
    (r"(?i)\.(env|pem|key|p12|pfx)(\b|$)", "data_sensitivity"),
]

# Patterns that suggest external impact in tool input
_EXTERNAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(email|smtp|sendgrid|mailgun|ses\.)", "external_impact"),
    (r"(?i)(publish|deploy|release|broadcast)", "external_impact"),
    (r"(?i)(slack|discord|teams|webhook)", "external_impact"),
]

# Patterns that suggest irreversibility
_IRREVERSIBLE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(delete|remove|drop|truncate|purge)", "reversibility"),
    (r"(?i)(push\s+--force|reset\s+--hard)", "reversibility"),
    (r"(?i)(format|wipe|shred)", "reversibility"),
]

# Bash commands that indicate network access
_NETWORK_BASH_PATTERNS = [
    r"(?i)(curl|wget|ssh|scp|rsync|nc\b|ncat|telnet)",
    r"(?i)(docker\s+push|git\s+push|npm\s+publish)",
]


def _scan_content(text: str, patterns: list[tuple[str, str]]) -> Dict[str, int]:
    """Scan text for patterns, return dimension bumps (max 1 bump per dim)."""
    bumps: Dict[str, int] = {}
    for pattern, dim in patterns:
        if re.search(pattern, text):
            bumps[dim] = max(bumps.get(dim, 0), 1)
    return bumps


def classify_tool_call(
    tool_name: str,
    tool_input: Dict[str, Any],
    policy: Policy | None = None,
    autonomy_context: int = 0,
    source: str = "unknown",
) -> Action:
    """Classify a raw tool call into a scored 5D Action.

    Steps:
        1. Start from policy's tool baseline for this tool name.
        2. If Bash, apply bash_overrides for matching command patterns.
        3. Scan full tool_input text for sensitive/external/irreversible patterns.
        4. Clamp all dimensions to [0, 4].
        5. Apply autonomy_context from caller.

    Args:
        tool_name: Name of the tool (e.g. "Bash", "Edit").
        tool_input: Raw tool input dictionary.
        policy: Policy with baselines and overrides. Defaults to Policy().
        autonomy_context: Current autonomy level (0=interactive, 4=unattended).
        source: Who triggered this action.

    Returns:
        A fully-scored Action ready for scoring.
    """
    if policy is None:
        policy = Policy()

    # Step 1: Start from tool baseline
    baseline = policy.get_tool_baseline(tool_name)
    dims: Dict[str, int] = {name: 0 for name in DIMENSION_NAMES}
    for name in DIMENSION_NAMES:
        if name in baseline:
            dims[name] = baseline[name]

    # Step 2: Bash-specific overrides
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        bash_bumps = policy.get_bash_overrides(command)
        for dim_name, val in bash_bumps.items():
            if dim_name in dims:
                dims[dim_name] = max(dims[dim_name], val)

        # Network access detection for Bash
        for pattern in _NETWORK_BASH_PATTERNS:
            if re.search(pattern, command):
                dims["external_impact"] = max(dims["external_impact"], 2)
                break

    # Step 3: Content heuristic scan over stringified tool_input
    input_text = str(tool_input)

    for patterns in [_SENSITIVE_PATTERNS, _EXTERNAL_PATTERNS, _IRREVERSIBLE_PATTERNS]:
        bumps = _scan_content(input_text, patterns)
        for dim_name, bump in bumps.items():
            dims[dim_name] = min(4, dims[dim_name] + bump)

    # Step 4: Clamp all dims
    for name in DIMENSION_NAMES:
        dims[name] = max(0, min(4, dims[name]))

    # Step 5: Autonomy context from caller
    dims["autonomy_context"] = max(0, min(4, autonomy_context))

    return Action(
        tool_name=tool_name,
        tool_input=tool_input,
        data_sensitivity=dims["data_sensitivity"],
        tool_privilege=dims["tool_privilege"],
        reversibility=dims["reversibility"],
        external_impact=dims["external_impact"],
        autonomy_context=dims["autonomy_context"],
        source=source,
    )
