"""5D Risk Governance Engine — Tool-call classifier.

Maps a raw tool call (tool name + input dict) into a fully-scored
Action by combining policy baselines, bash overrides, content
heuristics across all five dimensions, and autonomy signals.

The classifier is intentionally conservative: when in doubt, it
bumps dimensions UP, never down.

Hybrid autonomy model (2026-05-10):
  - Callers can pass autonomy_context as an int directly (explicit override).
  - Callers can pass autonomy_signals (an AutonomySignals dataclass)
    and the classifier will derive autonomy_context from the signals.
  - When both are present, the explicit int wins.
  - When neither is present, defaults to 0 (interactive).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .policy import Policy
from .schema import DIMENSION_NAMES, Action, AutonomySignals


# ─── Content heuristics ────────────────────────────────────────

# D — data sensitivity
_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(password|secret|token|api[_-]?key|credential|auth[_-]?key)", "data_sensitivity"),
    (r"(?i)(ssn|social.?security|passport|credit.?card|tax[_-]?id|driver.?license)", "data_sensitivity"),
    (r"(?i)\.(env|pem|key|p12|pfx|keystore|jks)(\b|$)", "data_sensitivity"),
    (r"(?i)(bearer\s+[a-z0-9_\-]{20,}|authorization:\s*bearer)", "data_sensitivity"),
    (r"(?i)(/etc/(passwd|shadow|sudoers)|/\.ssh/|/\.aws/credentials)", "data_sensitivity"),
]

# T — tool privilege (content patterns; bash overrides are separate)
_PRIVILEGE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(subprocess\.|os\.system|os\.popen|os\.exec)", "tool_privilege"),
    (r"(?i)(os\.chmod|os\.chown|os\.setuid|pwd\.setuid)", "tool_privilege"),
    (r"(?i)(\bsudo\b|\bsu\s+-|sudoers)", "tool_privilege"),
    (r"(?i)(iam\.(assume_role|attach_user_policy|create_user|create_access_key))", "tool_privilege"),
    (r"(?i)(setfacl|chgrp|chcon|setcap)", "tool_privilege"),
    (r"(?i)(kubectl\s+(apply|delete|exec|edit|patch))", "tool_privilege"),
]

# E — external impact
_EXTERNAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(email|smtp|sendgrid|mailgun|ses\.send|postmark)", "external_impact"),
    (r"(?i)(publish|deploy|release|broadcast)", "external_impact"),
    (r"(?i)(slack|discord|teams|webhook|telegram|twilio)", "external_impact"),
    (r"(?i)(requests\.(post|put|delete|patch)|httpx\.(post|put|delete|patch)|aiohttp\.(post|put|delete|patch))", "external_impact"),
    (r"(?i)(boto3\.|botocore\.|google\.cloud\.|azure\.|aws\s+s3\s+cp)", "external_impact"),
    (r"(?i)(stripe|paypal|braintree|adyen|square)", "external_impact"),
    (r"(?i)(twitter|x\.com|facebook|linkedin|instagram|tiktok)\.(post|tweet|share)", "external_impact"),
]

# R — reversibility
_IRREVERSIBLE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(delete|remove|drop|truncate|purge|destroy)", "reversibility"),
    (r"(?i)(push\s+--force|reset\s+--hard|force[_-]push)", "reversibility"),
    (r"(?i)(format|wipe|shred|fdisk)", "reversibility"),
    (r"(?i)(shutil\.(rmtree|move)|os\.unlink|pathlib\..*\.unlink)", "reversibility"),
    (r"(?i)(\bopen\b\s*\([^)]*['\"]w['\"])", "reversibility"),
    (r"(?i)((update|insert|delete)\s+(?:from|into)?\s*\w+(?!\s+where))", "reversibility"),
    (r"(?i)(transfer|wire|payment|charge|refund)", "reversibility"),
]

# Bash command patterns
_NETWORK_BASH_PATTERNS = [
    r"(?i)(curl|wget|ssh|scp|rsync|nc\b|ncat|telnet)",
    r"(?i)(docker\s+push|git\s+push|npm\s+publish|gh\s+release)",
    r"(?i)(aws\s+(s3|ec2|iam|lambda)|gcloud\s|az\s)",
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
    policy: Optional[Policy] = None,
    autonomy_context: Optional[int] = None,
    autonomy_signals: Optional[AutonomySignals] = None,
    source: str = "unknown",
) -> Action:
    """Classify a raw tool call into a scored 5D Action.

    Steps:
        1. Start from policy's tool baseline for this tool name.
        2. If Bash, apply bash_overrides + network detection.
        3. Scan full tool_input text for content heuristics
           (D, T, R, E patterns).
        4. Clamp all dimensions to [0, 4].
        5. Determine A (autonomy_context):
            - If autonomy_context int is provided, use it (override).
            - Else if autonomy_signals is provided, derive from signals.
            - Else default to 0 (interactive).

    Args:
        tool_name: Name of the tool (e.g. "Bash", "Edit").
        tool_input: Raw tool input dictionary.
        policy: Policy with baselines and overrides. Defaults to Policy().
        autonomy_context: Explicit autonomy level (0=interactive, 4=unattended).
            When provided, overrides autonomy_signals derivation.
        autonomy_signals: Optional AutonomySignals dataclass. When the
            explicit int is not provided, the classifier derives
            autonomy_context from these signals.
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

    # Step 2: Bash-specific overrides and network detection
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        bash_bumps = policy.get_bash_overrides(command)
        for dim_name, val in bash_bumps.items():
            if dim_name in dims:
                dims[dim_name] = max(dims[dim_name], val)

        for pattern in _NETWORK_BASH_PATTERNS:
            if re.search(pattern, command):
                dims["external_impact"] = max(dims["external_impact"], 2)
                break

    # Step 3: Content heuristic scan across all four content dimensions
    input_text = str(tool_input)
    for patterns in [
        _SENSITIVE_PATTERNS,
        _PRIVILEGE_PATTERNS,
        _EXTERNAL_PATTERNS,
        _IRREVERSIBLE_PATTERNS,
    ]:
        bumps = _scan_content(input_text, patterns)
        for dim_name, bump in bumps.items():
            dims[dim_name] = min(4, dims[dim_name] + bump)

    # Step 4: Clamp content dims
    for name in DIMENSION_NAMES:
        dims[name] = max(0, min(4, dims[name]))

    # Step 5: Autonomy context (hybrid: explicit int wins, else derive)
    if autonomy_context is not None:
        dims["autonomy_context"] = max(0, min(4, autonomy_context))
    elif autonomy_signals is not None:
        dims["autonomy_context"] = autonomy_signals.derive_autonomy_context()
    else:
        dims["autonomy_context"] = 0

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
