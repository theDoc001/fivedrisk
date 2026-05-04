"""Versioned detector corpus for 5D runtime scanners."""

from __future__ import annotations

DETECTOR_CORPUS_VERSION = "2026-04-14.2"

# Input-side prompt-injection / hostile instruction corpus.
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)ignore\s+(previous|all|prior|above|your)\s+(instructions?|prompts?|rules?|context|system)", "override"),
    (r"(?i)forget\s+(everything|all\s+previous|what\s+you\s+(were|was)\s+told)", "forget"),
    (r"(?i)disregard\s+(?:(?:your|all|any)\s+)?(?:previous|prior\s+)?(instructions?|rules?|context)", "disregard"),
    (r"(?i)override\s+(your|all|previous|system|the)\s+(instructions?|settings?|rules?|prompt)", "override"),
    (r"(?i)you\s+are\s+now\s+(a|an|the)\s+\w+", "role-hijack"),
    (r"(?i)act\s+as\s+(if\s+you\s+(are|were)|a|an|the)\s+\w+", "role-hijack"),
    (r"(?i)pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*\w+", "role-hijack"),
    (r"(?i)roleplay\s+as\s+(a|an|the)?\s*\w+", "role-hijack"),
    (r"(?i)new\s+(instruction|directive|command|rule|system\s+prompt|order)", "new-instruction"),
    (r"(?i)\[SYSTEM\]|\[INST\]|\[OVERRIDE\]|\[ADMIN\]|\[ROOT\]", "system-tag"),
    (r"(?i)<\s*system\s*>|<\s*instructions?\s*>|<\s*prompt\s*>", "xml-injection"),
    (r"(?i)\bjailbreak\b", "jailbreak"),
    (r"(?i)\bDAN\s+mode\b|\bDeveloper\s+Mode\b|\bGPT-4\s+simulator\b", "jailbreak"),
    (r"(?i)do\s+anything\s+now", "jailbreak"),
    (r"(?i)(print|repeat|reveal|expose|show|output|display)\s+(your|the)\s+(system\s+)?(instructions?|prompt|rules?|configuration)", "exfil-prompt"),
    (r"(?i)what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|rules?)", "exfil-prompt"),
    (r"(?i)step\s+1[.:].{1,80}step\s+2[.:]", "multi-step"),
    (r"(?i)first[,.]?\s+.{5,60}[,.]?\s+then[,.]?\s+.{5,60}[,.]?\s+finally", "multi-step"),
    (r"(?i)base64[.:\s]+[A-Za-z0-9+/]{20,}={0,2}", "encoded-payload"),
    (r"(?i)(decode|eval|exec)\s*\(\s*['\"][A-Za-z0-9+/]{10,}", "encoded-exec"),
    (r"[\u200b\u200c\u200d\u2060\ufeff]{3,}", "zero-width-chars"),
    (r"(?i)\\u00[0-9a-f]{2}.*\\u00[0-9a-f]{2}.*\\u00[0-9a-f]{2}", "unicode-escape-chain"),
    (r"(?i)(send|email|post|upload|exfil(trate)?)\s+.{0,30}(password|token|key|secret|credential)", "exfil-data"),
    (r"(?i)(copy|dump|extract)\s+(all|the|my)\s+(files?|data|vault|notes?|emails?)", "exfil-data"),
]

# Output-side leakage / exfil / corrupted-model echoes.
EGRESS_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(password|passwd|secret|token|api[_-]?key|auth[_-]?key)\s*[:=]\s*\S{4,}", "credential"),
    (r"(?i)(ssn|social.?security)\s*[:=]?\s*\d{3}", "pii-ssn"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "pii-ssn-format"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "pii-credit-card"),
    (r"(?i)(BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+(PRIVATE\s+)?KEY)", "crypto-key"),
    (r"(?i)ignore\s+(previous|all|prior)\s+(instructions?|prompts?|rules?)", "llm-injection-echo"),
    (r"(?i)(curl|wget)\s+.{0,30}(http|https)://", "exfil-command"),
    (r"(?i)base64\s+(encode|decode)\s+.{0,60}(password|token|key|secret)", "encoded-exfil"),
]

# Tools whose outputs often enter future prompts and should be scanned for
# hostile retrieved instructions before being added to model context.
RETRIEVAL_TOOLS = frozenset({"WebFetch", "WebSearch", "Read"})
