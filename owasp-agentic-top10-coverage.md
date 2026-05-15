# OWASP Agentic Top 10 (2026) — fivedrisk coverage

**Scope:** This document maps fivedrisk's runtime controls and test suite to the OWASP Top 10 for Agentic Applications (2026). fivedrisk is a runtime gating library, not a compliance product. This mapping describes which categories the library is designed to address through testable controls, and which are out of scope.

**OWASP reference:** [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

**Status convention:**
- **Strong**: dedicated controls plus dedicated tests
- **Partial**: controls present but coverage limited or surface narrower than the full category
- **Out of scope**: the category sits above (organizational) or below (training/infrastructure) fivedrisk's runtime-action layer

---

## Mapping

| ASI item | Status | fivedrisk control | Test marker |
|---|---|---|---|
| ASI01 Agent Goal Hijack | Strong | Input scanner (24 patterns covering instruction overrides, role hijacks, system-tag injection, jailbreak markers, exfiltration prompts), Markov drift detects compositional goal drift | `asi01_goal_hijack` |
| ASI02 Tool Misuse and Exploitation | Strong | `@gate` decorator scores every tool call across all 5 dimensions, tool_privilege content heuristics (subprocess, chmod, sudo, IAM, kubectl), Bash overrides for destructive commands | `asi02_tool_misuse` |
| ASI03 Identity and Privilege Abuse | Partial | tool_privilege dimension, agent_identity passthrough in audit log, policy floor rules. Cryptographic identity validation and identity-aware policy hooks are post-OSS scope | `asi03_identity_abuse` |
| ASI04 Agentic Supply Chain Vulnerabilities | Partial | Destination policy (allowlist/denylist) for outbound endpoints, classifier flags pip install / docker / npm publish. Full MCP-registry-trust and package-pin verification are out of scope | `asi04_supply_chain` |
| ASI05 Unexpected Code Execution | Strong | Classifier heuristics for subprocess/exec/system calls, Bash overrides for rm -rf / docker / git push --force, `@gate` blocks RED-band actions before execution | `asi05_code_execution` |
| ASI06 Context Management and Retrieval Manipulation | Strong | `scan_retrieved_content()` runs injection-pattern detection on retrieved content before it enters context, RETRIEVAL_TOOLS frozenset flags WebFetch/WebSearch/Read outputs for scanning | `asi06_context_manipulation` |
| ASI07 Insecure Inter-Agent Communication | Partial | agent_identity passthrough on every audited action enables SOC/SIEM correlation, audit log records source per action. Cryptographic message integrity, mutual auth, and policy on inter-agent message contracts are post-OSS scope | `asi07_inter_agent_comm` |
| ASI08 Cascading Failures | Strong | Markov SafetyDrift (16-state, 4×4) detects session-level escalation across compositional action sequences, SessionAccumulator O(1) counter-based drift tracking as light alternative, absorption-probability escalation bumps the next action's band when sequence trends dangerous | `asi08_cascading` |
| ASI09 Human-Agent Trust Exploitation | Partial | HITL card mechanism gives reviewers full 5D context, autonomy_context dimension tracks oversight state, AutonomySignals derives autonomy from session state. Trust modeling between human reviewer and agent over time is out of scope | `asi09_trust_exploit` |
| ASI10 Rogue Agents | Partial | Markov drift catches behavioral deviation from baseline, output leakage scanner detects injection-echo (corrupted-model signal), policy floor rules enforce hard limits regardless of score. Detection of subtle long-term drift across sessions is out of scope | `asi10_rogue_agent` |

---

## What "Strong" and "Partial" actually mean

The classifications above reflect whether fivedrisk has a dedicated runtime control surface for the category, AND whether the test suite exercises that surface. They do NOT mean "fivedrisk fully prevents this attack class on its own." Defence-in-depth always wants multiple layers.

A test marker measures coverage breadth, not real-world attack-class diversity.

## What "Out of scope" actually means

ASI04 (supply chain), ASI07 (inter-agent communication), ASI09 (trust modeling), and ASI10 (long-term drift) are categories where fivedrisk addresses important slices but does not cover the full attack surface. Deployers need additional controls: package supply-chain scanning (e.g. dependabot, snyk), cryptographic message authentication for agent-to-agent communication, longitudinal behavior analysis tooling, and human-reviewer trust models.

## What this document is not

This is not a compliance attestation. fivedrisk is open source, designed for environments where AI governance frameworks matter, and the audit log fivedrisk produces may be useful as evidence inside a compliance programme. It does not make any deployment OWASP-compliant on its own.

## Reproducing the mapping

The markers are registered in `pyproject.toml` under `[tool.pytest.ini_options]`. To verify a category's tests pass:

```bash
pytest -m asi01_goal_hijack -v
pytest -m asi08_cascading -v
```

To run only Agentic-tagged tests:

```bash
pytest -m "asi01_goal_hijack or asi02_tool_misuse or asi05_code_execution or asi06_context_manipulation or asi08_cascading"
```

## Forward work

- Expand ASI03 to a typed `AgentIdentity` field on `Action` and indexable audit-log columns (post-OSS scope; see `OSS-AGENT-ID-PASSTHROUGH-001` deferred items).
- ASI07 strengthening: structured inter-agent message contracts with cryptographic verification (post-OSS).
- ASI10 strengthening: longitudinal cross-session drift profiles (post-OSS).

---

*Document version: aligned with fivedrisk v0.4.2 codebase and OWASP Agentic Top 10 (2026). Updated whenever marker totals or scope decisions change.*
