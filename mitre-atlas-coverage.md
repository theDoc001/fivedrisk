# MITRE ATLAS — fivedrisk coverage (doc-only v0.5.0)

**Scope:** This document maps fivedrisk's runtime controls to MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems). ATLAS is a structured knowledge base of adversary tactics, techniques, and real-world case studies targeting AI and machine learning systems.

**MITRE ATLAS reference:** [atlas.mitre.org](https://atlas.mitre.org/). Version 5.4.0 (February 2026): 16 tactics, 84 techniques, 56 sub-techniques, 32 mitigations, 42 case studies.

**Document status:** v0.5.0 ships the mapping and status-per-technique PLUS real per-technique pytest markers. 19 dedicated ATLAS tests in `fivedrisk/tests/test_atlas_coverage.py` plus existing OWASP LLM Top 10 tests that share marker coverage. Run any technique's tests with `pytest -m atlas_t0051`. Coverage continues to expand in v0.6.0+.

**Status convention:**
- **Strong**: dedicated controls plus tests today
- **Partial**: controls present, tests planned for v0.6.0
- **Out of scope**: ATLAS technique sits above (organizational) or below (training-time / model-layer) fivedrisk's runtime-action layer

---

## Coverage by tactic

ATLAS tactics that map to fivedrisk's runtime-action layer:

| ATLAS tactic | fivedrisk relevance | Status |
|---|---|---|
| Reconnaissance (AML.TA0002) | scan_input_for_injection catches reconnaissance prompts; destination policy blocks outbound recon attempts | Partial |
| ML Model Access (AML.TA0000) | tool_privilege dimension + destination policy gate access to model endpoints | Partial |
| Initial Access (AML.TA0003) | injection scanner + retrieved-content scanner block injection-as-initial-access | Strong |
| Execution (AML.TA0005) | `@gate` decorator prevents execution of RED-band actions; classifier flags subprocess/exec patterns | Strong |
| Persistence (AML.TA0006) | audit log of every action creates persistence-detection surface | Partial |
| Defense Evasion (AML.TA0007) | injection scanner detects role-hijack, jailbreak, encoded-payload evasion | Strong |
| Discovery (AML.TA0009) | exfiltration-prompt detection in injection scanner, file-access classification | Partial |
| Collection (AML.TA0035) | data_sensitivity dimension + leakage scanner detects collection patterns | Partial |
| Exfiltration (AML.TA0010) | output leakage scanner (PII, credentials, crypto keys); destination policy blocks unauthorized destinations | Strong |
| Impact (AML.TA0011) | reversibility dimension + RED gate prevents destructive actions | Strong |

ATLAS tactics that sit outside fivedrisk's layer:

- **Resource Development (AML.TA0001)** — adversary infrastructure prep, not runtime
- **ML Model Poisoning (training data poisoning)** — training-time, not runtime
- **Lateral Movement (AML.TA0008)** — typically explicitly excluded by ATLAS for AI systems
- **Command and Control (AML.TA0036)** — typically explicitly excluded for AI systems

---

## Coverage by technique (illustrative subset)

Full per-technique mapping is forthcoming as part of v0.6.0 work. This subset shows the shape of the mapping:

| ATLAS technique | fivedrisk control | Status |
|---|---|---|
| AML.T0051 LLM Prompt Injection | scan_input_for_injection, 24 regex patterns (override, role-hijack, jailbreak, system-tag, encoded-payload, zero-width-chars, exfil-data) | Strong |
| AML.T0051.000 Direct Prompt Injection | Same as above | Strong |
| AML.T0051.001 Indirect Prompt Injection | scan_retrieved_content runs same patterns on WebFetch/WebSearch/Read outputs | Strong |
| AML.T0050 Command and Scripting Interpreter | classifier flags subprocess.*, os.system, os.popen, os.exec patterns; Bash override for rm -rf, git push --force, docker | Strong |
| AML.T0057 LLM Data Leakage | output leakage scanner detects credentials, PII (SSN, credit card), crypto keys, injection-echo, exfiltration commands | Strong |
| AML.T0048 External Harms | external_impact dimension; classifier flags requests/httpx/aiohttp HTTP writes, boto3/cloud SDKs, payment APIs (stripe, paypal), social platform sends | Strong |
| AML.T0040 ML Model Inference API Access | destination policy allowlist/denylist for outbound endpoints | Partial |
| AML.T0049 Tool Misuse | tool_privilege dimension; @gate decorator scores every tool call across all 5 dimensions before execution | Strong |
| AML.T0024 Exfiltration via ML Inference API | output leakage scanner detects exfiltration patterns in model outputs | Strong |
| AML.T0058 Publish Hallucinated Entities | scope-limited: fivedrisk does not validate model outputs for factual accuracy. Out of scope |
| AML.T0064 Cascading | Markov SafetyDrift detects compositional risk escalation across action sequences | Strong |

---

## What "Strong" and "Partial" actually mean

**Strong**: there is a dedicated control surface AND existing tests exercise that surface (under markers like `llm01_prompt_injection`, `safety_drift`, etc. from the OWASP LLM Top 10 doc). v0.6.0 will add `atlas_t*` markers to those existing tests.

**Partial**: there is a control surface but coverage is narrower than the full ATLAS technique surface. New tests will land in v0.6.0.

**Out of scope**: the technique sits outside the runtime-action layer.

---

## What this document is not

This is not a compliance attestation. fivedrisk is open source, designed for environments where AI security threat catalogues matter, and the audit log fivedrisk produces may be useful as evidence inside a security programme. It does not make any deployment ATLAS-compliant on its own.

---

## Reproducing the coverage

Markers are registered in `pyproject.toml`. Run any technique:

```bash
pytest -m atlas_t0051        # all LLM Prompt Injection sub-techniques
pytest -m atlas_t0051_001    # Indirect prompt injection only
pytest -m atlas_t0064        # Cascading compositional failure
pytest -m atlas_t0057        # LLM Data Leakage
```

## v0.6.0+ roadmap for ATLAS

1. Expand "Partial" coverage to "Strong" by adding new test cases against specific techniques (estimated 15-20 additional cases).
2. Add real ATLAS case-study reproductions where the public case-study text gives enough detail.
3. Track ATLAS version updates (currently aligned with v5.4.0, February 2026); refresh markers as MITRE publishes new techniques.

---

*Document version: aligned with fivedrisk v0.4.2 codebase and MITRE ATLAS v5.4.0 (February 2026). Updated whenever marker totals or scope decisions change.*
