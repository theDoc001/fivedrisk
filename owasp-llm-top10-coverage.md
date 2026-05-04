# OWASP LLM Top 10 — fivedrisk coverage

**Scope:** This document maps fivedrisk's runtime controls and test suite to the OWASP Top 10 for LLM Applications. fivedrisk is a runtime gating library, not a compliance product. This mapping describes which OWASP categories the library is designed to address through testable controls, and which are out of scope.

**Status convention:**
- **Strong**: dedicated controls plus dedicated tests
- **Partial**: controls present but coverage limited or surface narrower than the full category
- **Out of scope**: the category sits above (organizational) or below (training/model layer) fivedrisk's runtime-action layer

**Reproducing test counts:**

```bash
pip install -e ".[langgraph,dev]"
pytest -m llm01_prompt_injection --collect-only -q
pytest -m llm02_insecure_output --collect-only -q
# ...etc
```

---

## Mapping

| OWASP item | Status | fivedrisk control | Test marker | Tests |
|---|---|---|---|---|
| LLM01 Prompt Injection | Strong | Input scanner (24 patterns), pre-tool hook blocking, injection benchmark suite | `llm01_prompt_injection` | 40 |
| LLM02 Insecure Output Handling | Strong | Output scanner, post-tool leakage block, egress benchmark suite | `llm02_insecure_output` | 40 |
| LLM03 Training Data Poisoning | Out of scope | Training-time concern, not addressed at runtime | n/a | n/a |
| LLM04 Model Denial of Service | Partial | Sliding-window rate limiter, burst limiter, HITL queue depth limiter | `llm04_model_dos` | 5 |
| LLM05 Supply Chain Vulnerabilities | Out of scope | Package supply chain concern, not action-level | n/a | n/a |
| LLM06 Sensitive Information Disclosure | Strong | Output scanner detects credentials, PII (SSN, credit card), crypto keys, exfiltration patterns | `llm06_sensitive_disclosure` | 40 |
| LLM07 Insecure Plugin Design | Partial | `@gate` decorator on tool functions, tool privilege classification, destination policy allowlist | `llm07_insecure_plugin` | 2 (gate decorator) plus broader coverage in `test_classifier.py` and `test_runtime_controls.py` (untagged) |
| LLM08 Excessive Agency | Strong (core) | Per-action 5D scoring with autonomy_context dimension, HITL enforcement at ORANGE, blocked at RED | `llm08_excessive_agency` | 11 |
| LLM09 Overreliance | Out of scope | Human-factors / UX concern, not a runtime control surface | n/a | n/a |
| LLM10 Model Theft | Out of scope | Model-layer security, not action-layer | n/a | n/a |

**fivedrisk-specific category (not in OWASP):**

| Category | Status | Control | Marker | Tests |
|---|---|---|---|---|
| Compositional / sequence drift | Strong | Markov chain over (data exposure tier × activity risk tier), 16-state, absorption-probability escalation. Catches sequences that score GREEN individually but compose to RED. | `safety_drift` | 55 |

---

## What "Strong" and "Partial" actually mean

The marker totals above represent tests that exercise the relevant control surface. They do not represent independent attack scenarios.

For example, the LLM01 marker count (40) includes:
- `TestInputScanner` (test_hooks.py) targeted unit tests of the regex pattern engine
- `test_prompt_injection_benchmark_suite` (test_runtime_benchmarks.py) parametrised over 12 attack cases adapted from OWASP, garak, and Giskard guidance
- `test_runtime_policy_benchmark_suite` (test_runtime_benchmarks.py) parametrised broader runtime cases
- Various integration tests in the runtime benchmark file

A test marker measures coverage breadth, not real-world attack-class diversity.

## What "Out of scope" actually means

LLM03, LLM05, LLM09, and LLM10 sit outside fivedrisk's runtime layer. Marking them out of scope means fivedrisk does not claim to address them and a deployer needs other controls (training data hygiene, dependency scanning, user education, model access control respectively).

## What this document is not

This is not a compliance attestation. fivedrisk is open source, designed for environments where AI governance frameworks matter, and the audit log fivedrisk produces may be useful as evidence inside a compliance programme. It does not make any deployment OWASP-compliant on its own.

## Reproducing the mapping

The markers are registered in `pyproject.toml` under `[tool.pytest.ini_options]`. To verify a category's tests pass:

```bash
pytest -m llm01_prompt_injection -v
pytest -m llm08_excessive_agency -v
pytest -m safety_drift -v
```

To run only OWASP-tagged tests:

```bash
pytest -m "llm01_prompt_injection or llm02_insecure_output or llm04_model_dos or llm06_sensitive_disclosure or llm07_insecure_plugin or llm08_excessive_agency"
```

## Forward work

- **OWASP Agentic Top 10 mapping** (separate document, planned for v0.5.0)
- Expand LLM07 marker coverage to include destination-policy and tool-privilege classification tests
- Add LLM01 cases for newer evasion techniques (Unicode tag injection, encoding-layer chaining)

---

*Document version: aligned with fivedrisk v0.4.0 codebase. Updated whenever marker totals or scope decisions change.*
