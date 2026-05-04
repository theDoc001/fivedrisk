# Changelog

All notable changes to **fivedrisk** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — v0.5.0 planned

Target ship: TBD. Forcing functions: PyPI publish, HN Show HN submission, awesome-llm-security PR.

### Added (post-v0.4.0 housekeeping, pre-PyPI release)
- Apache-2.0 LICENSE file at repo root (closes the GitHub "no recognised LICENSE" API gap)
- CHANGELOG.md (this file) following Keep a Changelog format
- `.gitignore` entries for iCloud sync duplicates (`* 2.*`)
- GitHub Actions CI workflow (`.github/workflows/tests.yml`) running pytest on Python 3.10 and 3.12
- Live Tests badge in README backed by GitHub Actions (replaces the static badge)
- pytest markers tagging tests against OWASP LLM Top 10 categories (`llm01_prompt_injection`, `llm02_insecure_output`, `llm04_model_dos`, `llm06_sensitive_disclosure`, `llm07_insecure_plugin`, `llm08_excessive_agency`) plus a fivedrisk-specific `safety_drift` marker
- `owasp-llm-top10-coverage.md` mapping OWASP LLM Top 10 categories to fivedrisk controls and test markers
- pyproject.toml metadata: project urls now point to `theDoc001/fivedrisk`, description and keywords sanitised, Changelog url added
- **First PyPI release** (this Unreleased section ships as v0.4.0 on PyPI)

### Planned (v0.5.0)
- E (Exposure) and A (Authority) dimension scoring (DEV-008), full 5-dimensional model
- R-dimension Markov accumulator (DEV-003 Option A), closes session-level reversibility gap
- `@gate` latency benchmark suite plus published p50/p95/p99 numbers
- OWASP Agentic Top 10 coverage report (separate from the OWASP LLM Top 10 doc shipped in 0.4.0)
- 5D-schema-v0.1 working draft published as `docs/spec/5d-schema-v0.1.md`

---

## [0.4.0] — 2026-04-16

### Added
- SafetyDrift MVP (`drift.py`): session-level cumulative risk accumulator across 5 attack scenarios. O(1) per action, no Markov math at this tier.
- Full Markov chain SafetyDrift (16-state, 4×4) targeted for Standard tier.
- Injection scanner (`hooks.py:scan_input_for_injection`): 24 regex patterns, zero external dependencies.
- Output leakage scanner (`hooks.py:scan_output_for_leakage`): credentials, PII (SSN, credit card), crypto keys, injection-echo detection, exfiltration command patterns.
- `@gate` decorator for sync and async functions.
- Rate limiting / DoS defense (`hooks.py:rate_limit_check`): sliding window 120/60s, burst detection 30/10s, HITL queue depth limiter.
- LangGraph integration node (`langgraph_node.py`).
- 309 tests across the package.

### Changed
- Auto-approve permanently removed from planner — HITL always required (P-004).
- `/approve` command accepts optional instructions parameter.

### Notes
- Apache-2.0 (per repo description and pitch material). LICENSE file added post-v0.4.0 during pre-release housekeeping (see Unreleased).
- Per-action overhead: ~0.3ms scoring, ~27ms PromptArmor (when enabled), ~50–200ms LLM Guard (when enabled, selective per ScanProfile).

---

## Earlier

Pre-v0.4.0 history is captured in `ARCHITECTURE.md` (spec-coverage matrix from v0.3.0 baseline) and `VALIDATION_NOTES_2026-04-14.md`.
