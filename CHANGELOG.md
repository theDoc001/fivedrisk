# Changelog

All notable changes to **fivedrisk** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [0.5.3] (2026-06-15)

DX patch release. Six small documentation and clarity fixes captured from the first external embed (Speci ingest scoring) plus the previously-landed `gateway.py` IPC module. No public API or schema changes. No behavior changes.

### Added (DX)
- **"Score a custom (non-tool-call) action" recipe** in `README.md` and `docs/quickstart.md`. Constructing an `Action` directly with the five dimensions is now documented for vault writes, ingest events, scheduled jobs, and any event that is not an agent tool call.
- **Dimension scale + direction statement** at every definition site. `schema.py` module header, `Action` dataclass docstring, and the `README.md` Dimensions table now all carry the explicit anchor: scores run 0 to 4, higher = more risk on every axis, no inverted axis. Speci-style silent inversion (HIGH score for SAFE actions) is now flagged in plain text.
- **M0 to M4 example-model mapping table** in `README.md`, `router.py` module docstring, and the `ModelClass` enum docstring. Includes example mappings for OpenAI, Anthropic, Google, and local-model deployments. The class is an abstraction over capability, not a model name.
- **`score()` + `DecisionLog` one-call quickstart** in `docs/quickstart.md`. Pairs `score()` with `DecisionLog.log()` for callers scoring outside the `@gate` decorator.
- **Public API stability section** in `README.md`. Names the nine stable public symbols (`score`, `classify_tool_call`, `Action`, `ScoredAction`, `Band`, `Policy`, `load_policy`, `DecisionLog`, `hooks.gate`); breaking changes to these require a major version bump.
- **`fivedrisk.gateway` IPC module** (`python -m fivedrisk.gateway stdio|score|resolve`). Persistent stdio and one-shot subprocess modes that let non-Python plugins (OpenClaw, Node, Go, Rust) call the scoring engine over JSON-lines. See `gateway.py` module docstring for the request/response shape.

### Changed (DX)
- **`score()` docstring** in `scorer.py` now explicitly documents the YELLOW-fold behavior: by default YELLOW collapses into GREEN (3-band experience); set `enable_yellow_band: true` in `policy.yaml` for the 4-band audit-log experience. Previously documented only as an inline code comment.
- **Duplicate `DIM_MAX` constant** removed from `scorer.py`. The canonical definition lives in `schema.py`; `scorer.py` now imports it. Tightens the schema dependency and removes a code smell.

### Notes
- Test count: 444 passing, 0 failing (unchanged across the DX patch).
- No PyPI long_description action needed; pulls from `fivedrisk/README.md` on twine upload.
- Downstream consumers embedding fivedrisk are recommended to pin a specific patch version (`fivedrisk==0.5.3`) until they have tested against the next release. The Public API stability section names which symbols are safe across patch versions.

---
## [0.5.2] — 2026-05-23

Hygiene-and-DX release. Repositions fivedrisk as the deterministic pre-filter that runs BEFORE LLM-based guards, adds a five-preset policy library, ships three copy-paste-runnable examples, and lands a 5-minute quickstart. No public API or schema changes. Test count unchanged at 424 passing, 0 failing.

### Added
- **Policy presets** (`fivedrisk/policies/presets/`). Five YAML presets covering common deployment archetypes: `read_only.yaml`, `human_approval_required.yaml`, `financial_operations.yaml`, `customer_data.yaml`, `code_execution.yaml`. Load with `load_policy("path/to/preset.yaml")` or use as a starting point for your own policy. Each preset documents the threshold reasoning inline.
- **Examples** (`examples/`). Two new runnable integrations: `minimal_gate.py` (smallest possible `@gate` wiring) and `langgraph_multi_step.py` (the `fivedrisk_gate_node` inside a LangGraph state machine, routing GREEN, YELLOW, ORANGE, RED to the right edges). An OpenAI Agents SDK integration example is queued for a later release once it has been validated end-to-end against the live SDK.
- **Quickstart** (`docs/quickstart.md`). Under-100-line end-to-end walkthrough a developer can run in 5 minutes. Includes scope-narrowing guidance: narrow the agent's tool surface, narrow the autonomy context, and extend `policy.yaml` `tool_defaults` and `bash_overrides` to match your exact deployment.

### Changed
- **README opener rewritten.** Now leads with the two-stage architectural wedge: fast deterministic lane (fivedrisk, 0.2 to 2.9 ms per scenario) plus LLM-observer slow lane (LLM Guard, Lakera, Pangea, 100 to 700 ms per check). New section "What fivedrisk is not" explicitly disclaims general LLM guardrail framing, semantic content scanning, and replacement for AI governance best practices (tool and scope narrowing, prompt guardrails, system prompts).
- **Sovereign-AI framing.** "Built in Vienna, Austria. Architecturally sovereign: no external services, no hyperscaler dependency, runs entirely on your own infrastructure." Replaces ambiguous regulatory-anchoring language with concrete architectural facts.

### Notes
- v0.5.1 was tagged locally on 2026-05-19 but never reached PyPI. The docs-only README changes from 0.5.1 are bundled into 0.5.2; no separate 0.5.1 publish.
- CLAUDE.md quality rule #7 now mandates PyPI publish before every git tag push. The 0.5.1 gap is what motivated the rule.
- Pre-commit lint extended. Two additional regex locks added covering commercial-brand seeding and premature deployment-maturity phrasing. Enforced on every staged diff.

---
## [0.5.1] — 2026-05-19

Docs-only release. No code, behavior, or test changes from v0.5.0.

### Changed
- README opener refreshed to lead with worldview positioning: deterministic action-layer governance, open source, local-first, no hyperscaler dependency. The library is unchanged; the positioning catches up with how it has been used in practice.

### Notes
- pyproject version bumped 0.5.0 → 0.5.1 to mark the documentation refresh.
- No PyPI long_description action needed; it pulls from `dev/fivedrisk/README.md` on twine upload.
- Manual GitHub UI step: update repo description on github.com/theDoc001/fivedrisk to align with new README opener.

---
## [0.4.1] — 2026-05-08

Patch release. No API breakage; ships safely on top of any v0.4.0 install.

### Fixed
- **Plugin hooks: bash variable expansion (Bug 1)**. `dev/fivedrisk-plugin/hooks/hooks.json` was wrapping `$TOOL_INPUT` and `$TOOL_RESULT` in single quotes, which prevents shell expansion. The plugin was scoring the literal string `$TOOL_INPUT` on every PreToolUse / PostToolUse hook. Switched to escaped double quotes so the variables expand at the shell level before the value reaches the scorer.
- **Plugin hooks: argparse positioning (Bug 2)**. `--format` is a top-level CLI flag, not a subcommand flag. The hook command now invokes `python -m fivedrisk --format json score -` (top-level flag before subcommand). PostToolUse adds `--dry-run` so accidental write attempts on read-only filesystems do not bubble up as hook failures.
- **Logger resilience (Bug 3)**. `DecisionLog.__init__` now wraps schema initialization in a try/except. If the configured DB path is unwritable (read-only FS, sandbox restriction, missing parent directory), the logger falls back to the system temp directory and emits a `RuntimeWarning` describing the fallback. The agent is no longer taken down by a logging-side I/O error. A `fallback_active` attribute is exposed for callers that want to detect the condition. Two new tests cover the unwritable-path scenario.

### Test count
- 311 passing, 0 failing (was 308 / 1 in v0.4.0). The previously-failing `test_langgraph_blocks_when_session_required_and_missing` passes after the logger resilience fix; two new tests added for the fallback path itself.

### Notes
- The plugin is now end-to-end operable on any environment where the system temp directory is writable. Read-only or sandbox-restricted filesystems no longer crash the hook chain.
- Pitch claim "309 tests with 0 failures" should be updated to "311 tests with 0 failures" after this patch lands publicly.

---

## [0.5.0] — Unreleased (first PyPI release)

Major release. DEV-008 full 5D classification, DEV-003 Markov audit, cost-management MVP, acting-identity primitive, NDJSON event emission, MITRE ATLAS coverage with real tests, OWASP Agentic Top 10 coverage doc, 3-band default with opt-in 4-band compliance model, audit pass, pre-publish cleanup. First release to PyPI.

### Added (cost-management + identity capture sprint)
- **Cost-management primitives**. New `BudgetAccumulator` (per-session token spend with reservation, commit, cancel), `token_costs.py` table for common LLM classes (OpenAI GPT-4-class, Anthropic Claude Sonnet/Opus, Google Gemini Pro, Mistral Large). New `Policy` attributes `max_session_budget_tokens` and `max_tool_call_budget_tokens`. `Policy.admit_session()` admission check. `@gate` extended with per-tool-call reservation enforcement that raises `BudgetExceededError` when projected spend exceeds the configured cap. NDJSON `budget_intervention` event records every rejection. Additional Operational FinOps capabilities (multi-agent budget envelopes, useful-progress monitoring, wall-clock and retry caps) are on the project roadmap.
- **Acting identity primitive**. New `ActingIdentity` dataclass with `PrincipalType` (USER/SERVICE/ROLE/AGENT/ANONYMOUS) and `AttestationSource` (HTTP_HEADER/JWT_CLAIM/ENV_VAR/AGENT_DECLARED/NONE) enums, optional `roles` and `data_scope`. `Action.acting_identity` field flows through to audit log and NDJSON events. New `Policy.identity_required` attribute denies ANONYMOUS callers with `IdentityRequiredError` and emits `identity_required_denial` NDJSON event. Identity-aware policy evaluation beyond admission is on the project roadmap.
- **NDJSON event emission layer** (`events.NDJSONEventChannel`). Sibling to the SQLite `DecisionLog`. Emits `risk_decision`, `budget_intervention`, and `identity_required_denial` events with shared `trace_id` and `session_id` correlation. SIEM-friendly stream format. Best-effort write; failures warn but do not interrupt the action pipeline. Configured via `configure(event_path=...)`.
- `@gate` accepts new optional kwargs `_fivedrisk_acting_identity`, `_fivedrisk_model_class`, `_fivedrisk_input_tokens` for per-call override of decorator defaults.
- `configure()` extended with `event_path`, `default_model_class`, `default_estimated_input_tokens` parameters.

### Changed (DEV-008 — true 5D classification)
- `classifier.py` rewritten with content heuristics across all four content dimensions (D, T, R, E); `tool_privilege` now has 6 content heuristic patterns where it had none before.
- New `AutonomySignals` dataclass on `schema.py` for hybrid autonomy derivation (caller passes signals dict, classifier derives autonomy_context). `classify_tool_call` accepts `autonomy_signals` kwarg; explicit `autonomy_context` int still wins when both are provided.
- New `tests/test_classifier_per_dim.py` with 56 tests covering all five dimensions.

### Changed (audit / cleanup)
- **BREAKING**: Removed legacy 3-band shim. `Band.GO`, `Band.ASK`, `Band.STOP` aliases deleted along with `score_light()` and the `Policy` fields `stop_threshold`, `ask_threshold`, `composite_ask`. The canonical band system is 4-band (`GREEN`, `YELLOW`, `ORANGE`, `RED`). No installed users existed at v0.4.1 publish time, so this is the cheapest moment to make this break.
- `policy.yaml` defaults rewritten to drop legacy threshold keys. Two sample policy files updated.
- `__version__` now read dynamically via `importlib.metadata` instead of a hardcoded string.
- README LangGraph example fixed: `fivedrisk_node` → `fivedrisk_gate_node` (the real export name).
- README `Performance` section added with measured p50/p95/p99 numbers from `benchmarks/bench_minimal.py` (~40-70µs p50 for 5D core, ~5ms p50 including SQLite audit-log write). Replaces the stale "~0.3ms scoring" claim.
- `policy.tier` vestigial field removed (no consumers).

### Added (other)
- **Agent identity passthrough** via `Action.metadata["agent_identity"]`. Opaque string flows through to the audit log for SOC/SIEM correlation. README documents the reserved key. Structured parsing and identity-aware policy hooks for `agent_identity` (workload identity) are post-OSS scope.
- `benchmarks/bench_minimal.py` reproduces published performance numbers. Self-bootstrapping import (works without pip editable install) for compatibility with iCloud paths and Python 3.14.
- README `Planned` section listing future capability surfaces (SPIFFE/MCP reference, MITRE ATLAS coverage, NIST AI RMF mapping, OWASP Agentic Top 10 coverage, regulatory crosswalks, decision log analysis cookbook).
- ARCHITECTURE.md §18 row flipped from ❌ BACKLOG to ⚠️ PARTIAL (opaque identity passthrough only).
- YELLOW band documentation expanded to highlight cost-management benefits (automatic model routing, enhanced audit logging without HITL latency).
- New beacon coverage docs: `owasp-agentic-top10-coverage.md`, `mitre-atlas-coverage.md`, `decision-log-cookbook.md`.
- New example: `examples/spiffe_mcp_passthrough.py` runnable end-to-end pattern with mocks for SPIRE workload API and MCP server.

### Band system: 3-band default, opt-in 4-band

- `Policy.enable_yellow_band: bool = False`. Default is a 3-band experience (GREEN / ORANGE / RED). Score ranges that would have landed YELLOW now return GREEN, removing configuration friction for users who do not need a moderate-risk tier.
- Set `enable_yellow_band: true` in `policy.yaml` for the 4-band compliance model. Adds a stable YELLOW label for audit queries and dashboards. Within YELLOW, model-class promotion for sensitive data is a separate opt-in via `yellow_model_escalation: true`.
- `_route_model` in `scorer.py` no longer auto-promotes the model class for ORANGE. ORANGE signals `approval_required=True`; the caller's HITL stack decides what model the reviewer (or AI-assisted HITL pipeline) uses.
- ORANGE no longer forbids `downgrade_allowed`; the routing recommendation is advisory across all bands.

### Notes
- Test count: 405 (was 311 in v0.4.1). DEV-008 added 56 tests; cost MVP + identity + NDJSON added 42 tests; shim removal removed 4.
- Per-action overhead measurement: ~40-70µs p50 / ~59-294µs p99 for the classify + score core path (sandbox aarch64 vs M1 macOS). Audit-log write dominates at ~5ms p50 in default SQLite configuration; configure WAL mode or async writes for sub-millisecond per-action gating.

### Changed
- **BREAKING**: Removed legacy 3-band shim. `Band.GO`, `Band.ASK`, `Band.STOP` aliases deleted along with `score_light()` and the `Policy` fields `stop_threshold`, `ask_threshold`, `composite_ask`. The canonical band system is 4-band (`GREEN`, `YELLOW`, `ORANGE`, `RED`). No installed users existed at v0.4.1 publish time, so this is the cheapest moment to make this break.
- `policy.yaml` defaults rewritten to drop the legacy threshold keys. Two sample policy files updated.
- `__version__` now read dynamically via `importlib.metadata` instead of a hardcoded string.
- README LangGraph example fixed: `fivedrisk_node` → `fivedrisk_gate_node` (the real export name).
- README `Performance` section added with measured p50/p95/p99 numbers from `benchmarks/bench_minimal.py` (~40µs p50 for 5D core, ~5ms p50 including SQLite audit-log write). Replaces the stale "~0.3ms scoring" claim.
- `policy.tier` vestigial field removed (no consumers).

### Added
- **Agent identity passthrough** via `Action.metadata["agent_identity"]`. Opaque string flows through to the audit log for SOC/SIEM correlation. README documents the reserved key. Structured parsing and identity-aware policy hooks are post-OSS scope.
- `benchmarks/bench_minimal.py` reproduces the published performance numbers.
- README `Planned` section listing future capability surfaces (SPIFFE/MCP reference, MITRE ATLAS coverage, NIST AI RMF mapping, OWASP Agentic Top 10 coverage, regulatory crosswalks, decision log analysis cookbook).
- ARCHITECTURE.md §18 row flipped from ❌ BACKLOG to ⚠️ PARTIAL (opaque identity passthrough only).
- YELLOW band documentation expanded to highlight cost-management benefits (automatic model routing, enhanced audit logging without HITL latency).

### Fixed
- Pre-existing tier-talk and stale-docstring sweep: `drift.py`, `ARCHITECTURE.md`, `CHANGELOG.md`, `VALIDATION_NOTES_2026-04-14.md`. The runtime path uses the 16-state Markov chain; prior documentation incorrectly framed it as planned.

### Notes
- Test count: 307 (was 311 in v0.4.1). Four shim-validation tests removed alongside the shim.
- Per-action overhead measurement: ~40µs p50 / ~59µs p99 for the classify + score core path. Audit-log write dominates at ~5ms p50 in default SQLite configuration; configure WAL mode or async writes for sub-millisecond per-action gating.

---

## [Unreleased] — v0.5.0 planned

Target ship: TBD.

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
- Full Markov chain SafetyDrift (16-state, 4×4) shipped in `markov.py`; default in the runtime hooks.
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
