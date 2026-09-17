# Changelog

All notable changes to **fivedrisk** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [0.7.0] - 2026-09-14

> ## 🔴 SECURITY RELEASE. Upgrade if you rely on the deterministic floor.
>
> **Affected versions: 0.6.0 and earlier, including the current PyPI release.**
> Two defects let an action that should have been floored pass at a lower band, or not fire at all.
> Both are fixed here. Neither requires a configuration change to be exposed; if you use `checksum`
> floor axes or a rule set that mixes floor bands, you were affected by default.
>
> **SEC-1 — the checksum axis could read across a field boundary (fail-open).** Candidate extraction
> joined the whole tool input into one haystack, so digits from two adjacent fields could form a
> checksum-valid candidate that belonged to neither, and — the direction that matters — a genuine
> identifier could fail to be extracted at all because the joined text broke the window it needed.
>
> **Measured against the published `0.6.0` wheel downloaded from PyPI, not against a source tree.**
> With a Luhn-valid test card number present and a `checksum: luhn` floor declared, across **26
> combinations** of one neighbouring field's rendering and its position relative to the identifier,
> **17 failed to fire (65.4%, Wilson 95% interval 46.2% to 80.6%)**. On this release, **0 of the
> same 26 fail (0%, Wilson 95% interval 0% to 12.9%)**. Extraction is now bounded per field.
>
> **Whether the floor fired could not be predicted from the field name**, which is what made this
> hard to notice: it turned on how the neighbouring value happened to be rendered and on which side
> of the identifier it sat. A timestamp written `2026-09-14` disarmed the floor while the same
> timestamp written `2026-09-14T10:00:00Z` did not, and `{"amount": "149.99", "card": …}` disarmed
> it in both positions. If you declared a `checksum` floor on 0.6.0 or earlier, assume it did not
> fire reliably rather than assuming your field shapes were among the lucky ones.
>
> **SEC-2 — `first_red_line_hit` returned the first firing rule, not the strictest.** A soft floor
> listed earlier swallowed a hard red line firing on the same action, so the reduction could report
> YELLOW where `Policy.matched_floor` over the identical rules returned RED. **List position decided
> a security verdict.** Detail in the Fixed section below.
>
> **What to do**: upgrade, then re-run any stored analysis that depended on floor outcomes. Decisions
> already written to your audit log were recorded as they were computed and are not rewritten by this
> release.

### Changed — BREAKING: `retry_budget` is now enforced, and is opt-in

- 🔴 **`retry_budget` did nothing.** It was parsed onto the `Policy` object and read by no code path,
  so an operator could set it, a reviewer approve it and a change record capture it, while the control
  it named did not exist. It is now **enforced**: it bounds how many times one action may be attempted
  within one session before the attempt is denied with `RetryBudgetExceededError`.
- **The default changed from `5` to `None`, which enforces nothing.** Turning enforcement on by default
  would deny agents that legitimately retry. The right number is per action class, and depends on
  whether this interception point sits below the caller's own retry policy, so it is not a value to
  choose on a deployment's behalf. `Policy.retry_budget` is now `Optional[int]`.
- **A stated limit**: attempts are counted per `(session, tool, tool_input_hash)`. A caller supplying
  no session id cannot have attempts correlated, so the budget does not engage for it. A deployment
  relying on `retry_budget` should also set `configure(require_session_id=True)`.
- **`ScoredAction.retry_count` is now written.** It was declared, serialised into the CLI JSON and the
  LangGraph state, and never set — a constant `0` in an evidence surface, which is a false zero rather
  than a missing value.
- `fivedrisk validate` no longer reports `retry_budget` as accepted-but-not-enforced, because it now is.

### Changed — BREAKING: fail-open is no longer a setting

- 🔴 **`configure(enforce_destination_policy=...)` is REMOVED.** It defaulted to `False`, under which a
  destination missing from a **declared** allowlist merely appended a note to the decision rationale and
  **left the verdict unchanged**. Declaring an allowlist is the enforcement decision; a configuration that
  lets a non-allowlisted destination proceed is a fail-open, and fail-open should not be a setting.
- **A destination missing from a declared allowlist is now always blocked.** If you set an allowlist and
  relied on the default to only warn, those actions now block. The denylist is unaffected — it always
  blocked.
- The `"warn"` destination decision is no longer produced by any path and its dead handling is removed.

### Added — policy provenance in the decision record

- **Policy presets load by name**: `load_policy("read_only")` resolves a packaged preset and records
  `preset_name` on the `Policy`. `list_presets()` enumerates them, and an unknown name raises with the
  loadable names listed. Loading a preset **by path** leaves `preset_name` unset, because a copied file is
  no longer the preset.
- 🔴 **`config_hash` and the new `policy_preset` column are now written by the production gate path.**
  `config_hash` previously had no production caller at all, so a decision record could not answer *which
  policy content decided*. Both are additive and nullable; on pre-existing logs, NULL means the column did
  not exist when the row was written, not that no policy applied.

### Fixed — silently ignored policy keys

- **`validate` now names any top-level policy key it is ignoring**, with a spelling suggestion when the
  key is a near miss of a real one. Previously `fivedrisk validate` returned `Policy valid` on a file
  containing `max_sesion_budget_tokens` — one letter short of `max_session_budget_tokens`, the only
  shipped cost control — so a budget cap could be authored, reviewed, approved and deployed while the
  cap stayed at its default. A silently ignored key is worse than a rejected one: it enters a change
  record as a control that does not exist.
- **`retry_budget` is reported as accepted but NOT ENFORCED.** It is parsed onto the `Policy` object and
  no code path reads it. It remains accepted so no existing policy breaks; it is scheduled for removal.

Both are warnings rather than errors, so no policy that validated before fails now.

### Fixed - destination extraction was gated on two hardcoded tool names

- **`extract_external_destinations` now reads the structured destination keys for EVERY tool**, not
  only for tools literally named `WebFetch` or `WebSearch`. The key names (`url`, `urls`, `domain`,
  `domains`, `host`, `hosts`) are the signal; the caller's tool name is not.

  **The gap was not uniform, which is what made it worth a release.** A generic URL pattern runs
  before the structured read and requires an alphabetic TLD, so a public host such as
  `evil.example.com` was still extracted from a custom-named tool while `http://127.0.0.1/admin` and
  `http://192.168.1.1/x` returned nothing at all. **Loopback and RFC1918 are the destination class a
  destination control most exists to catch**, so the control was blindest exactly where it mattered
  and appeared to work everywhere else.

  Found by using this library in another project, where the calling tool is named `speci.fetch_url`.
  The change only ever widens what is extracted, so a destination allowlist may now see hosts it did
  not see before; nothing that was extracted before stops being extracted.

### Fixed
- 🔴 **SEC-1: the checksum axis no longer reads across a field boundary.** Candidate extraction was
  performed over the joined tool input rather than per field, so a checksum-valid candidate could be
  assembled from digits belonging to two different fields, and a real identifier could be missed
  because the join altered the window around it. The second direction is the fail-open, and it is the
  one that was measured: against the published `0.6.0` wheel, with a Luhn-valid test PAN and a
  `checksum: luhn` floor declared, **17 of 26 combinations of a neighbouring field's rendering and
  its position failed to fire a floor that should have fired** (65.4%, Wilson 95% interval 46.2% to
  80.6%); **0 of the same 26 fail on this release**. Extraction is now bounded to the field it came
  from. The rate is quoted over renderings rather than over field names deliberately: the outcome
  turned on how a neighbouring value was written, not on which field it was, so a table labelled by
  field name is not reproducible from its labels.
- **`ActingIdentity` now actually reaches the audit log.** Its docstring said the fields "flow through to the audit log and NDJSON events unchanged". The NDJSON half was true; the audit-log half was not — `acting_identity` appeared **zero times** in `logger.py`, so a decision logged with an identity persisted nothing about who authorised it. A user reading that sentence believed their audit trail answered "who authorised this action" and it could not answer it at all. Now persisted as two queryable columns, `acting_principal_id` and `acting_principal_type`; absent identity stores NULL rather than a placeholder, so "no identity supplied" stays distinguishable from a real anonymous principal.
- **`update_outcome` no longer destroys the outcome sequence.** It overwrote the single `outcome` column, so a decision that went pending → approved → executed left no trace of having been anything but its last state, and "what happened, in what order" was unanswerable from the row that recorded it. `outcome` still holds the latest value and is still overwritten (no change for existing readers); the full ordered sequence now accumulates in a new `outcome_history` column.
- **`first_red_line_hit` now returns the STRICTEST firing rule, not the first one** (`fivedrisk.policy`). It ordered candidates on block-dominance alone and ignored `band`, so a soft floor listed earlier in the rule set swallowed a hard red line firing on the same action: the reduction could report YELLOW, or even GREEN, where `Policy.matched_floor` over the identical rules floored the action at RED. Two reductions over one rule set with opposite answers is a fail-open decided by list position. Band is now the primary sort key and block-dominance the tiebreak within a band, which preserves the sealed-blocklist rule (a blocklist hit is still reported ahead of an allowlist violation of the same severity) and keeps the short-circuit. Signature and return type are unchanged; behaviour is unchanged for any rule set whose floors share one band (including every set left at the `FloorRule` default of `Band.RED`) and for any action matched by a single rule, and where it differs it can only return a rule of band greater than or equal to the previous answer. The exposed shape is therefore narrow and worth stating precisely: a rule set that **mixes floor bands**, reduced through this exported helper rather than through `Policy.matched_floor` / `score()`, which were always band-correct. New regression suite `tests/test_red_line_reduction_strictest.py` pins the reduction contract, including the cross-reduction invariant that `first_red_line_hit` is never softer than `matched_floor`.

### Added
- **Floor attribution on the decision record: `ScoredAction.fired_rule_id` and `ScoredAction.floor_band`**, persisted as two nullable `decisions` columns. When a policy floor raises an action's band, the record now says WHICH rule did it and at what band, in a queryable field. Previously the only trace was prose appended to `rationale` (`"… [reason text]"`), degrading to the bare string `"floor:RED"` for a rule with no `reason` — so "a benign action was caught, show me the rule rather than the verdict" was a text-search question, and an unnamed floor rule was indistinguishable from no floor at all. `FloorRule.id` already existed and was simply discarded by the scorer; nothing new is computed. Two fields rather than one because `FloorRule.id` defaults to `""`: `floor_band` is set whenever a floor matched (that is what makes a hit observable), `fired_rule_id` only when the rule is named. Both are `None` when no floor matched, and `to_dict()` OMITS them in that case, so an unfloored action serialises byte-identically to before. `rationale` is unchanged — this adds a field, it does not move a fact out of a string. Attribution names the rule whose band was ENFORCED (the `matched_floor` winner), never an earlier weaker match. A pre-existing decision log is migrated on open with additive `ALTER TABLE`; historical rows read back `NULL` rather than a backfilled guess. New regression suite `tests/test_fired_rule_id_attribution.py`.
- **Audit-record columns: `config_hash` and the `prev_hash` / `record_hash` chain seam**, plus `Policy.content_hash()` and `DecisionLog.verify_chain()`. `policy_version` is a string the author types: two deployments can both say `0.2.0` with different thresholds, weights and floor rules, and a policy can change while its version stays the same — the case that matters when someone asks why an action scored differently last month. `config_hash` records which policy CONTENT decided (supply `policy.content_hash()` to `log()`; optional, so existing callers are unaffected). `record_hash` covers a row's decision-time fields folded together with the previous row's hash, so editing or deleting a row invalidates every later row rather than only its own, and `verify_chain()` reports the first row that does not recompute. **Stated limits, because an over-read integrity check is worse than none**: the chain deliberately excludes `outcome` / `outcome_history`, which are mutable by design — including them would make verification fail on ordinary authorised use, and an alarm that fires on correct work is one people learn to click past. It is tamper-EVIDENCE, not proof: the database is a local file, and anything that can write it can rewrite the tail. `content_hash()` is a content digest, not a signature — it proves two policies are the same policy, not that either is authentic.
- **All six new columns are additive and nullable, and old rows are never back-filled.** `DecisionLog.MIGRATION_NOTE` states what a pre-0.7.0 row cannot answer, in the words a reader needs: NULL in these columns means **the column did not exist when the row was written**, never "there was no identity", "no policy applied" or "the chain is intact". They cannot be back-filled — the identity and the policy content are not recoverable from a stored row, and a hash chain computed now over rows written earlier would attest to nothing. New suite `tests/test_decision_log_audit_columns.py`, including migration of a pre-existing log.
- **Public floor-rule compilers: `fivedrisk.parse_axis_predicate` and `fivedrisk.parse_value_match`**, plus `FieldValuePredicate` on the package root. `load_policy` compiles the `floor:` block for you when your policy is a YAML file on disk; callers whose policy lives in a database, a service config, an API payload, or a YAML shape of their own had no supported way to compile one axis spec, and the only compilers were private underscore symbols free to change without notice. Both dataclasses were already public, so hand-construction was always possible — and that is the trap this closes: building an `AxisPredicate` directly **skips every check the loader applies** (a non-empty `values`, an integer `negate_within >= 0`, cues present whenever `negate_within > 0`), so the identical spec could compile two ways and match differently depending on which path produced it. `AxisPredicate(values=())` is constructible and can never fire; the compiler refuses it. No behaviour change to any existing path: the functions are the ones `load_policy` has always used, exported under stable names, and the previous private names remain as aliases so existing imports keep working. New suite `tests/test_policy_public_compilers.py` pins the export, the aliases, and that the direct and loader paths agree on one spec.

### Added — documentation the code had shipped without

- **`SECURITY.md`.** Supported versions, how to report a vulnerability privately, what to
  expect and by when (stated as a target rather than a promise, because this is maintained in
  personal time), and the coordinated-disclosure posture. It carries the SEC-1 and SEC-2
  advisory for 0.6.0 and earlier, and it states what is OUT of scope for a security report,
  because the two things this library does not claim (authenticity, and any judgement about
  whether an agent's decision was correct) are the two it is most likely to be over-read as
  claiming.
- **`docs/audit-trail.md`.** `verify_chain()` and the six audit columns shipped in this
  release and were documented in the changelog and nowhere else. A changelog is a record of
  change, not documentation of state, and a reader arriving at 0.7.0 has no reason to read the
  0.6.x entries. The page shows the command and its **real output**, including what an edited
  row looks like (`ok: false`, `first_bad_id: 2`), and it repeats the limits before the
  capability: evidence rather than proof, a digest rather than a signature, and outcomes
  deliberately outside the chain. README now points at it from both the feature list and the
  audit-log section.
- **Three dead repo-relative links fixed**, and all 49 of them in the 23 tracked markdown
  files now resolve against the index. `fivedrisk/README.md` linked `LICENSE` from inside a
  subdirectory, so it resolved to `fivedrisk/LICENSE`, which does not exist. The validation
  notes linked `.github/workflows/ci.yml`, which resolved one directory too deep AND names a
  workflow that has never existed; the tracked workflows are `bench.yml` and `tests.yml`.

---
## [0.6.0] - 2026-07-25

> **0.6.0** — framework integrations. Adds native, fail-closed adapters for the mainstream 2026 agent frameworks over one shared verdict socket, a structured Claude Code hook, a TypeScript gateway client, a setup skill, two new red-line floor axes, and an opt-in decision-memory primitive. No break to the nine locked public symbols. Folds in the prepared-but-unpublished 0.5.4 remediation cycle.

### Added
- **Adapter kit** (`fivedrisk.adapters`) — `to_verdict()`, the one canonical scoring path every integration builds on (extracted from the gateway with no behavior change), plus the canonical never-demote `band_to_sentinel()` map (RED→block, ORANGE never execute, unknown→block).
- **Native framework adapters** (`fivedrisk.framework_adapters`) — thin fail-closed shims for **CrewAI** (`make_crewai_pre_tool_hook`), **OpenAI Agents SDK** (`make_openai_tool_input_guardrail`), **Google ADK** (`make_adk_before_tool_callback`), **Pydantic AI** (`make_pydantic_process_tool_call`), and **Microsoft Agent Framework** (`make_ms_agent_framework_middleware`). Frameworks are optional deps (lazy-imported); the package stays PyYAML-only.
- **Claude Code structured hook** (`fivedrisk.claude_code`, CLI `fivedrisk claude-hook`) — PreToolUse gate that maps ORANGE to Claude Code's native `ask` (human approval) instead of a hard deny, plus a PostToolUse verify-close that normalizes the tool-output field so egress leaks are actually scanned.
- **TypeScript gateway client** (`clients/typescript`, npm `fivedrisk-gateway`) — gate any JS/TS agent through the engine over the JSON-lines gateway, with guards for **Vercel AI SDK** (`guardVercelTool`) and **Genkit** (`guardGenkitTool`). Fails closed on every transport failure.
- **Setup skill** (`fivedrisk-setup`) — install → detect your framework → wire the adapter → verify → run an example, plus a field-engineering reference.
- **Red-line floor matcher axes** (`fivedrisk.policy`) — `value_match` (`FieldValuePredicate`) binds a predicate to a NAMED field's VALUE (not the joined haystack of all values), and an opt-in token-window negation (`negate_within` / `negate_cues`) suppresses a pattern hit when a negation cue is within N tokens. Both fail closed: the regex axes treat an oversize (>100k) haystack as a hit rather than truncating and silently missing a token past the cap, and `value_match` scans every same-named field so a case-variant key cannot shadow a dangerous value.
- **Decision memory** (opt-in, `fivedrisk.logger`) — a store for decisions you explicitly choose to keep. Storage-only and inert by default: it has no engine consumer, so a remembered decision can never override or demote a fresh score.

### Fixed
- `examples/minimal_gate.py` caught `ValueError`, but `@gate` raises `BandBlockError` (a `FivedriskDenial`, which deliberately does not subclass `ValueError`), so the demo crashed on the RED block it exists to show. Fixed and regression-locked.

---
## [0.5.4] - 2026-07-13

> **0.5.4** (2026-07 remediation cycle, audit `CODE_AUDIT_2026-07-06.md`). No public-API break: the nine locked symbols (`score`, `classify_tool_call`, `Action`, `ScoredAction`, `Band`, `Policy`, `load_policy`, `DecisionLog`, `hooks.gate`) are unchanged.

### Fixed — engine correctness
- **Bash-override risk downgrade (H1).** `Policy.get_bash_overrides` now takes the per-dimension **max** across matching patterns; `docker exec … rm -rf` no longer scores lower (ORANGE) than plain `rm -rf` (RED).
- **Drift (Low-11/Low-12/M16/M17).** The Markov tracker keeps feeding its counter fallback in the high-risk regime; `_apply_drift` re-routes with the effective policy (honors `yellow_model_escalation`); unobserved absorbing states get identity rows; markov input validation raises `ValueError` (survives `python -O`).
- **`@gate` policy binding (M3).** Policy/log resolve at call time, so a `configure()` after decoration is honored (was silently pinned to defaults).
- **Unconfigured hook overhead (M4).** A shared default `DecisionLog` replaces per-call construction (no per-call schema DDL).
- **Session-state growth + thread safety (M1/M2).** Budget reservation and per-session state are lock-guarded; `_drift_trackers`/`_budget_accumulators` are FIFO-capped.
- **Destination userinfo bypass (M8).** `https://allowed@evil.com` now resolves to `evil.com`.
- **Policy regex safety (M5).** A malformed `bash_overrides` regex is skipped (defined best-effort) instead of crashing scoring; `validate` compiles them.
- **PostToolUse egress blocks are now audited (M7).** `DecisionLog.log_egress_block` records leakage/injection-echo/semantic-review blocks.
- **Decision-log fallback path (M18).** Falls back to a per-uid `0700` temp subdir, not a squattable fixed name.
- **`DecisionLog` corrupted-file recovery.** Catches `DatabaseError` (superclass) and falls back to a writable temp DB.
- **langgraph node (M14) / minimal example (M15).** Docstrings match the real band contract; the destructive example is simulated (no real shell).

### Fixed — integrations (C1/H6–H10, M12)
- **OpenClaw plugin ↔ gateway wire protocol (C1).** Reconciled: gateway emits a startup `{"ready", protocol_version}` handshake + echoes request `id`; the plugin conforms (flat request/decision, startup timeout). Live end-to-end test added.
- **Claude Code hook (H6).** ORANGE now exits `2` (blocks) with stderr guidance; the plugin reads hook input from stdin, not an empty env var.
- **Generated-policy YAML injection (H7) + duplicate `tool_defaults` (H8).** Keys are allowlisted; generated entries merge into the preset's block instead of overwriting it.
- **Playbook CLI commands (H9), skill demo policy load (H10), bridge reliability (M12).** Corrected to real subcommands; `configure(policy_path=…)`; stdin error listener, null-line guard, restart mutex, per-child timers.

### Fixed — CI & docs (H5/M13/M19, M7)
- **Perf-regression gate (H5/M13).** Env mismatch now fails instead of skipping; CI runs on a baseline-matched runner; median-of-N + ratio-and-absolute gate removes false failures.
- **Test-count reconciliation (M19).** README claim matches the live count; the docs-currency guard is now strict.
- **Canonical docs (M7).** `docs/spec/taxonomy.md` (bands vs dispositions), `docs/spec/deployment.md`, and a decision-log alerting runbook.

### Added
- **`scan-output` CLI subcommand (E1).** Wraps the shipped `fivedrisk_post_tool` egress scan (leakage / injection-echo) so the Claude Code plugin's PostToolUse hook can block on tool output (`python -m fivedrisk scan-output -`, exit 2 on block).
- **Gateway governance parity (E2).** `fivedrisk.gateway` (non-Python hosts) now reuses the SDK input layers: prompt-injection scan + policy-driven semantic review before scoring (a hit blocks), and Markov session-drift after scoring. Destination policy stays SDK/configure-side.
- **`FivedriskDenial`** base exception (see below).
- **`SessionRequiredError` / `DestinationBlockError`** — two new `FivedriskDenial` subclasses for the session-required and destination-policy gate blocks (see the Changed — BEHAVIOR note).
- **`validate` floor-control warning.** `fivedrisk validate` now warns when a RED/ORANGE floor rule is gated on `command_contains` — a best-effort, case-sensitive substring that is evadable (casing/whitespace/encoding). Hard/regulated controls should key on `tool_name` alone (unconditional). `FloorRule` docstring + README floor example updated to steer hard controls to `tool_name`-only floors.

### Fixed — validate accuracy
- **`green_score` placement warning (docs-guard follow-up).** `green_score` is removed from the band-score placement-warning key set: it is the "everything below yellow" floor (always 0.0) and `load_policy` never reads it from `bands:`, so warning an operator to "move it under `bands:`" was misleading (it is inert wherever placed). The placement warning now only covers the three keys `bands:` actually reads (`yellow_score`/`orange_score`/`red_score`).

### Fixed — test isolation
- **Autouse config-flag reset (`tests/conftest.py`).** `configure()` mutates process-global flags (`require_session_id`, destination allow/deny lists); a test that set one leaked it into later tests, making the suite order-dependent. An autouse fixture now restores those scalar flags to their module defaults after each test.

### Changed — BEHAVIOR
- **Denial exceptions no longer subclass `ValueError` (Low-9).** `BudgetExceededError` and `IdentityRequiredError` now subclass a new `FivedriskDenial` base, not `ValueError`. A gate DENY that subclassed `ValueError` was silently swallowed by any caller's broad `except ValueError` — a fail-open. **Action required if you caught denials via `except ValueError`:** catch `FivedriskDenial` (or the specific subclasses) instead.
- **Sibling `@gate` blocks now fail-closed (Low-9 follow-up).** The two remaining `@gate` DENY sites that still raised a bare `ValueError` — the **session-required** block and the **destination-policy** block (sync + async) — now raise `SessionRequiredError` and `DestinationBlockError` (both `FivedriskDenial` subclasses), so a caller's broad `except ValueError` can no longer swallow them and let the action run. **Action required if you caught these via `except ValueError`:** catch `FivedriskDenial` (or the specific subclasses) instead. Adversarial QA reproducers cover both sites.
- **Model routing ships no opinionated model names (Low-5).** `DEFAULT_MODEL_CONFIGS` model names are now `None` (M0–M4 structure + tuning + `configs=` override retained); populate models for your own stack. `ModelConfig.is_local`/`is_cloud` now derive from the model class/tier. The cost table (`token_costs.py`) is unchanged.
- **`EscalationSignal.confidence` defaults to `None` (Low-3)** — "not reported" no longer forces escalation (was `0.0`, which always escalated a default-constructed signal).

### Fixed — low-severity batch (L1–L22)
- Reversibility classifier lookahead removed (Low-2); router `get_config` no longer KeyErrors (Low-4); token_costs docstring matches code (Low-8); `DecisionLog` sets `busy_timeout` for concurrent writers (Low-13); benchmark percentile off-by-one + no in-place sort (Low-14); benchmark temp DBs pid-unique + cleaned up (Low-16); CI runs the bench once (Low-18); `tests/golden_set/*.json` now ships in the wheel (Low-19); plus Low-1/6/7/15/17/22. `rate_limit_check` + HITL-queue counters (dead, never invoked) removed (Low-10); `configure()` drops the `rate_limit_max`/`hitl_queue_max` kwargs.

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

---

## Earlier

Pre-v0.4.0 history is captured in `ARCHITECTURE.md` (spec-coverage matrix from v0.3.0 baseline) and `VALIDATION_NOTES_2026-04-14.md`.
