# fivedrisk — AI Agent Risk Governance Engine

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml/badge.svg)](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/fivedrisk.svg)](https://pypi.org/project/fivedrisk/)

**fivedrisk is the fast deterministic policy gate that runs before your LLM-based safety stack.**

Every AI agent action is scored on five risk dimensions, banded GREEN / YELLOW / ORANGE / RED, and resolved in 0.2 to 2.9 ms on a single CPU thread. No LLM in the decision path. No external service. No hyperscaler dependency. Apache 2.0. **Built in Vienna, Austria. Architecturally sovereign: no external services, no hyperscaler dependency, runs entirely on your own infrastructure.**

### The two-stage gate

The two stages answer different questions. fivedrisk asks whether an action is permitted: rules evaluated over the action envelope, its policy, the caller's identity and the sequence so far, with the record naming the policy that decided. A semantic scanner asks whether a span of text is malicious or sensitive, which is a judgment, and it is reserved for the YELLOW and ORANGE bands where that judgment is what the decision turns on.

The order is the design. The deterministic stage runs first and reaches a verdict with no model call, so every action it resolves costs no inference, no round trip and no tokens, and no prompt leaves your estate. The expensive stage runs only where it changes the outcome.

They run in series because the questions differ, not because one is a cheaper version of the other. A deterministic gate fails by holding a wrong rule, which you can read, test and fix. A semantic scanner fails by making a wrong call on an input nobody anticipated. Neither failure mode substitutes for the other.

How much of your action volume never reaches the second stage depends on your traffic and your policy, and that fraction is what decides the saving. Measure it on yours rather than taking a number from a README.

```
agent action
    │
    ▼
[fivedrisk]  ← 0.2 to 2.9 ms, deterministic, audited
    │
    ├── GREEN  ─────────────► execute
    ├── YELLOW ─► LLM scanner ──► execute / log / escalate  (100–700 ms only when needed)
    ├── ORANGE ─► HITL ────────► approve / deny
    └── RED    ─────────────► block, audit, alert
```

### What fivedrisk is

A runtime action-governance layer for AI agents. Per-action 5D scoring, HITL escalation, append-only audit log, 16-state Markov SafetyDrift for compositional attacks, identity passthrough, NDJSON event stream for SIEM. Think OPA for AI agents.

### What fivedrisk is not

A general LLM guardrail suite. A semantic content scanner. A replacement for one. A replacement for best practices in AI governance (tool and scope narrowing, prompt guardrails, system prompts). It is the deterministic pre-filter that lets those scanners and practices scale.

### Quickstart in 5 minutes

```bash
pip install fivedrisk
python -c "import fivedrisk; print(fivedrisk.__version__)"
```

Full walkthrough including scope-narrowing guidance and per-deployment tuning: [`docs/quickstart.md`](../docs/quickstart.md). Copy-paste-runnable integrations: [`examples/`](../examples/). Policy presets for common deployment archetypes: [`fivedrisk/policies/presets/`](policies/presets/).

```python
from fivedrisk.hooks import gate

@gate(tool_name="write_to_database", autonomy_context=2)
async def write_record(table: str, data: dict) -> None:
    ...  # only executes if 5D scores GREEN or YELLOW
         # ORANGE → human approval required
         # RED    → blocked, never runs
```

---

## What it does

fivedrisk scores every AI agent action on **5 risk dimensions** (0–4 each):

| Dimension | What it measures |
|---|---|
| **D** — Data Sensitivity | Public → PII → financial → credentials |
| **T** — Tool Privilege | Read-only → write → admin → destructive |
| **R** — Reversibility | Undoable → hard-to-undo → irreversible |
| **E** — External Impact | Local → internal API → external → untrusted |
| **A** — Autonomy Context | User-direct → agent-supervised → fully autonomous |

5D stays deterministic. Bands signal what fivedrisk wants your stack to do; your stack chooses the LLM and the workflow.

**Default 3-band:**

- **GREEN** — execute, normal logging.
- **ORANGE** — HITL approval required. fivedrisk signals; your stack handles the LLM choice. No auto model promotion.
- **RED** — blocked.

**Opt-in 4-band compliance mode** (`enable_yellow_band: true` in `policy.yaml`): surfaces YELLOW as a stable moderate-risk tier for audit queries and dashboards. Optional model escalation within YELLOW via `yellow_model_escalation: true`.

fivedrisk is one layer in a defence-in-depth AI governance stack.

---

## Features

- **5D scoring engine** — deterministic, ~40µs per action (p50) on M1, no LLM calls
- **Markov SafetyDrift** — 16-state Markov chain detects cumulative risk across action sequences; catches compositional attacks that individual scoring misses
- **Session accumulator** — O(1) counter-based drift tracking for the common case
- **Injection scanner** — 24+ regex patterns covering GPT-5/Opus-era evasion (Base64, zero-width Unicode, role hijacks, encoded exec calls)
- **Output leakage scanner** — PII, credentials, crypto keys, injection-echo detection
- **`@gate` decorator** — wrap any sync or async function with full 5D gating
- **Agent SDK hooks** — `fivedrisk_pre_tool` / `fivedrisk_post_tool` for Anthropic Agent SDK
- **LangGraph node** — drop-in integration for LangGraph pipelines
- **Destination policy** — allowlist/denylist for outbound endpoints
- **Audit log** — append-only SQLite decision log plus optional NDJSON event stream for SIEM delivery
- **Policy floor enforcement** — floor rules in `policy.yaml` cannot be overridden at runtime
- **Defence-in-depth test suite** — pytest markers per OWASP LLM Top 10 category, plus 39-scenario attack-class benchmark (`python -m fivedrisk benchmark`)
- **418 tests** with 0 failures

---

## Install

```bash
pip install fivedrisk
```

For LangGraph integration:
```bash
pip install "fivedrisk[langgraph]"
```

---

## Quick start (30 seconds)

```python
from fivedrisk import classify_tool_call, score, load_policy, Band

policy = load_policy("policy.yaml")  # or use defaults
action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"}, policy)
result = score(action, policy)

print(result.band)                      # Band.ORANGE
print(result.rationale)  # "ORANGE — Bash: Reversibility=3 (≥ ORANGE threshold 3)"
print(result.routing)    # RoutingDecision(model_floor=M3, approval_required=True)
```

**With the `@gate` decorator:**
```python
from fivedrisk.hooks import gate, configure

configure(policy_path="policy.yaml")

@gate(tool_name="send_email", autonomy_context=1)
def send_email(to: str, body: str) -> None:
    # only executes if 5D scores GREEN or YELLOW
    smtp.send(to, body)
```

**With Anthropic Agent SDK:**
```python
from fivedrisk.hooks import fivedrisk_pre_tool, fivedrisk_post_tool

# Register as PreToolUse and PostToolUse hooks in your agent
```

**With LangGraph:**
```python
from fivedrisk.langgraph_node import fivedrisk_gate_node
# Add fivedrisk_gate_node to your StateGraph before any tool-executing node
```

---

## SafetyDrift — why sequence risk matters

A single READ of a config file scores GREEN. But 10 GREENs followed by a write to an external API using credentials extracted two steps earlier is a RED sequence. Most tools miss this.

fivedrisk tracks cumulative session state via a **16-state Markov chain** over `(data_exposure_tier × activity_risk_tier)`. When absorption probability into a dangerous state crosses 0.3, the next action is escalated to ORANGE. At 0.7, it's escalated to RED.

```python
from fivedrisk.markov import MarkovDriftTracker, make_default_transition_matrix

tracker = MarkovDriftTracker(make_default_transition_matrix(), session_id="abc")
bump = tracker.record(scored_action)
if bump:
    print(f"Drift: {bump.reason}, escalated to {bump.escalated_band}")
```

---

## Policy configuration

```yaml
# policy.yaml
thresholds:
  red_threshold: 4
  orange_threshold: 3
  orange_score: 1.8
  yellow_score: 1.0

[floor]
# These rules block regardless of per-action score
- tool_name: "Bash"
  command_contains: "DROP TABLE"
  band: RED
  reason: "floor:no-destructive-sql"
```

---

## Benchmark

```bash
python -m fivedrisk benchmark
python -m fivedrisk benchmark --format json --include-results
python -m fivedrisk validate policy.yaml
python benchmarks/bench_aiid_patterns.py
```

Runs 39 offline expectation checks across: prompt injection (14 scenarios), egress/output leakage (12 scenarios), runtime policy (10 scenarios), and retrieved-content fixtures (3 scenarios). No external API calls. Deterministic. Safe to run in CI.

A passing run means observed behavior matched the built-in scenario expectations. It includes positive controls that should be detected, escalated, blocked, or isolated, plus negative controls that should be allowed. It is not open-ended adversarial proof; real deployment evidence needs targeted profiles, unseen cases, baseline comparison, and optional observer/HITL measurements.

Deployment profiles can add `semantic_review_patterns` to escalate content classes, such as impersonation or high-impact medical claims, to an observer/HITL path without changing the default deterministic gate.

---

## Performance

Measured on Apple M1, single-thread. Reproducible from `benchmarks/bench_minimal.py`.

| Operation | p50 | p99 |
|---|---|---|
| **5D core (classify + score)** | **40µs** | **42µs** |
| Injection scan, 30 char clean | 11µs | 12µs |
| Injection scan, 3000 char clean | 669µs | 685µs |
| Leakage scan, 200 char clean | 23µs | 23µs |
| 5D + injection + leakage scan | 64µs | 65µs |
| 5D + Markov drift | 43µs | 44µs |
| 5D + SQLite audit-log write (I/O) | 440µs | 1ms |
| `@gate` sync overhead (incl. log write) | 439µs | 1.1ms |
| `@gate` async overhead | 421µs | 660µs |

The numbers above are fivedrisk's own. This project publishes no timing for any other tool: measure your chosen semantic scanner on your own traffic.

Injection scanner is linear in input length; for large RAG contexts, chunk and parallelize. Run the bench script on your target hardware for numbers that match your install.

---

## Audit log

fivedrisk produces an append-only decision log entry for every agent action. Each entry records:
- Risk band and rationale
- Dimension scores (all 5 axes)
- Model routing decision and approval history
- Session drift state
- Injection and leakage scan results
- Optional agent identity claim (see below)

### Agent identity passthrough

fivedrisk accepts opaque agent identity claims through `Action.metadata["agent_identity"]`. The string flows through unchanged into the audit log for SOC/SIEM correlation. SVID, JWT, and X.509 subject strings are supported as opaque data today.

```python
action.metadata["agent_identity"] = "spiffe://example.org/agents/triage-bot"
```

Cryptographic validation, structured parsing, and identity-aware policy hooks are post-OSS scope.

### Reserved metadata keys

- `agent_identity` — opaque identity claim string. Do not overwrite with arbitrary values.

---

## Identity capture

`Action.acting_identity` is a typed pass-through primitive for the principal an action is being taken on behalf of. Distinct from `agent_identity` (the AI agent's own workload identity); `acting_identity` is who authorized the action.

```python
from fivedrisk import gate, ActingIdentity, PrincipalType, AttestationSource

ai = ActingIdentity(
    principal_id="user-42",
    principal_type=PrincipalType.USER,
    attestation_source=AttestationSource.HTTP_HEADER,
)

# Per-call override
fn("...", session_id="s1", _fivedrisk_acting_identity=ai)
```

Declare `identity_required: true` in `policy.yaml` to deny actions where the caller supplied no identity. The deny surfaces as `IdentityRequiredError` and emits an `identity_required_denial` NDJSON event.

Identity-aware policy evaluation beyond admission, cryptographic validation, and SPIFFE/SPIRE native binding are post-OSS scope.

---

## Cost management primitives

Per-session token budgeting with direct DENY at @gate when a reservation would exceed the session cap.

```yaml
# policy.yaml
max_session_budget_tokens: 100000
max_tool_call_budget_tokens: 4096
```

```python
from fivedrisk import gate, configure

configure(event_path="audit.ndjson", default_model_class="claude-sonnet-class")

@gate(tool_name="summarize", estimated_input_tokens=2000)
def summarize(text: str, session_id: str) -> str:
    ...
```

If the projected token spend exceeds `max_session_budget_tokens`, @gate raises `BudgetExceededError` and emits a `budget_intervention` NDJSON event.

Additional Operational FinOps capabilities (Tool Manifest admission layers, useful-progress monitoring, multi-agent budget envelopes, wall-clock / retry / delegation caps) are on the project roadmap.

---

## Non-Python integrations (gateway)

Non-Python hosts (Node, Go, Rust, the OpenClaw plugin) call the engine over JSON-lines via `fivedrisk.gateway`:

```bash
python -m fivedrisk.gateway stdio --policy policy.yaml   # long-lived, one JSON request/decision per line
python -m fivedrisk.gateway score --policy policy.yaml   # one-shot
```

**The gateway has governance parity with the SDK hooks.** It classifies, scores, bands, logs, and also reuses the input layers: prompt-injection scanning and policy-driven semantic review run before scoring (a hit blocks with `band: "RED"`), and Markov session-drift is applied after scoring (drift accumulates across calls on a `stdio` connection). The one layer that stays SDK/configure-side is the destination allow/deny policy — it's driven by `configure()` arguments, not the policy file the gateway loads.

---

## Documentation & reference

- **Taxonomy (bands vs dispositions)** — `docs/spec/taxonomy.md`. The single source of truth for what GREEN/YELLOW/ORANGE/RED mean and how they map to the EXECUTE/LOG_ELEVATED/ROUTE_OBSERVER/ROUTE_HITL/BLOCK disposition ladder.
- **Deployer setup guide** — `docs/spec/deployment.md`. Band→disposition ladder, session budget cap, and the fail-closed default.
- **Decision-log cookbook + alerting runbook** — `decision-log-cookbook.md`. Audit queries plus, for every operational signal the engine emits, where it lands and a recommended SIEM alert.

### Other public modules a deployer can reach

- **Destination egress policy** — `check_destination_policy` (in `fivedrisk.hooks`): allow/deny outbound hosts; enable via `configure(destination_denylist=[...], destination_allowlist=[...])`. A destination missing from a declared allowlist is **blocked** — there is no setting that downgrades it to a warning.
- **NDJSON event stream** — `NDJSONEventChannel` (`fivedrisk.events`): `risk_decision` / `budget_intervention` / `identity_required_denial` events for SIEM correlation; enable via `configure(event_path="audit.ndjson")`.
- **Session token budget** — `BudgetAccumulator` (`fivedrisk.budget_accumulator`): see §Cost management primitives above.
- **Gateway** — `fivedrisk.gateway`: see §Non-Python integrations above (SDK-parity: injection + semantic review + drift; destination policy stays SDK-side).

---

## Planned

Future capability surfaces signalled here for search and contributor expectations. No commitment dates.

- SPIFFE / MCP reference example (end-to-end workload identity demo)
- NIST AI RMF mapping

---

## Architecture

```
fivedrisk/
├── schema.py        # Band, Action, ScoredAction, HITLCard, ModelClass
├── scorer.py        # score(), model routing (§12-19)
├── classifier.py    # classify_tool_call() with policy baselines
├── hooks.py         # @gate, Agent SDK hooks, injection/leakage scanners
├── drift.py         # SessionAccumulator (O(1) counter-based)
├── markov.py        # MarkovDriftTracker, Gauss-Jordan, absorption probs
├── detectors.py     # Versioned detector corpus (2026-04-14.2)
├── policy.py        # Policy dataclass + YAML loader
├── router.py        # ModelRouter, EscalationSignal
├── logger.py        # DecisionLog (SQLite, append-only)
├── langgraph_node.py# LangGraph integration
├── benchmarks.py    # 39-case offline benchmark harness
└── tests/           # 418 tests
```

**Coverage**: 14/21 governance spec sections fully implemented.

---

## License

Apache 2.0. See [LICENSE](../LICENSE).

Built by [Loren Angoni](https://langoni.me). Contributions welcome.

> "An ambition that doesn't get executed is a hallucination."
