# fivedrisk — AI Agent Risk Governance Engine

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml/badge.svg)](https://github.com/theDoc001/fivedrisk/actions/workflows/tests.yml)

**Per-action risk scoring and governance for AI agents.** Drop one decorator on your tool functions, or wire in the Agent SDK hooks — every action is scored, gated, and logged before it runs.

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
- **424 tests** with 0 failures

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
from fivedrisk import load_policy

configure(policy=load_policy("policy.yaml"))

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
```

Runs 39 offline attack scenarios across: prompt injection (12 categories), output leakage (8 categories), runtime tool misuse (19 scenarios). No external API calls. Deterministic. Safe to run in CI.

---

## Performance

Measured on Apple Silicon M1, Python 3.14, single-thread, quiet system. Reproducible from `benchmarks/bench_minimal.py`.

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

External optional layers (not in fivedrisk):

- [PromptArmor](https://promptarmor.com): ~20-30ms typical
- [LLM Guard](https://llm-guard.com) (token scanners): ~10-15ms typical
- [LLM Guard](https://llm-guard.com) (ML scanners): ~50-200ms typical

Injection scanner is linear in input length; for large RAG contexts, chunk and parallelize. macOS background scheduling can widen p99 under load; numbers above are quiet-system. SQLite writes are substantially slower inside iCloud Drive directories (not a fivedrisk issue).

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

Per-session token budgeting with direct DENY at @gate when a reservation would exceed the session cap. Pure accounting; the budget accumulator does NOT feed the 5D Score function.

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

If the projected token spend exceeds `max_session_budget_tokens`, @gate raises `BudgetExceededError` directly and emits a `budget_intervention` NDJSON event. The 5D Score function is not modified by budget pressure; budget breach is a separate admission gate.

Additional Operational FinOps capabilities (Tool Manifest admission layers, useful-progress monitoring, multi-agent budget envelopes, wall-clock / retry / delegation caps) are on the project roadmap.

---

## Planned

Future capability surfaces signalled here for search and contributor expectations. No commitment dates.

- SPIFFE / MCP reference example (end-to-end workload identity demo)
- MITRE ATLAS coverage with real tests
- NIST AI RMF mapping
- OWASP Agentic Top 10 coverage doc
- Regulatory crosswalks (AI Act Article 12, NIS2, DORA, ISO 42001)
- Decision log analysis cookbook (sample SQL for common compliance queries)

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
└── tests/           # 424 tests
```

**Coverage**: 14/21 governance spec sections fully implemented.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [Loren Angoni](https://langoni.me). Contributions welcome.

> "An ambition that doesn't get executed is a hallucination."
