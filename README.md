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

![fivedrisk demo — injection blocked, rm -rf stopped, SafetyDrift escalation](https://github.com/user-attachments/assets/5d6b9631-c36b-4674-bd3f-3897555f26f8)

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

Actions receive a band: **GREEN** (execute) / **YELLOW** (log + conditional) / **ORANGE** (HITL required) / **RED** (blocked).

---

## Features

- **5D scoring engine** — deterministic, <1ms per action, no LLM calls
- **Markov SafetyDrift** — 16-state Markov chain detects cumulative risk across action sequences; catches compositional attacks that individual scoring misses
- **Session accumulator** — O(1) counter-based drift tracking for the common case
- **Injection scanner** — 24+ regex patterns covering GPT-5/Opus-era evasion (Base64, zero-width Unicode, role hijacks, encoded exec calls)
- **Output leakage scanner** — PII, credentials, crypto keys, injection-echo detection
- **`@gate` decorator** — wrap any sync or async function with full 5D gating
- **Agent SDK hooks** — `fivedrisk_pre_tool` / `fivedrisk_post_tool` for Anthropic Agent SDK
- **LangGraph node** — drop-in integration for LangGraph pipelines
- **Destination policy** — allowlist/denylist for outbound endpoints
- **Audit log** — append-only SQLite decision log, every action recorded
- **Policy floor enforcement** — floor rules in `policy.yaml` cannot be overridden at runtime
- **OWASP-aligned benchmark suite** — 39 offline attack scenarios (injection, exfiltration, drift)
- **309 tests** — 0 failures

---

## Install

```bash
pip install fivedrisk

# With LangGraph integration
pip install "fivedrisk[langgraph]"
```

Or from source (latest main):
```bash
pip install git+https://github.com/theDoc001/fivedrisk.git
pip install "git+https://github.com/theDoc001/fivedrisk.git#egg=fivedrisk[langgraph]"
```

---

## Quick start (30 seconds)

```python
from fivedrisk import classify_tool_call, score, load_policy, Band

policy = load_policy("policy.yaml")  # or use defaults
action = classify_tool_call("Bash", {"command": "rm -rf /tmp/cache"}, policy)
result = score(action, policy)

print(result.band)       # Band.ORANGE
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
from fivedrisk.langgraph_node import fivedrisk_node
# Add fivedrisk_node to your StateGraph before any tool-executing node
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

## Audit log

fivedrisk produces an append-only decision log entry for every agent action. Each entry records:
- Risk band and rationale
- Dimension scores (all 5 axes)
- Model routing decision and approval history
- Session drift state
- Injection and leakage scan results

---

## Architecture
```text
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
└── tests/           # 309 tests
```


**Coverage**: 14/21 governance spec sections fully implemented.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [Loren Angoni](https://langoni.me). Contributions welcome.

> "An ambition that doesn't get executed is a hallucination."
